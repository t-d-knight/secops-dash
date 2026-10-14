#!/usr/bin/env python3
"""
Monthly per-site action pack: the lists a service has to work through, as
one Excel workbook per site (plus a whole-of-region one with a Site column).
The exec report (exec_report.py) says how things are trending; this says
which accounts, hosts and external risks to fix.

Tabs:
  Summary              row counts per tab, as-at date, how to use it
  Stale accounts       Falcon Identity STALE_ACCOUNT
  Weak-compromised pw  WEAK_PASSWORD / CREDENTIAL_THEFT (same pair as the exec report tile)
  Duplicate passwords  DUPLICATE_PASSWORD
  No MFA - people      ACCOUNT_WITHOUT_MFA_CONFIGURED, people and generic logons
  No MFA - svc&mailbox the same for service accounts / mailboxes (usually a cloud-sync scope fix)
  Generic accounts     accounts classified generic (identity_categories.classify_account)
  VPN & remote-app     extra shared-domain accounts for VPN / MANAD over RDS (identity_categories.classify_access)
  Stale sensors        managed hosts silent longer than reporting.stale_sensor_days
  Missing sensors      machines with no Falcon sensor: in-use AD computer accounts (servers,
                       DCs, workstations) first, then devices only seen on the network
  External risks       Hadrian: confirmed risks (verified / unpatched tech / infected
                       device) plus anything critical/high, incl. infostealer infections
  USB file writes      per person x PC x USB drive for the month: files and volume by
                       category, folders, the biggest business files, flags to follow up
  USB drives           each drive used: make/model/serial, how many people and PCs
  USB malware          detections from the scan Falcon runs when a drive is plugged in

The USB tabs cover the previous calendar month (the pack runs on the 1st);
everything else is as at the run date.

Endpoint vulnerability tabs (top remediations, worst endpoints/servers) are
deliberately not here yet: Falcon vulnerability assessment currently covers
~9% of active hosts (2026-10-06), so those lists would name dormant machines.
Add them once coverage is fixed.

Account names are NOT masked here (unlike the exec report) -- the service
needs them to act. These files hold real usernames and compromised-account
details: distribute per site, to that site's contacts only.

    python3 action_pack.py --config config.yaml              # every site + region
    python3 action_pack.py --config config.yaml --site SITE-A
    python3 action_pack.py --config config.yaml --since 2026-10-01 --until 2026-10-31   # USB period

Writes reports/monthly-YYYY-MM/<site>-actions-YYYY-MM.xlsx (gitignored).
"""
import argparse
import datetime as dt
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

import config as config_mod
import discovery_classes as dc
import identity_categories as ic
import usb_categories as uc
from db import pg_connect

SITE = "(%(site)s::text IS NULL OR {col} = %(site)s::text)"
HEADER_FILL = PatternFill("solid", fgColor="0F172A")
HEADER_FONT = Font(bold=True, color="FFFFFF")
TITLE_FONT = Font(bold=True, size=14)

IDENTITY_COLS = ["Display name", "UPN", "Account (SAM)", "Account type", "Shared-domain access", "Domain", "OU",
                 "Enabled", "Identity risk", "Password last changed", "Created", "Other risk factors"]
ACCESS_LABEL = ("CASE e.access_account " + " ".join(f"WHEN '{k}' THEN '{v}'" for k, v in ic.ACCESS_LABEL.items())
                + " ELSE '' END")
KIND_LABEL = ("CASE COALESCE(e.account_kind, 'human') WHEN 'human' THEN 'Person' WHEN 'service' THEN 'Service' "
              "WHEN 'mailbox' THEN 'Mailbox/resource' WHEN 'generic' THEN 'Generic' ELSE e.account_kind END"
              " || CASE WHEN e.is_privileged THEN ' (admin)' ELSE '' END")


def identity_sql(factors: Sequence[str], with_issue: bool = False, kinds: Optional[Sequence[str]] = None) -> str:
    """Accounts carrying any of `factors`, enabled first, then by identity
    risk. "Other risk factors" lists everything else flagged on the account,
    so a service can see e.g. a stale account that also has no MFA."""
    flist = ", ".join(f"'{f}'" for f in factors)
    issue = (f"string_agg(DISTINCT f.factor_type, ', ') FILTER (WHERE f.factor_type IN ({flist})) AS issue, "
             if with_issue else "")
    return f"""
        SELECT e.site_label, {issue}e.display_name, e.upn, e.sam_account_name, {KIND_LABEL}, {ACCESS_LABEL},
               e.domain, e.ou,
               CASE WHEN e.enabled THEN 'Yes' WHEN e.enabled IS FALSE THEN 'No' ELSE '?' END,
               initcap(e.risk_severity), e.password_last_change::date, e.account_created::date,
               (SELECT string_agg(o.factor_type, ', ' ORDER BY o.factor_type) FROM identity_risk_factors o
                 WHERE o.source = e.source AND o.entity_id = e.entity_id AND o.factor_type NOT IN ({flist}))
        FROM identity_entities e
        JOIN identity_risk_factors f ON f.source = e.source AND f.entity_id = e.entity_id
        WHERE NOT e.retired AND f.factor_type IN ({flist}) AND {SITE.format(col="e.site_label")}
          AND COALESCE(e.account_kind, 'human') <> 'out_of_scope'
          {f"AND COALESCE(e.account_kind, 'human') IN {ic.sql_in(kinds)}" if kinds else ""}
        GROUP BY e.source, e.entity_id
        ORDER BY e.enabled IS NOT TRUE,
                 CASE e.risk_severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                 e.display_name"""


TABS: List[Tuple[str, str, List[str], str]] = [
    # (tab name, sql, columns after Site, what to do)
    ("Stale accounts", identity_sql(["STALE_ACCOUNT"]), IDENTITY_COLS,
     "Accounts with no recent activity. Disable (or confirm still needed) -- enabled ones first."),
    ("Weak-compromised pw", identity_sql(["WEAK_PASSWORD", "CREDENTIAL_THEFT"], with_issue=True),
     ["Issue"] + IDENTITY_COLS,
     "Weak or stolen passwords. Force a reset; for CREDENTIAL_THEFT also review recent sign-ins."),
    ("Duplicate passwords", identity_sql(["DUPLICATE_PASSWORD"]), IDENTITY_COLS,
     "Accounts sharing a password with another account. Reset to unique passwords."),
    ("No MFA - people", identity_sql(["ACCOUNT_WITHOUT_MFA_CONFIGURED"], kinds=("human", "generic")), IDENTITY_COLS,
     "People (and generic logons) with no MFA method registered. Enrol, or disable if unused."),
    ("No MFA - svc & mailbox", identity_sql(["ACCOUNT_WITHOUT_MFA_CONFIGURED"], kinds=("service", "mailbox")),
     IDENTITY_COLS,
     "Service accounts and mailboxes flagged for no MFA. Usually they shouldn't be cloud-synced at all: move them to "
     "an OU outside the sync scope, or exclude them from the MFA policy deliberately."),
    ("Generic accounts", f"""
        SELECT e.site_label, e.display_name, e.upn, e.sam_account_name, {KIND_LABEL}, e.domain, e.ou,
               CASE WHEN e.enabled THEN 'Yes' WHEN e.enabled IS FALSE THEN 'No' ELSE '?' END,
               array_to_string(e.ad_groups, ', '), e.account_created::date,
               (SELECT string_agg(o.factor_type, ', ' ORDER BY o.factor_type) FROM identity_risk_factors o
                 WHERE o.source = e.source AND o.entity_id = e.entity_id)
        FROM identity_entities e
        WHERE NOT e.retired AND e.account_kind = 'generic' AND {SITE.format(col="e.site_label")}
        ORDER BY e.enabled IS NOT TRUE, e.display_name""",
     ["Display name", "UPN", "Account (SAM)", "Account type", "Domain", "OU", "Enabled", "AD groups", "Created",
      "Risk factors"],
     "Shared logons nobody is accountable for (from the generic-accounts groups/OUs). Replace with named accounts "
     "or disable -- enabled ones first."),
    ("VPN & remote-app accts", f"""
        SELECT e.site_label, e.display_name, e.upn, e.sam_account_name, {ACCESS_LABEL},
               CASE WHEN e.enabled THEN 'Yes' WHEN e.enabled IS FALSE THEN 'No' ELSE '?' END,
               CASE WHEN EXISTS (SELECT 1 FROM identity_risk_factors o WHERE o.source = e.source
                                 AND o.entity_id = e.entity_id AND o.factor_type = 'STALE_ACCOUNT') THEN 'Yes' ELSE '' END,
               e.ou, array_to_string(ARRAY(SELECT g FROM unnest(e.ad_groups) g
                                           WHERE g ~* '(vpn|manad|remote|terminal|rds|rdp)'), ', '),
               (SELECT string_agg(o.factor_type, ', ' ORDER BY o.factor_type) FROM identity_risk_factors o
                 WHERE o.source = e.source AND o.entity_id = e.entity_id AND o.factor_type <> 'STALE_ACCOUNT')
        FROM identity_entities e
        WHERE NOT e.retired AND e.access_account IS NOT NULL AND {SITE.format(col="e.site_label")}
        ORDER BY e.enabled IS NOT TRUE,
                 NOT EXISTS (SELECT 1 FROM identity_risk_factors o WHERE o.source = e.source
                             AND o.entity_id = e.entity_id AND o.factor_type = 'STALE_ACCOUNT'),
                 e.access_account, e.display_name""",
     ["Display name", "UPN", "Account (SAM)", "Used for", "Enabled", "Stale", "OU", "Access groups", "Other risk factors"],
     "Second accounts in the shared domain that exist only for VPN or remote apps (MANAD). Enabled + stale ones are "
     "listed first: disable them now. Legacy = in neither a VPN nor a remote-app group; confirm and remove."),
    # Every enabled account at the site -- the roster sites otherwise build by hand from AD
    # exports, but across every OU (vendor and other accounts outside the usual user OU too).
    # Enabled-but-stale first: those are the ones to confirm or disable.
    ("All accounts", f"""
        SELECT e.site_label, e.display_name, e.upn, e.sam_account_name, e.title, e.department, {KIND_LABEL},
               CASE WHEN e.enabled THEN 'Yes' WHEN e.enabled IS FALSE THEN 'No' ELSE '?' END,
               CASE WHEN EXISTS (SELECT 1 FROM identity_risk_factors o WHERE o.source = e.source AND o.entity_id = e.entity_id AND o.factor_type = 'STALE_ACCOUNT') THEN 'Yes' ELSE '' END,
               e.last_activity::date, e.password_last_change::date,
               CASE WHEN e.password_never_expires THEN 'Yes' WHEN e.password_never_expires IS FALSE THEN 'No' END,
               e.account_expires::date, e.ou, array_to_string(e.ad_groups, ', '),
               (SELECT string_agg(o.factor_type, ', ' ORDER BY o.factor_type) FROM identity_risk_factors o
                 WHERE o.source = e.source AND o.entity_id = e.entity_id)
        FROM identity_entities e
        WHERE NOT e.retired AND e.enabled IS NOT FALSE AND COALESCE(e.account_kind, 'human') <> 'out_of_scope'
          AND {SITE.format(col="e.site_label")}
        ORDER BY NOT EXISTS (SELECT 1 FROM identity_risk_factors o WHERE o.source = e.source AND o.entity_id = e.entity_id AND o.factor_type = 'STALE_ACCOUNT'), e.display_name""",
     ["Display name", "UPN", "Account (SAM)", "Title", "Department", "Account type", "Enabled", "Stale",
      "Last activity", "Password last changed", "Password never expires", "Account expires", "OU", "AD groups",
      "Risk factors"],
     "Every enabled account at the site, in any OU, for checking who should still have one. Stale accounts come "
     "first: confirm they're still needed, or disable them. Last activity is Falcon's most recent sign-in or use of the "
     "account. Manager and employee ID aren't included -- take them from AD if needed."),
    ("Stale sensors", f"""
        SELECT site_label, hostname, product_type, os_version, last_seen::date,
               (now()::date - last_seen::date) AS days_silent, sensor_version,
               array_to_string(ous, ' / '), array_to_string(groups, ', ')
        FROM assets
        WHERE source = 'falcon' AND NOT retired AND last_seen < now() - (%(stale_days)s || ' days')::interval
          AND {SITE.format(col="site_label")}
        ORDER BY last_seen""",
     ["Hostname", "Type", "OS", "Last seen", "Days silent", "Sensor version", "OU", "Host groups"],
     "Managed hosts whose Falcon sensor hasn't checked in. Decommissioned: remove from Falcon. "
     "Still in use: fix the sensor -- these hosts are unprotected and unassessed."),
    ("Missing sensors", f"""
        SELECT site_label, {dc.sql_case()}, COALESCE(hostname, '(no hostname)'), os_version,
               array_to_string(ips, ', '), mac_vendor, last_seen::date, description, {dc.sql_case(part=1)}
        FROM assets
        WHERE source = 'falcon_unmanaged' AND NOT retired AND discovery_class IN {dc.sql_in(dc.ACTIONABLE)}
          AND {SITE.format(col="site_label")}
        ORDER BY CASE discovery_class WHEN 'domain_controller_no_sensor' THEN 1 WHEN 'server_no_sensor' THEN 2
                                      WHEN 'cloud_no_sensor' THEN 3 WHEN 'workstation_no_sensor' THEN 4
                                      WHEN 'vmware_nic' THEN 5 ELSE 6 END, hostname""",
     ["Class", "Hostname", "OS", "IPs", "MAC vendor", "Last seen", "AD description", "What to do"],
     "Machines with no Falcon sensor. Named servers/workstations are AD accounts in active use -- install a "
     "sensor or record why not. Network-only devices: identify by IP (PC, VM, or printer/IoT that can't take one)."),
    ("External risks", f"""
        SELECT vf.site_label, vf.vendor_priority, vf.risk_type, vf.plugin_family, vf.title, vf.hostname,
               vf.first_found::date, vf.state, left(vf.solution, 500)
        FROM vuln_findings vf
        WHERE vf.source = 'hadrian' AND vf.state IN ('OPEN','REOPENED')
          AND (vf.risk_type IN ('Verified','UnpatchedTechnology','InfectedDevice')
               OR vf.vendor_priority IN ('Critical','High'))
          AND (vf.risk_type <> 'InfectedDevice' OR {ic.ACTIVE_LEAK_SQL})
          AND {SITE.format(col="vf.site_label")}
        ORDER BY CASE WHEN vf.vendor_priority IN ('Critical','High') THEN 1
                      WHEN vf.risk_type = 'InfectedDevice' THEN 2 ELSE 3 END,
                 CASE vf.vendor_priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3
                                         WHEN 'Low' THEN 4 ELSE 5 END,
                 vf.first_found""",
     ["Severity", "Type", "Category", "Risk", "Asset", "First seen", "State", "Remediation"],
     "Internet-facing risks found by Hadrian: confirmed ones plus anything critical/high. "
     "Infostealer leaks are only listed when they name one of our accounts that's still enabled -- reset it and "
     "find the device."),
]


# Removable media: per person x PC x USB drive over the period. Business data
# first -- that's what the service has to ask about.
USB_PERIOD = "w.day BETWEEN %(since)s AND %(until)s AND {site}".format(site=SITE.format(col="w.site_label"))
USB_BIZ = f"w.category IN {uc.sql_in(uc.BUSINESS)}"
USB_CAT_COLS = ", ".join(
    f"COALESCE(SUM(w.files) FILTER (WHERE w.category = '{k}'), 0)" for k in uc.ORDER)
TABS += [
    ("USB file writes", f"""
        WITH s AS (SELECT w.user_key, w.aid, w.device_serial,
                          left(string_agg(DISTINCT f, ', '), 600) AS samples
                   FROM usb_file_writes_daily w, unnest(w.sample_files) f
                   WHERE {USB_PERIOD} AND {USB_BIZ} GROUP BY 1, 2, 3)
        SELECT max(w.site_label), max(w.display_name), max(w.user_name), max(w.title), max(w.department),
               max(w.hostname),
               NULLIF(concat_ws(' ', max(w.device_make), max(w.device_model)), ''), NULLIF(w.device_serial, ''),
               max(w.connection_type), COUNT(DISTINCT w.day), SUM(w.files),
               COALESCE(SUM(w.files) FILTER (WHERE {USB_BIZ}), 0),
               round(SUM(w.bytes) / 1048576.0, 1), round(COALESCE(SUM(w.bytes) FILTER (WHERE {USB_BIZ}), 0) / 1048576.0, 1),
               {USB_CAT_COLS},
               concat_ws('; ',
                 CASE WHEN SUM(w.files) FILTER (WHERE w.category = 'email') > 0 THEN 'Email / mailbox data' END,
                 CASE WHEN SUM(w.files) FILTER (WHERE w.category = 'clinical') > 0 THEN 'Medical images' END,
                 CASE WHEN SUM(w.files) FILTER (WHERE w.category = 'data') > 0 THEN 'Spreadsheets / databases' END,
                 CASE WHEN SUM(w.files) FILTER (WHERE {USB_BIZ}) >= %(bulk_files)s THEN 'Bulk copy' END,
                 CASE WHEN SUM(w.bytes) >= %(bulk_mb)s * 1048576.0 THEN 'Large volume' END,
                 CASE WHEN w.device_serial = '' THEN 'Drive not identified' END,
                 CASE WHEN w.user_key = '' THEN 'No user (system / service)' END),
               left(array_to_string((array_agg(DISTINCT w.folder))[1:8], ', '), 400),
               max(s.samples), min(w.first_write)::date, max(w.last_write)::date
        FROM usb_file_writes_daily w
        LEFT JOIN s ON s.user_key = w.user_key AND s.aid = w.aid AND s.device_serial = w.device_serial
        WHERE {USB_PERIOD}
        GROUP BY w.user_key, w.aid, w.device_serial
        ORDER BY COALESCE(SUM(w.files) FILTER (WHERE {USB_BIZ}), 0) DESC, SUM(w.bytes) DESC""",
     ["Person", "Username", "Title", "Department", "PC", "USB drive", "Drive serial", "Connection", "Days",
      "Files", "Business files", "Volume (MB)", "Business volume (MB)"]
     + [uc.LABEL[k] for k in uc.ORDER]
     + ["Flags", "Folders on drive", "Largest business files", "First write", "Last write"],
     "Files written to USB drives, one row per person, PC and drive, business data first. Check the flagged rows "
     "with the person or their manager: was it needed, and is the drive approved and encrypted? Email, "
     "medical images and spreadsheets/databases are the likeliest to hold patient or staff data."),
    ("USB drives", f"""
        SELECT max(w.site_label), NULLIF(concat_ws(' ', max(w.device_make), max(w.device_model)), ''),
               NULLIF(w.device_serial, ''), max(w.connection_type),
               COUNT(DISTINCT w.user_key) FILTER (WHERE w.user_key <> ''),
               left(string_agg(DISTINCT COALESCE(w.display_name, w.user_name), ', ')
                    FILTER (WHERE w.user_key <> ''), 400),
               COUNT(DISTINCT w.aid), left(string_agg(DISTINCT w.hostname, ', '), 400),
               SUM(w.files), COALESCE(SUM(w.files) FILTER (WHERE {USB_BIZ}), 0), round(SUM(w.bytes) / 1048576.0, 1),
               min(w.first_write)::date, max(w.last_write)::date,
               concat_ws('; ',
                 CASE WHEN COUNT(DISTINCT w.user_key) FILTER (WHERE w.user_key <> '') > 1 THEN 'Shared drive' END,
                 CASE WHEN COUNT(DISTINCT w.site_label) > 1 THEN 'Used at more than one site' END,
                 CASE WHEN w.device_serial = '' THEN 'Not identified -- one row for all such writes' END)
        FROM usb_file_writes_daily w
        WHERE {USB_PERIOD}
        GROUP BY w.device_serial
        ORDER BY COUNT(DISTINCT w.user_key) DESC, COALESCE(SUM(w.files) FILTER (WHERE {USB_BIZ}), 0) DESC""",
     ["USB drive", "Serial", "Connection", "People", "Who", "PCs", "Which PCs", "Files", "Business files",
      "Volume (MB)", "First used", "Last used", "Flags"],
     "Every removable drive written to this month. Use it to decide which drives to approve (and require "
     "encryption on) and which to block in the Falcon device control policy -- shared drives first."),
    ("USB malware", f"""
        SELECT a.site_label, a.created_at::date, a.hostname, a.user_name, a.name, initcap(a.severity),
               a.file_name, a.file_path,
               CASE WHEN a.quarantined THEN 'Yes' WHEN a.quarantined IS FALSE THEN 'No' ELSE '?' END,
               COALESCE(a.disposition, a.status), u.status
        FROM security_alerts a JOIN usb_scans u ON u.scan_id = a.scan_id
        WHERE a.created_at >= %(since)s AND a.created_at < %(until)s::date + 1
          AND {SITE.format(col="a.site_label")}
        ORDER BY a.created_at DESC""",
     ["Date", "PC", "User", "Detection", "Severity", "File", "Path", "Quarantined", "Alert status", "Scan"],
     "Malware or unwanted software found by the scan Falcon runs when a drive is plugged in. Not quarantined: "
     "remove it and scan the drive. Repeat finds on one PC or person: find the drive and its owner."),
]


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def write_sheet(wb: Workbook, title: str, cols: List[str], rows: List[Tuple]) -> None:
    ws = wb.create_sheet(title[:31])
    ws.append(cols)
    for c in ws[1]:
        c.font, c.fill = HEADER_FONT, HEADER_FILL
    widths = [len(c) for c in cols]
    for r in rows:
        ws.append(list(r))
        for i, v in enumerate(r):
            widths[i] = max(widths[i], min(len(str(v)) if v is not None else 0, 60))
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w + 2
        if any(isinstance(r[i - 1], dt.date) for r in rows[:50]):
            for cell in ws[get_column_letter(i)][1:]:
                cell.number_format = "yyyy-mm-dd"
    ws.freeze_panes = "A2"
    if rows:
        ws.auto_filter.ref = ws.dimensions


def build_workbook(cur, site: Optional[str], as_at: dt.date, stale_days: int, since: dt.date, until: dt.date,
                   bulk_files: int = 100, bulk_mb: int = 1024) -> Tuple[Workbook, Dict[str, int]]:
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"
    counts: Dict[str, int] = {}
    region = site is None
    for name, sql, cols, _ in TABS:
        cur.execute(sql, {"site": site, "stale_days": stale_days, "since": since, "until": until,
                          "bulk_files": bulk_files, "bulk_mb": bulk_mb})
        rows = cur.fetchall()
        # region workbook keeps the Site column; a site's own workbook drops it
        rows = [r if region else r[1:] for r in rows]
        write_sheet(wb, name, (["Site"] if region else []) + cols, rows)
        counts[name] = len(rows)

    summary["A1"] = f"Security action pack -- {'Whole of region' if region else site}"
    summary["A1"].font = TITLE_FONT
    summary["A2"] = (f"As at {as_at:%d %B %Y}. Point-in-time lists from the secops dashboard's latest collection; "
                     f"USB tabs cover {since:%d %b} - {until:%d %b %Y}.")
    summary.append([])
    summary.append(["List", "Items", "What to do"])
    for c in summary[4]:
        c.font, c.fill = HEADER_FONT, HEADER_FILL
    for name, _, _, todo in TABS:
        summary.append([name, counts[name], todo])
    summary.append([])
    for line in (
        "Endpoint vulnerability lists (top remediations, worst endpoints/servers) will be added once "
        "Falcon vulnerability assessment covers the whole estate.",
        "This workbook contains real account names and compromised-credential details. "
        "Keep it within the site's security contacts.",
    ):
        summary.append([line])
    summary.column_dimensions["A"].width = 24
    summary.column_dimensions["B"].width = 8
    summary.column_dimensions["C"].width = 110
    for row in summary.iter_rows(min_row=5):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")
    return wb, counts


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--site", help="one site (its label); default is every site plus the region workbook")
    ap.add_argument("--out-dir", help="default: reports/monthly-YYYY-MM")
    ap.add_argument("--since", help="USB tabs: first day (default: first of last month)")
    ap.add_argument("--until", help="USB tabs: last day, inclusive (default: end of last month)")
    args = ap.parse_args()

    cfg = config_mod.load_config(args.config)
    labels = [s["label"] for s in cfg.get("sites", [])] + [cfg.get("ungrouped_label", "Ungrouped")]
    if args.site and args.site not in labels:
        ap.error(f"unknown site {args.site!r}; configured: {', '.join(labels)}")
    as_at = dt.date.today()
    stale_days = int(cfg.get("reporting", {}).get("stale_sensor_days", 7))
    until = dt.date.fromisoformat(args.until) if args.until else as_at.replace(day=1) - dt.timedelta(days=1)
    since = dt.date.fromisoformat(args.since) if args.since else until.replace(day=1)
    bulk_files = int(cfg.get("reporting", {}).get("usb_bulk_files", 100))
    bulk_mb = int(cfg.get("reporting", {}).get("usb_bulk_mb", 1024))
    out_dir = args.out_dir or os.path.join("reports", f"monthly-{as_at:%Y-%m}")
    os.makedirs(out_dir, exist_ok=True)

    conn = pg_connect(cfg)
    cur = conn.cursor()
    jobs: List[Optional[str]] = [args.site] if args.site else [None] + labels
    for site in jobs:
        wb, counts = build_workbook(cur, site, as_at, stale_days, since, until, bulk_files, bulk_mb)
        path = os.path.join(out_dir, f"{safe_name(site or 'region')}-actions-{as_at:%Y-%m}.xlsx")
        wb.save(path)
        print(f"[action_pack] wrote {path} " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    conn.close()


if __name__ == "__main__":
    main()
