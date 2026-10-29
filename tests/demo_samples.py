#!/usr/bin/env python3
"""
Demo sample reports: the committed reports/sample-* files (weekly exec report,
region + one site; monthly action pack and scorecard; Servers and programme
impact reports), rendered from a
believable (entirely made-up) four-site estate with months of history, so
the charts and trend arrows have something to show.

  PGHOST=127.0.0.1 PGUSER=postgres python3 tests/demo_samples.py [--out reports]

Runs every collector once against the e2e mocks (tests/mock_vendors.py) so
each table holds rows shaped exactly as the collectors write them, then
clones those rows into hundreds of hosts, accounts, alerts and emails spread
over HISTORY_DAYS, rolls up with --backfill-days, and back-fills the daily
snapshot tables along a gently improving curve. Needs a Postgres it may
DROP/CREATE the database `secops_demo` on. Deterministic (fixed seed), but
dates are relative to today, so re-running moves the window along.

The numbers are tuned to read "not bad, room to improve": most things
trending the right way, a few stubborn ones that aren't.
"""
import argparse
import datetime as dt
import math
import os
import random
import shutil
import subprocess
import sys
import tempfile

import psycopg2
import psycopg2.extras

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import mock_vendors  # noqa: E402
import run_e2e  # noqa: E402

DB = "secops_demo"
PG = run_e2e.PG
HISTORY_DAYS = 120
R = random.Random(20261013)
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
TODAY = dt.date.today()

# key, label, email domain, managed hosts, people, patch speed (median days to fix crit/high; lower = better)
SITES = [
    ("RVH", "Riverside Health", "riversidehealth.test", 520, 1300, 9),
    ("LKH", "Lakeside Health", "lakesidehealth.test", 260, 640, 16),
    ("NGH", "Northgate Hospital", "northgate.test", 340, 820, 12),
    ("HCH", "Hillcrest Community Health", "hillcrest.test", 150, 360, 22),
    ("UNGROUPED", "Ungrouped", "unmapped.test", 25, 40, 30),
]
EXTRA_SITES = """
  - key: NGH
    label: Northgate Hospital
    match: {email_domains: ["northgate.test"]}
  - key: HCH
    label: Hillcrest Community Health
    match: {email_domains: ["hillcrest.test"]}
ungrouped_label: Ungrouped"""

# product_key, vendor, platform, share of hosts with it, base severity mix, remote-no-auth share, fix id/title
PRODUCTS = [
    ("google:chrome", "google", "ws", 0.92, (0.15, 0.55, 0.25, 0.05), 0.10, "Update Google Chrome"),
    ("microsoft:edge", "microsoft", "ws", 0.98, (0.10, 0.50, 0.35, 0.05), 0.05, "Update Microsoft Edge"),
    ("mozilla:firefox", "mozilla", "ws", 0.22, (0.10, 0.45, 0.40, 0.05), 0.05, "Update Mozilla Firefox"),
    ("adobe:acrobat_reader_dc", "adobe", "ws", 0.80, (0.10, 0.55, 0.30, 0.05), 0.00, "Update Adobe Acrobat Reader"),
    ("microsoft:windows_11", "microsoft", "ws11", 1.00, (0.08, 0.60, 0.30, 0.02), 0.08, "Install the monthly cumulative update"),
    ("microsoft:windows_10", "microsoft", "ws10", 1.00, (0.10, 0.60, 0.28, 0.02), 0.08, "Upgrade to Windows 11"),
    ("microsoft:office", "microsoft", "ws", 0.95, (0.05, 0.55, 0.35, 0.05), 0.00, "Update Microsoft 365 Apps"),
    ("zoom:zoom_client", "zoom", "ws", 0.35, (0.05, 0.35, 0.50, 0.10), 0.00, "Update Zoom Workplace"),
    ("7-zip:7-zip", "7-zip", "ws", 0.40, (0.00, 0.60, 0.40, 0.00), 0.00, "Update 7-Zip"),
    ("oracle:jre", "oracle", "any", 0.18, (0.10, 0.50, 0.35, 0.05), 0.05, "Update or remove Java SE"),
    ("microsoft:windows_server_2019", "microsoft", "srv19", 1.00, (0.10, 0.60, 0.28, 0.02), 0.15, "Install the monthly cumulative update"),
    ("microsoft:windows_server_2022", "microsoft", "srv22", 1.00, (0.08, 0.60, 0.30, 0.02), 0.15, "Install the monthly cumulative update"),
    ("microsoft:windows_server_2016", "microsoft", "srv16", 1.00, (0.12, 0.60, 0.26, 0.02), 0.15, "Install the monthly cumulative update"),
    ("microsoft:.net_framework", "microsoft", "srv", 0.85, (0.05, 0.55, 0.40, 0.00), 0.05, "Update .NET runtime"),
    ("vmware:tools", "vmware", "srv", 0.70, (0.05, 0.40, 0.50, 0.05), 0.00, "Update VMware Tools"),
    ("openssl:openssl", "openssl", "srv", 0.35, (0.10, 0.40, 0.45, 0.05), 0.20, "Update OpenSSL"),
    ("apache:log4j", "apache", "srv", 0.04, (1.00, 0.00, 0.00, 0.00), 1.00, "Update Apache Log4j"),
]
SEVS = ("critical", "high", "medium", "low")
SLA = {"critical": 2, "high": 14, "medium": 30, "low": 60}

WS_OS = [("Windows 11 24H2", 0.55), ("Windows 11 23H2", 0.33), ("Windows 10 22H2", 0.12)]
SRV_OS = [("Windows Server 2022", 0.45), ("Windows Server 2019", 0.38), ("Windows Server 2016", 0.15),
          ("Windows Server 2012 R2", 0.02)]

FIRST = ["Alex", "Sam", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Quinn", "Avery", "Drew", "Kai",
         "Robin", "Charlie", "Frankie", "Harper", "Rowan", "Sage", "Toni", "Ellis"]
LAST = ["Nguyen", "Smith", "Patel", "Brown", "Wilson", "Taylor", "Kelly", "Martin", "Lee", "Walker", "Chen", "Hall",
        "Young", "King", "Wright", "Green", "Baker", "Hill", "Scott", "Adams"]
DEPTS = ["Ward 3", "Emergency", "Pharmacy", "Radiology", "Theatre", "Outpatients", "Finance", "HR", "Community Care",
         "Pathology", "Health Information", "Aged Care"]


def wpick(pairs):
    x, acc = R.random(), 0.0
    for v, w in pairs:
        acc += w
        if x <= acc:
            return v
    return pairs[-1][0]


def ts(days_ago: float) -> dt.datetime:
    return NOW - dt.timedelta(days=days_ago)


def improve(days_ago: float) -> float:
    """1.0 today, rising to ~1.6 at the start of history: things used to take longer."""
    return 1.0 + 0.6 * min(days_ago, HISTORY_DAYS) / HISTORY_DAYS


def template(cur, table, where, *a):
    cur.execute(f"SELECT * FROM {table} WHERE {where} LIMIT 1", a)
    row = cur.fetchone()
    assert row, f"no template row in {table} where {where}"
    return dict(row)


def insert(cur, table, rows, conflict="ON CONFLICT DO NOTHING"):
    if not rows:
        return
    cols = list(rows[0])
    psycopg2.extras.execute_values(
        cur, f"INSERT INTO {table} ({', '.join(cols)}) VALUES %s {conflict}",
        [tuple(r[c] for c in cols) for r in rows], page_size=2000)


def run(cfgp, *args):
    r = subprocess.run([sys.executable, *args, "--config", cfgp], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-3000:], r.stderr[-3000:])
        sys.exit(f"{args[0]} failed")
    return r.stdout


# ------------------------------------------------------------------ estate
def seed_hosts(cur):
    ws_t = template(cur, "assets", "source_asset_id = 'aid1'")
    srv_t = template(cur, "assets", "source_asset_id = 'aid2'")
    hosts = []
    for key, label, dom, n, _, _ in SITES:
        key_tag = key
        servers = max(3, int(n * 0.14))
        for i in range(n):
            srv = i < servers
            dc = srv and i < 2
            os_ = wpick(SRV_OS if srv else WS_OS)
            seen = R.random()
            last_seen = ts(R.uniform(10, 45)) if seen < 0.03 else ts(R.uniform(0, 1.5))
            h = dict(srv_t if srv else ws_t)
            h.update(source_asset_id=f"d-{key}-{i:04d}",
                     hostname=f"{key}-{'DC' if dc else 'SRV' if srv else 'WS'}{i:04d}",
                     os_version=os_, product_type="domain_controller" if dc else "server" if srv else "workstation",
                     platform="Windows", last_seen=last_seen, first_seen=ts(R.uniform(200, 1500)),
                     rfm="yes" if R.random() < 0.006 else "no", site_label=label, site_tag=key_tag,
                     site_matched_by="falcon_groups", groups=[], tags=[], ips=[f"10.{len(hosts) % 250}.{i % 250}.{R.randint(2, 250)}"],
                     mac_addresses=[], collected_at=NOW, retired=False, managed=True)
            hosts.append(h)
    insert(cur, "assets", hosts)

    # unmanaged: devices AD or the network knows about with no sensor
    um = []
    for cls, tmpl, share in [("workstation_no_sensor", "u2", 0.035), ("server_no_sensor", "u2", 0.008),
                             ("network_device", "u1", 0.05), ("vmware_nic", "u5", 0.02)]:
        t = template(cur, "assets", "source_asset_id = %s", tmpl)
        for key, label, _, n, _, _ in SITES:
            for i in range(max(1, int(n * share * R.uniform(0.7, 1.3)))):
                u = dict(t)
                u.update(source_asset_id=f"u-{cls}-{key}-{i}", discovery_class=cls, site_label=label, site_tag=key,
                         hostname=(f"{key}-{'WS' if 'work' in cls else 'SRV'}{9000 + i}$" if "sensor" in cls else None),
                         ips=[f"10.{200 + len(um) % 50}.{i % 250}.{R.randint(2, 250)}"],
                         last_seen=ts(R.uniform(0, 3)), collected_at=NOW, retired=False, managed_twin=None)
                um.append(u)
    insert(cur, "assets", um)
    # Falcon patch status for the servers (the Servers report and the scorecard's
    # "patched in 35 days"): most inside a monthly cycle, a long tail, a few never confirmed
    patches = []
    for h in hosts:
        if h["product_type"] == "workstation":
            continue
        age = wpick([(R.uniform(1, 7), 0.12), (R.uniform(8, 35), 0.53), (R.uniform(36, 90), 0.11),
                     (R.uniform(91, 400), 0.21), (None, 0.03)])
        patches.append(dict(aid=h["source_asset_id"], hostname=h["hostname"], device_type="Server",
                            reboot_required=R.random() < 0.03, active_patches=R.randint(80, 200),
                            pending_patches=R.randint(0, 6), installed_patches=psycopg2.extras.Json([]),
                            last_patch_confirmed=ts(age) if age is not None else None, collected_at=NOW))
    insert(cur, "host_patch_status", patches)
    return hosts


def seed_vulns(cur, hosts):
    t = template(cur, "vuln_findings", "source_rule_id = 'v1'")
    t.pop("id")
    cur.execute("SELECT COALESCE(MAX(id), 0) AS m FROM vuln_findings")
    next_id = cur.fetchone()["m"] + 1000
    speed = {s[1]: s[5] for s in SITES}
    rows, cves, kev, epss = [], [], [], []
    # each product ships fixes roughly monthly, 1-3 CVEs per release, on its own
    # staggered cycle so the weekly opened/fixed bars wobble rather than spike
    releases = {}
    for p in PRODUCTS:
        rel, d = [], HISTORY_DAYS + R.uniform(0, 28)
        while d > 2:
            n_cves = R.choice((1, 1, 2, 2, 3))
            sev = [wpick(list(zip(SEVS, p[4]))) for _ in range(n_cves)]
            rel.append((d, [(f"CVE-2026-{R.randint(10000, 59999)}", s) for s in sev]))
            d -= R.uniform(25, 31)
        releases[p[0]] = rel
    kev_cves = set()
    for p in PRODUCTS:
        for d, cl in releases[p[0]]:
            for cve, sev in cl:
                if sev in ("critical", "high") and R.random() < (0.5 if p[0] == "apache:log4j" else 0.07):
                    kev_cves.add(cve)
                    kev.append(dict(cve_id=cve, vendor_project=p[1], product=p[0].split(":")[1],
                                    vulnerability_name=f"{p[0]} vulnerability", date_added=TODAY - dt.timedelta(days=int(d)),
                                    due_date=TODAY - dt.timedelta(days=int(d) - 21), known_ransomware_campaign_use="Unknown"))
                epss.append(dict(cve_id=cve, epss=round(R.betavariate(0.6, 8) if cve not in kev_cves else R.uniform(0.3, 0.9), 4),
                                 percentile=round(R.uniform(0.3, 0.99), 3)))

    def applies(p, h):
        plat, os_ = p[2], h["os_version"]
        if plat == "ws":
            return h["product_type"] == "workstation"
        if plat == "ws11":
            return os_.startswith("Windows 11")
        if plat == "ws10":
            return os_.startswith("Windows 10")
        if plat.startswith("srv") and plat != "srv":
            return os_.startswith("Windows Server 20" + plat[3:]) and not os_.endswith("R2")
        if plat == "srv":
            return h["product_type"] != "workstation"
        return True

    for h in hosts:
        laggard = R.random() < 0.06          # the few machines nobody patches
        stale = h["last_seen"] < ts(7)
        for p in PRODUCTS:
            if not applies(p, h) or R.random() > p[3]:
                continue
            for d, cl in releases[p[0]]:
                found = d - R.lognormvariate(math.log(1.5), 0.9)
                if found < 0:
                    continue
                med = speed[h["site_label"]] * improve(found) * (1.8 if h["product_type"] != "workstation" else 1.0)
                for cve, sev in cl:
                    m = med * {"critical": 0.1, "high": 0.5, "medium": 0.9, "low": 1.1}[sev]
                    fix_after = R.lognormvariate(math.log(m), 0.7)
                    if laggard or stale or (p[0] == "microsoft:windows_10" and R.random() < 0.5):
                        fix_after = 10 ** 6
                    fixed = found - fix_after > 0.2
                    remote = R.random() < p[5]
                    r = dict(t)
                    r.update(id=next_id, source_asset_id=h["source_asset_id"], source_rule_id=f"{h['source_asset_id']}-{cve}",
                             state="FIXED" if fixed else "OPEN", severity=sev,
                             cvss_score={"critical": 9.8, "high": 8.1, "medium": 5.5, "low": 3.1}[sev],
                             cvss_vector=("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if remote else
                                          "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H"),
                             title=cve, is_remote_no_auth=remote, exploit_available=remote or cve in kev_cves,
                             product_key=p[0], product_vendor=p[1], product_family=None,
                             site_label=h["site_label"], site_tag=h["site_tag"], asset_type=h["product_type"],
                             hostname=h["hostname"], first_found=ts(found),
                             last_found=ts(found - fix_after) if fixed else h["last_seen"],
                             last_fixed=ts(found - fix_after) if fixed else None,
                             last_seen_in_export=NOW, created_at=ts(found), updated_at=NOW,
                             fix_id=f"{p[0]}:{d:.0f}", fix_title=p[6], vendor_priority=None)
                    rows.append(r)
                    cves.append(dict(finding_id=next_id, cve=cve))
                    next_id += 1
    insert(cur, "vuln_findings", rows)
    insert(cur, "vuln_finding_cves", cves)
    insert(cur, "cisa_kev", kev)
    insert(cur, "epss_scores", epss)
    cur.execute("SELECT setval(pg_get_serial_sequence('vuln_findings', 'id'), (SELECT MAX(id) FROM vuln_findings))")
    print(f"  vulns: {len(rows):,} findings ({sum(r['state'] == 'OPEN' for r in rows):,} open), {len(kev)} KEV CVEs")


def seed_external(cur):
    at = template(cur, "external_assets", "asset_id = 'a1'")
    rt = template(cur, "vuln_findings", "source = 'hadrian' AND source_rule_id = 'r1'")
    rt.pop("id")
    assets, risks = [], []
    titles = [("Expired TLS certificate", "medium", "Potential"), ("Weak TLS cipher suites", "low", "Potential"),
              ("Missing security headers", "low", "Potential"), ("Exposed login portal", "medium", "Potential"),
              ("Unpatched web server", "high", "UnpatchedTechnology"), ("SPF record too permissive", "low", "Potential"),
              ("Open RDP service", "high", "UnpatchedTechnology"), ("Self-signed certificate", "low", "Potential"),
              ("Outdated jQuery library", "medium", "Potential"), ("Server version disclosed", "low", "Potential"), ("Outdated CMS plugin", "high", "UnpatchedTechnology"),
              ("Subdomain takeover risk", "medium", "Potential"), ("Directory listing enabled", "low", "Potential")]
    for key, label, dom, n, _, speed in SITES[:4]:
        for i in range(max(6, n // 25)):
            a = dict(at)
            name = f"{['portal', 'mail', 'vpn', 'www', 'apps', 'remote', 'intranet', 'booking', 'jobs', 'api', 'sso', 'cdn'][i % 12]}{i // 12 or ''}.{dom}"
            a.update(asset_id=f"x-{key}-{i}", name=name, ips=[f"203.0.113.{(len(assets) * 7) % 250 + 1}"], site_label=label, site_tag=key, collected_at=NOW, retired=False,
                     first_seen=ts(R.uniform(100, 700)), last_seen=ts(0))
            assets.append(a)
        for i in range(int(n / 9)):
            title, sev, rtype = R.choice(titles)
            found = R.uniform(0, HISTORY_DAYS)
            fix_after = R.lognormvariate(math.log(speed * 0.6 * improve(found) * {"critical": 0.3, "high": 0.6}.get(sev, 1.5)), 0.6)
            fixed = found - fix_after > 0.5
            r = dict(rt)
            r.update(source_asset_id=f"x-{key}-{i % max(6, n // 25)}", source_rule_id=f"xr-{key}-{i}", title=title,
                     severity=sev, risk_type=rtype, state="FIXED" if fixed else "OPEN", site_label=label, site_tag=key,
                     hostname=assets[-1]["name"], first_found=ts(found), last_found=ts(0 if not fixed else found - fix_after),
                     last_fixed=ts(found - fix_after) if fixed else None, last_seen_in_export=NOW,
                     created_at=ts(found), updated_at=NOW, vendor_priority=sev.title())
            risks.append(r)
    insert(cur, "external_assets", assets)
    insert(cur, "vuln_findings", risks)
    print(f"  external: {len(assets)} assets, {len(risks)} risks")


# ------------------------------------------------------------------ alerts
def seed_alerts(cur, hosts):
    t = template(cur, "security_alerts", "alert_id = 'al1'")
    names = [("Malicious PowerShell", "Execution", "PowerShell", "high"),
             ("Suspicious scheduled task", "Persistence", "Scheduled Task", "medium"),
             ("Credential dumping attempt", "Credential Access", "LSASS Memory", "critical"),
             ("Adware/PUP blocked", "Defense Evasion", "Masquerading", "low"),
             ("Ransomware behaviour blocked", "Impact", "Data Encrypted for Impact", "critical"),
             ("Suspicious script download", "Command and Control", "Ingress Tool Transfer", "medium"),
             ("Unusual sign-in location", "Initial Access", "Valid Accounts", "medium"),
             ("Office macro launched process", "Execution", "Malicious File", "high")]
    rows = []
    for d in range(HISTORY_DAYS):
        for _ in range(int(R.uniform(2, 7) * (1.25 if d % 7 in (1, 2) else 1.0))):
            h = R.choice(hosts)
            name, tactic, tech, sev = R.choice(names)
            created = ts(d + R.uniform(0, 1))
            hours = R.lognormvariate(math.log(14 * improve(d)), 0.9)
            closed = created + dt.timedelta(hours=hours)
            is_closed = closed < NOW and not (d < 4 and R.random() < 0.5)
            disp = wpick([("false_positive", 0.55), ("true_positive", 0.18), ("ignored", 0.27)]) if is_closed else None
            a = dict(t)
            a.update(alert_id=f"al-{len(rows)}", created_at=created, updated_at=closed if is_closed else created,
                     closed_at=closed if is_closed else None, severity=sev,
                     severity_score={"critical": 90, "high": 70, "medium": 50, "low": 30}[sev],
                     status="closed" if is_closed else "new", name=name, tactic=tactic, technique=tech,
                     hostname=h["hostname"], source_asset_id=h["source_asset_id"], site_label=h["site_label"],
                     site_tag=h["site_tag"], disposition=disp, alert_type=None, scan_id=None, file_name=None,
                     file_path=None, quarantined=None)
            rows.append(a)
    insert(cur, "security_alerts", rows)
    print(f"  alerts: {len(rows):,}")


# ------------------------------------------------------------------ identity
def seed_identity(cur):
    t = template(cur, "identity_entities", "entity_id = 'e2'")
    ents, facs, mfa = [], [], []
    mfa_t = template(cur, "entra_mfa_registration", "user_id = 'm1'")
    for key, label, dom, _, people, speed in SITES:
        stale_rate = 0.07 + speed / 200          # slower sites carry more dead accounts
        for i in range(people + int(people * 0.12)):
            kind = "human" if i < people else wpick([("service", 0.5), ("mailbox", 0.35), ("generic", 0.15)])
            access = "vpn" if kind == "human" and key == "RVH" and R.random() < 0.18 else None
            fn, ln = R.choice(FIRST), R.choice(LAST)
            sam = f"{fn[0].lower()}{ln.lower()}{i}" if kind == "human" else f"{kind[:3]}_{key.lower()}{i}"
            e = dict(t)
            e.update(entity_id=f"id-{key}-{i}", display_name=f"{fn} {ln}" if kind == "human" else sam,
                     upn=f"{sam}@{dom}", domain=f"{key}.LOCAL", sam_account_name=sam, ou=f"{key.lower()}.local/Users",
                     enabled=R.random() > 0.03, account_kind=kind, access_account=access, site_label=label,
                     site_tag=key, site_matched_by="email_domains", collected_at=NOW, retired=False,
                     last_activity=ts(R.uniform(0, 30)), roles=[], ad_groups=[], is_privileged=R.random() < 0.02)
            ents.append(e)
            f = []
            if R.random() < (stale_rate * (2.2 if access or kind != "human" else 1.0)):
                f.append("STALE_ACCOUNT")
                e["last_activity"] = ts(R.uniform(95, 900))
            for ftype, p in [("WEAK_PASSWORD", 0.025), ("DUPLICATE_PASSWORD", 0.05), ("HAS_ATTACK_PATH", 0.012),
                             ("ACCOUNT_WITHOUT_MFA_CONFIGURED", 0.06 if kind == "human" else 0.0),
                             ("CREDENTIAL_SCANNING", 0.002), ("GEO_ANOMALY", 0.002), ("STALE_ACCOUNT_USAGE", 0.0008)]:
                if R.random() < p:
                    f.append(ftype)
            facs += [dict(source=e["source"], entity_id=e["entity_id"], factor_type=x, factor_severity="medium") for x in f]
            if kind == "human" and not access:
                m = dict(mfa_t)
                m.update(user_id=e["entity_id"], upn=e["upn"], is_mfa_registered=R.random() < 0.93,
                         site_label=label, site_tag=key, collected_at=NOW)
                mfa.append(m)
    insert(cur, "identity_entities", ents)
    insert(cur, "identity_risk_factors", facs)
    insert(cur, "entra_mfa_registration", mfa)
    print(f"  identity: {len(ents):,} accounts, {len(facs):,} risk factors")


# ------------------------------------------------------------------ email
def seed_email(cur):
    t = template(cur, "email_events", "event_id = 'h1'")
    ev, flow = [], []
    for key, label, dom, n, people, _ in SITES:
        for d in range(HISTORY_DAYS):
            day = TODAY - dt.timedelta(days=d)
            weekend = day.weekday() >= 5
            inc = int(people * R.uniform(9, 13) * (0.35 if weekend else 1.0))
            internal = int(inc * R.uniform(0.25, 0.35))
            for prefix, total in (("", inc), ("internal_", internal)):
                ms_q = int(total * (0.06 if not prefix else 0.002) * R.uniform(0.8, 1.2))
                junk = int(total * (0.04 if not prefix else 0.003) * R.uniform(0.8, 1.2))
                phish = int(total * (0.0025 if not prefix else 0.0001) * R.uniform(0.5, 1.6))
                malw = int(total * 0.0004 * R.uniform(0, 2)) if not prefix else 0
                spam = int(total * (0.05 if not prefix else 0.001) * R.uniform(0.8, 1.2))
                gray = int(total * (0.08 if not prefix else 0.01) * R.uniform(0.8, 1.2))
                cpq = phish + malw + spam + int(gray * 0.3)
                vals = {"incoming": total, "ms_junk": junk, "ms_quarantine": ms_q,
                        "ms_quarantine_not_cp": int(ms_q * 0.7), "not_cp_quarantined": total - cpq,
                        "cp_clean": total - phish - malw - spam - gray, "cp_graymail": gray, "cp_spam": spam,
                        "cp_phishing": phish, "cp_suspicious_phishing": int(phish * 0.6), "cp_malware": malw,
                        "cp_quarantined": cpq, "restore_requested": int(cpq * 0.02), "restored": int(cpq * 0.015),
                        "restore_declined": int(cpq * 0.004), "monitor_mode": 0}
                flow += [dict(snapshot_date=day, site_label=label, metric=prefix + m, value=v) for m, v in vals.items()]
            for _ in range(int(R.uniform(1, 4) * people / 400)):
                kind = wpick([("phishing", 0.6), ("malware", 0.15), ("dlp", 0.15), ("spam", 0.1)])
                e = dict(t)
                e.update(event_id=f"ev-{key}-{d}-{len(ev)}", created_at=ts(d + R.uniform(0, 1)), event_type=kind,
                         severity=wpick([("medium", 0.55), ("low", 0.2), ("high", 0.2), ("critical", 0.05)]), site_label=label, site_tag=key,
                         recipient_domain=dom, direction="outbound" if kind == "dlp" else "inbound",
                         description=f"{kind.title()} email detected", state="remediated" if R.random() < 0.9 else "detected")
                ev.append(e)
    insert(cur, "email_events", ev)
    # DMARC: our own mail passes; a trickle of spoofing and one misconfigured sender fails
    dt_ = template(cur, "dmarc_daily", "TRUE")
    dm = []
    for key, label, dom, n, people, _ in SITES[:4]:
        for d in range(1, 30):
            for ip, name, msgs, ok in [("40.107.0.1", "Microsoft", people * 6, 1.0), ("185.0.0.9", "spoofer", 20, 0.0),
                                       ("198.51.100.20", "Newsletter platform", people // 4, 0.55)]:
                x = dict(dt_)
                m = int(msgs * R.uniform(0.7, 1.3))
                x.update(report_date=TODAY - dt.timedelta(days=d), header_from=dom, source_ip=ip, source_name=name,
                         messages=m, dmarc_pass=int(m * ok), spf_aligned=int(m * ok), dkim_aligned=int(m * ok),
                         site_label=label, site_tag=key)
                dm.append(x)
    insert(cur, "dmarc_daily", dm)
    cur.execute("DELETE FROM daily_email_flow_metrics")
    insert(cur, "daily_email_flow_metrics", flow)
    print(f"  email: {len(ev):,} security events, {HISTORY_DAYS} days of mail flow")


# ------------------------------------------------------------------ usb
def seed_usb(cur, hosts):
    t = template(cur, "usb_file_writes_daily", "category = 'data'")
    st = template(cur, "usb_scans", "scan_id = 'sc_usb1'")
    cats = [("documents", 0.35, 400_000), ("data", 0.15, 2_000_000), ("images", 0.2, 3_000_000),
            ("archives", 0.08, 40_000_000), ("email", 0.02, 900_000_000), ("medical_images", 0.03, 60_000_000),
            ("other", 0.17, 1_000_000)]
    ws = [h for h in hosts if h["product_type"] == "workstation"]
    users = []
    for i in range(160):
        h = R.choice(ws)
        fn, ln = R.choice(FIRST), R.choice(LAST)
        users.append((h, f"{fn[0].lower()}{ln.lower()}{i}", f"{fn} {ln}", R.choice(DEPTS), f"SN{R.randint(10**6, 10**7)}"))
    rows, scans = [], []
    for d in range(1, 45):
        day = TODAY - dt.timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for h, sam, name, dept, serial in R.sample(users, R.randint(14, 30)):
            for _ in range(R.randint(1, 3)):
                cat, _, size = R.choices(cats, weights=[w for _, w, _ in cats])[0]
                files = R.randint(1, 40)
                r = dict(t)
                r.update(day=day, aid=h["source_asset_id"], user_key=sam, device_serial=serial,
                         folder=R.choice(["(top level)", "Exports", "Reports", "Scans", "Backup"]), category=cat,
                         user_name=sam, display_name=name, department=dept, title=None, hostname=h["hostname"],
                         files=files, bytes=int(files * size * R.uniform(0.3, 1.5)), site_label=h["site_label"],
                         site_tag=h["site_tag"], collected_at=NOW,
                         first_write=ts(d), last_write=ts(d), sample_files=[], file_types=[])
                rows.append(r)
            s = dict(st)
            s.update(scan_id=f"sc-{d}-{serial}", aid=h["source_asset_id"], hostname=h["hostname"], created_on=ts(d),
                     completed_on=ts(d), last_updated=ts(d), files_malicious=1 if R.random() < 0.01 else 0,
                     files_quarantined=0, site_label=h["site_label"], site_tag=h["site_tag"], collected_at=NOW)
            scans.append(s)
    insert(cur, "usb_file_writes_daily", rows)
    insert(cur, "usb_scans", scans)
    print(f"  usb: {len(rows):,} write rows, {len(scans):,} scans")


# ------------------------------------------------------------------ snapshot history
# Point-in-time columns where a higher number is good news (or just size):
# back-filled flat-ish rather than "was worse".
NEUTRAL = {"managed_hosts", "workstations", "servers", "domain_controllers", "assets", "external_assets",
           "external_domains", "external_ips", "unmanaged_assets"}
GOOD_METRICS = ("total:", "mfa_registered", "mfa_users",
                # daily_impact_metrics: denominators and good counts, which mustn't read as worse in the past
                "servers_active", "servers_patched_35d", "dcs_active", "hosts_active", "managed_hosts",
                "enabled_accounts", "people_accounts")
SNAPSHOT_TABLES = ["daily_site_metrics", "daily_sla_metrics", "daily_product_metrics", "daily_kev_metrics",
                   "daily_epss_metrics", "daily_source_metrics", "daily_asset_metrics", "daily_identity_metrics",
                   "daily_impact_metrics"]


# The programme action log (normally read from a workbook on the share): what the
# programme surfaced and what happened to it. Made-up, generic items; sources, severities
# and statuses use the workbook's drop-down values (impact.SOURCES / SEVERITIES / STATUSES).
ACTIONS = [
    # days ago found, what, source, site, severity, action, owner team, status, days ago closed
    (44, "Internet-facing VPN appliance missing a critical patch", "Weekly report", "Northgate Hospital", "Critical",
     "Patched out of hours; vendor advisory tracked", "Infrastructure", "Done", 41),
    (40, "Domain takeover risk: DNS record pointing at a released cloud host", "Dashboard", "Riverside Health",
     "High", "Stale DNS record removed", "Infrastructure", "Done", 39),
    (37, "Infostealer leak naming an enabled staff account", "Identity digest", "Lakeside Health", "High",
     "Password reset, sessions revoked, device checked", "Cyber", "Done", 36),
    (33, "Domain controller with no endpoint sensor", "Action pack", "Hillcrest Community Health", "High",
     "Sensor installed and verified", "Infrastructure", "Done", 26),
    (29, "Web server software with an actively exploited flaw on a public site", "Weekly report", "Riverside Health",
     "Critical", "Hosting provider patched; risk closed after rescan", "Applications", "Done", 24),
    (24, "Legacy file server on an unsupported OS still sharing data", "Servers report", "Northgate Hospital",
     "High", "Isolated to one VLAN pending migration; replacement scheduled", "Infrastructure", "Accepted risk", 18),
    (19, "Dormant admin account used after 200+ days", "Alert", "Lakeside Health", "High",
     "Confirmed legitimate; account moved to a named owner", "Cyber", "Done", 17),
    (14, "Shared clinical workstations without multi-factor sign-in", "Action pack", "Hillcrest Community Health",
     "Medium", "Tap-and-go MFA pilot on one ward", "Applications", "In progress", None),
    (9, "Browser update service disabled by policy on servers", "Dashboard", "Riverside Health",
     "Medium", "Policy change through change control", "Infrastructure", "In progress", None),
    (4, "Publicly reachable directory service on an old host name", "Weekly report", "Northgate Hospital", "High",
     "Firewall rule raised; awaiting change window", "Infrastructure", "Open", None),
]


def seed_actions(cur):
    rows = [dict(row_no=i + 2, found=TODAY - dt.timedelta(days=f), what=w, source=src, site_label=site,
                 severity=sev, action=act, owner_team=team, status=st,
                 closed=TODAY - dt.timedelta(days=c) if c is not None else None, ticket_ref=None, notes=None)
            for i, (f, w, src, site, sev, act, team, st, c) in enumerate(ACTIONS)]
    cur.execute("DELETE FROM impact_actions")
    insert(cur, "impact_actions", rows)


def backfill_snapshots(cur, days=45):
    """Copy today's snapshot rows back `days` days. Counts of bad things were
    ~12% higher at the start, with day-to-day wobble and a plateau in the
    middle, so arrows mostly point the right way without being a straight line."""
    for table in SNAPSHOT_TABLES:
        cur.execute(f"SELECT * FROM {table} WHERE snapshot_date::date = %s", (TODAY,))
        today = [dict(r) for r in cur.fetchall()]
        if not today:
            continue
        rows = []
        for d in range(1, days + 1):
            day = TODAY - dt.timedelta(days=d)
            for r in today:
                n = dict(r)
                n["snapshot_date"] = day.isoformat() if isinstance(r["snapshot_date"], str) else day
                metric = str(r.get("metric") or "")
                good = metric.startswith(GOOD_METRICS)
                drift = 0.12 * (d / days) + 0.03 * math.sin(d / 4.0)
                for k, v in r.items():
                    if k == "snapshot_date" or not isinstance(v, (int, float)) or isinstance(v, bool) or v is None:
                        continue
                    if k in NEUTRAL or good:
                        f = 1.0 - 0.01 * (d / days)
                    elif k.startswith(("avg_", "max_")) or "rate" in k:
                        continue
                    else:
                        f = 1.0 + drift + R.uniform(-0.015, 0.015)
                    n[k] = max(0, int(round(v * f)))
                rows.append(n)
        insert(cur, table, rows)
    # alert open counts are a snapshot column on a per-event-day table
    cur.execute("SELECT site_label, open_total, open_crit_high FROM daily_alert_metrics WHERE snapshot_date = %s", (TODAY,))
    for site, ot, och in [tuple(r.values()) for r in cur.fetchall()]:
        for d in range(1, days + 1):
            f = 1.0 + 0.2 * (d / days) + R.uniform(-0.08, 0.08)
            cur.execute("UPDATE daily_alert_metrics SET open_total = %s, open_crit_high = %s "
                        "WHERE snapshot_date = %s AND site_label = %s AND open_total IS NULL",
                        (int((ot or 0) * f), int((och or 0) * f), TODAY - dt.timedelta(days=d), site))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=os.path.join(ROOT, "reports"), help="where the sample-* files go")
    args = ap.parse_args()

    admin = psycopg2.connect(dbname="postgres", **PG)
    admin.autocommit = True
    admin.cursor().execute(f"DROP DATABASE IF EXISTS {DB}")
    admin.cursor().execute(f"CREATE DATABASE {DB}")

    tmp = tempfile.mkdtemp()
    cfg_text = run_e2e.CONFIG.replace(f"name: {run_e2e.DB}", f"name: {DB}").replace("\nungrouped_label: Ungrouped", EXTRA_SITES)
    cfgp = os.path.join(tmp, "config.yaml")
    open(cfgp, "w").write(cfg_text)
    open(os.path.join(tmp, "secrets.yaml"), "w").write(run_e2e.SECRETS)

    print("== collectors against the mocks (templates for every table)")
    srv = mock_vendors.start(run_e2e.PORT)
    run(cfgp, "collect.py")
    srv.shutdown()

    conn = psycopg2.connect(dbname=DB, **PG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    print("== seeding the demo estate")
    hosts = seed_hosts(cur)
    seed_vulns(cur, hosts)
    seed_external(cur)
    seed_alerts(cur, hosts)
    seed_identity(cur)
    seed_email(cur)
    seed_usb(cur, hosts)
    conn.commit()

    print("== rollups")
    run(cfgp, "rollup_daily_metrics.py", "--backfill-days", str(HISTORY_DAYS))
    run(cfgp, "reclassify_product_families.py")
    run(cfgp, "impact.py", "--only", "metrics")
    backfill_snapshots(cur)
    seed_actions(cur)
    conn.commit()
    conn.close()

    print("== reports")
    out = os.path.join(tmp, "out")
    os.makedirs(out)
    run(cfgp, "exec_report.py", "--period", "week", "--out", os.path.join(out, "exec-region.html"), "--no-pdf")
    run(cfgp, "exec_report.py", "--period", "week", "--site", "Riverside Health",
        "--out", os.path.join(out, "exec-site.html"), "--no-pdf")
    first = TODAY.replace(day=1)
    last_month = (first - dt.timedelta(days=1)).replace(day=1)
    run(cfgp, "action_pack.py", "--out-dir", out, "--since", last_month.isoformat(),
        "--until", (first - dt.timedelta(days=1)).isoformat())
    pack = next(f for f in os.listdir(out) if f.startswith("region-") and f.endswith(".xlsx"))
    # this month so far: the snapshot history covers the whole of it
    run(cfgp, "scorecard.py", "--out-dir", out, "--month", TODAY.strftime("%Y-%m"), "--no-pdf")
    cards = {f.split("-scorecard-")[0]: f for f in os.listdir(out) if "-scorecard-" in f}
    run(cfgp, "server_report.py", "--out-dir", os.path.join(out, "servers"), "--no-pdf")
    run(cfgp, "impact_report.py", "--out-dir", os.path.join(out, "impact"), "--no-pdf")
    os.makedirs(args.out, exist_ok=True)
    shutil.copy(os.path.join(out, "exec-region.html"), os.path.join(args.out, "sample-exec-report.html"))
    shutil.copy(os.path.join(out, "exec-site.html"), os.path.join(args.out, "sample-exec-report-site.html"))
    shutil.copy(os.path.join(out, pack), os.path.join(args.out, "sample-action-pack.xlsx"))
    shutil.copy(os.path.join(out, cards["region"]), os.path.join(args.out, "sample-scorecard.html"))
    shutil.copy(os.path.join(out, cards["Riverside_Health"]), os.path.join(args.out, "sample-scorecard-site.html"))
    for sub, name in (("servers", "sample-servers-report.html"), ("impact", "sample-impact-report.html")):
        html_ = next((f for f in os.listdir(os.path.join(out, sub)) if f.endswith(".html")), None) \
            if os.path.isdir(os.path.join(out, sub)) else None
        if html_:
            shutil.copy(os.path.join(out, sub, html_), os.path.join(args.out, name))
    print(f"samples written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
