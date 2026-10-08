#!/usr/bin/env python3
"""
Five-page exec security posture report: what moved the dial this week,
month or quarter, for people who will never open Grafana -- region-wide,
or for a single site.

Page 1 is the estate: managed devices, OS support status, machines with no
sensor and internet-facing assets. Page 2 is endpoint vulnerabilities
(Falcon Spotlight): KEV, SLA, network
exposure, sensor coverage and which product families drive it. Page 3 is
the external attack surface (Hadrian). Page 4 is email (Check Point HEC
mail flow and threats). Page 5 is the behaviour/people side (alert volume
and disposition, identity risk). All five are rendered into one HTML file
with print page-breaks between them, so it opens as one document but
prints/exports as five pages.

Pulls from the daily_* rollups (rollup_daily_metrics.py) wherever one
exists -- they're already the right shape for "this period vs that one".
Two things have no rollup table and are queried live against their source
table instead:
  - alert disposition (true_positive/false_positive/ignored) -- the
    security_alerts.disposition column (added alongside this report;
    see db_schema.py) isn't aggregated into daily_alert_metrics
  - identity_risk_factors -- wholesale-replaced every collector run, so
    the tile values are "right now"; their trend arrows come from
    daily_identity_metrics snapshots instead

Trend lines under the headline tiles come in two kinds:
  - point-in-time counts (open vulns, KEV, open alerts, identity): the
    daily snapshot in force at the start of the period vs the one at its
    end (see snapshot_trend)
  - counts of things that happened in the period (opened/fixed, alerts,
    email threats): this period vs the previous one of the same kind,
    shown only once history fully covers that previous period (see
    flow_trend)

Email direction (inbound/outbound/internal) comes from email_events.direction
(site_resolver.email_direction), which classifies a message by whether its
sender/recipient domains are in any site's configured `email_domains`. If no
site has `email_domains` set, everything lands in "Unclassified" -- that's
not a bug, it means email_domains needs configuring in config.yaml first.

No new dependencies: charts are hand-rolled inline SVG, the page is a
single self-contained HTML file (works offline, prints cleanly to PDF via
the browser's own print dialog -- no headless-browser/PDF library needed).

    python3 exec_report.py --config config.yaml --period week --all-sites
    python3 exec_report.py --config config.yaml --period quarter --all-sites
    python3 exec_report.py --config config.yaml --period month --site SITE-A
    python3 exec_report.py --config config.yaml --since 2026-07-01 --until 2026-09-30

--all-sites writes reports/<period>/region.html plus one <site>.html per
configured site (and the ungrouped bucket) from a single DB connection.
Otherwise the default --out is reports/exec-report-<period>[-<site>].html.
reports/ is created if missing and gitignored -- it holds real site names
and counts.
"""
import argparse
import datetime as dt
import html
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

import config as config_mod
import identity_categories as ic
import os_lifecycle
from db import pg_connect
from email_types import THREAT_EVENT_TYPES

SEVERITY_COLOR = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#d97706",
    "low": "#2563eb", "info": "#64748b",
}
GOOD = "#16a34a"   # green is reserved for genuinely good numbers, same rule as the Grafana dashboards
INK = "#0f172a"
MUTED = "#64748b"
FAINT = "#94a3b8"
BORDER = "#e2e8f0"

DIRECTION_LABEL = {"inbound": "Inbound", "outbound": "Outbound", "internal": "Internal", "unknown": "Unclassified"}
DIRECTION_COLOR = {"inbound": "#0ea5e9", "outbound": "#d97706", "internal": "#64748b", "unknown": "#cbd5e1"}
DIRECTION_ORDER = ("inbound", "outbound", "internal", "unknown")


# --------------------------------------------------------------- periods
@dataclass
class Period:
    kind: str            # week | month | quarter | custom
    since: dt.date
    until: dt.date       # inclusive
    label: str           # human: "Week 41, 2026 (05 Oct - 11 Oct)"
    slug: str            # file/folder-safe: "week-2026-W41"
    prev_since: dt.date  # the previous period of the same kind, for flow trends
    prev_until: dt.date
    prev_word: str       # "previous week"


def week_period(ref: dt.date) -> Period:
    """The last full Monday-Sunday week before `ref`."""
    since = ref - dt.timedelta(days=ref.weekday() + 7)
    until = since + dt.timedelta(days=6)
    yr, wk, _ = since.isocalendar()
    return Period("week", since, until,
                  f"Week {wk}, {yr} ({since.strftime('%d %b')} - {until.strftime('%d %b')})",
                  f"week-{yr}-W{wk:02d}", since - dt.timedelta(days=7), since - dt.timedelta(days=1),
                  "previous week")


def month_period(ref: dt.date) -> Period:
    """The last full calendar month before `ref`."""
    until = ref.replace(day=1) - dt.timedelta(days=1)
    since = until.replace(day=1)
    prev_until = since - dt.timedelta(days=1)
    return Period("month", since, until, since.strftime("%B %Y"), f"month-{since.strftime('%Y-%m')}",
                  prev_until.replace(day=1), prev_until, "previous month")


def _quarter_start(d: dt.date) -> dt.date:
    return dt.date(d.year, (d.month - 1) // 3 * 3 + 1, 1)


def quarter_period(ref: dt.date) -> Period:
    """The last full calendar quarter before `ref`."""
    until = _quarter_start(ref) - dt.timedelta(days=1)
    since = _quarter_start(until)
    prev_until = since - dt.timedelta(days=1)
    q = (since.month - 1) // 3 + 1
    return Period("quarter", since, until, f"Q{q} {since.year}", f"quarter-{since.year}-Q{q}",
                  _quarter_start(prev_until), prev_until, "previous quarter")


def custom_period(since: dt.date, until: dt.date) -> Period:
    days = (until - since).days + 1
    return Period("custom", since, until, f"{since.isoformat()} to {until.isoformat()}",
                  f"{since.isoformat()}_{until.isoformat()}",
                  since - dt.timedelta(days=days), since - dt.timedelta(days=1), f"previous {days} days")


# ----------------------------------------------------------------- query
# Every query takes named params and is filtered by SITE: with site=None
# it's region-wide (all sites, including Ungrouped/TEST), otherwise one
# site_label.
SITE = "(%(site)s::text IS NULL OR site_label = %(site)s::text)"
# Endpoint vuln figures (page 1) exclude Hadrian's external risks, which get
# their own page: ~360 low-severity web/TLS/DNS hygiene items would otherwise
# read as "new vulnerabilities" next to Spotlight's.
ENDPOINT = "source <> 'hadrian'"
# reporting.vuln_bulk_load_dates (set in main): days a vulnerability source
# stamped a mass of findings as "first found" because collection started or
# coverage expanded, not because they were new -- e.g. Spotlight's initial
# load and the day assessment was switched on for the rest of the estate.
# Excluded from "opened", and no snapshot/period comparison crosses one.
BULK_DATES: List[dt.date] = []
OS_EOS: Dict[str, dt.date] = os_lifecycle.table()   # + reporting.os_end_of_support, set in main
NOT_BULK = "snapshot_date <> ALL(%(bulk)s::date[])"


def after_bulk() -> str:
    """Snapshot filter: only snapshots taken after the latest bulk load."""
    return f"snapshot_date::date > '{max(BULK_DATES).isoformat()}'" if BULK_DATES else "TRUE"
EXTERNAL = "source = 'hadrian'"


def q1(cur, sql: str, **params) -> Any:
    cur.execute(sql, params)
    return cur.fetchone()


def qall(cur, sql: str, **params) -> List[Tuple]:
    cur.execute(sql, params)
    return cur.fetchall()


def fetch_vulns(cur, p: Period, site: Optional[str], days_last_seen: int = 30, flows_only: bool = False) -> dict:
    """flows_only: just the opened/fixed movement (what a previous-period
    comparison needs) -- skips the point-in-time queries over every open
    finding, which are the expensive part at millions of rows."""
    # daily_vuln_flow_metrics is per event day, so summing over the period
    # is right (daily_product_metrics.new_*/fixed_* are rolling windows and
    # must not be summed -- see rollup_daily_metrics.py).
    movement = q1(cur, f"""
        SELECT COALESCE(SUM(opened) FILTER (WHERE {NOT_BULK}),0), COALESCE(SUM(fixed),0),
               COALESCE(SUM(opened) FILTER (WHERE severity='critical' AND {NOT_BULK}),0),
               COALESCE(SUM(opened) FILTER (WHERE severity='high' AND {NOT_BULK}),0),
               COALESCE(SUM(fixed) FILTER (WHERE severity='critical'),0),
               COALESCE(SUM(fixed) FILTER (WHERE severity='high'),0),
               COALESCE(SUM(opened) FILTER (WHERE NOT {NOT_BULK}),0)
        FROM daily_vuln_flow_metrics WHERE snapshot_date BETWEEN %(since)s AND %(until)s AND {SITE} AND {ENDPOINT}
    """, since=p.since, until=p.until, site=site, bulk=BULK_DATES)
    bucket = "day" if p.kind == "week" else "week"
    buckets = qall(cur, f"""
        SELECT GREATEST(date_trunc('{bucket}', snapshot_date)::date, %(since)s::date) AS b,
               COALESCE(SUM(opened) FILTER (WHERE {NOT_BULK}),0), COALESCE(SUM(fixed),0)
        FROM daily_vuln_flow_metrics WHERE snapshot_date BETWEEN %(since)s AND %(until)s AND {SITE} AND {ENDPOINT}
        GROUP BY 1 ORDER BY 1
    """, since=p.since, until=p.until, site=site, bulk=BULK_DATES)
    if flows_only:
        return {"opened": movement[0], "fixed": movement[1], "bulk_opened": movement[6]}
    open_now = dict(qall(cur, f"""
        SELECT severity, COUNT(*) FROM vuln_findings WHERE state IN ('OPEN','REOPENED') AND {SITE} AND {ENDPOINT}
        GROUP BY severity""", site=site))
    kev = q1(cur, f"""
        SELECT COALESCE(SUM(kev_open_total),0), COALESCE(SUM(kev_open_crit),0),
               COALESCE(SUM(kev_open_high),0), COALESCE(SUM(kev_ransomware_total),0),
               COALESCE(SUM(kev_past_due_total),0)
        FROM daily_kev_metrics
        WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM daily_kev_metrics WHERE snapshot_date <= %(until)s)
          AND {SITE}
    """, until=p.until + dt.timedelta(days=1), site=site)
    mttr = qall(cur, f"""
        SELECT severity, COALESCE(SUM(fixed_count),0) AS n,
               CASE WHEN SUM(fixed_count) > 0 THEN SUM(avg_remediation_days * fixed_count) / SUM(fixed_count) END,
               CASE WHEN SUM(fixed_count) > 0 THEN 100.0 * SUM(sla_compliant_count) / SUM(fixed_count) END
        FROM daily_mttr_metrics WHERE snapshot_date BETWEEN %(since)s AND %(until)s AND {SITE} AND {ENDPOINT}
        GROUP BY severity
        ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
    """, since=p.since, until=p.until, site=site)
    # Same staleness window as the rollups (reporting.days_last_seen), so
    # these match the daily snapshots their trend arrows compare.
    exposure = q1(cur, f"""
        SELECT COUNT(*) FILTER (WHERE age > COALESCE(sp.threshold_days, 60)),
               COUNT(*) FILTER (WHERE age > COALESCE(sp.threshold_days, 60) AND vf.severity = 'critical'),
               COUNT(*) FILTER (WHERE age > COALESCE(sp.threshold_days, 60) AND vf.severity = 'high'),
               COUNT(*) FILTER (WHERE vf.is_remote_no_auth AND vf.severity IN ('critical','high')),
               COUNT(*) FILTER (WHERE vf.severity IN ('critical','high'))
        FROM (SELECT severity, site_label, source, state, last_found, is_remote_no_auth,
                     EXTRACT(EPOCH FROM now() - first_found) / 86400.0 AS age FROM vuln_findings) vf
        LEFT JOIN sla_policy sp ON sp.severity = vf.severity
        WHERE vf.state IN ('OPEN','REOPENED') AND vf.last_found >= now() - (%(days)s || ' days')::interval
          AND {SITE.replace("site_label", "vf.site_label")} AND vf.{ENDPOINT}
    """, days=days_last_seen, site=site)
    sensors = q1(cur, f"""
        SELECT COALESCE(SUM(managed_hosts),0), COALESCE(SUM(stale_sensors),0) FROM daily_asset_metrics
        WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM daily_asset_metrics WHERE snapshot_date <= %(until)s)
          AND {SITE}
    """, until=p.until + dt.timedelta(days=1), site=site)
    return {
        "open_now": open_now,
        "sla_breach": exposure[0], "sla_breach_crit": exposure[1], "sla_breach_high": exposure[2],
        "sla_breach_ch": exposure[1] + exposure[2], "remote_ch": exposure[3], "open_ch_windowed": exposure[4],
        "sla_days": dict(qall(cur, "SELECT severity, threshold_days FROM sla_policy")),
        "managed_hosts": sensors[0], "stale_sensors": sensors[1],
        "opened": movement[0], "fixed": movement[1],
        "opened_crit": movement[2], "opened_high": movement[3],
        "fixed_crit": movement[4], "fixed_high": movement[5], "bulk_opened": movement[6],
        "buckets": buckets, "bucket": bucket,
        "kev_open": kev[0], "kev_crit": kev[1], "kev_high": kev[2],
        "kev_ransomware": kev[3], "kev_past_due": kev[4],
        "mttr": mttr,
    }


def fetch_alerts(cur, p: Period, site: Optional[str]) -> dict:
    new_counts = q1(cur, f"""
        SELECT COALESCE(SUM(new_critical),0), COALESCE(SUM(new_high),0),
               COALESCE(SUM(new_medium),0), COALESCE(SUM(new_low),0), COALESCE(SUM(closed_today),0)
        FROM daily_alert_metrics WHERE snapshot_date BETWEEN %(since)s AND %(until)s AND {SITE}
    """, since=p.since, until=p.until, site=site)
    # open_* is NULL on days no run snapshotted (backfilled history).
    open_now = q1(cur, f"""
        SELECT COALESCE(SUM(open_total),0), COALESCE(SUM(open_crit_high),0)
        FROM daily_alert_metrics
        WHERE snapshot_date = (SELECT MAX(snapshot_date) FROM daily_alert_metrics
                               WHERE snapshot_date <= %(until)s AND open_total IS NOT NULL)
          AND {SITE}
    """, until=p.until + dt.timedelta(days=1), site=site)
    bucket = "day" if p.kind == "week" else "week"
    buckets = qall(cur, f"""
        SELECT GREATEST(date_trunc('{bucket}', snapshot_date)::date, %(since)s::date) AS b,
               COALESCE(SUM(new_critical + new_high + new_medium + new_low),0)
        FROM daily_alert_metrics WHERE snapshot_date BETWEEN %(since)s AND %(until)s AND {SITE}
        GROUP BY 1 ORDER BY 1
    """, since=p.since, until=p.until, site=site)
    disposition = qall(cur, f"""
        SELECT COALESCE(disposition, status, 'unknown') AS disp, COUNT(*)
        FROM security_alerts WHERE closed_at >= %(since)s AND closed_at < %(until_excl)s AND {SITE}
        GROUP BY 1 ORDER BY 2 DESC
    """, since=p.since, until_excl=p.until + dt.timedelta(days=1), site=site)
    return {
        "new_crit": new_counts[0], "new_high": new_counts[1],
        "new_med": new_counts[2], "new_low": new_counts[3], "closed": new_counts[4],
        "open_total": open_now[0], "open_crit_high": open_now[1],
        "buckets": buckets, "bucket": bucket, "disposition": disposition,
    }


def fetch_identity(cur, site: Optional[str]) -> dict:
    """Current counts for the stakeholder identity categories
    (identity_categories.py): distinct enabled accounts per category and per
    group. "Right now" only -- identity_risk_factors is replaced every run;
    trends come from the daily cat:/catgroup: snapshots. Factors carry no site
    of their own, so it's taken from the entity."""
    row = q1(cur, ic.counts_sql(SITE.replace("site_label", "e.site_label")), site=site)
    n = len(ic.CATEGORIES)
    stale_access = q1(cur, f"""
        SELECT count(*) FROM identity_entities e
        WHERE NOT e.retired AND {ic.ENABLED_FILTER} AND e.access_account IS NOT NULL
          AND {SITE.replace("site_label", "e.site_label")}
          AND EXISTS (SELECT 1 FROM identity_risk_factors f WHERE f.source = e.source AND f.entity_id = e.entity_id
                      AND f.factor_type = 'STALE_ACCOUNT')""", site=site)[0]
    return {"cats": {c.key: int(row[i]) for i, c in enumerate(ic.CATEGORIES)},
            "groups": {g: int(row[n + i]) for i, g in enumerate(ic.GROUPS)},
            "stale_access": int(stale_access)}


def fetch_email(cur, p: Period, site: Optional[str]) -> dict:
    rows = qall(cur, f"""
        SELECT direction, event_type, COALESCE(SUM(events),0), COALESCE(SUM(high_plus),0)
        FROM daily_email_metrics WHERE snapshot_date BETWEEN %(since)s AND %(until)s AND {SITE}
        GROUP BY direction, event_type ORDER BY direction, 3 DESC
    """, since=p.since, until=p.until, site=site)
    # Split threats (phishing/malware/dlp/anomaly) from bulk mail
    # classification (graymail/spam/shadow_it/alert) -- on real data,
    # graymail+spam alone was ~97% of all HEC events, so counting
    # everything under "threats" drowns the real signal (see email_types.py).
    by_direction: Dict[str, List[Tuple[str, int, int]]] = {}
    totals: Dict[str, List[int]] = {}
    bulk_totals: Dict[str, int] = {}
    all_by_direction: Dict[str, List[Tuple[str, int, int]]] = {}
    for direction, etype, n, hp in rows:
        d = direction or "unknown"
        all_by_direction.setdefault(d, []).append((etype, n, hp))
        if etype in THREAT_EVENT_TYPES:
            by_direction.setdefault(d, []).append((etype, n, hp))
            t = totals.setdefault(d, [0, 0])
            t[0] += n
            t[1] += hp
        else:
            bulk_totals[d] = bulk_totals.get(d, 0) + n
    dmarc = q1(cur, f"SELECT COALESCE(SUM(messages),0), COALESCE(SUM(dmarc_pass),0) FROM dmarc_daily "
                    f"WHERE report_date BETWEEN %(since)s AND %(until)s AND {SITE}",
               since=p.since, until=p.until, site=site)
    return {"by_direction": by_direction, "totals": totals, "bulk_totals": bulk_totals,
            "all_by_direction": all_by_direction,
            "dmarc_messages": dmarc[0], "dmarc_pass": dmarc[1]}


def fetch_email_flow(cur, p: Period, site: Optional[str]) -> Dict[str, int]:
    """Mail-flow funnel totals for the period (daily_email_flow_metrics,
    collectors/checkpoint_hec_flow.py). Counts emails, not events."""
    return {m: int(v) for m, v in qall(cur, f"""
        SELECT metric, COALESCE(SUM(value),0) FROM daily_email_flow_metrics
        WHERE snapshot_date BETWEEN %(since)s AND %(until)s AND {SITE} GROUP BY 1""",
        since=p.since, until=p.until, site=site)}


def funnel_stages(f: Dict[str, int]) -> dict:
    """Derive the funnel boxes from the stored counts. Microsoft's SCL 7-9
    is quarantined before mail reaches users' mailboxes, so Check Point's
    stage is what Microsoft let through; "delivered" is what neither
    quarantined (counted directly, not by subtraction of overlapping sets)."""
    external = f.get("incoming", 0)
    # incoming + internal, as Check Point's console counts "Inbound" (the
    # collector keeps the two disjoint, internal ones as internal_<metric>)
    f = {m: f.get(m, 0) + f.get("internal_" + m, 0) for m in [k for k in f if not k.startswith("internal_")]}
    inbound = f.get("incoming", 0)
    ms_q, junk = f.get("ms_quarantine", 0), f.get("ms_junk", 0)
    delivered = max(f.get("not_cp_quarantined", 0) - f.get("ms_quarantine_not_cp", 0), 0)
    return {
        "external": external, "internal": max(inbound - external, 0),
        "inbound": inbound, "ms_inbox": max(inbound - junk - ms_q, 0), "ms_junk": junk, "ms_quarantine": ms_q,
        "to_cp": max(inbound - ms_q, 0), "clean": f.get("cp_clean", 0), "graymail": f.get("cp_graymail", 0),
        "spam": f.get("cp_spam", 0), "malicious": f.get("cp_phishing", 0) + f.get("cp_malware", 0),
        "malware": f.get("cp_malware", 0), "suspicious": f.get("cp_suspicious_phishing", 0),
        "cp_quarantined": f.get("cp_quarantined", 0), "delivered": delivered,
        "filtered": max(inbound - delivered, 0),
        "restore_requested": f.get("restore_requested", 0), "restored": f.get("restored", 0),
        "restore_declined": f.get("restore_declined", 0),
    }


def fetch_estate(cur, site: Optional[str]) -> dict:
    """What's being protected, right now: Falcon-managed devices by type and
    OS (with vendor support status), machines with no sensor, and Hadrian's
    internet-facing domains and IPs. Per-site rows for the region report."""
    eos = os_lifecycle.sql_eos("os_version", OS_EOS)
    os_rows = qall(cur, f"""
        SELECT COALESCE(os_version, 'Unknown'), count(*),
               count(*) FILTER (WHERE last_seen > now() - interval '7 days'),
               count(*) FILTER (WHERE product_type = 'workstation'),
               count(*) FILTER (WHERE product_type IN ('server', 'domain_controller'))
        FROM assets WHERE source = 'falcon' AND NOT retired AND {SITE}
        GROUP BY 1 ORDER BY 2 DESC""", site=site)
    dev = q1(cur, f"""
        SELECT count(*), count(*) FILTER (WHERE last_seen > now() - interval '7 days'),
               count(*) FILTER (WHERE product_type = 'workstation'), count(*) FILTER (WHERE product_type = 'server'),
               count(*) FILTER (WHERE product_type = 'domain_controller')
        FROM assets WHERE source = 'falcon' AND NOT retired AND {SITE}""", site=site)
    missing = q1(cur, f"""
        SELECT count(*) FILTER (WHERE discovery_class IN ('domain_controller_no_sensor','server_no_sensor',
                                                          'workstation_no_sensor','cloud_no_sensor')),
               count(*) FILTER (WHERE discovery_class IN ('vmware_nic','network_device'))
        FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND {SITE}""", site=site)
    ext = q1(cur, f"""
        SELECT count(*) FILTER (WHERE asset_type = 'Domain'), count(*) FILTER (WHERE asset_type ILIKE '%%ip')
        FROM external_assets WHERE source = 'hadrian' AND NOT retired AND {SITE}""", site=site)
    by_site = [] if site else qall(cur, f"""
        SELECT s.site_label, COALESCE(a.ws,0), COALESCE(a.srv,0), COALESCE(a.unsup,0), COALESCE(m.n,0),
               COALESCE(x.domains,0), COALESCE(x.ips,0)
        FROM dim_site s
        LEFT JOIN (SELECT site_label, count(*) FILTER (WHERE product_type = 'workstation') ws,
                          count(*) FILTER (WHERE product_type IN ('server','domain_controller')) srv,
                          count(*) FILTER (WHERE {eos} < current_date) unsup
                   FROM assets WHERE source = 'falcon' AND NOT retired GROUP BY 1) a ON a.site_label = s.site_label
        LEFT JOIN (SELECT site_label, count(*) n FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired
                     AND discovery_class IN ('domain_controller_no_sensor','server_no_sensor','workstation_no_sensor',
                                             'cloud_no_sensor') GROUP BY 1) m ON m.site_label = s.site_label
        LEFT JOIN (SELECT site_label, count(*) FILTER (WHERE asset_type = 'Domain') domains,
                          count(*) FILTER (WHERE asset_type ILIKE '%%ip') ips
                   FROM external_assets WHERE source = 'hadrian' AND NOT retired GROUP BY 1) x
               ON x.site_label = s.site_label
        WHERE COALESCE(a.ws,0) + COALESCE(a.srv,0) + COALESCE(m.n,0) + COALESCE(x.domains,0) > 0
        ORDER BY COALESCE(a.ws,0) + COALESCE(a.srv,0) DESC""")
    today = dt.date.today()
    oses = []
    for name, n, active, ws, srv in os_rows:
        end = os_lifecycle.lookup(name, OS_EOS)
        status = ("unknown" if end is None else "unsupported" if end < today
                  else "ending" if (end - today).days < os_lifecycle.ENDING_SOON_DAYS else "supported")
        oses.append((name, int(n), int(active), int(ws), int(srv), end, status))
    return {
        "devices": dev[0], "active": dev[1], "workstations": dev[2], "servers": dev[3], "dcs": dev[4],
        "oses": oses,
        "unsupported": sum(o[1] for o in oses if o[6] == "unsupported"),
        "ending": sum(o[1] for o in oses if o[6] == "ending"),
        "missing_named": missing[0], "missing_network": missing[1],
        "domains": ext[0], "ips": ext[1], "by_site": by_site,
    }


def fetch_site_breakdown(cur) -> List[Tuple]:
    """Region report: every site, worst first."""
    return qall(cur, f"""
        SELECT site_label,
               COUNT(*) FILTER (WHERE severity='critical') AS crit,
               COUNT(*) FILTER (WHERE severity='high') AS high,
               COUNT(*) AS total
        FROM vuln_findings WHERE state IN ('OPEN','REOPENED') AND {ENDPOINT}
        GROUP BY site_label ORDER BY crit DESC, high DESC
    """)


def fetch_product_breakdown(cur, site: Optional[str], limit: int = 10) -> List[Tuple]:
    """Which product families the exposure sits in -- the actionable "what
    to patch" view. Region-wide it also says how many sites each family's
    open crit/high are spread across."""
    return qall(cur, f"""
        SELECT COALESCE(product_family, 'Unknown'),
               COUNT(*) FILTER (WHERE severity='critical') AS crit,
               COUNT(*) FILTER (WHERE severity='high') AS high,
               COUNT(*) AS total,
               COUNT(DISTINCT site_label) FILTER (WHERE severity IN ('critical','high')) AS sites
        FROM vuln_findings WHERE state IN ('OPEN','REOPENED') AND {SITE} AND {ENDPOINT}
        GROUP BY 1 ORDER BY crit DESC, high DESC LIMIT %(limit)s
    """, site=site, limit=limit)


CONFIRMED_TYPES = ("Verified", "UnpatchedTechnology", "InfectedDevice")

RISK_TYPE_LABEL = {"Verified": "Verified", "UnpatchedTechnology": "Unpatched tech",
                   "InfectedDevice": "Infected device", "Potential": "Potential"}
VENDOR_SEV_ORDER = "CASE vendor_priority WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 " \
                   "WHEN 'Low' THEN 4 ELSE 5 END"


def fetch_external(cur, p: Period, site: Optional[str]) -> dict:
    """Hadrian: external assets and risks. Severity is Hadrian's own
    (vendor_priority keeps Info distinct; vuln_findings.severity folds it
    into low). "Confirmed" = Verified / UnpatchedTechnology / InfectedDevice;
    Potential risks are unverified, often old, and shown separately."""
    assets = dict(qall(cur, f"""
        SELECT CASE WHEN asset_type ILIKE '%%ip' THEN 'ip' ELSE 'domain' END, COUNT(*)
        FROM external_assets WHERE source = 'hadrian' AND NOT retired AND {SITE} GROUP BY 1""", site=site))
    open_rows = qall(cur, f"""
        SELECT COALESCE(vendor_priority, 'Unknown'), COALESCE(risk_type, 'Unknown'),
               COALESCE(plugin_family, 'other'), COUNT(*)
        FROM vuln_findings WHERE {EXTERNAL} AND state IN ('OPEN','REOPENED') AND {SITE}
        GROUP BY 1, 2, 3""", site=site)
    movement = q1(cur, f"""
        SELECT COALESCE(SUM(opened),0), COALESCE(SUM(fixed),0) FROM daily_vuln_flow_metrics
        WHERE snapshot_date BETWEEN %(since)s AND %(until)s AND {SITE} AND {EXTERNAL}""",
                  since=p.since, until=p.until, site=site)
    top = qall(cur, f"""
        SELECT vendor_priority, risk_type, title, hostname, site_label, first_found::date
        FROM vuln_findings WHERE {EXTERNAL} AND state IN ('OPEN','REOPENED') AND {SITE}
          AND vendor_priority IN ('Critical','High','Medium')
          AND (risk_type IN {CONFIRMED_TYPES} OR vendor_priority IN ('Critical','High'))
        ORDER BY CASE WHEN vendor_priority IN ('Critical','High') THEN 1
                      WHEN risk_type = 'InfectedDevice' THEN 2 ELSE 3 END,
                 {VENDOR_SEV_ORDER},
                 CASE risk_type WHEN 'InfectedDevice' THEN 1 WHEN 'Verified' THEN 2
                                WHEN 'UnpatchedTechnology' THEN 3 ELSE 4 END,
                 first_found
        LIMIT 12""", site=site)
    # Remediation SLA, same policy windows as endpoint (sla_policy). Hadrian's
    # Info folds into low here (vuln_findings.severity has no info band).
    sla_open = {r[0]: r[1:] for r in qall(cur, f"""
        SELECT vf.severity, COUNT(*),
               COUNT(*) FILTER (WHERE now() - vf.first_found <= make_interval(days => COALESCE(sp.threshold_days, 60)))
        FROM vuln_findings vf LEFT JOIN sla_policy sp ON sp.severity = vf.severity
        WHERE vf.{EXTERNAL} AND vf.state IN ('OPEN','REOPENED') AND {SITE.replace("site_label", "vf.site_label")}
        GROUP BY 1""", site=site)}
    sla_fixed = {r[0]: r[1:] for r in qall(cur, f"""
        SELECT severity, COALESCE(SUM(fixed_count),0), COALESCE(SUM(sla_compliant_count),0)
        FROM daily_mttr_metrics WHERE snapshot_date BETWEEN %(since)s AND %(until)s AND {SITE} AND {EXTERNAL}
        GROUP BY 1""", since=p.since, until=p.until, site=site)}
    sla_days = dict(qall(cur, "SELECT severity, threshold_days FROM sla_policy"))
    sla_rows = [(sev, sla_days.get(sev), *sla_open.get(sev, (0, 0)), *sla_fixed.get(sev, (0, 0)))
                for sev in ("critical", "high", "medium", "low")
                if sla_open.get(sev, (0,))[0] or sla_fixed.get(sev, (0,))[0]]
    total_open = sum(r[3] for r in open_rows)
    confirmed = [r for r in open_rows if r[1] in CONFIRMED_TYPES]
    sev = lambda rows, v: sum(r[3] for r in rows if r[0] == v)
    cats: Dict[str, List[int]] = {}
    for _, rtype, cat, n in open_rows:
        c = cats.setdefault(cat, [0, 0])
        c[0 if rtype in CONFIRMED_TYPES else 1] += n
    return {
        "domains": assets.get("domain", 0), "ips": assets.get("ip", 0),
        "open_total": total_open,
        "confirmed": sum(r[3] for r in confirmed),
        "unverified": total_open - sum(r[3] for r in confirmed),
        "confirmed_crit_high": sev(confirmed, "Critical") + sev(confirmed, "High"),
        "confirmed_medium": sev(confirmed, "Medium"),
        "crit_high_any": sev(open_rows, "Critical") + sev(open_rows, "High"),
        "leaked_creds": q1(cur, f"""
            SELECT count(*) FROM vuln_findings vf WHERE vf.{EXTERNAL} AND vf.state IN ('OPEN','REOPENED')
              AND vf.risk_type = 'InfectedDevice' AND {SITE.replace("site_label", "vf.site_label")}
              AND {ic.ACTIVE_LEAK_SQL}""", site=site)[0],
        "opened": movement[0], "fixed": movement[1],
        "categories": sorted(cats.items(), key=lambda kv: (-kv[1][0], -kv[1][1])),
        "top": top,
        "sla": sla_rows,
    }


# ---------------------------------------------------------------- trends
def snapshot_trend(cur, table: str, expr: str, p: Period, site: Optional[str],
                   where: str = "TRUE") -> Optional[dict]:
    """Change in SUM(expr) across `table`'s daily snapshots over the period,
    for point-in-time counts (open X right now). The collector runs early
    in the morning, so the snapshot dated `since` is the state at the start
    of the period and the one dated until+1 the state at its end: compare
    the latest snapshot on/before each. If history doesn't reach back to the
    start, falls back to the earliest snapshot inside the period -- the
    returned "since" date says which was used. None when there aren't two
    distinct snapshot days to compare yet.

    Both ends come from the same table, so the delta is self-consistent even
    where the tile's own value is queried live with a slightly different
    filter. `table`/`expr`/`where` are code-controlled constants, never user
    input. snapshot_date is cast because daily_site_metrics stores it as TEXT."""
    d = "snapshot_date::date"
    base_sql = f"FROM {table} WHERE {where} AND {SITE}"
    end = q1(cur, f"SELECT MAX({d}) {base_sql} AND {d} <= %(at)s",
             at=p.until + dt.timedelta(days=1), site=site)[0]
    if end is None:
        return None
    base = (q1(cur, f"SELECT MAX({d}) {base_sql} AND {d} <= %(at)s", at=p.since, site=site)[0]
            or q1(cur, f"SELECT MIN({d}) {base_sql} AND {d} BETWEEN %(since)s AND %(until)s",
                  since=p.since, until=p.until, site=site)[0])
    if base is None or base >= end:
        return None
    vals = dict(qall(cur, f"SELECT {d}, COALESCE(SUM({expr}),0) {base_sql} AND {d} IN (%(a)s, %(b)s) GROUP BY 1",
                     a=base, b=end, site=site))
    return {"from": int(vals.get(base, 0)), "to": int(vals.get(end, 0)), "since": base}


def history_start(cur) -> Dict[str, Optional[dt.date]]:
    """First day each flow source has data for (region-wide: a site with no
    events in a period genuinely had none, it isn't missing history). That
    first day is the initial load -- e.g. 219,900 Spotlight findings all
    stamped first_found within 30 minutes of the first collection -- so a
    previous period only counts as covered if it starts strictly after it."""
    return {
        # a bulk load restarts endpoint history: no previous period may reach back past one
        "vulns": max([d for d in [q1(cur, f"SELECT MIN(snapshot_date) FROM daily_vuln_flow_metrics "
                                           f"WHERE {ENDPOINT}")[0]] + BULK_DATES if d], default=None),
        "external": q1(cur, f"SELECT MIN(snapshot_date) FROM daily_vuln_flow_metrics WHERE {EXTERNAL}")[0],
        # first daily snapshot taken after Hadrian was first collected: earlier
        # snapshots hold 0 external assets/risks because there was no data yet,
        # not because there were none, so they can't be a trend baseline
        "external_snap": q1(cur, f"SELECT MIN(snapshot_date) FROM daily_source_metrics WHERE {EXTERNAL}")[0],
        "alerts": q1(cur, "SELECT MIN(created_at)::date FROM security_alerts")[0],
        "email": q1(cur, "SELECT MIN(snapshot_date) FROM daily_email_metrics")[0],
        "email_flow": q1(cur, "SELECT MIN(snapshot_date) FROM daily_email_flow_metrics")[0],
    }


def fetch_trends(cur, p: Period, site: Optional[str], hist: Dict[str, Optional[dt.date]],
                 top_family: Optional[str] = None) -> dict:
    prev = Period(p.kind, p.prev_since, p.prev_until, "", "", p.prev_since, p.prev_until, "")

    def covered(source: str) -> bool:
        return hist[source] is not None and hist[source] < p.prev_since

    pv = fetch_vulns(cur, prev, site, flows_only=True) if covered("vulns") else None
    pa = fetch_alerts(cur, prev, site) if covered("alerts") else None
    pe = fetch_email(cur, prev, site) if covered("email") else None
    pf = funnel_stages(fetch_email_flow(cur, prev, site)) if covered("email_flow") else None
    px = fetch_external(cur, prev, site) if covered("external") else None
    ext_since = hist["external_snap"] and f"snapshot_date >= '{hist['external_snap'].isoformat()}'"
    return {
        "open_vulns": snapshot_trend(cur, "daily_source_metrics", "total", p, site, f"{ENDPOINT} AND {after_bulk()}"),
        "kev_open": snapshot_trend(cur, "daily_kev_metrics", "kev_open_total", p, site, after_bulk()),
        "open_alerts": snapshot_trend(cur, "daily_alert_metrics", "open_total", p, site,
                                      "open_total IS NOT NULL"),
        "idcat": {k: snapshot_trend(cur, "daily_identity_metrics", "value", p, site, f"metric = '{m}'")
                  for k, m in [(c.key, f"cat:{c.key}") for c in ic.CATEGORIES]
                  + [(f"group:{g}", f"catgroup:{g}") for g in ic.GROUPS]},
        "prev_word": p.prev_word,
        "vuln_history_start": hist.get("vulns"),
        "prev_opened": pv and pv["opened"], "prev_fixed": pv and pv["fixed"],
        "prev_alerts": pa and (pa["new_crit"] + pa["new_high"] + pa["new_med"] + pa["new_low"]),
        "prev_inbound": pe and pe["totals"].get("inbound", [0, 0])[0],
        "prev_outbound": pe and pe["totals"].get("outbound", [0, 0])[0],
        "prev_flow_inbound": pf and pf["inbound"], "prev_flow_malicious": pf and pf["malicious"],
        "top_family": top_family and snapshot_trend(
            cur, "daily_product_metrics", "open_crit + open_high", p, site,
            "product_family = '%s' AND %s" % (top_family.replace("'", "''"), after_bulk())),
        "remote_ch": snapshot_trend(cur, "daily_site_metrics", "remote_crit + remote_high", p, site, after_bulk()),
        "stale_sensors": snapshot_trend(cur, "daily_asset_metrics", "stale_sensors", p, site),
        "devices": snapshot_trend(cur, "daily_asset_metrics", "managed_hosts", p, site),
        "unsupported_os": snapshot_trend(cur, "daily_asset_metrics", "unsupported_os", p, site,
                                         "unsupported_os IS NOT NULL"),
        "ext_domains": snapshot_trend(cur, "daily_asset_metrics", "external_domains", p, site,
                                      "external_domains IS NOT NULL"),
        "ext_ips": snapshot_trend(cur, "daily_asset_metrics", "external_ips", p, site, "external_ips IS NOT NULL"),
        "ext_assets": snapshot_trend(cur, "daily_asset_metrics", "external_assets", p, site, ext_since)
                      if ext_since else None,
        "ext_open": snapshot_trend(cur, "daily_source_metrics", "total", p, site, EXTERNAL),
        "prev_ext_opened": px and px["opened"], "prev_ext_fixed": px and px["fixed"],
    }


# ------------------------------------------------------------------ SVG
def compact(n: float) -> str:
    """1234 -> 1.2k, 4550279 -> 4.6M: short enough to sit above a bar."""
    n = float(n)
    for div, suffix in ((1e6, "M"), (1e3, "k")):
        if abs(n) >= div:
            v = n / div
            return f"{v:.1f}{suffix}" if v < 100 else f"{v:.0f}{suffix}"
    return f"{n:.0f}"


def svg_bars(buckets: Sequence[Tuple[dt.date, int, int]], bucket: str = "week", names=("Opened", "Fixed"),
             colors=("#dc2626", "#16a34a"), width=640, height=150) -> str:
    if not buckets:
        return '<p class="empty">No data for this period.</p>'
    pad_l, pad_b, pad_t = 30, 24, 22   # pad_t leaves room for the tallest bar's value label
    plot_w, plot_h = width - pad_l - 10, height - pad_b - pad_t
    vmax = max((max(row[1:]) for row in buckets), default=0) or 1
    n = len(buckets)
    group_w = plot_w / n
    bar_w = group_w / (len(names) + 1.2)
    label_fmt = "%a %d" if bucket == "day" else "%d %b"
    bars, labels = [], []
    for i, row in enumerate(buckets):
        b = row[0]
        gx = pad_l + i * group_w
        for j, v in enumerate(row[1:]):
            bh = (v / vmax) * plot_h
            bx = gx + j * bar_w + bar_w * 0.3
            by = pad_t + (plot_h - bh)
            bars.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w*0.9:.1f}" height="{bh:.1f}" '
                        f'fill="{colors[j]}" rx="1.5"><title>{names[j]} {b}: {v}</title></rect>')
            if v:   # printed value -- the PDF has no hover, so the number has to be on the page
                bars.append(f'<text x="{bx + bar_w * 0.45:.1f}" y="{by - 3:.1f}" font-size="8" fill="{INK}" '
                            f'text-anchor="middle">{compact(v)}</text>')
        labels.append(f'<text x="{gx + group_w/2:.1f}" y="{height-6}" font-size="9" fill="{MUTED}" '
                       f'text-anchor="middle">{b.strftime(label_fmt)}</text>')
    legend = "".join(
        f'<rect x="{pad_l + i*90}" y="0" width="10" height="10" fill="{c}" rx="2"/>'
        f'<text x="{pad_l + i*90 + 14}" y="9" font-size="10" fill="{INK}">{n_}</text>'
        for i, (n_, c) in enumerate(zip(names, colors))
    )
    return (f'<svg viewBox="0 0 {width} {height+16}" width="100%" style="max-width:{width}px">'
            f'<g transform="translate(0,16)">{"".join(bars)}{"".join(labels)}</g>{legend}</svg>')


def svg_funnel(st: dict, width=640) -> str:
    """Inbound -> Microsoft -> Check Point -> delivered, as stacked rows of
    labelled boxes (equal widths -- proportional ones would make the small,
    important boxes unreadable; each shows its share of inbound instead)."""
    if not st["inbound"]:
        return '<p class="empty">No mail-flow data for this period.</p>'
    inbound = st["inbound"]
    pad_l, row_h, gap = 112, 46, 22
    plot_w = width - pad_l
    out, y = [], 0

    def share(n):
        pc = 100.0 * n / inbound
        return "<0.1%" if 0 < pc < 0.1 else f"{pc:.1f}%" if pc < 10 else f"{pc:.0f}%"

    def boxes(cells, fills):
        nonlocal y
        w = plot_w / len(cells)
        for i, ((label, n), fill) in enumerate(zip(cells, fills)):
            x = pad_l + i * w
            ink = "#ffffff" if fill in (SEVERITY_COLOR["critical"], INK, "#475569") else INK
            out.append(f'<rect x="{x + 2:.1f}" y="{y}" width="{w - 4:.1f}" height="{row_h}" rx="4" fill="{fill}"/>'
                       f'<text x="{x + w / 2:.1f}" y="{y + 18}" font-size="10" fill="{ink}" text-anchor="middle">'
                       f'{html.escape(label)}</text>'
                       f'<text x="{x + w / 2:.1f}" y="{y + 36}" font-size="13" font-weight="700" fill="{ink}" '
                       f'text-anchor="middle">{n:,} <tspan font-size="10" font-weight="400">({share(n)})</tspan></text>')
        y += row_h

    def stage(label):
        out.append(f'<text x="0" y="{y + row_h / 2 + 4}" font-size="10" font-weight="700" fill="{MUTED}">'
                   f'{html.escape(label)}</text>')

    def arrow(text):
        nonlocal y
        out.append(f'<text x="{pad_l + plot_w / 2:.1f}" y="{y + 15}" font-size="10" fill="{MUTED}" '
                   f'text-anchor="middle">&#8595; {html.escape(text)} &#8595;</text>')
        y += gap

    stage("INBOUND")
    boxes([("Inbound + internal emails", inbound)], ["#cbd5e1"])
    arrow(f"{inbound:,} emails")
    stage("MICROSOFT 365")
    boxes([("Inbox", st["ms_inbox"]), ("Junk folder", st["ms_junk"]), ("Quarantined", st["ms_quarantine"])],
          ["#e2e8f0", "#cbd5e1", "#475569"])
    arrow(f"{st['to_cp']:,} passed on to Check Point")
    stage("CHECK POINT")
    boxes([("Clean", st["clean"]), ("Graymail + spam", st["graymail"] + st["spam"]),
           ("Phishing + malware", st["malicious"]), ("Suspicious", st["suspicious"])],
          ["#e2e8f0", "#cbd5e1", SEVERITY_COLOR["critical"], SEVERITY_COLOR["medium"]])
    arrow(f"{st['delivered']:,} delivered")
    stage("END USERS")
    boxes([("Delivered to users", st["delivered"])], ["#cbd5e1"])
    return f'<svg viewBox="0 0 {width} {y}" width="100%" style="max-width:{width}px">{"".join(out)}</svg>'


def svg_stacked_bar(parts: Sequence[Tuple[str, int, str]], width=640, height=36) -> str:
    """parts: [(label, value, color), ...]"""
    total = sum(v for _, v, _ in parts) or 1
    x = 0.0
    rects, legend = [], []
    for i, (label, v, color) in enumerate(parts):
        w = (v / total) * width
        rects.append(f'<rect x="{x:.1f}" y="0" width="{max(w,0):.1f}" height="{height}" fill="{color}">'
                     f'<title>{html.escape(label)}: {v} ({v/total*100:.0f}%)</title></rect>')
        legend.append(f'<span class="legend-dot" style="background:{color}"></span>'
                      f'{html.escape(label)} <b>{v:,}</b>')
        x += w
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" style="max-width:{width}px">'
            f'{"".join(rects)}</svg><div class="legend-row">{" &nbsp;&nbsp; ".join(legend)}</div>')


# ----------------------------------------------------------------- tiles
def fmt_value(value: Any) -> str:
    """Thousands separators for tile figures: 4550279 -> 4,550,279, and
    "31048 / 235" -> "31,048 / 235". Anything already formatted passes through."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:,.0f}"
    if isinstance(value, str):
        return re.sub(r"(?<![\d.,])\d{4,}(?![\d.,%])", lambda m: f"{int(m.group(0)):,}", value)
    return str(value)


def tile(label: str, value: str, color: str = INK, sub: str = "", trend: str = "") -> str:
    value = fmt_value(value)
    sub_html = f'<div class="tile-sub">{html.escape(sub)}</div>' if sub else ""
    return (f'<div class="tile"><div class="tile-value" style="color:{color}">{html.escape(str(value))}</div>'
            f'<div class="tile-label">{html.escape(label)}</div>{sub_html}{trend}</div>')


def _change(old: int, new: int, up_is_bad: bool = True) -> str:
    """'▲ 367 (+0.1%)' coloured by whether the move is good or bad."""
    delta = int(new) - int(old)
    if delta == 0:
        return f'<span style="color:{MUTED}">&#9644; no change</span>'
    worse = (delta > 0) == up_is_bad
    arrow = "&#9650;" if delta > 0 else "&#9660;"
    if old:
        pc = 100.0 * delta / float(old)
        pct_txt = f' ({"+" if pc > 0 else "-"}{"&lt;0.1" if abs(pc) < 0.1 else f"{abs(pc):.1f}"}%)'
    else:
        pct_txt = ""
    return (f'<span style="color:{SEVERITY_COLOR["critical"] if worse else GOOD}">'
            f'{arrow} {abs(delta)}{pct_txt}</span>')


def trend_line(t: Optional[dict]) -> str:
    """Point-in-time tiles: '▲ 367 (+0.1%) since 05 Oct'. Every one is a
    count of bad things, so up is red and down is green (same reserved-
    green rule as the tile values)."""
    if t is None:
        return f'<div class="tile-trend" style="color:{FAINT}">No earlier snapshot to compare yet</div>'
    return (f'<div class="tile-trend">{_change(t["from"], t["to"])} '
            f'<span style="color:{MUTED}">since {t["since"].strftime("%d %b")}</span></div>')


def flow_line(prev: Optional[int], now: int, prev_word: str, up_is_bad: bool = True) -> str:
    """Period-count tiles: '▲ 12 (+8.0%) vs previous week'."""
    if prev is None:
        return f'<div class="tile-trend" style="color:{FAINT}">No full {prev_word} to compare yet</div>'
    return (f'<div class="tile-trend">{_change(prev, now, up_is_bad)} '
            f'<span style="color:{MUTED}">vs {prev_word}</span></div>')


def opened_fixed_line(prev_opened: Optional[int], prev_fixed: Optional[int], prev_word: str,
                      opened: int, fixed: int) -> str:
    if prev_opened is None:
        return flow_line(None, 0, prev_word)
    return (f'<div class="tile-trend">opened {_change(prev_opened, opened)}, '
            f'fixed {_change(prev_fixed, fixed, up_is_bad=False)} '
            f'<span style="color:{MUTED}">vs {prev_word}</span></div>')


_EMAIL_RX = re.compile(r"\b([A-Za-z0-9])[A-Za-z0-9._%+'-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def mask_emails(text: str) -> str:
    """Infostealer risk titles name the compromised account. The report is
    meant for wide circulation, so it shows B*****@domain; the full detail
    stays in Hadrian and the database."""
    return _EMAIL_RX.sub(lambda m: f"{m.group(1)}*****@{m.group(2)}", text)


def pct(n: float, d: float) -> str:
    # n/d often arrive as Decimal (Postgres SUM()), which can't mix with
    # float in a single expression -- cast explicitly rather than require
    # every caller to remember that.
    return f"{(100.0 * float(n) / float(d)):.0f}%" if d else "n/a"


def email_table(rows: List[Tuple[str, int, int]]) -> str:
    body = "".join(
        f'<tr><td>{html.escape(t)}</td><td class="num">{n:,}</td><td class="num">{hp:,}</td></tr>'
        for t, n, hp in rows)
    return (f'<table><tr><th>Type</th><th class="num">Events</th><th class="num">High+</th></tr>'
            f'{body or "<tr><td colspan=3 class=empty>None this period.</td></tr>"}</table>')


def email_volume_table(rows: List[Tuple[str, int, int]]) -> str:
    """Every event_type (threat + bulk) with its share of total volume --
    "how much mail actually comes through" is as much the point here as
    the threat/bulk split itself."""
    total = sum(n for _, n, _ in rows)
    body = "".join(
        f'<tr><td>{html.escape(t)}</td><td class="num">{n:,}</td><td class="num">{pct(n, total)}</td></tr>'
        for t, n, _ in sorted(rows, key=lambda r: -r[1]))
    return (f'<table><tr><th>Type</th><th class="num">Events</th><th class="num">% of total</th></tr>'
            f'{body or "<tr><td colspan=3 class=empty>None this period.</td></tr>"}</table>'
            f'<p class="legend-row">{total:,} total events this period</p>')


# ----------------------------------------------------------------- build
TREND_NOTE = ("Arrows on current counts compare the daily snapshot at the start of the period with the one at "
              "its end (or the earliest available, if history is shorter); arrows on period counts compare "
              "with the {prev_word}.")


def header(p: Period, scope: str, page: str) -> str:
    generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<header>
  <div><h1>Security Posture Report &mdash; {html.escape(scope)}</h1>
       <div class="period">{html.escape(p.label)} &middot; Page {page}</div></div>
  <div class="meta">Generated {generated}<br>secops-dashboard</div>
</header>"""


def _sev_table(rows: List[Tuple], first_col: str, extra_col: Optional[str] = None) -> str:
    """(name, crit, high, total[, extra]) rows -> table, worst first."""
    head = (f'<tr><th>{first_col}</th><th class="num">Crit</th><th class="num">High</th>'
            f'<th class="num">Total open</th>{f"<th class=num>{extra_col}</th>" if extra_col else ""}</tr>')
    body = "".join(
        f'<tr><td>{html.escape(str(r[0]))}</td><td class="num" style="color:{SEVERITY_COLOR["critical"]}">{r[1]:,}</td>'
        f'<td class="num" style="color:{SEVERITY_COLOR["high"]}">{r[2]:,}</td><td class="num">{r[3]:,}</td>'
        + (f'<td class="num">{r[4]:,}</td>' if extra_col else "") + '</tr>'
        for r in rows)
    span = 5 if extra_col else 4
    return f'<table>{head}{body or f"<tr><td colspan={span} class=empty>No open vulnerabilities.</td></tr>"}</table>'


def top_family_tile(products: List[Tuple], open_ch: int, tr: dict, region: bool) -> str:
    """The product family holding the most open crit+high: one place where
    a tooling fix (enforced updates, patch management) moves the headline."""
    top = max(products, key=lambda r: r[1] + r[2], default=None)
    if not top or not (top[1] + top[2]):
        return tile("Top product family (critical+high)", 0, GOOD, "no open critical/high")
    n = top[1] + top[2]
    spread = f", across {top[4]} sites" if region else ""
    return tile(f"Critical+high in {top[0]}", n, SEVERITY_COLOR["high"],
                f"{pct(n, open_ch)} of all open critical/high{spread}", trend_line(tr.get("top_family")))


def sla_gap_note(v: dict) -> str:
    """The documented remediation policy vs reality, stated once -- on
    record, without a permanently-red headline tile."""
    d = v["sla_days"]
    if not v["open_ch_windowed"] or "critical" not in d or "high" not in d:
        return ""
    share = 100.0 * v["sla_breach_ch"] / v["open_ch_windowed"]
    if v["sla_breach_ch"] < v["open_ch_windowed"]:
        share = min(share, 99.9)   # never round "almost all" up to a literal 100%
    return (f'<p class="legend-row">Policy: critical within {d["critical"]} days, high within {d["high"]} days. '
            f'{share:.1f}% of open critical/high currently exceed it '
            f'({v["sla_breach_crit"]:,} critical, {v["sla_breach_high"]:,} high).</p>')


def build_page_estate(p: Period, scope: str, site: Optional[str], es: dict, tr: dict) -> str:
    status_style = {"unsupported": ("Unsupported", SEVERITY_COLOR["critical"]),
                    "ending": ("Ends within 12 months", SEVERITY_COLOR["medium"]),
                    "supported": ("Supported", MUTED), "unknown": ("Not assessed", FAINT)}
    os_rows = "".join(
        f'<tr><td>{html.escape(name)}</td><td class="num">{n:,}</td><td class="num">{active:,}</td>'
        f'<td class="num">{ws:,}</td><td class="num">{srv:,}</td>'
        f'<td class="num">{end.strftime("%d %b %Y") if end else "&ndash;"}</td>'
        f'<td style="color:{status_style[st][1]}">{status_style[st][0]}</td></tr>'
        for name, n, active, ws, srv, end, st in es["oses"])
    worst = [(o[0], o[1]) for o in es["oses"] if o[6] == "unsupported"][:2]
    ending = [(o[0], o[5], o[1]) for o in es["oses"] if o[6] == "ending"]
    site_rows = "".join(
        f'<tr><td>{html.escape(r[0])}</td>' + "".join(f'<td class="num">{int(x):,}</td>' for x in r[1:3])
        + f'<td class="num" style="color:{SEVERITY_COLOR["critical"] if r[3] else INK}">{int(r[3]):,}</td>'
        + "".join(f'<td class="num">{int(x):,}</td>' for x in r[4:]) + '</tr>'
        for r in es["by_site"])
    site_section = "" if site is not None else f"""
<h2>Estate by site</h2>
<table><tr><th>Site</th><th class="num">Workstations</th><th class="num">Servers</th><th class="num">Unsupported OS</th>
<th class="num">Missing a sensor</th><th class="num">Domains</th><th class="num">Public IPs</th></tr>
{site_rows or '<tr><td colspan="7" class="empty">No assets recorded.</td></tr>'}</table>"""
    scope_note = "Org-wide figures across all sites" if site is None else f"Figures for {html.escape(site)} only"

    return f"""<div class="page">
{header(p, scope, "1 of 5 &mdash; Estate")}

<h2>What we're protecting</h2>
<div class="tiles tiles-3">
  {tile("Managed devices", f"{es['devices']:,}", INK,
        f"{es['workstations']:,} workstations, {es['servers']:,} servers, {es['dcs']:,} DCs -- "
        f"{es['active']:,} active this week", trend_line(tr.get("devices")))}
  {tile("Devices on an unsupported OS", f"{es['unsupported']:,}",
        SEVERITY_COLOR["critical"] if es["unsupported"] else GOOD,
        ", ".join(f"{n:,} {name}" for name, n in worst) or "none", trend_line(tr.get("unsupported_os")))}
  {tile("OS support ending within 12 months", f"{es['ending']:,}",
        SEVERITY_COLOR["medium"] if es["ending"] else GOOD,
        ", ".join(f"{name} ({end:%b %Y})" for name, end, _ in ending) or "none")}
  {tile("Machines missing a sensor", f"{es['missing_named']:,}",
        SEVERITY_COLOR["high"] if es["missing_named"] else GOOD,
        f"in-use servers/workstations in AD -- plus {es['missing_network']:,} unidentified network devices")}
  {tile("Internet-facing domains", f"{es['domains']:,}", INK, "monitored by Hadrian", trend_line(tr.get("ext_domains")))}
  {tile("Public IP addresses", f"{es['ips']:,}", INK, "monitored by Hadrian", trend_line(tr.get("ext_ips")))}
</div>

<h2>Operating systems (Falcon-managed devices)</h2>
<table><tr><th>Operating system</th><th class="num">Devices</th><th class="num">Active (7d)</th>
<th class="num">Workstations</th><th class="num">Servers</th><th class="num">Support ends</th><th>Status</th></tr>
{os_rows or '<tr><td colspan="7" class="empty">No managed devices.</td></tr>'}</table>
{site_section}

<footer>Page 1 of 5 &mdash; secops-dashboard. {scope_note}; current as of generation time. Devices = Falcon-managed
hosts; "missing a sensor" = in-use AD computer accounts Falcon has no sensor on (duplicates, service accounts,
appliances and out-of-scope services excluded). Support dates are the vendor's end of security updates; Windows 11
is reported without its feature-update build, so isn't assessed. Override dates (e.g. Windows 10 Extended Security
Updates) under reporting.os_end_of_support. {TREND_NOTE.format(prev_word=html.escape(tr["prev_word"]))}</footer>
</div>"""


def build_page1(p: Period, scope: str, site: Optional[str], v: dict, products: List[Tuple],
                sites: List[Tuple], tr: dict) -> str:
    crit_open = v["open_now"].get("critical", 0)
    high_open = v["open_now"].get("high", 0)
    total_open = sum(v["open_now"].values())
    net_vuln = v["opened"] - v["fixed"]
    net_color = GOOD if net_vuln <= 0 else SEVERITY_COLOR["high"]

    mttr_rows = "".join(
        f'<tr><td style="color:{SEVERITY_COLOR.get(sev,INK)}">{sev.title()}</td><td class="num">{n}</td>'
        f'<td class="num">{f"{avg:.1f}d" if avg is not None else "n/a"}</td>'
        f'<td class="num">{f"{sla:.0f}%" if sla is not None else "n/a"}</td></tr>'
        for sev, n, avg, sla in v["mttr"])
    by = "day" if v["bucket"] == "day" else "week"
    scope_note = "Org-wide figures across all sites" if site is None else f"Figures for {html.escape(site)} only"
    history_note = f" ({tr['vuln_history_start']:%d %b %Y})" if tr.get("vuln_history_start") else ""
    bulk_note = (f'<p class="legend-row">"Opened" excludes {v["bulk_opened"]:,} findings first detected in a bulk '
                 f'load ({", ".join(d.strftime("%d %b") for d in BULK_DATES if p.since <= d <= p.until)}) '
                 f'-- coverage starting or expanding, '
                 f'not new vulnerabilities.</p>' if v.get("bulk_opened") else "")
    site_section = "" if site is not None else f"""
<h2>Open critical+high, by site</h2>
{_sev_table(sites, "Site")}"""

    return f"""<div class="page">
{header(p, scope, "2 of 5 &mdash; Endpoint Vulnerabilities")}

<h2>Headline</h2>
<div class="tiles tiles-3">
  {tile("Open vulnerabilities", total_open, SEVERITY_COLOR["high"] if crit_open or high_open else INK,
        f"{crit_open:,} critical, {high_open:,} high", trend_line(tr["open_vulns"]))}
  {tile("Opened vs fixed this period", f"{v['opened']} / {v['fixed']}", net_color,
        f"net {'+' if net_vuln>0 else ''}{net_vuln:,}", opened_fixed_line(tr["prev_opened"], tr["prev_fixed"], tr["prev_word"], v["opened"], v["fixed"]))}
  {tile("Known exploited (KEV) open", v["kev_open"], SEVERITY_COLOR["critical"] if v["kev_open"] else GOOD,
        f"{v['kev_past_due']:,} past due, {v['kev_ransomware']:,} ransomware-linked", trend_line(tr["kev_open"]))}
  {top_family_tile(products, crit_open + high_open, tr, site is None)}
  {tile("Remotely exploitable, no auth", v["remote_ch"], SEVERITY_COLOR["critical"] if v["remote_ch"] else GOOD,
        "critical/high reachable over the network without credentials", trend_line(tr["remote_ch"]))}
  {tile("Stale sensors", v["stale_sensors"], SEVERITY_COLOR["medium"] if v["stale_sensors"] else GOOD,
        f"of {v['managed_hosts']:,} managed hosts -- vulns on these go unseen", trend_line(tr["stale_sensors"]))}
</div>

<h2>Endpoint vulnerabilities &mdash; opened vs fixed by {by}</h2>
{svg_bars(v["buckets"], v["bucket"])}
{bulk_note}

<div class="row">
  <div class="col">
    <h2>Open critical+high, by product family</h2>
    {_sev_table(products, "Product family", "Sites" if site is None else None)}
  </div>
  <div class="col">
    <h2>Mean time to remediate (this period)</h2>
    <table><tr><th>Severity</th><th class="num">Fixed</th><th class="num">Avg days</th><th class="num">SLA met</th></tr>
    {mttr_rows or '<tr><td colspan="4" class="empty">No fixes recorded this period.</td></tr>'}</table>
    {sla_gap_note(v)}
  </div>
</div>
{site_section}

<footer>Page 2 of 5 &mdash; secops-dashboard. {scope_note}; endpoint vulnerabilities only (Falcon
Spotlight -- external risks are on page 3); "opened/fixed" and the bar chart cover the report period only;
open, KEV, exposure and sensor counts are current as of generation time. "Remotely exploitable" = network
attack vector, no privileges or user interaction needed, with a known exploit. Vulnerability age is measured
from first detection; anything already present when collection began dates from then{history_note}.
{TREND_NOTE.format(prev_word=html.escape(tr["prev_word"]))}</footer>
</div>"""


def build_page_email(p: Period, scope: str, site: Optional[str], em: dict, flow: Dict[str, int], tr: dict) -> str:
    st = funnel_stages(flow)
    has_flow = bool(st["inbound"])
    in_total = em["totals"].get("inbound", [0, 0])
    out_total = em["totals"].get("outbound", [0, 0])
    classified = sum(t[0] for d, t in em["totals"].items() if d != "unknown")
    unclassified = em["totals"].get("unknown", [0, 0])[0]
    dir_parts = [(DIRECTION_LABEL[d], em["totals"].get(d, [0, 0])[0], DIRECTION_COLOR[d])
                 for d in DIRECTION_ORDER if em["totals"].get(d, [0, 0])[0]]
    dir_note = ""
    if classified == 0 and unclassified:
        dir_note = ('<p class="empty">All email traffic is Unclassified -- add each site\'s real mail domain(s) '
                     'to its <code>email_domains</code> in config.yaml to split this into inbound/outbound.</p>')
    bulk_total = sum(em["bulk_totals"].values())
    bulk_note = (f'<p class="empty">Plus {bulk_total:,} graymail / spam / shadow IT events this period '
                 f'(bulk mail classification, not counted as threats above).</p>' if bulk_total else "")
    scope_note = "Org-wide figures across all sites" if site is None else f"Figures for {html.escape(site)} only"
    admin_note = (f'<p class="legend-row">Admin actions: {st["restore_requested"]:,} restore requests, '
                  f'{st["restored"]:,} emails released from quarantine, {st["restore_declined"]:,} requests declined.</p>'
                  if has_flow else "")
    # the funnel counts emails and supersedes the event-based volume table; keep that only as a fallback
    volume_section = "" if has_flow else (
        '<h2>Inbound mail volume by type (this period)</h2>'
        + email_volume_table(em["all_by_direction"].get("inbound", [])))

    return f"""<div class="page">
{header(p, scope, "4 of 5 &mdash; Email")}

<h2>Headline</h2>
<div class="tiles tiles-3">
  {tile("Emails handled", f"{st['inbound']:,}" if has_flow else "n/a", INK,
        f"{st['external']:,} from outside, {st['internal']:,} internal" if has_flow else "mail-flow collector not run",
        flow_line(tr["prev_flow_inbound"], st["inbound"], tr["prev_word"], up_is_bad=False) if has_flow else "")}
  {tile("Filtered before reaching users", pct(st["filtered"], st["inbound"]) if has_flow else "n/a", INK,
        f"{st['filtered']:,} emails quarantined by Microsoft or Check Point" if has_flow else "")}
  {tile("Phishing + malware caught", f"{st['malicious']:,}" if has_flow else "n/a",
        SEVERITY_COLOR["critical"] if st["malicious"] else INK,
        f"phishing + malware ({st['malware']:,} malware), {st['suspicious']:,} suspicious" if has_flow else "",
        flow_line(tr["prev_flow_malicious"], st["malicious"], tr["prev_word"]) if has_flow else "")}
  {tile("Inbound email threats", in_total[0], SEVERITY_COLOR["high"] if in_total[1] else INK,
        f"{in_total[1]:,} high+ severity", flow_line(tr["prev_inbound"], in_total[0], tr["prev_word"]))}
  {tile("Outbound email threats", out_total[0], SEVERITY_COLOR["high"] if out_total[1] else INK,
        f"{out_total[1]} high+ severity", flow_line(tr["prev_outbound"], out_total[0], tr["prev_word"]))}
  {tile("DMARC pass rate", pct(em["dmarc_pass"], em["dmarc_messages"]), INK,
        f"{em['dmarc_messages']} messages seen")}
</div>

<h2>Inbound mail flow (this period)</h2>
{svg_funnel(st)}
{admin_note}

<h2>Email traffic by direction (this period)</h2>
{svg_stacked_bar(dir_parts) if dir_parts else '<p class="empty">No email events recorded.</p>'}
{dir_note}
{bulk_note}

<div class="row">
  <div class="col">
    <h2>Inbound threats</h2>
    {email_table(em["by_direction"].get("inbound", []))}
  </div>
  <div class="col">
    <h2>Outbound threats</h2>
    {email_table(em["by_direction"].get("outbound", []))}
  </div>
</div>

{volume_section}

<footer>Page 4 of 5 &mdash; secops-dashboard. {scope_note}; Check Point Harmony Email &amp; Collaboration.
Mail flow counts emails (Microsoft's spam verdict: junk = SCL 5-6, quarantined = SCL 7-9; then Check Point's
verdict); "inbound" includes internal mail, as Check Point's console counts it. "Phishing + malware" is Check
Point's per-email verdict -- broader than the console's "Malicious" box. Threat tables count security events (one
email can raise several). Site = recipient domain.
{TREND_NOTE.format(prev_word=html.escape(tr["prev_word"]))}</footer>
</div>"""


def build_page_external(p: Period, scope: str, site: Optional[str], x: dict, tr: dict) -> str:
    sev_color = {"Critical": SEVERITY_COLOR["critical"], "High": SEVERITY_COLOR["high"],
                 "Medium": SEVERITY_COLOR["medium"], "Low": SEVERITY_COLOR["low"], "Info": SEVERITY_COLOR["info"]}
    site_col = site is None
    top_rows = "".join(
        f'<tr><td style="color:{sev_color.get(sev, INK)}">{html.escape(sev or "")}</td>'
        f'<td>{html.escape(RISK_TYPE_LABEL.get(rtype, rtype or ""))}</td><td>{html.escape(mask_emails(title or ""))}</td>'
        f'<td>{html.escape(host or "")}</td>' + (f'<td>{html.escape(sl)}</td>' if site_col else "") +
        f'<td class="num">{ff.strftime("%d %b") if ff else ""}</td></tr>'
        for sev, rtype, title, host, sl, ff in x["top"])
    cat_rows = "".join(
        f'<tr><td>{html.escape(c.replace("-", " "))}</td><td class="num">{conf}</td><td class="num">{unv}</td></tr>'
        for c, (conf, unv) in x["categories"])
    net = x["opened"] - x["fixed"]
    sla_rows = "".join(
        f'<tr><td style="color:{SEVERITY_COLOR.get(sev, INK)}">{sev.title()}</td>'
        f'<td class="num">{f"{days}d" if days is not None else "n/a"}</td>'
        f'<td class="num">{pct(within, n_open)} <span style="color:{MUTED}">({within}/{n_open})</span></td>'
        f'<td class="num">{n_fixed}</td><td class="num">{pct(fixed_ok, n_fixed)}</td></tr>'
        for sev, days, n_open, within, n_fixed, fixed_ok in x["sla"])
    scope_note = "Org-wide figures across all sites" if site is None else f"Figures for {html.escape(site)} only"

    return f"""<div class="page">
{header(p, scope, "3 of 5 &mdash; External Attack Surface")}

<h2>Headline</h2>
<div class="tiles tiles-3">
  {tile("External assets monitored", x["domains"] + x["ips"], INK,
        f"{x['domains']} domains, {x['ips']} IPs", trend_line(tr["ext_assets"]))}
  {tile("Open external risks", x["open_total"], SEVERITY_COLOR["medium"] if x["open_total"] else GOOD,
        f"{x['confirmed']} confirmed, {x['unverified']} unverified (potential)", trend_line(tr["ext_open"]))}
  {tile("Confirmed risks open", x["confirmed"], SEVERITY_COLOR["high"] if x["confirmed_crit_high"] else
        (SEVERITY_COLOR["medium"] if x["confirmed"] else GOOD),
        f"{x['confirmed_crit_high']} critical/high, {x['confirmed_medium']} medium")}
  {tile("Leaked credentials", x["leaked_creds"], SEVERITY_COLOR["critical"] if x["leaked_creds"] else GOOD,
        "infostealer leaks naming a still-enabled account of ours")}
  {tile("Critical / high open (any type)", x["crit_high_any"],
        SEVERITY_COLOR["high"] if x["crit_high_any"] else GOOD)}
  {tile("Opened vs fixed this period", f"{x['opened']} / {x['fixed']}",
        GOOD if net <= 0 else SEVERITY_COLOR["high"], f"net {'+' if net > 0 else ''}{net}",
        opened_fixed_line(tr["prev_ext_opened"], tr["prev_ext_fixed"], tr["prev_word"], x["opened"], x["fixed"]))}
</div>

<h2>Confirmed and high-severity external risks</h2>
<table><tr><th>Severity</th><th>Type</th><th>Risk</th><th>Asset</th>{"<th>Site</th>" if site_col else ""}<th class="num">First seen</th></tr>
{top_rows or f'<tr><td colspan="{6 if site_col else 5}" class="empty">No confirmed or high-severity external risks open.</td></tr>'}</table>

<div class="row">
  <div class="col">
    <h2>Open external risks by category</h2>
    <table><tr><th>Category</th><th class="num">Confirmed</th><th class="num">Unverified (potential)</th></tr>
    {cat_rows or '<tr><td colspan="3" class="empty">No open external risks.</td></tr>'}</table>
  </div>
  <div class="col">
    <h2>Remediation SLA</h2>
    <table><tr><th>Severity</th><th class="num">Window</th><th class="num">Open within SLA</th>
    <th class="num">Fixed in period</th><th class="num">Fixed within SLA</th></tr>
    {sla_rows or '<tr><td colspan="5" class="empty">No open or fixed external risks.</td></tr>'}</table>
  </div>
</div>

<footer>Page 3 of 5 &mdash; secops-dashboard. {scope_note}; external attack surface from Hadrian. "Confirmed" =
verified, unpatched-technology and infected-device risks; "potential" risks are unverified detections, many
predating the current review workflow. Severities are Hadrian's own. A risk closed because a rescan no longer
finds it counts as fixed. Assets take their site from their Hadrian tag, or from their apex domain if untagged.
SLA windows are the same policy as endpoint vulnerabilities; Hadrian's Info severity counts as low.
{TREND_NOTE.format(prev_word=html.escape(tr["prev_word"]))}</footer>
</div>"""


def build_page2(p: Period, scope: str, site: Optional[str], a: dict, idn: dict, tr: dict) -> str:
    disp_colors = {"true_positive": SEVERITY_COLOR["high"], "false_positive": GOOD,
                   "ignored": MUTED, "closed": FAINT, "new": MUTED, "in_progress": "#0ea5e9"}
    disp_parts = [(d.replace("_", " ").title(), n, disp_colors.get(d, FAINT)) for d, n in a["disposition"]]
    tp = next((n for d, n in a["disposition"] if d == "true_positive"), 0)
    fp = next((n for d, n in a["disposition"] if d == "false_positive"), 0)
    closed_with_verdict = tp + fp
    alerts_opened = a["new_crit"] + a["new_high"] + a["new_med"] + a["new_low"]

    cats, groups, idt = idn["cats"], idn["groups"], tr["idcat"]

    def change_cell(t: Optional[dict]) -> str:
        if t is None:
            return f'<span style="color:{FAINT}">&ndash;</span>'
        return f'{_change(t["from"], t["to"])} <span style="color:{MUTED}">since {t["since"].strftime("%d %b")}</span>'

    def cat_table(group: str) -> str:
        rows = "".join(
            f'<tr><td><b>{html.escape(c.label)}</b><div class="tile-sub">{html.escape(c.action)}</div></td>'
            f'<td class="num">{cats[c.key]:,}</td><td class="num">{change_cell(idt.get(c.key))}</td></tr>'
            for c in ic.CATEGORIES if c.group == group)
        return (f'<h2>{html.escape(ic.GROUPS[group])}</h2><table><tr><th>Category</th><th class="num">Accounts</th>'
                f'<th class="num">Change</th></tr>{rows}</table>')
    by = "day" if a["bucket"] == "day" else "week"
    scope_note = "Org-wide figures across all sites" if site is None else f"Figures for {html.escape(site)} only"

    return f"""<div class="page">
{header(p, scope, "5 of 5 &mdash; Alerts &amp; Identity")}

<h2>Headline</h2>
<div class="tiles tiles-3">
  {tile("Alerts opened vs closed", f"{alerts_opened} / {a['closed']}",
        INK, f"{a['open_crit_high']} crit/high open now", flow_line(tr["prev_alerts"], alerts_opened, tr["prev_word"]))}
  {tile("True / false positive rate", pct(tp, closed_with_verdict) + " / " + pct(fp, closed_with_verdict),
        INK, f"{closed_with_verdict} alerts closed with a verdict")}
  {tile("Open alerts now", a["open_total"], SEVERITY_COLOR["high"] if a["open_crit_high"] else INK,
        f"{a['open_crit_high']} crit/high", trend_line(tr["open_alerts"]))}
  {tile("Accounts showing signs of compromise", f"{groups['compromise']:,}",
        SEVERITY_COLOR["critical"] if groups["compromise"] else GOOD,
        "stolen credentials, password attacks, suspicious sign-ins, attacker techniques",
        trend_line(idt.get("group:compromise")))}
  {tile("Stale accounts still enabled", f"{cats['stale_accounts']:,}",
        SEVERITY_COLOR["medium"] if cats["stale_accounts"] else GOOD,
        f"incl. {idn['stale_access']:,} unused VPN / remote-app accounts in the shared domain"
        if idn["stale_access"] else "", trend_line(idt.get("stale_accounts")))}
  {tile("Reused passwords", f"{cats['reused_passwords']:,}",
        SEVERITY_COLOR["high"] if cats["reused_passwords"] else GOOD, "accounts sharing a password with another",
        trend_line(idt.get("reused_passwords")))}
</div>

<h2>Alerts &mdash; volume by {by}</h2>
{svg_bars(a["buckets"], a["bucket"], names=("New alerts",), colors=("#0ea5e9",))}

<h2>Alert disposition (closed this period)</h2>
{svg_stacked_bar(disp_parts) if disp_parts else '<p class="empty">No alerts closed this period.</p>'}

{cat_table("compromise")}
{cat_table("exposure")}

<footer>Page 5 of 5 &mdash; secops-dashboard. {scope_note}; alert counts and the bar chart cover the report
period only and exclude informational-severity alerts. Identity risk (Falcon Identity Protection) is current as of
generation time and counts enabled accounts (or unknown status), grouped into actionable categories; the full
risk-factor list is on the SecOps dashboards and in the site action packs.
{TREND_NOTE.format(prev_word=html.escape(tr["prev_word"]))}</footer>
</div>"""


def build_html(p: Period, scope: str, site: Optional[str], v: dict, a: dict, idn: dict,
               em: dict, products: List[Tuple], sites: List[Tuple], x: dict, flow: Dict[str, int], es: dict,
               tr: dict) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Security Posture Report -- {html.escape(scope)} -- {html.escape(p.label)}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: {INK};
          background: #f8fafc; margin: 0; }}
  .page {{ max-width: 900px; margin: 0 auto 24px; background: #fff; padding: 36px 40px 48px; }}
  header {{ display: flex; justify-content: space-between; align-items: baseline;
            border-bottom: 3px solid {INK}; padding-bottom: 14px; margin-bottom: 22px; }}
  h1 {{ font-size: 22px; margin: 0; }}
  .period {{ font-size: 15px; color: {MUTED}; }}
  .meta {{ font-size: 11px; color: {MUTED}; text-align: right; }}
  h2 {{ font-size: 14px; text-transform: uppercase; letter-spacing: .04em; color: {MUTED};
        border-bottom: 1px solid {BORDER}; padding-bottom: 6px; margin: 26px 0 12px; }}
  .tiles {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 4px; }}
  .tiles-3 {{ grid-template-columns: repeat(3, 1fr); }}
  .tile {{ border: 1px solid {BORDER}; border-radius: 8px; padding: 12px 14px; }}
  .tile-value {{ font-size: 26px; font-weight: 700; line-height: 1.1; }}
  .tile-label {{ font-size: 11px; color: {MUTED}; margin-top: 3px; }}
  .tile-sub {{ font-size: 10px; color: {MUTED}; margin-top: 2px; }}
  .tile-trend {{ font-size: 10px; font-weight: 600; margin-top: 4px; font-variant-numeric: tabular-nums; }}
  .row {{ display: flex; gap: 24px; align-items: flex-start; }}
  .col {{ flex: 1; min-width: 0; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ text-align: left; font-size: 10px; text-transform: uppercase; color: {MUTED};
        border-bottom: 1px solid {BORDER}; padding: 4px 6px; }}
  td {{ padding: 4px 6px; border-bottom: 1px solid #f1f5f9; }}
  td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .legend-row {{ font-size: 11px; color: {MUTED}; margin-top: 4px; }}
  .legend-dot {{ display: inline-block; width: 9px; height: 9px; border-radius: 2px; margin-right: 4px; }}
  .empty {{ color: {MUTED}; font-size: 12px; font-style: italic; }}
  footer {{ margin-top: 32px; padding-top: 10px; border-top: 1px solid {BORDER};
            font-size: 10px; color: {MUTED}; }}
  @media screen {{
    .page {{ box-shadow: 0 1px 4px rgba(15,23,42,.08); border-radius: 4px; }}
  }}
  @page {{ size: A4; margin: 12mm 12mm 14mm; }}
  @media print {{
    * {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}   /* keep severity colours */
    body {{ background: #fff; }}
    .page {{ padding: 0; max-width: none; margin: 0; box-shadow: none; break-after: page; }}
    .page:last-child {{ break-after: auto; }}
    /* Tighter than on screen so each section fits one A4 page: scale the whole
       page a little and trim the spacing that's generous on a monitor. */
    html {{ zoom: 0.84; }}
    header {{ margin-bottom: 12px; padding-bottom: 8px; }}
    h2 {{ margin: 14px 0 8px; padding-bottom: 4px; }}
    .tiles {{ gap: 8px; }}
    .tile {{ padding: 8px 12px; }}
    .tile-value {{ font-size: 22px; }}
    table {{ font-size: 11px; }}
    th {{ padding: 3px 6px; }}
    td {{ padding: 2px 6px; }}
    footer {{ margin-top: 14px; padding-top: 6px; font-size: 9px; }}
    h2 {{ break-after: avoid; }}
    .row, .tiles, tr, svg {{ break-inside: avoid; }}
  }}
</style></head>
<body>
{build_page_estate(p, scope, site, es, tr)}
{build_page1(p, scope, site, v, products, sites, tr)}
{build_page_external(p, scope, site, x, tr)}
{build_page_email(p, scope, site, em, flow, tr)}
{build_page2(p, scope, site, a, idn, tr)}
</body></html>
"""


def render(cur, p: Period, site: Optional[str], hist: Dict[str, Optional[dt.date]], days_last_seen: int) -> str:
    scope = "Whole of region" if site is None else site
    sites = fetch_site_breakdown(cur) if site is None else []
    products = fetch_product_breakdown(cur, site)
    # the family with the most open crit+high leads page 1 -- where a
    # tooling fix moves the most numbers
    top = max(products, key=lambda r: r[1] + r[2], default=None)
    return build_html(p, scope, site, fetch_vulns(cur, p, site, days_last_seen), fetch_alerts(cur, p, site),
                      fetch_identity(cur, site), fetch_email(cur, p, site), products,
                      sites, fetch_external(cur, p, site), fetch_email_flow(cur, p, site), fetch_estate(cur, site),
                      fetch_trends(cur, p, site, hist, top and top[0]))


def site_labels(cfg: Dict[str, Any]) -> List[str]:
    """Every configured site plus the ungrouped bucket -- Ungrouped gets its
    own report so the hosts still waiting on a site mapping stay visible."""
    return [s["label"] for s in cfg.get("sites", [])] + [cfg.get("ungrouped_label", "Ungrouped")]


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


CHROMIUM_NAMES = ("chromium-browser", "chromium", "google-chrome", "google-chrome-stable", "headless_shell")


def find_chromium(configured: Optional[str] = None) -> Optional[str]:
    if configured:
        return configured if os.path.exists(configured) else shutil.which(configured)
    return next((p for p in (shutil.which(n) for n in CHROMIUM_NAMES) if p), None)


def html_to_pdf(chromium: str, html_path: str, pdf_path: str) -> None:
    """Print the report to PDF with headless Chromium (faithful for the inline
    SVG and the CSS layout; the page's @page/@media print rules set A4 and
    the page breaks). A throwaway profile per call so parallel runs don't
    fight over one. Writes via a temp name so publish.py never sees half a file."""
    tmp = pdf_path + ".partial"
    with tempfile.TemporaryDirectory(prefix="secops-chromium-") as profile:
        r = subprocess.run(
            [chromium, "--headless=new", "--disable-gpu", "--no-first-run", f"--user-data-dir={profile}",
             "--no-pdf-header-footer", "--print-to-pdf-no-header", f"--print-to-pdf={tmp}",
             "file://" + os.path.abspath(html_path)],
            capture_output=True, text=True, timeout=180)
    if r.returncode != 0 or not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
        raise RuntimeError(f"chromium exited {r.returncode}: {(r.stderr or r.stdout)[-400:]}")
    os.replace(tmp, pdf_path)


def write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


# ------------------------------------------------------------------ main
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--period", choices=["week", "month", "quarter"], default="month",
                    help="the last FULL week (Mon-Sun) / calendar month / calendar quarter before today")
    ap.add_argument("--since", help="override: explicit start date YYYY-MM-DD")
    ap.add_argument("--until", help="override: explicit end date YYYY-MM-DD (inclusive)")
    scope = ap.add_mutually_exclusive_group()
    scope.add_argument("--site", help="one site's report (its site label, e.g. SITE-A); default is whole of region")
    scope.add_argument("--all-sites", action="store_true",
                       help="whole-of-region report plus one per site, into reports/<period>/ (or --out-dir)")
    ap.add_argument("--out", help="output HTML path for a single report")
    ap.add_argument("--out-dir", help="--all-sites output folder (default: reports/<period>)")
    ap.add_argument("--pdf", action=argparse.BooleanOptionalAction, default=None,
                    help="also write a PDF next to each HTML (default: reporting.pdf in config, else on)")
    args = ap.parse_args()

    today = dt.date.today()
    if args.since and args.until:
        p = custom_period(dt.date.fromisoformat(args.since), dt.date.fromisoformat(args.until))
    else:
        p = {"week": week_period, "month": month_period, "quarter": quarter_period}[args.period](today)

    cfg = config_mod.load_config(args.config)
    OS_EOS.clear()
    OS_EOS.update(os_lifecycle.table(cfg.get("reporting", {}).get("os_end_of_support")))
    BULK_DATES[:] = sorted(dt.date.fromisoformat(str(d))
                           for d in cfg.get("reporting", {}).get("vuln_bulk_load_dates") or [])
    labels = site_labels(cfg)
    if args.site and args.site not in labels:
        ap.error(f"unknown site {args.site!r}; configured: {', '.join(labels)}")

    make_pdf = args.pdf if args.pdf is not None else bool(cfg.get("reporting", {}).get("pdf", True))
    chromium = find_chromium(cfg.get("reporting", {}).get("chromium_path")) if make_pdf else None
    if make_pdf and not chromium:
        print("[exec_report] WARNING: no Chromium found (dnf install chromium, or set reporting.chromium_path) "
              "-- writing HTML only")
        make_pdf = False

    conn = pg_connect(cfg)
    cur = conn.cursor()
    hist = history_start(cur)

    if args.all_sites:
        out_dir = args.out_dir or os.path.join("reports", p.slug)
        jobs = [(None, os.path.join(out_dir, "region.html"))] + [
            (s, os.path.join(out_dir, f"{safe_name(s)}.html")) for s in labels]
    else:
        suffix = f"-{safe_name(args.site)}" if args.site else ""
        jobs = [(args.site, args.out or os.path.join("reports", f"exec-report-{p.slug}{suffix}.html"))]

    for site, path in jobs:
        write(path, render(cur, p, site, hist, int(cfg.get("reporting", {}).get("days_last_seen", 30))))
        print(f"[exec_report] wrote {path} ({p.since} to {p.until}, {site or 'whole of region'})")
        if make_pdf:
            pdf = os.path.splitext(path)[0] + ".pdf"
            try:
                html_to_pdf(chromium, path, pdf)
                print(f"[exec_report] wrote {pdf}")
            except Exception as e:   # the HTML is still good; don't lose the rest of the run
                print(f"[exec_report] PDF failed for {path}: {e}")
    conn.close()


if __name__ == "__main__":
    main()
