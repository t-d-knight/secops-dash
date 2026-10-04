#!/usr/bin/env python3
"""
Derives the daily snapshot tables from the collected data via SQL
aggregation: the vuln snapshots (daily_site_metrics, daily_sla_metrics,
daily_product_metrics, daily_kev_metrics, daily_epss_metrics,
daily_mttr_metrics) from vuln_findings, plus daily_source_metrics,
daily_asset_metrics, daily_alert_metrics, daily_identity_metrics and
daily_email_metrics from the other collectors' tables, instead of each being computed by its
own independent vendor pull. Table names/columns for the first three are
unchanged from before, so existing Power BI reports keep working.

daily_mttr_metrics tracks mean/median time-to-remediate per site+severity
per day, plus SLA compliance rate of what got fixed -- the "asset_risk_summary"
view (db_schema.py) covers the complementary "worst devices right now" hit
list; it's a live view, not a daily snapshot, since it's a ranking of
current state rather than a trend.

Staleness policy (reporting.days_last_seen) is applied HERE, uniformly,
to every rollup — not baked into ingestion — so vuln_findings itself stays
a complete, unfiltered mirror of vendor state.

fixed_* counts are windowed off vuln_findings.last_fixed (state='FIXED'),
fixing the previous fill_daily_product_metrics.py bug where fixed_* counted
ALL-TIME fixed findings every single day instead of "fixed since N days ago".

--dry-run prints the computed rollup for today without writing, so it can be
diffed against the old scripts' output during a validation window before
cutover (see the plan / README for the rollout sequence).
"""
import argparse
import datetime as dt
from typing import Any, Dict, List, Tuple

import config as config_mod
import db_schema
from db import pg_connect

SEVERITIES = ("critical", "high", "medium", "low")


def _site_labels(cfg: Dict[str, Any]) -> List[Tuple[str, str]]:
    site_cfg = {s["key"]: s["label"] for s in cfg.get("sites", [])}
    ungrouped = cfg.get("ungrouped_label", "Ungrouped")
    label_to_tag = {v: k for k, v in site_cfg.items()}
    labels = list(site_cfg.values()) + [ungrouped]
    return [(lab, label_to_tag.get(lab, "UNGROUPED" if lab == ungrouped else lab)) for lab in labels]


# ------------------------------------------------------------
#  SITE METRICS
# ------------------------------------------------------------

def rollup_site_metrics(cur, cfg: Dict[str, Any], snapshot_date: dt.date, days_last_seen: int) -> Dict[str, Dict[str, Any]]:
    cur.execute(
        """
        SELECT
            site_label,
            max(site_tag) AS site_tag,
            count(*) FILTER (WHERE severity = 'critical') AS crit,
            count(*) FILTER (WHERE severity = 'high') AS high,
            count(*) FILTER (WHERE severity = 'medium') AS medium,
            count(*) FILTER (WHERE severity = 'low') AS low,
            count(*) AS total,
            count(*) FILTER (WHERE severity = 'critical' AND is_remote_no_auth) AS remote_crit,
            count(*) FILTER (WHERE severity = 'high' AND is_remote_no_auth) AS remote_high,
            count(DISTINCT source_asset_id) AS assets
        FROM vuln_findings
        WHERE state IN ('OPEN','REOPENED')
          AND last_found >= now() - (%(days)s || ' days')::interval
        GROUP BY site_label
        """,
        {"days": days_last_seen},
    )
    cols = [d.name for d in cur.description]
    rows = {r[0]: dict(zip(cols, r)) for r in cur.fetchall()}

    out: Dict[str, Dict[str, Any]] = {}
    for lab, tag in _site_labels(cfg):
        r = rows.get(lab)
        if r:
            out[lab] = {**r, "site_tag": r.get("site_tag") or tag}
        else:
            out[lab] = {
                "site_tag": tag, "crit": 0, "high": 0, "medium": 0, "low": 0,
                "total": 0, "remote_crit": 0, "remote_high": 0, "assets": 0,
            }
    return out


def write_site_metrics(cur, snapshot_date: dt.date, data: Dict[str, Dict[str, Any]]) -> None:
    for lab, d in data.items():
        cur.execute(
            """
            INSERT INTO daily_site_metrics (
                snapshot_date, site_label, site_tag,
                crit, high, medium, low, total,
                remote_crit, remote_high, assets
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (snapshot_date, site_label) DO UPDATE SET
                site_tag = EXCLUDED.site_tag, crit = EXCLUDED.crit, high = EXCLUDED.high,
                medium = EXCLUDED.medium, low = EXCLUDED.low, total = EXCLUDED.total,
                remote_crit = EXCLUDED.remote_crit, remote_high = EXCLUDED.remote_high,
                assets = EXCLUDED.assets;
            """,
            (snapshot_date.isoformat(), lab, d["site_tag"], d["crit"], d["high"],
             d["medium"], d["low"], d["total"], d["remote_crit"], d["remote_high"], d["assets"]),
        )


# ------------------------------------------------------------
#  SLA METRICS
# ------------------------------------------------------------

def rollup_sla_metrics(cur, days_last_seen: int) -> List[Dict[str, Any]]:
    cur.execute(
        """
        SELECT
            vf.site_label,
            max(vf.site_tag) AS site_tag,
            initcap(vf.severity) AS risk,
            count(*) AS total_vulns,
            count(*) FILTER (
                WHERE EXTRACT(EPOCH FROM now() - vf.first_found) / 86400.0 > sp.threshold_days
            ) AS sla_breaches,
            count(*) FILTER (WHERE vf.is_remote_no_auth) AS remote_no_auth_vulns,
            count(*) FILTER (
                WHERE vf.is_remote_no_auth AND
                EXTRACT(EPOCH FROM now() - vf.first_found) / 86400.0 > sp.threshold_days
            ) AS remote_no_auth_breaches
        FROM vuln_findings vf
        JOIN sla_policy sp ON sp.severity = vf.severity
        WHERE vf.state IN ('OPEN','REOPENED')
          AND vf.last_found >= now() - (%(days)s || ' days')::interval
        GROUP BY vf.site_label, vf.severity
        """,
        {"days": days_last_seen},
    )
    cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def write_sla_metrics(cur, snapshot_date: dt.date, rows: List[Dict[str, Any]]) -> None:
    for r in rows:
        cur.execute(
            """
            INSERT INTO daily_sla_metrics (
                snapshot_date, site_label, site_tag, risk,
                total_vulns, sla_breaches, remote_no_auth_vulns, remote_no_auth_breaches
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (snapshot_date, site_label, risk) DO UPDATE SET
                site_tag = EXCLUDED.site_tag, total_vulns = EXCLUDED.total_vulns,
                sla_breaches = EXCLUDED.sla_breaches,
                remote_no_auth_vulns = EXCLUDED.remote_no_auth_vulns,
                remote_no_auth_breaches = EXCLUDED.remote_no_auth_breaches;
            """,
            (snapshot_date.isoformat(), r["site_label"], r["site_tag"], r["risk"],
             r["total_vulns"], r["sla_breaches"], r["remote_no_auth_vulns"], r["remote_no_auth_breaches"]),
        )


# ------------------------------------------------------------
#  PRODUCT METRICS
# ------------------------------------------------------------

def rollup_product_metrics(cur, days_last_seen: int, new_window_days: int) -> List[Dict[str, Any]]:
    cur.execute(
        """
        SELECT
            site_label,
            max(site_tag) AS site_tag,
            coalesce(product_key, 'Unknown') AS product,
            max(product_vendor) AS vendor,
            max(product_family) AS product_family,
            count(*) FILTER (WHERE state IN ('OPEN','REOPENED') AND severity='critical') AS open_crit,
            count(*) FILTER (WHERE state IN ('OPEN','REOPENED') AND severity='high') AS open_high,
            count(*) FILTER (WHERE state IN ('OPEN','REOPENED') AND severity='medium') AS open_medium,
            count(*) FILTER (WHERE state IN ('OPEN','REOPENED') AND severity='low') AS open_low,
            count(*) FILTER (WHERE state IN ('OPEN','REOPENED')) AS open_total,
            count(*) FILTER (WHERE state IN ('OPEN','REOPENED') AND severity='critical'
                              AND first_found >= now() - (%(new_days)s || ' days')::interval) AS new_crit,
            count(*) FILTER (WHERE state IN ('OPEN','REOPENED') AND severity='high'
                              AND first_found >= now() - (%(new_days)s || ' days')::interval) AS new_high,
            count(*) FILTER (WHERE state IN ('OPEN','REOPENED') AND severity='medium'
                              AND first_found >= now() - (%(new_days)s || ' days')::interval) AS new_medium,
            count(*) FILTER (WHERE state IN ('OPEN','REOPENED') AND severity='low'
                              AND first_found >= now() - (%(new_days)s || ' days')::interval) AS new_low,
            count(*) FILTER (WHERE state IN ('OPEN','REOPENED')
                              AND first_found >= now() - (%(new_days)s || ' days')::interval) AS new_total,
            count(*) FILTER (WHERE state='FIXED' AND severity='critical'
                              AND last_fixed >= now() - (%(new_days)s || ' days')::interval) AS fixed_crit,
            count(*) FILTER (WHERE state='FIXED' AND severity='high'
                              AND last_fixed >= now() - (%(new_days)s || ' days')::interval) AS fixed_high,
            count(*) FILTER (WHERE state='FIXED' AND severity='medium'
                              AND last_fixed >= now() - (%(new_days)s || ' days')::interval) AS fixed_medium,
            count(*) FILTER (WHERE state='FIXED' AND severity='low'
                              AND last_fixed >= now() - (%(new_days)s || ' days')::interval) AS fixed_low,
            count(*) FILTER (WHERE state='FIXED'
                              AND last_fixed >= now() - (%(new_days)s || ' days')::interval) AS fixed_total
        FROM vuln_findings
        WHERE (state IN ('OPEN','REOPENED') AND last_found >= now() - (%(days)s || ' days')::interval)
           OR state = 'FIXED'
        GROUP BY site_label, coalesce(product_key, 'Unknown')
        """,
        {"days": days_last_seen, "new_days": new_window_days},
    )
    cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def write_product_metrics(cur, snapshot_date: dt.date, rows: List[Dict[str, Any]]) -> None:
    for r in rows:
        cur.execute(
            """
            INSERT INTO daily_product_metrics (
                snapshot_date, site_label, site_tag, product, vendor, product_family,
                open_crit, open_high, open_medium, open_low, open_total,
                new_crit, new_high, new_medium, new_low, new_total,
                fixed_crit, fixed_high, fixed_medium, fixed_low, fixed_total
            ) VALUES (
                %(snapshot_date)s, %(site_label)s, %(site_tag)s, %(product)s, %(vendor)s, %(product_family)s,
                %(open_crit)s, %(open_high)s, %(open_medium)s, %(open_low)s, %(open_total)s,
                %(new_crit)s, %(new_high)s, %(new_medium)s, %(new_low)s, %(new_total)s,
                %(fixed_crit)s, %(fixed_high)s, %(fixed_medium)s, %(fixed_low)s, %(fixed_total)s
            )
            ON CONFLICT (snapshot_date, site_label, product) DO UPDATE SET
                site_tag = EXCLUDED.site_tag, vendor = EXCLUDED.vendor, product_family = EXCLUDED.product_family,
                open_crit = EXCLUDED.open_crit, open_high = EXCLUDED.open_high,
                open_medium = EXCLUDED.open_medium, open_low = EXCLUDED.open_low, open_total = EXCLUDED.open_total,
                new_crit = EXCLUDED.new_crit, new_high = EXCLUDED.new_high,
                new_medium = EXCLUDED.new_medium, new_low = EXCLUDED.new_low, new_total = EXCLUDED.new_total,
                fixed_crit = EXCLUDED.fixed_crit, fixed_high = EXCLUDED.fixed_high,
                fixed_medium = EXCLUDED.fixed_medium, fixed_low = EXCLUDED.fixed_low, fixed_total = EXCLUDED.fixed_total;
            """,
            {**r, "snapshot_date": snapshot_date.isoformat()},
        )


# ------------------------------------------------------------
#  KEV METRICS
# ------------------------------------------------------------

def rollup_kev_metrics(cur, cfg: Dict[str, Any], days_last_seen: int) -> Dict[str, Dict[str, Any]]:
    cur.execute(
        """
        SELECT
            vf.site_label,
            max(vf.site_tag) AS site_tag,
            count(*) FILTER (WHERE k.cve_id IS NOT NULL) AS kev_open_total,
            count(*) FILTER (WHERE k.cve_id IS NOT NULL AND vf.severity='critical') AS kev_open_crit,
            count(*) FILTER (WHERE k.cve_id IS NOT NULL AND vf.severity='high') AS kev_open_high,
            count(*) FILTER (WHERE k.cve_id IS NOT NULL AND vf.severity='medium') AS kev_open_medium,
            count(*) FILTER (WHERE k.cve_id IS NOT NULL AND vf.severity='low') AS kev_open_low,
            count(*) FILTER (WHERE k.known_ransomware_campaign_use = 'Known') AS kev_ransomware_total,
            count(*) FILTER (WHERE k.due_date IS NOT NULL AND k.due_date < CURRENT_DATE) AS kev_past_due_total,
            count(*) FILTER (WHERE k.cve_id IS NULL) AS non_kev_open_total
        FROM vuln_findings vf
        LEFT JOIN LATERAL (
            SELECT k.cve_id, k.due_date, k.known_ransomware_campaign_use
            FROM vuln_finding_cves fc
            JOIN cisa_kev k ON k.cve_id = fc.cve
            WHERE fc.finding_id = vf.id
            ORDER BY k.date_added DESC
            LIMIT 1
        ) k ON TRUE
        WHERE vf.state IN ('OPEN','REOPENED')
          AND vf.last_found >= now() - (%(days)s || ' days')::interval
        GROUP BY vf.site_label
        """,
        {"days": days_last_seen},
    )
    cols = [d.name for d in cur.description]
    rows = {r[0]: dict(zip(cols, r)) for r in cur.fetchall()}

    out: Dict[str, Dict[str, Any]] = {}
    for lab, tag in _site_labels(cfg):
        r = rows.get(lab)
        if r:
            out[lab] = {**r, "site_tag": r.get("site_tag") or tag}
        else:
            out[lab] = {
                "site_tag": tag, "kev_open_total": 0, "kev_open_crit": 0, "kev_open_high": 0,
                "kev_open_medium": 0, "kev_open_low": 0, "kev_ransomware_total": 0,
                "kev_past_due_total": 0, "non_kev_open_total": 0,
            }
    return out


def write_kev_metrics(cur, snapshot_date: dt.date, data: Dict[str, Dict[str, Any]]) -> None:
    for lab, d in data.items():
        cur.execute(
            """
            INSERT INTO daily_kev_metrics (
                snapshot_date, site_label, site_tag,
                kev_open_total, kev_open_crit, kev_open_high, kev_open_medium, kev_open_low,
                kev_ransomware_total, kev_past_due_total, non_kev_open_total
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (snapshot_date, site_label) DO UPDATE SET
                site_tag = EXCLUDED.site_tag,
                kev_open_total = EXCLUDED.kev_open_total, kev_open_crit = EXCLUDED.kev_open_crit,
                kev_open_high = EXCLUDED.kev_open_high, kev_open_medium = EXCLUDED.kev_open_medium,
                kev_open_low = EXCLUDED.kev_open_low, kev_ransomware_total = EXCLUDED.kev_ransomware_total,
                kev_past_due_total = EXCLUDED.kev_past_due_total, non_kev_open_total = EXCLUDED.non_kev_open_total;
            """,
            (snapshot_date.isoformat(), lab, d["site_tag"], d["kev_open_total"], d["kev_open_crit"],
             d["kev_open_high"], d["kev_open_medium"], d["kev_open_low"], d["kev_ransomware_total"],
             d["kev_past_due_total"], d["non_kev_open_total"]),
        )


# ------------------------------------------------------------
#  EPSS METRICS
#  "High EPSS" threshold (0.5 = coin-flip-or-better odds of exploitation
#  in the next 30 days) matches common risk-based-vuln-management practice
#  pairing EPSS with KEV. high_epss_non_kev_total is the predictive
#  watchlist: findings likely to be exploited soon that KEV hasn't
#  confirmed yet.
# ------------------------------------------------------------

HIGH_EPSS_THRESHOLD = 0.5


def rollup_epss_metrics(cur, cfg: Dict[str, Any], days_last_seen: int) -> Dict[str, Dict[str, Any]]:
    cur.execute(
        """
        SELECT
            vf.site_label,
            max(vf.site_tag) AS site_tag,
            avg(e.epss) AS avg_epss,
            max(e.epss) AS max_epss,
            count(*) FILTER (WHERE e.epss >= %(thresh)s) AS high_epss_open_total,
            count(*) FILTER (WHERE e.epss >= %(thresh)s AND k.cve_id IS NULL) AS high_epss_non_kev_total
        FROM vuln_findings vf
        LEFT JOIN LATERAL (
            SELECT es.epss
            FROM vuln_finding_cves fc
            JOIN epss_scores es ON es.cve_id = fc.cve
            WHERE fc.finding_id = vf.id
            ORDER BY es.epss DESC
            LIMIT 1
        ) e ON TRUE
        LEFT JOIN LATERAL (
            SELECT k.cve_id
            FROM vuln_finding_cves fc2
            JOIN cisa_kev k ON k.cve_id = fc2.cve
            WHERE fc2.finding_id = vf.id
            LIMIT 1
        ) k ON TRUE
        WHERE vf.state IN ('OPEN','REOPENED')
          AND vf.last_found >= now() - (%(days)s || ' days')::interval
        GROUP BY vf.site_label
        """,
        {"days": days_last_seen, "thresh": HIGH_EPSS_THRESHOLD},
    )
    cols = [d.name for d in cur.description]
    rows = {r[0]: dict(zip(cols, r)) for r in cur.fetchall()}

    out: Dict[str, Dict[str, Any]] = {}
    for lab, tag in _site_labels(cfg):
        r = rows.get(lab)
        if r:
            out[lab] = {**r, "site_tag": r.get("site_tag") or tag}
        else:
            out[lab] = {
                "site_tag": tag, "avg_epss": None, "max_epss": None,
                "high_epss_open_total": 0, "high_epss_non_kev_total": 0,
            }
    return out


def write_epss_metrics(cur, snapshot_date: dt.date, data: Dict[str, Dict[str, Any]]) -> None:
    for lab, d in data.items():
        cur.execute(
            """
            INSERT INTO daily_epss_metrics (
                snapshot_date, site_label, site_tag,
                avg_epss, max_epss, high_epss_open_total, high_epss_non_kev_total
            ) VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (snapshot_date, site_label) DO UPDATE SET
                site_tag = EXCLUDED.site_tag,
                avg_epss = EXCLUDED.avg_epss, max_epss = EXCLUDED.max_epss,
                high_epss_open_total = EXCLUDED.high_epss_open_total,
                high_epss_non_kev_total = EXCLUDED.high_epss_non_kev_total;
            """,
            (snapshot_date.isoformat(), lab, d["site_tag"], d["avg_epss"], d["max_epss"],
             d["high_epss_open_total"], d["high_epss_non_kev_total"]),
        )


# ------------------------------------------------------------
#  MTTR METRICS
#  Cohort = findings whose last_fixed date is exactly snapshot_date (not a
#  rolling window like daily_product_metrics.fixed_*), so this trends as a
#  proper daily time series: "of what closed today, how long did it take,
#  and did it beat its SLA band?" broken down by severity.
# ------------------------------------------------------------

def rollup_mttr_metrics(cur, snapshot_date: dt.date) -> List[Dict[str, Any]]:
    cur.execute(
        """
        SELECT
            vf.site_label,
            max(vf.site_tag) AS site_tag,
            vf.severity,
            count(*) AS fixed_count,
            round(avg(EXTRACT(EPOCH FROM vf.last_fixed - vf.first_found) / 86400.0)::numeric, 2) AS avg_remediation_days,
            round((percentile_cont(0.5) WITHIN GROUP (
                ORDER BY EXTRACT(EPOCH FROM vf.last_fixed - vf.first_found) / 86400.0
            ))::numeric, 2) AS median_remediation_days,
            count(*) FILTER (
                WHERE EXTRACT(EPOCH FROM vf.last_fixed - vf.first_found) / 86400.0 <= sp.threshold_days
            ) AS sla_compliant_count
        FROM vuln_findings vf
        JOIN sla_policy sp ON sp.severity = vf.severity
        WHERE vf.state = 'FIXED'
          AND vf.last_fixed >= %(snap)s::date
          AND vf.last_fixed <  %(snap)s::date + INTERVAL '1 day'
        GROUP BY vf.site_label, vf.severity
        """,
        {"snap": snapshot_date.isoformat()},
    )
    cols = [d.name for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    for r in rows:
        r["sla_compliance_rate"] = (
            round(100.0 * r["sla_compliant_count"] / r["fixed_count"], 2) if r["fixed_count"] else None
        )
    return rows


def write_mttr_metrics(cur, snapshot_date: dt.date, rows: List[Dict[str, Any]]) -> None:
    for r in rows:
        cur.execute(
            """
            INSERT INTO daily_mttr_metrics (
                snapshot_date, site_label, site_tag, severity,
                fixed_count, avg_remediation_days, median_remediation_days,
                sla_compliant_count, sla_compliance_rate
            ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (snapshot_date, site_label, severity) DO UPDATE SET
                site_tag = EXCLUDED.site_tag,
                fixed_count = EXCLUDED.fixed_count,
                avg_remediation_days = EXCLUDED.avg_remediation_days,
                median_remediation_days = EXCLUDED.median_remediation_days,
                sla_compliant_count = EXCLUDED.sla_compliant_count,
                sla_compliance_rate = EXCLUDED.sla_compliance_rate;
            """,
            (snapshot_date.isoformat(), r["site_label"], r["site_tag"], r["severity"],
             r["fixed_count"], r["avg_remediation_days"], r["median_remediation_days"],
             r["sla_compliant_count"], r["sla_compliance_rate"]),
        )



# ------------------------------------------------------------
#  V2 DOMAINS (written as snapshot rows so every panel can trend)
#  Each is a single INSERT ... SELECT: recomputing a day overwrites it.
# ------------------------------------------------------------

def rollup_source_metrics(cur, snapshot_date: dt.date, days_last_seen: int) -> None:
    """Open vulns per site AND source -- splits endpoint (Spotlight) from
    external (Hadrian) so they can be trended separately."""
    cur.execute("DELETE FROM daily_source_metrics WHERE snapshot_date = %s", (snapshot_date,))
    cur.execute(
        """
        INSERT INTO daily_source_metrics
            (snapshot_date, site_label, source, crit, high, medium, low, total, kev, sla_breaches, assets)
        SELECT %(snap)s, site_label, source,
            count(*) FILTER (WHERE severity='critical'),
            count(*) FILTER (WHERE severity='high'),
            count(*) FILTER (WHERE severity='medium'),
            count(*) FILTER (WHERE severity='low'),
            count(*),
            count(*) FILTER (WHERE has_kev),
            count(*) FILTER (WHERE sla_breach),
            count(DISTINCT source_asset_id)
        FROM fact_vuln_findings_current
        WHERE last_found >= now() - (%(days)s || ' days')::interval
        GROUP BY site_label, source
        """,
        {"snap": snapshot_date, "days": days_last_seen},
    )


def rollup_asset_metrics(cur, cfg: Dict[str, Any], snapshot_date: dt.date) -> None:
    stale = int(cfg.get("reporting", {}).get("stale_sensor_days", 7))
    cur.execute("DELETE FROM daily_asset_metrics WHERE snapshot_date = %s", (snapshot_date,))
    cur.execute(
        """
        INSERT INTO daily_asset_metrics
            (snapshot_date, site_label, managed_hosts, stale_sensors, rfm_hosts, unmanaged_assets, external_assets)
        SELECT %(snap)s, s.site_label,
            COALESCE(a.managed, 0), COALESCE(a.stale, 0), COALESCE(a.rfm, 0),
            COALESCE(a.unmanaged, 0), COALESCE(x.ext, 0)
        FROM sites s
        LEFT JOIN (
            SELECT site_label,
                count(*) FILTER (WHERE source = 'falcon') AS managed,
                count(*) FILTER (WHERE source = 'falcon' AND last_seen < now() - (%(stale)s || ' days')::interval) AS stale,
                count(*) FILTER (WHERE source = 'falcon' AND lower(rfm) = 'yes') AS rfm,
                count(*) FILTER (WHERE source = 'falcon_unmanaged') AS unmanaged
            FROM assets WHERE NOT retired GROUP BY site_label
        ) a ON a.site_label = s.site_label
        LEFT JOIN (
            SELECT site_label, count(*) AS ext FROM external_assets WHERE NOT retired GROUP BY site_label
        ) x ON x.site_label = s.site_label
        """,
        {"snap": snapshot_date, "stale": stale},
    )


def rollup_alert_metrics(cur, snapshot_date: dt.date) -> None:
    cur.execute("DELETE FROM daily_alert_metrics WHERE snapshot_date = %s", (snapshot_date,))
    cur.execute(
        """
        INSERT INTO daily_alert_metrics
            (snapshot_date, site_label, new_critical, new_high, new_medium, new_low,
             open_total, open_crit_high, closed_today, median_hours_to_close)
        SELECT %(snap)s, s.site_label,
            COALESCE(count(*) FILTER (WHERE a.created_at::date = %(snap)s AND a.severity='critical'), 0),
            COALESCE(count(*) FILTER (WHERE a.created_at::date = %(snap)s AND a.severity='high'), 0),
            COALESCE(count(*) FILTER (WHERE a.created_at::date = %(snap)s AND a.severity='medium'), 0),
            COALESCE(count(*) FILTER (WHERE a.created_at::date = %(snap)s AND a.severity='low'), 0),
            COALESCE(count(*) FILTER (WHERE a.status <> 'closed'), 0),
            COALESCE(count(*) FILTER (WHERE a.status <> 'closed' AND a.severity IN ('critical','high')), 0),
            COALESCE(count(*) FILTER (WHERE a.closed_at::date = %(snap)s), 0),
            round((percentile_cont(0.5) WITHIN GROUP (
                ORDER BY EXTRACT(EPOCH FROM a.closed_at - a.created_at) / 3600.0
            ) FILTER (WHERE a.closed_at::date = %(snap)s))::numeric, 2)
        FROM sites s
        LEFT JOIN security_alerts a ON a.site_label = s.site_label
        GROUP BY s.site_label
        """,
        {"snap": snapshot_date},
    )


def rollup_identity_metrics(cur, snapshot_date: dt.date) -> None:
    """Long format (metric, value) so new risk-factor types need no schema change."""
    cur.execute("DELETE FROM daily_identity_metrics WHERE snapshot_date = %s", (snapshot_date,))
    cur.execute(
        """
        INSERT INTO daily_identity_metrics (snapshot_date, site_label, metric, value)
        SELECT %(snap)s, site_label, metric, sum(v)::int FROM (
            SELECT site_label, 'risk:' || COALESCE(risk_severity, 'unknown') AS metric, count(*) AS v
            FROM identity_entities WHERE NOT retired GROUP BY 1, 2
          UNION ALL
            SELECT e.site_label, 'factor:' || f.factor_type, count(DISTINCT e.entity_id)
            FROM identity_risk_factors f
            JOIN identity_entities e ON e.source = f.source AND e.entity_id = f.entity_id AND NOT e.retired
            GROUP BY 1, 2
          UNION ALL
            SELECT site_label, 'entra_risky:' || COALESCE(risk_level, 'unknown'), count(*)
            FROM entra_risky_users GROUP BY 1, 2
          UNION ALL
            SELECT site_label, 'mfa_users', count(*) FROM entra_mfa_registration GROUP BY 1
          UNION ALL
            SELECT site_label, 'mfa_registered', count(*) FILTER (WHERE is_mfa_registered)
            FROM entra_mfa_registration GROUP BY 1
        ) x
        GROUP BY site_label, metric
        """,
        {"snap": snapshot_date},
    )


def rollup_email_metrics(cur, snapshot_date: dt.date, lookback_days: int = 3) -> None:
    """Per day the event was CREATED (not run day), recomputed over a short
    window because HEC events arrive/settle late."""
    start = snapshot_date - dt.timedelta(days=lookback_days)
    cur.execute("DELETE FROM daily_email_metrics WHERE snapshot_date >= %s", (start,))
    cur.execute(
        """
        INSERT INTO daily_email_metrics (snapshot_date, site_label, event_type, events, high_plus)
        SELECT created_at::date, site_label, COALESCE(event_type, 'unknown'),
               count(*), count(*) FILTER (WHERE severity IN ('critical','high'))
        FROM email_events
        WHERE created_at::date >= %s AND created_at::date <= %s
        GROUP BY 1, 2, 3
        """,
        (start, snapshot_date),
    )

# ------------------------------------------------------------
#  MAIN
# ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Roll up vuln_findings into daily snapshot tables")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--new-window-days", type=int, default=7, help="new_*/fixed_* window in days")
    parser.add_argument("--dry-run", action="store_true", help="Print computed rollup without writing")
    args = parser.parse_args()

    cfg = config_mod.load_config(args.config)
    db_schema.ensure_schema(cfg)
    days_last_seen = cfg.get("reporting", {}).get("days_last_seen", 30)
    snapshot_date = dt.date.today()

    conn = pg_connect(cfg)
    cur = conn.cursor()

    site_data = rollup_site_metrics(cur, cfg, snapshot_date, days_last_seen)
    sla_rows = rollup_sla_metrics(cur, days_last_seen)
    product_rows = rollup_product_metrics(cur, days_last_seen, args.new_window_days)
    kev_data = rollup_kev_metrics(cur, cfg, days_last_seen)
    epss_data = rollup_epss_metrics(cur, cfg, days_last_seen)
    mttr_rows = rollup_mttr_metrics(cur, snapshot_date)

    if args.dry_run:
        print(f"[rollup] DRY RUN for {snapshot_date}")
        print(f"[rollup] site_metrics: {site_data}")
        print(f"[rollup] sla_metrics ({len(sla_rows)} rows): {sla_rows}")
        print(f"[rollup] product_metrics ({len(product_rows)} rows, showing up to 10): {product_rows[:10]}")
        print(f"[rollup] kev_metrics: {kev_data}")
        print(f"[rollup] epss_metrics: {epss_data}")
        print(f"[rollup] mttr_metrics ({len(mttr_rows)} rows): {mttr_rows}")
        conn.close()
        return

    write_site_metrics(cur, snapshot_date, site_data)
    write_sla_metrics(cur, snapshot_date, sla_rows)
    write_product_metrics(cur, snapshot_date, product_rows)
    write_kev_metrics(cur, snapshot_date, kev_data)
    write_epss_metrics(cur, snapshot_date, epss_data)
    write_mttr_metrics(cur, snapshot_date, mttr_rows)

    rollup_source_metrics(cur, snapshot_date, days_last_seen)
    rollup_asset_metrics(cur, cfg, snapshot_date)
    rollup_alert_metrics(cur, snapshot_date)
    rollup_identity_metrics(cur, snapshot_date)
    rollup_email_metrics(cur, snapshot_date)

    conn.commit()
    conn.close()
    print(f"[rollup] Wrote vuln snapshots (daily_site/sla/product/kev/epss/mttr, "
          f"{len(product_rows)} product rows, {len(mttr_rows)} mttr rows) and "
          f"daily_source/asset/alert/identity/email metrics for {snapshot_date}.")


if __name__ == "__main__":
    main()
