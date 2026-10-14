#!/usr/bin/env python3
"""
Dashboard-as-code for the five SecOps dashboards. Edit the panel
definitions here and re-run; the generated JSON is committed alongside so it
can be imported without running anything.

  python3 grafana/build_dashboards.py          # writes grafana/secops-*.json + vuln-dashboard.json

Every dashboard shares the `secops` tag (they link to each other, keeping
$site and the time range) and the same conventions:
severity is red -> orange -> amber -> yellow, never green; green only ever
means a genuinely good number (coverage, pass rate, things closed).

SQL notes: '${__from:date}' / '${__to:date}' bound date-based panels;
$site is the multi-select site variable (sourced from dim_site).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import discovery_classes as dc
import usb_categories as uc
from email_types import BULK_EVENT_TYPES, THREAT_EVENT_TYPES, sql_in

DS = {"type": "postgres", "uid": "${DS_POSTGRESQL}"}
HERE = os.path.dirname(os.path.abspath(__file__))

SEV_COLORS = {"Critical": "red", "High": "orange", "Medium": "dark-yellow", "Low": "yellow",
              "critical": "red", "high": "orange", "medium": "dark-yellow", "low": "yellow", "info": "blue"}
IN_RANGE_TS = "{col} >= '${{__from:date}}'::date AND {col} < '${{__to:date}}'::date + 1"
IN_RANGE_D = "{col} BETWEEN '${{__from:date}}'::date AND '${{__to:date}}'::date"


def rng_ts(col):
    return IN_RANGE_TS.format(col=col)


def rng_d(col):
    return IN_RANGE_D.format(col=col)


class Builder:
    def __init__(self):
        self.panels = []
        self.y = 0
        self.x = 0
        self.row_h = 0
        self.next_id = 1
        self.current_row = None

    def _id(self):
        self.next_id += 1
        return self.next_id

    def _place(self, w, h):
        if self.x + w > 24:
            self.y += self.row_h
            self.x = 0
            self.row_h = 0
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.row_h = max(self.row_h, h)
        return pos

    def newline(self):
        if self.x:
            self.y += self.row_h
            self.x = 0
            self.row_h = 0

    def add(self, p):
        if self.current_row is not None and self.current_row["collapsed"]:
            self.current_row["panels"].append(p)
        else:
            self.panels.append(p)
        return p

    def row(self, title, collapsed=False, note=None):
        """A section. `note`: one or two lines under the header saying what the section is
        and its main caveat (rows can't carry a description themselves); per-panel
        definitions go in the panel descriptions (the hover i)."""
        self.newline()
        r = {"id": self._id(), "type": "row", "title": title, "collapsed": collapsed,
             "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1}, "panels": []}
        self.panels.append(r)
        self.current_row = r
        self.y += 1
        if note:
            self.text(note, h=2)
        return r

    def text(self, content, w=24, h=5):
        return self.add({"id": self._id(), "type": "text", "title": "", "gridPos": self._place(w, h),
                         "options": {"mode": "markdown", "content": content}})

    def _panel(self, ptype, title, sql, w, h, fmt="table", defaults=None, overrides=None, options=None,
               description=None):
        p = {"id": self._id(), "type": ptype, "title": title, "gridPos": self._place(w, h), "datasource": DS,
             "fieldConfig": {"defaults": defaults or {}, "overrides": overrides or []},
             "options": options or {},
             "targets": [{"refId": "A", "format": fmt, "rawQuery": True, "editorMode": "code", "rawSql": " ".join(sql.split())}]}
        if description:
            p["description"] = description
        return self.add(p)

    def stat(self, title, sql, w=4, h=4, unit="short", thresholds=None, description=None, decimals=None,
             color=None):
        d = {"unit": unit}
        if decimals is not None:
            d["decimals"] = decimals
        if thresholds:
            d["thresholds"] = {"mode": "absolute", "steps": thresholds}
            d["color"] = {"mode": "thresholds"}
        elif color:
            d["color"] = {"mode": "fixed", "fixedColor": color}
        return self._panel("stat", title, sql, w, h, defaults=d, description=description,
                           options={"reduceOptions": {"calcs": ["lastNotNull"]},
                                    "colorMode": "value" if thresholds or color else "none", "graphMode": "none"})

    def delta(self, title, sql, w=6, h=4, suffix=None, decimals=0, description=None):
        """Change-over-time tile. Every one counts a bad thing, so any rise is red and any
        fall (or no change) green. suffix " pts" for differences between percentages."""
        return self.stat(title, sql, w=w, h=h, unit=f"suffix:{suffix}" if suffix else "short", decimals=decimals,
                         thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 0.000001}],
                         description=description)

    def ts(self, title, sql, w=12, h=8, unit="short", colors=None, stack=False, bars=False, description=None,
           minmax=None):
        custom = {"fillOpacity": 15}
        if stack:
            custom["stacking"] = {"mode": "normal"}
        if bars:
            custom.update({"drawStyle": "bars", "fillOpacity": 80})
        ov = [{"matcher": {"id": "byName", "options": n},
               "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
              for n, c in (colors or {}).items()]
        d = {"unit": unit, "custom": custom}
        if minmax:
            d["min"], d["max"] = minmax
        return self._panel("timeseries", title, sql, w, h, fmt="time_series",
                           defaults=d, overrides=ov, description=description,
                           options={"legend": {"displayMode": "list", "placement": "bottom"}})

    def table(self, title, sql, w=24, h=9, overrides=None, description=None, links=None):
        ov = list(overrides or [])
        for col, url in (links or {}).items():
            ov.append({"matcher": {"id": "byName", "options": col},
                       "properties": [{"id": "links", "value": [{"title": "Open", "url": url, "targetBlank": True}]}]})
        return self._panel("table", title, sql, w, h, overrides=ov, description=description,
                           options={"showHeader": True, "footer": {"show": False}})

    def bars(self, title, sql, w=8, h=8, unit="short", thresholds=None, minmax=None, description=None):
        d = {"unit": unit}
        if minmax:
            d["min"], d["max"] = minmax
        if thresholds:
            d["thresholds"] = {"mode": "absolute", "steps": thresholds}
            d["color"] = {"mode": "thresholds"}
        return self._panel("bargauge", title, sql, w, h, defaults=d, description=description,
                           options={"displayMode": "gradient", "orientation": "horizontal", "showUnfilled": True,
                                    "reduceOptions": {"values": True, "calcs": [], "fields": ""}})


def bg(col, mode="continuous-GrYlRd"):
    return {"matcher": {"id": "byName", "options": col},
            "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background"}},
                           {"id": "color", "value": {"mode": mode}}]}


def thresh_bg(col, steps):
    return {"matcher": {"id": "byName", "options": col},
            "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background"}},
                           {"id": "thresholds", "value": {"mode": "absolute", "steps": steps}},
                           {"id": "color", "value": {"mode": "thresholds"}}]}


def sev_cell(col="Severity"):
    return {"matcher": {"id": "byName", "options": col},
            "properties": [{"id": "custom.cellOptions", "value": {"type": "color-text"}},
                           {"id": "mappings", "value": [{"type": "value", "options": {
                               k: {"color": v, "index": i} for i, (k, v) in enumerate(SEV_COLORS.items())}}]}]}


BAD_UP = [{"color": "green", "value": None}, {"color": "orange", "value": 1}, {"color": "red", "value": 10}]
GOOD_PCT = [{"color": "red", "value": None}, {"color": "orange", "value": 80}, {"color": "green", "value": 95}]
NEUTRAL = [{"color": "text", "value": None}]
# share of enabled accounts gone stale: some churn is normal, a quarter is a cleanup job
STALE_PCT = [{"color": "green", "value": None}, {"color": "orange", "value": 10}, {"color": "red", "value": 25}]


HOVER = "Hover the **i** on any panel for exactly what it counts."


def dashboard(uid, title, description, b: Builder, help=None, tags=(), time_from="now-30d"):
    """`help`: panel title -> description, for panels that don't set their own -- kept
    together per dashboard so the definitions read as one glossary."""
    def walk(ps):
        for p in ps:
            yield p
            yield from walk(p.get("panels") or [])
    for p in walk(b.panels):
        if p["type"] not in ("row", "text") and not p.get("description") and (help or {}).get(p["title"]):
            p["description"] = help[p["title"]]
    return {
        "__inputs": [{"name": "DS_POSTGRESQL", "label": "PostgreSQL",
                      "description": "Postgres datasource pointing at the secops_dashboard database",
                      "type": "datasource", "pluginId": "postgres", "pluginName": "PostgreSQL"}],
        "__requires": [{"type": "grafana", "id": "grafana", "name": "Grafana", "version": "10.0.0"},
                       {"type": "datasource", "id": "postgres", "name": "PostgreSQL", "version": "1.0.0"}],
        "id": None, "uid": uid, "title": title, "description": description,
        "tags": ["secops", *tags], "timezone": "browser", "schemaVersion": 39, "version": 1,
        "editable": True, "graphTooltip": 1, "refresh": "1h",
        "time": {"from": time_from, "to": "now"}, "timepicker": {},
        "annotations": {"list": []},
        "links": [{"type": "dashboards", "tags": ["secops"], "asDropdown": False, "title": "SecOps",
                   "includeVars": True, "keepTime": True}],
        "templating": {"list": [{
            "name": "site", "type": "query", "label": "Site", "datasource": DS,
            "query": "SELECT site_label FROM dim_site ORDER BY site_label = 'Ungrouped', site_label",
            "definition": "SELECT site_label FROM dim_site", "refresh": 1, "sort": 0,
            "multi": True, "includeAll": True, "current": {"text": "All", "value": "$__all"}}]},
        "panels": b.panels,
    }


OVERVIEW_HELP = {
    "Open Crit/High alerts": "Falcon detections of critical or high severity not yet closed.",
    "Email threats (range)": "Phishing and malware emails Check Point flagged in the selected range "
                             "(including suspected), by recipient site.",
    "DMARC pass (range)": "Share of mail claiming to be from our domains that passed DMARC, from receiving "
                          "servers' aggregate reports in the selected range.",
    "Site scorecard": "Per site: open critical/high endpoint and external vulns, KEV findings and SLA breaches "
                      "(seen in 30 days, as at the last nightly run); open critical/high alerts; high-risk accounts; "
                      "Entra risky users and MFA %; email threats and DMARC pass % in range; stale sensors and "
                      "unmanaged devices.",
    "Open vulns by source": "Open findings per day from the nightly snapshot, split endpoint (Falcon) vs external "
                            "(Hadrian).",
    "New alerts per day by severity": "Falcon detections by the day they were raised.",
    "Identity risk": "High-risk accounts per day: Falcon Identity Protection and Entra ID Protection.",
    "Email threats per day": "Check Point email security events per day, by type.",
    "Unmapped examples (add these to config.yaml)": "Hosts and accounts no site rule matched, with the attributes "
                                                     "a rule could use (domain, OU, groups, email domain).",
}

# =====================================================================
#  1. SecOps Overview
# =====================================================================
def overview():
    b = Builder()
    b.text("Every feed, per site. Drill into the linked dashboards (top right) for detail. If a number looks "
           f"too good, check **Data freshness** at the bottom first. {HOVER}", h=2)

    b.row("Posture at a glance", note="**Vulns** = Falcon Exposure Management (endpoints) + Hadrian (external), "
          "open and seen in the last 30 days, as at the last nightly run. **Alerts** = Falcon detections not yet "
          "closed. **Email** and **DMARC** follow the time picker.")
    # dash_vuln_site_summary: pre-computed nightly by rollup_daily_metrics.py (the live
    # fact view took 1-2 minutes per panel at estate scale)
    b.stat("Open Crit + High vulns",
           "SELECT COALESCE(sum(n), 0) FROM dash_vuln_site_summary WHERE site_label IN ($site) "
           "AND severity IN ('critical','high') AND seen_30d",
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}, {"color": "red", "value": 500}],
           description="As at the last nightly run (pre-computed by rollup_daily_metrics.py).")
    b.stat("Open KEV findings",
           "SELECT COALESCE(sum(n), 0) FROM dash_vuln_site_summary WHERE site_label IN ($site) AND has_kev "
           "AND seen_30d", thresholds=BAD_UP, description="As at the last nightly run (pre-computed by rollup_daily_metrics.py).")
    b.stat("Open Crit/High alerts",
           "SELECT count(*) FROM security_alerts WHERE site_label IN ($site) AND status <> 'closed' "
           "AND severity IN ('critical','high')", thresholds=BAD_UP)
    b.stat("High-risk identities",
           "SELECT (SELECT count(*) FROM identity_entities WHERE site_label IN ($site) AND NOT retired "
           "AND risk_severity = 'high') + (SELECT count(*) FROM entra_risky_users WHERE site_label IN ($site) "
           "AND risk_level = 'high')", thresholds=BAD_UP,
           description="Falcon Identity Protection HIGH-risk accounts + Entra ID users at HIGH risk.")
    b.stat("Email threats (range)",
           f"SELECT count(*) FROM email_events WHERE site_label IN ($site) AND {rng_ts('created_at')} "
           "AND event_type IN ('phishing','malware','suspicious_phishing','suspicious_malware')",
           thresholds=NEUTRAL)
    b.stat("DMARC pass (range)",
           f"SELECT round(100.0 * sum(dmarc_pass) / NULLIF(sum(messages),0), 1) FROM dmarc_daily "
           f"WHERE site_label IN ($site) AND {rng_d('report_date')}",
           unit="percent", thresholds=GOOD_PCT, decimals=1)

    b.row("Site scorecard", note="One row per site, worst KEV exposure first. Vulnerability columns are as at the "
          "last nightly run; email and DMARC follow the time picker; the rest are live.")
    b.table("Site scorecard", """
        WITH v AS (
            SELECT site_label,
                   sum(n) FILTER (WHERE severity IN ('critical','high') AND source <> 'hadrian') AS ep_ch,
                   sum(n) FILTER (WHERE severity IN ('critical','high') AND source = 'hadrian') AS ext_ch,
                   sum(n) FILTER (WHERE has_kev) AS kev,
                   sum(n) FILTER (WHERE sla_breach) AS sla
            FROM dash_vuln_site_summary WHERE seen_30d GROUP BY 1),
        a AS (SELECT site_label, count(*) FILTER (WHERE status <> 'closed' AND severity IN ('critical','high')) AS al
              FROM security_alerts GROUP BY 1),
        i AS (SELECT site_label, count(*) FILTER (WHERE risk_severity = 'high') AS hi
              FROM identity_entities WHERE NOT retired GROUP BY 1),
        r AS (SELECT site_label, count(*) AS ru FROM entra_risky_users GROUP BY 1),
        m AS (SELECT site_label, round(100.0 * count(*) FILTER (WHERE is_mfa_registered) / NULLIF(count(*),0), 1) AS mfa
              FROM entra_mfa_registration GROUP BY 1),
        e AS (SELECT site_label, count(*) AS em FROM email_events WHERE """ + rng_ts("created_at") + """
              AND event_type IN ('phishing','malware','suspicious_phishing','suspicious_malware') GROUP BY 1),
        d AS (SELECT site_label, round(100.0 * sum(dmarc_pass) / NULLIF(sum(messages),0), 1) AS dm
              FROM dmarc_daily WHERE """ + rng_d("report_date") + """ GROUP BY 1),
        h AS (SELECT site_label,
                     count(*) FILTER (WHERE source = 'falcon' AND last_seen < now() - interval '7 days') AS stale,
                     count(*) FILTER (WHERE source = 'falcon_unmanaged') AS unm
              FROM assets WHERE NOT retired GROUP BY 1)
        SELECT s.site_label AS "Site",
               COALESCE(v.ep_ch,0) AS "Endpoint C+H", COALESCE(v.ext_ch,0) AS "External C+H",
               COALESCE(v.kev,0) AS "KEV", COALESCE(v.sla,0) AS "SLA breaches",
               COALESCE(a.al,0) AS "Open C+H alerts", COALESCE(i.hi,0) AS "High-risk IDs",
               COALESCE(r.ru,0) AS "Entra risky users", m.mfa AS "MFA registered %",
               COALESCE(e.em,0) AS "Email threats", d.dm AS "DMARC pass %",
               COALESCE(h.stale,0) AS "Stale sensors", COALESCE(h.unm,0) AS "Unmanaged"
        FROM sites s
        LEFT JOIN v ON v.site_label = s.site_label LEFT JOIN a ON a.site_label = s.site_label
        LEFT JOIN i ON i.site_label = s.site_label LEFT JOIN r ON r.site_label = s.site_label
        LEFT JOIN m ON m.site_label = s.site_label LEFT JOIN e ON e.site_label = s.site_label
        LEFT JOIN d ON d.site_label = s.site_label LEFT JOIN h ON h.site_label = s.site_label
        WHERE s.site_label IN ($site)
        ORDER BY s.site_label = 'Ungrouped', COALESCE(v.kev,0) DESC, COALESCE(v.ep_ch,0) DESC
    """, h=10, overrides=[
        thresh_bg("KEV", BAD_UP), thresh_bg("Open C+H alerts", BAD_UP), thresh_bg("High-risk IDs", BAD_UP),
        thresh_bg("Entra risky users", BAD_UP), thresh_bg("MFA registered %", GOOD_PCT),
        thresh_bg("DMARC pass %", GOOD_PCT), thresh_bg("Stale sensors", BAD_UP),
        bg("Endpoint C+H"), bg("External C+H"), bg("SLA breaches")])

    b.row("Trends", note="From the nightly snapshots. A step change usually means coverage changed (more hosts "
          "assessed, a feed added) rather than risk -- check before reading it as a trend.")
    b.ts("Open vulns by source", f"""
        SELECT snapshot_date::timestamp AS time,
               sum(total) FILTER (WHERE source = 'falcon_spotlight') AS "Endpoint (Falcon)",
               sum(total) FILTER (WHERE source = 'hadrian') AS "External (Hadrian)",
               sum(kev) AS "KEV"
        FROM daily_source_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date')}
        GROUP BY 1 ORDER BY 1""", colors={"KEV": "red"})
    b.ts("New alerts per day by severity", f"""
        SELECT snapshot_date::timestamp AS time, sum(new_critical) AS "Critical", sum(new_high) AS "High",
               sum(new_medium) AS "Medium", sum(new_low) AS "Low"
        FROM daily_alert_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date')}
        GROUP BY 1 ORDER BY 1""", colors=SEV_COLORS, stack=True, bars=True)
    b.ts("Identity risk", f"""
        SELECT snapshot_date::timestamp AS time,
               sum(value) FILTER (WHERE metric = 'risk:high') AS "Falcon high-risk",
               sum(value) FILTER (WHERE metric = 'risk:medium') AS "Falcon medium-risk",
               sum(value) FILTER (WHERE metric LIKE 'entra_risky:%') AS "Entra risky users"
        FROM daily_identity_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date')}
        GROUP BY 1 ORDER BY 1""", colors={"Falcon high-risk": "red", "Falcon medium-risk": "dark-yellow"})
    b.ts("Email threats per day", f"""
        SELECT snapshot_date::timestamp AS time,
               sum(events) FILTER (WHERE event_type LIKE '%phishing%') AS "Phishing",
               sum(events) FILTER (WHERE event_type LIKE '%malware%') AS "Malware",
               sum(events) FILTER (WHERE event_type NOT LIKE '%phishing%' AND event_type NOT LIKE '%malware%') AS "Other"
        FROM daily_email_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date')}
        GROUP BY 1 ORDER BY 1""", stack=True, bars=True)

    b.row("Data freshness & site mapping", collapsed=False, note="If a feed's last success is old, every panel "
          "built on it is stale. Anything that landed in **Ungrouped** needs a site rule in config.yaml.")
    b.table("Data freshness (latest run per feed)", """
        SELECT collector AS "Feed", status AS "Last run status",
               round(EXTRACT(EPOCH FROM now() - last_success) / 3600.0, 1) AS "Hours since last success",
               last_run AS "Last run", left(error, 200) AS "Error"
        FROM collector_freshness ORDER BY collector""", w=12, h=9, overrides=[
        thresh_bg("Hours since last success", [{"color": "green", "value": None}, {"color": "orange", "value": 26},
                                               {"color": "red", "value": 50}]),
        {"matcher": {"id": "byName", "options": "Last run status"},
         "properties": [{"id": "custom.cellOptions", "value": {"type": "color-text"}},
                        {"id": "mappings", "value": [{"type": "value", "options": {
                            "ok": {"color": "green", "index": 0}, "partial": {"color": "orange", "index": 1},
                            "error": {"color": "red", "index": 2}, "running": {"color": "blue", "index": 3}}}]}]}],
        description="A feed that hasn't succeeded in 26h+ is stale -- its numbers on every dashboard are old.")
    b.table("Site mapping gaps (what landed in Ungrouped)", """
        SELECT * FROM (
            SELECT 'Managed hosts' AS "Data", count(*) AS "Ungrouped",
                   round(100.0 * count(*) / NULLIF((SELECT count(*) FROM assets WHERE source='falcon' AND NOT retired),0),1) AS "% of total"
            FROM assets WHERE source = 'falcon' AND NOT retired AND site_matched_by = 'none'
          UNION ALL
            SELECT 'Unmanaged assets', count(*),
                   round(100.0 * count(*) / NULLIF((SELECT count(*) FROM assets WHERE source='falcon_unmanaged' AND NOT retired),0),1)
            FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND site_matched_by = 'none'
          UNION ALL
            SELECT 'Identities', count(*),
                   round(100.0 * count(*) / NULLIF((SELECT count(*) FROM identity_entities WHERE NOT retired),0),1)
            FROM identity_entities WHERE NOT retired AND site_matched_by = 'none'
          UNION ALL
            SELECT 'External assets', count(*),
                   round(100.0 * count(*) / NULLIF((SELECT count(*) FROM external_assets WHERE NOT retired),0),1)
            FROM external_assets WHERE NOT retired AND site_matched_by = 'none'
          UNION ALL
            SELECT 'Email events (30d)', count(*),
                   round(100.0 * count(*) / NULLIF((SELECT count(*) FROM email_events WHERE created_at > now() - interval '30 days'),0),1)
            FROM email_events WHERE created_at > now() - interval '30 days' AND site_matched_by = 'none'
          UNION ALL
            SELECT 'DMARC domains', count(DISTINCT header_from),
                   round(100.0 * count(DISTINCT header_from) / NULLIF((SELECT count(DISTINCT header_from) FROM dmarc_daily),0),1)
            FROM dmarc_daily WHERE site_matched_by = 'none'
        ) x ORDER BY "Ungrouped" DESC""", w=12, h=9, overrides=[bg("% of total")],
        description="Rows here need a matcher in config.yaml sites:. The next table shows examples to map.")
    b.table("Unmapped examples (add these to config.yaml)", """
        SELECT * FROM (
            (SELECT 'host' AS "Kind", hostname AS "Name",
                    concat_ws(' | ', 'domain=' || domain, 'ad_site=' || ad_site,
                              'groups=' || array_to_string(groups, ','), 'tags=' || array_to_string(tags, ',')) AS "Signals available"
             FROM assets WHERE source = 'falcon' AND NOT retired AND site_matched_by = 'none' LIMIT 25)
          UNION ALL
            (SELECT 'identity', coalesce(upn, sam_account_name, display_name), concat_ws(' | ', 'domain=' || domain, 'ou=' || ou)
             FROM identity_entities WHERE NOT retired AND site_matched_by = 'none' LIMIT 25)
          UNION ALL
            (SELECT 'dmarc domain', header_from, 'email_domains' FROM dmarc_daily WHERE site_matched_by = 'none'
             GROUP BY header_from LIMIT 25)
          UNION ALL
            (SELECT 'external asset', name, 'ips=' || array_to_string(ips, ',')
             FROM external_assets WHERE NOT retired AND site_matched_by = 'none' LIMIT 25)
        ) x""", h=9)
    return dashboard("secops-overview", "SecOps Overview",
                     "Cross-feed security posture per site: vulns, detections, identity, email, DMARC, coverage.", b,
                     help=OVERVIEW_HELP)


# =====================================================================
#  2. Endpoint & Identity
# =====================================================================
ENDPOINT_IDENTITY_HELP = {
    "Managed hosts": "Devices with a Falcon sensor (not retired), whatever their last check-in.",
    "Stale sensors (7d+)": "Managed hosts whose sensor hasn't checked in for 7+ days.",
    "Contained hosts": "Hosts currently network-contained from the Falcon console.",
    "Coverage trend": "Managed, unmanaged and stale-sensor counts per day from the nightly snapshot.",
    "Stale / degraded sensors": "Hosts silent 7+ days or in reduced-functionality mode, longest-silent first.",
    "Unmanaged assets": "Devices Falcon saw on the network or in AD that have no sensor, most recently seen first.",
    "Open alerts": "Falcon detections not yet closed (any severity, including informational).",
    "Open Critical": "Critical-severity Falcon detections not yet closed.",
    "New in range": "Falcon detections raised in the selected range.",
    "Median time to close (range)": "Median hours from raised to closed, for detections closed in the range.",
    "Unassigned > 24h": "Detections still 'new' (not picked up) a day after being raised.",
    "New alerts per day": "Falcon detections per day, stacked by severity.",
    "Top tactics (range)": "MITRE ATT&CK tactic of the detections raised in the range.",
    "High-risk accounts": "Accounts Falcon Identity Protection currently rates high risk.",
    "Medium-risk accounts": "Accounts Falcon Identity Protection currently rates medium risk.",
    "Enabled, password > 1 year": "Enabled accounts whose password was last changed over a year ago.",
    "Accounts by risk factor": "Accounts carrying each Falcon Identity risk factor right now (one account can have "
                               "several).",
    "Risk factor trend": "Accounts per risk factor per day, from the nightly snapshot.",
    "Users at risk": "Users Entra ID Protection currently flags at risk.",
    "Confirmed compromised": "Users an admin marked confirmed compromised in Entra ID Protection.",
    "Risk detections (range)": "Entra ID Protection risk detections (unfamiliar sign-in, leaked credentials, ...) "
                               "in the range.",
    "MFA registered": "Share of member users with an MFA method registered (guests excluded).",
    "Admins without MFA": "Users holding an admin role with no MFA method registered. Should be zero.",
    "MFA registration by site": "Share of member users with MFA registered, per site.",
    "Risky users": "Entra ID Protection's current risky-user list.",
    "Recent risk detections": "Entra ID Protection risk detections in the range, newest first.",
    "Files to removable media": "Files written to USB / removable drives in the range, all kinds.",
    "Business-data files": "Files written to removable drives that are business data: documents, spreadsheets & "
                           "data, email, medical images and archives (contents unknown, so counted as data).",
    "Email & medical images": "Outlook messages / mailbox exports and DICOM images written to removable drives "
                              "-- the most sensitive categories.",
    "Data to removable media": "Total size of the files written to removable drives in the range.",
    "People writing to USB": "Distinct users who wrote any file to a removable drive (system writes excluded).",
    "Drives used": "Distinct removable drives (by serial) written to. Drives Falcon couldn't name aren't counted.",
    "Files written per day by category": "Files written to removable drives per day, stacked by what kind of file.",
    "Business-data files by site": "Business-data files written to removable drives in the range, per site.",
    "Top removable-media writers": "People who wrote the most business-data files to removable drives in the range. "
                                   "Volume alone isn't wrongdoing -- check against role (imaging, records, IT).",
    "Email & medical image writes": "Every PC x user x drive x folder group in the range that wrote Outlook mail, "
                                    "mailbox exports or DICOM images, largest first. Sample files are the "
                                    "largest names in the group.",
    "USB scans (range)": "On-demand scans Falcon ran when a drive was plugged in.",
    "Incomplete scans": "USB scans that didn't finish -- usually the drive was removed mid-scan.",
    "Scans finding malware": "USB scans that found at least one malicious file.",
    "Detections from USB scans": "Falcon detections raised by a USB scan in the range.",
    "Recent USB scans": "USB insertion scans in the range, ones that found malware first.",
    "Sign-ins: success vs failure": "Entra sign-ins per day from Log Analytics.",
    "MFA denied": "Sign-ins where the user denied or failed the MFA prompt, per day.",
    "Legacy authentication by client": "Sign-ins using legacy protocols (IMAP, POP, SMTP auth, ...) that can't do "
                                       "MFA, per day.",
    "Risky sign-ins": "Sign-ins Entra rated risky, per day by risk level.",
    "Conditional Access blocks": "Sign-ins blocked by a Conditional Access policy, per day.",
}

def endpoint_identity():
    b = Builder()
    b.text(f"Falcon sensor coverage and detections, removable media, identity risk (Falcon Identity Protection) and Entra ID. {HOVER}",
           h=2)
    b.row("Endpoint coverage (Falcon)", note="A **stale** sensor hasn't checked in for 7+ days: the host is "
          "unprotected and unassessed, or decommissioned but not removed from Falcon.")
    b.stat("Managed hosts", "SELECT count(*) FROM assets WHERE source = 'falcon' AND NOT retired AND site_label IN ($site)",
           thresholds=NEUTRAL)
    b.stat("Stale sensors (7d+)", "SELECT count(*) FROM assets WHERE source = 'falcon' AND NOT retired "
           "AND site_label IN ($site) AND last_seen < now() - interval '7 days'", thresholds=BAD_UP)
    b.stat("Reduced functionality mode", "SELECT count(*) FROM assets WHERE source = 'falcon' AND NOT retired "
           "AND site_label IN ($site) AND lower(rfm) = 'yes'", thresholds=BAD_UP,
           description="Sensors in RFM -- usually an unsupported kernel/OS build. Protection is degraded.")
    b.stat("Unmanaged assets seen", "SELECT count(*) FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired "
           "AND site_label IN ($site)", thresholds=BAD_UP,
           description="Devices Falcon sensors saw on the network that have no sensor themselves.")
    b.stat("Sensor coverage", "SELECT round(100.0 * count(*) FILTER (WHERE managed) / NULLIF(count(*),0), 1) "
           "FROM assets WHERE NOT retired AND site_label IN ($site)", unit="percent", thresholds=GOOD_PCT, decimals=1,
           description="Managed / (managed + unmanaged-but-seen). Only as complete as Discover's visibility.")
    b.stat("Contained hosts", "SELECT count(*) FROM assets WHERE source = 'falcon' AND NOT retired "
           "AND site_label IN ($site) AND containment ILIKE 'contain%'", thresholds=BAD_UP)
    b.ts("Coverage trend", f"""
        SELECT snapshot_date::timestamp AS time, sum(managed_hosts) AS "Managed", sum(unmanaged_assets) AS "Unmanaged",
               sum(stale_sensors) AS "Stale sensors"
        FROM daily_asset_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date')} GROUP BY 1 ORDER BY 1""",
         colors={"Managed": "green", "Unmanaged": "orange", "Stale sensors": "red"})
    b.table("Stale / degraded sensors", """
        SELECT hostname AS "Host", site_label AS "Site", product_type AS "Type", os_version AS "OS",
               sensor_version AS "Sensor", rfm AS "RFM", last_seen AS "Last seen",
               round(EXTRACT(EPOCH FROM now() - last_seen) / 86400.0, 1) AS "Days silent"
        FROM assets WHERE source = 'falcon' AND NOT retired AND site_label IN ($site)
          AND (last_seen < now() - interval '7 days' OR lower(rfm) = 'yes')
        ORDER BY last_seen LIMIT 200""", w=12, h=8, overrides=[bg("Days silent")])
    b.table("Unmanaged assets", """
        SELECT coalesce(hostname, array_to_string(ips, ', ')) AS "Asset", site_label AS "Site", platform AS "Platform",
               os_version AS "OS", last_seen AS "Last seen", site_matched_by AS "Site matched by"
        FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND site_label IN ($site)
        ORDER BY last_seen DESC LIMIT 200""", w=24, h=8)

    b.row("Detections (Falcon alerts)", note="Falcon endpoint and identity detections. Informational-severity "
          "alerts are counted here but excluded from the exec reports.")
    b.stat("Open alerts", "SELECT count(*) FROM security_alerts WHERE status <> 'closed' AND site_label IN ($site)",
           thresholds=BAD_UP)
    b.stat("Open Critical", "SELECT count(*) FROM security_alerts WHERE status <> 'closed' AND severity = 'critical' "
           "AND site_label IN ($site)", thresholds=BAD_UP)
    b.stat("New in range", f"SELECT count(*) FROM security_alerts WHERE site_label IN ($site) AND {rng_ts('created_at')}",
           thresholds=NEUTRAL)
    b.stat("Median time to close (range)", f"""
        SELECT round((percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM closed_at - created_at) / 3600.0))::numeric, 1)
        FROM security_alerts WHERE closed_at IS NOT NULL AND site_label IN ($site) AND {rng_ts('closed_at')}""",
           unit="h", thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 24}, {"color": "red", "value": 72}])
    b.stat("Unassigned > 24h", "SELECT count(*) FROM security_alerts WHERE status = 'new' "
           "AND created_at < now() - interval '24 hours' AND site_label IN ($site)", thresholds=BAD_UP, w=8)
    b.ts("New alerts per day", f"""
        SELECT date_trunc('day', created_at) AS time,
               count(*) FILTER (WHERE severity = 'critical') AS "Critical", count(*) FILTER (WHERE severity = 'high') AS "High",
               count(*) FILTER (WHERE severity = 'medium') AS "Medium", count(*) FILTER (WHERE severity = 'low') AS "Low"
        FROM security_alerts WHERE site_label IN ($site) AND {rng_ts('created_at')} GROUP BY 1 ORDER BY 1""",
         colors=SEV_COLORS, stack=True, bars=True, w=16)
    b.table("Top tactics (range)", f"""
        SELECT coalesce(tactic, '(none)') AS "Tactic", count(*) AS "Alerts",
               count(*) FILTER (WHERE severity IN ('critical','high')) AS "Crit/High"
        FROM security_alerts WHERE site_label IN ($site) AND {rng_ts('created_at')}
        GROUP BY 1 ORDER BY 2 DESC LIMIT 12""", w=8, h=8)
    b.table("Open alerts", """
        SELECT created_at AS "Created", severity AS "Severity", status AS "Status", name AS "Alert",
               coalesce(hostname, user_name) AS "Host / user", site_label AS "Site", tactic AS "Tactic",
               product AS "Product", link AS "Link"
        FROM security_alerts WHERE status <> 'closed' AND site_label IN ($site)
        ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, created_at
        LIMIT 200""", h=9, overrides=[sev_cell()], links={"Link": "${__value.raw}"})

    usb_biz = f"category IN {uc.sql_in(uc.BUSINESS)}"
    usb_label = "CASE category " + " ".join(f"WHEN '{k}' THEN '{v}'" for k, v in uc.LABEL.items()) + \
        " ELSE category END"
    usb_where = f"site_label IN ($site) AND {rng_d('day')}"
    as_bytes = lambda col: {"matcher": {"id": "byName", "options": col}, "properties": [{"id": "unit", "value": "bytes"}]}
    b.row("Removable media (Falcon)", note="Files written to USB and other removable drives, and the scan Falcon "
          "runs when a drive is plugged in. **File-write history starts 5 Oct 2026** (Falcon keeps raw events "
          "about 7 days), so ranges reaching further back undercount; scan history goes back to 5 Sep.")
    b.stat("Files to removable media", f"SELECT COALESCE(sum(files), 0) FROM usb_file_writes_daily WHERE {usb_where}",
           thresholds=NEUTRAL)
    b.stat("Business-data files", f"SELECT COALESCE(sum(files) FILTER (WHERE {usb_biz}), 0) FROM usb_file_writes_daily "
           f"WHERE {usb_where}", thresholds=NEUTRAL)
    b.stat("Email & medical images", "SELECT COALESCE(sum(files), 0) FROM usb_file_writes_daily "
           f"WHERE category IN ('email', 'clinical') AND {usb_where}", thresholds=NEUTRAL)
    b.stat("Data to removable media", f"SELECT COALESCE(sum(bytes), 0) FROM usb_file_writes_daily WHERE {usb_where}",
           unit="bytes", thresholds=NEUTRAL)
    b.stat("People writing to USB", "SELECT count(DISTINCT user_key) FILTER (WHERE user_key <> '') "
           f"FROM usb_file_writes_daily WHERE {usb_where}", thresholds=NEUTRAL)
    b.stat("Drives used", "SELECT count(DISTINCT device_serial) FILTER (WHERE device_serial <> '') "
           f"FROM usb_file_writes_daily WHERE {usb_where}", thresholds=NEUTRAL)
    b.ts("Files written per day by category", f"""
        SELECT day::timestamp AS time, {usb_label} AS metric, sum(files) AS value
        FROM usb_file_writes_daily WHERE {usb_where} GROUP BY 1, 2 ORDER BY 1""",
         w=16, stack=True, bars=True, colors={uc.LABEL[k]: uc.COLOR[k] for k in uc.ORDER})
    b.bars("Business-data files by site", f"""
        SELECT site_label AS "Site", sum(files) AS "Files"
        FROM usb_file_writes_daily WHERE {usb_biz} AND {usb_where} GROUP BY 1 ORDER BY 2 DESC""",
           w=8, h=8, thresholds=[{"color": "blue", "value": None}])
    b.table("Top removable-media writers", f"""
        SELECT max(display_name) AS "Name", max(user_name) AS "Account", max(department) AS "Department",
               max(title) AS "Title", string_agg(DISTINCT site_label, ', ') AS "Site",
               count(DISTINCT aid) AS "PCs", count(DISTINCT device_serial) FILTER (WHERE device_serial <> '') AS "Drives",
               COALESCE(sum(files) FILTER (WHERE {usb_biz}), 0) AS "Business files",
               COALESCE(sum(files) FILTER (WHERE category IN ('email', 'clinical')), 0) AS "Email / medical",
               sum(files) AS "All files", sum(bytes) AS "Data",
               string_agg(DISTINCT {usb_label}, ', ') AS "Categories", max(last_write) AS "Last write"
        FROM usb_file_writes_daily WHERE user_key <> '' AND {usb_where}
        GROUP BY user_key ORDER BY 8 DESC, 10 DESC LIMIT 100""", h=9,
            overrides=[as_bytes("Data"), bg("Business files"), bg("Email / medical")])
    b.table("Email & medical image writes", f"""
        SELECT day AS "Day", COALESCE(NULLIF(display_name, ''), NULLIF(user_name, ''), '(system)') AS "User",
               department AS "Department", hostname AS "PC", site_label AS "Site", {usb_label} AS "Category",
               files AS "Files", bytes AS "Data", concat_ws(' ', device_make, device_model) AS "Drive",
               folder AS "Folder", array_to_string(sample_files, ', ') AS "Sample files"
        FROM usb_file_writes_daily WHERE category IN ('email', 'clinical') AND {usb_where}
        ORDER BY files DESC, bytes DESC LIMIT 200""", h=8, overrides=[as_bytes("Data")])
    b.stat("USB scans (range)", f"SELECT count(*) FROM usb_scans WHERE site_label IN ($site) AND {rng_ts('created_on')}",
           w=6, thresholds=NEUTRAL)
    b.stat("Incomplete scans", "SELECT count(*) FROM usb_scans WHERE status IS DISTINCT FROM 'completed' "
           f"AND site_label IN ($site) AND {rng_ts('created_on')}", w=6, thresholds=NEUTRAL)
    b.stat("Scans finding malware", "SELECT count(*) FROM usb_scans WHERE files_malicious > 0 "
           f"AND site_label IN ($site) AND {rng_ts('created_on')}", w=6, thresholds=BAD_UP)
    b.stat("Detections from USB scans", "SELECT count(*) FROM security_alerts a JOIN usb_scans s ON s.scan_id = a.scan_id "
           f"WHERE a.site_label IN ($site) AND {rng_ts('a.created_at')}", w=6, thresholds=BAD_UP)
    b.table("Recent USB scans", f"""
        SELECT created_on AS "Started", hostname AS "PC", site_label AS "Site", status AS "Status",
               array_to_string(drives, ', ') AS "Drives", files_traversed AS "Files seen",
               files_scanned AS "Scanned", files_malicious AS "Malicious", files_quarantined AS "Quarantined",
               round(EXTRACT(EPOCH FROM completed_on - created_on) / 60.0, 1) AS "Minutes"
        FROM usb_scans WHERE site_label IN ($site) AND {rng_ts('created_on')}
        ORDER BY files_malicious DESC NULLS LAST, created_on DESC LIMIT 200""", h=8,
            overrides=[thresh_bg("Malicious", [{"color": "transparent", "value": None}, {"color": "red", "value": 1}])])

    b.row("Identity risk (Falcon Identity Protection)", note="Current state from the latest Identity "
          "Protection pull; trends from the nightly snapshot. **Enabled** includes accounts whose status is unknown.")
    b.stat("High-risk accounts", "SELECT count(*) FROM identity_entities WHERE NOT retired AND risk_severity = 'high' "
           "AND site_label IN ($site)", thresholds=BAD_UP)
    b.stat("Medium-risk accounts", "SELECT count(*) FROM identity_entities WHERE NOT retired AND risk_severity = 'medium' "
           "AND site_label IN ($site)", thresholds=NEUTRAL)
    b.stat("Enabled, password > 1 year", "SELECT count(*) FROM identity_entities WHERE NOT retired AND enabled "
           "AND password_last_change < now() - interval '365 days' AND site_label IN ($site)", thresholds=BAD_UP)
    # Same population as the exec report's identity page (identity_categories: enabled or
    # unknown status, out-of-scope services excluded); "people" = human accounts minus
    # the shared-domain VPN / remote-app second accounts.
    enabled = ("FROM identity_entities e WHERE NOT e.retired AND e.enabled IS NOT FALSE "
               "AND COALESCE(e.account_kind, 'human') <> 'out_of_scope' AND e.site_label IN ($site)")
    stale = ("EXISTS (SELECT 1 FROM identity_risk_factors f WHERE f.source = e.source "
             "AND f.entity_id = e.entity_id AND f.factor_type = 'STALE_ACCOUNT')")
    people = "COALESCE(e.account_kind, 'human') = 'human' AND e.access_account IS NULL"
    b.stat("Enabled accounts", f"SELECT count(*) {enabled}", thresholds=NEUTRAL,
           description="Enabled (or unknown-status) accounts, all kinds: people, service, mailbox, generic, "
                       "VPN / remote-app. The denominator for the stale percentages.")
    b.stat("Stale: all enabled accounts", f"SELECT round(100.0 * count(*) FILTER (WHERE {stale}) / NULLIF(count(*), 0), 1) "
           f"{enabled}", unit="percent", decimals=1, thresholds=STALE_PCT,
           description="Enabled accounts Falcon Identity flags STALE_ACCOUNT (no recent activity). "
                       "Disable or confirm still needed.")
    b.stat("Stale: people's main accounts", f"SELECT round(100.0 * count(*) FILTER (WHERE {stale}) / "
           f"NULLIF(count(*), 0), 1) {enabled} AND {people}", unit="percent", decimals=1, thresholds=STALE_PCT,
           description="As left, for human accounts only, excluding service / mailbox / generic accounts and "
                       "shared-domain VPN / remote-app second accounts: roughly, staff who've left or moved on.")
    b.bars("Accounts by risk factor", """
        SELECT f.factor_type AS "Factor", count(DISTINCT f.entity_id) AS "Accounts"
        FROM identity_risk_factors f JOIN identity_entities e ON e.source = f.source AND e.entity_id = f.entity_id
        WHERE NOT e.retired AND e.site_label IN ($site) GROUP BY 1 ORDER BY 2 DESC LIMIT 15""", w=12, h=8,
           thresholds=[{"color": "orange", "value": None}])
    b.ts("Risk factor trend", f"""
        SELECT snapshot_date::timestamp AS time, replace(metric, 'factor:', '') AS metric, sum(value) AS value
        FROM daily_identity_metrics WHERE metric LIKE 'factor:%' AND site_label IN ($site) AND {rng_d('snapshot_date')}
        GROUP BY 1, 2 ORDER BY 1""", w=12)
    b.ts("Stale accounts, % of enabled", f"""
        SELECT snapshot_date::timestamp AS time,
               round(100.0 * sum(value) FILTER (WHERE metric = 'cat:stale_accounts')
                     / NULLIF(sum(value) FILTER (WHERE metric = 'total:enabled_accounts'), 0), 1) AS "All enabled accounts",
               round(100.0 * sum(value) FILTER (WHERE metric = 'total:stale_people')
                     / NULLIF(sum(value) FILTER (WHERE metric = 'total:enabled_people'), 0), 1) AS "People's main accounts"
        FROM daily_identity_metrics
        WHERE metric IN ('cat:stale_accounts', 'total:enabled_accounts', 'total:stale_people', 'total:enabled_people')
          AND site_label IN ($site) AND {rng_d('snapshot_date')}
        GROUP BY 1 HAVING sum(value) FILTER (WHERE metric = 'total:enabled_accounts') > 0 ORDER BY 1""",
         w=24, h=7, unit="percent", colors={"All enabled accounts": "orange", "People's main accounts": "red"},
         description="From the nightly identity snapshot (history from 14 Oct 2026, when the enabled-account "
                     "totals started being recorded).")
    b.table("Identity remediation list", """
        SELECT coalesce(e.upn, e.display_name) AS "Account", e.sam_account_name AS "sAMAccountName", e.domain AS "Domain",
               e.site_label AS "Site", e.risk_severity AS "Severity", round(e.risk_score::numeric, 2) AS "Score",
               string_agg(f.factor_type, ', ' ORDER BY f.factor_type) AS "Risk factors",
               e.enabled AS "Enabled",
               round(EXTRACT(EPOCH FROM now() - e.password_last_change) / 86400.0) AS "Password age (days)",
               e.ou AS "OU"
        FROM identity_entities e
        LEFT JOIN identity_risk_factors f ON f.source = e.source AND f.entity_id = e.entity_id
        WHERE NOT e.retired AND e.site_label IN ($site) AND e.risk_severity IN ('high','medium')
        GROUP BY e.source, e.entity_id, e.upn, e.display_name, e.sam_account_name, e.domain, e.site_label,
                 e.risk_severity, e.risk_score, e.enabled, e.password_last_change, e.ou
        ORDER BY e.risk_score DESC NULLS LAST LIMIT 500""", h=10, overrides=[sev_cell(), bg("Password age (days)")],
        description="Work list for the service desk (users) and cyber/systems (privileged/service accounts).")

    b.row("Entra ID", note="Entra ID Protection risk and MFA registration (needs the Entra app registration; "
          "empty until the **entra** collector is enabled).")
    b.stat("Users at risk", "SELECT count(*) FROM entra_risky_users WHERE site_label IN ($site)", thresholds=BAD_UP)
    b.stat("Confirmed compromised", "SELECT count(*) FROM entra_risky_users WHERE risk_state = 'confirmedCompromised' "
           "AND site_label IN ($site)", thresholds=BAD_UP)
    b.stat("Risk detections (range)", f"SELECT count(*) FROM entra_risk_detections WHERE site_label IN ($site) "
           f"AND {rng_ts('detected_at')}", thresholds=NEUTRAL)
    b.stat("MFA registered", "SELECT round(100.0 * count(*) FILTER (WHERE is_mfa_registered) / NULLIF(count(*),0), 1) "
           "FROM entra_mfa_registration WHERE site_label IN ($site)", unit="percent", thresholds=GOOD_PCT, decimals=1)
    b.stat("Admins without MFA", "SELECT count(*) FROM entra_mfa_registration WHERE is_admin AND NOT is_mfa_registered "
           "AND site_label IN ($site)", thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}], w=8)
    b.bars("MFA registration by site", """
        SELECT site_label AS "Site", round(100.0 * count(*) FILTER (WHERE is_mfa_registered) / NULLIF(count(*),0), 1) AS "MFA %"
        FROM entra_mfa_registration WHERE site_label IN ($site) GROUP BY 1 ORDER BY 2""", w=8, h=8, unit="percent",
           minmax=(0, 100), thresholds=GOOD_PCT)
    b.table("Risky users", """
        SELECT upn AS "User", site_label AS "Site", risk_level AS "Risk", risk_state AS "State",
               risk_detail AS "Detail", risk_last_updated AS "Updated", tenant AS "Tenant"
        FROM entra_risky_users WHERE site_label IN ($site)
        ORDER BY CASE risk_level WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, risk_last_updated DESC""",
            w=16, h=8, overrides=[sev_cell("Risk")])
    b.table("Recent risk detections", f"""
        SELECT detected_at AS "Detected", upn AS "User", site_label AS "Site", risk_event_type AS "Type",
               risk_level AS "Risk", risk_state AS "State", ip_address AS "IP", concat_ws(', ', city, country) AS "Location"
        FROM entra_risk_detections WHERE site_label IN ($site) AND {rng_ts('detected_at')}
        ORDER BY detected_at DESC LIMIT 200""", h=8, overrides=[sev_cell("Risk")])

    b.row("Sign-in activity (Log Analytics)", collapsed=True)
    for q, title, dims in (("signins", "Sign-ins: success vs failure", None),
                           ("mfa_failures", "MFA denied", None),
                           ("legacy_auth", "Legacy authentication by client", None),
                           ("risky_signins", "Risky sign-ins", None),
                           ("ca_failures", "Conditional Access blocks", None)):
        b.ts(title, f"""
            SELECT snapshot_date::timestamp AS time, dimension AS metric, sum(value) AS value
            FROM azure_log_metrics WHERE query_name = '{q}' AND site_label IN ($site) AND {rng_d('snapshot_date')}
            GROUP BY 1, 2 ORDER BY 1""", colors={"failure": "red", "success": "green", "high": "red", "medium": "dark-yellow"})
    return dashboard("secops-endpoint-identity", "Endpoint & Identity",
                     "Falcon sensor coverage and detections, removable media (USB writes and scans), Falcon Identity Protection risk, Entra ID risk/MFA and sign-in activity.", b,
                     help=ENDPOINT_IDENTITY_HELP)


# =====================================================================
#  3. Email & External exposure
# =====================================================================
EMAIL_EXTERNAL_HELP = {
    "Phishing (range)": "Check Point phishing events (including suspected) in the range.",
    "Malware (range)": "Check Point malware events (including suspected) in the range.",
    "Suspicious (range)": "Events Check Point marked suspicious rather than confirmed, in the range.",
    "DLP (range)": "Outbound data-loss-prevention matches in the range.",
    "Anomaly (range)": "Check Point anomaly events (unusual sending behaviour) in the range.",
    "High+ severity (range)": "Email events Check Point rated high or critical, in the range.",
    "Top sending domains (threats)": "Sender domains behind the most threat events, and how many sites they hit.",
    "Recent High+ email events": "High and critical email events in the range, newest first.",
    "Messages reported (range)": "Messages covered by DMARC aggregate reports in the range.",
    "DMARC pass": "Share of reported messages that passed DMARC.",
    "SPF aligned": "Share of reported messages whose SPF result aligned with the From domain.",
    "DKIM aligned": "Share of reported messages with an aligned DKIM signature.",
    "Rejected / quarantined": "Messages receivers rejected or quarantined because of our DMARC policy.",
    "DMARC pass rate by domain": "DMARC pass rate per day, per From domain.",
    "Domains": "Per From domain: volume, pass rates and what receivers did with failures.",
    "External assets": "Internet-facing assets Hadrian monitors (domains, IPs, services), excluding archived ones.",
    "Open external risks": "Risks Hadrian currently has open against our assets.",
    "Critical + High": "Open external risks rated critical or high.",
    "KEV on the internet": "Open external risks with a CVE on CISA's Known Exploited list.",
    "SLA breaches": "Open external risks older than their severity's SLA.",
    "Fixed (range)": "External risks Hadrian closed in the range (fixed, or no longer found).",
    "External risks trend": "Open external risks per day by severity, from the nightly snapshot.",
    "External asset inventory": "Every monitored internet-facing asset with its IPs, ports and technologies.",
}

def email_external():
    b = Builder()
    # event_type is split into genuine threats vs bulk mail classification
    # (see email_types.py) -- on real data, graymail+spam alone was ~97% of
    # all HEC events, which was swamping "Top sending domains (threats)"
    # with legitimate bulk senders (LinkedIn, Zoom, Canva notification
    # traffic) instead of actual phishing/malware senders.
    b.text(f"Check Point HEC email threats, DMARC alignment and the Hadrian external attack surface. {HOVER}", h=2)
    b.row("Email threats (Check Point HEC)", note="Security events Check Point raised on mail in the selected "
          "range: one email can raise more than one. Site = the recipient's domain.")
    for t, title in (("phishing", "Phishing"), ("malware", "Malware"), ("suspicious", "Suspicious"),
                      ("dlp", "DLP"), ("anomaly", "Anomaly")):
        b.stat(f"{title} (range)", f"SELECT count(*) FROM email_events WHERE site_label IN ($site) "
               f"AND event_type LIKE '%{t}%' AND {rng_ts('created_at')}", thresholds=NEUTRAL)
    b.stat("High+ severity (range)", f"SELECT count(*) FROM email_events WHERE site_label IN ($site) "
           f"AND severity IN ('critical','high') AND {rng_ts('created_at')}", thresholds=BAD_UP)
    b.stat("Not remediated", f"SELECT count(*) FROM email_events WHERE site_label IN ($site) "
           f"AND state IN ('new','detected','pending') AND event_type IN {sql_in(THREAT_EVENT_TYPES)} "
           f"AND {rng_ts('created_at')}", h=8, thresholds=BAD_UP,
           description="Threat events (not bulk/graymail) still in a detected/pending state -- not quarantined "
                        "or otherwise actioned.")
    # Widths below are picked to tile the 24-unit grid exactly (4+20=24,
    # 12+12=24) -- rebalance together if you add/remove a panel in this row.
    b.ts("Email events per day by type", f"""
        SELECT snapshot_date::timestamp AS time, event_type AS metric, sum(events) AS value
        FROM daily_email_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date')}
        GROUP BY 1, 2 ORDER BY 1""", w=20, h=8, stack=True, bars=True,
        description="Every HEC event type, including bulk mail classification (graymail/spam) -- see the "
                     "Top sending domains panels below for threats and bulk mail split apart.")
    b.table("Top sending domains (threats)", f"""
        SELECT sender_domain AS "Sender domain", count(*) AS "Events", count(DISTINCT site_label) AS "Sites hit"
        FROM email_events WHERE site_label IN ($site) AND {rng_ts('created_at')} AND sender_domain IS NOT NULL
        AND event_type IN {sql_in(THREAT_EVENT_TYPES)}
        GROUP BY 1 ORDER BY 2 DESC LIMIT 15""", w=12, h=8)
    b.table("Top sending domains (bulk / graymail)", f"""
        SELECT sender_domain AS "Sender domain", count(*) AS "Events", count(DISTINCT site_label) AS "Sites hit"
        FROM email_events WHERE site_label IN ($site) AND {rng_ts('created_at')} AND sender_domain IS NOT NULL
        AND event_type IN {sql_in(BULK_EVENT_TYPES)}
        GROUP BY 1 ORDER BY 2 DESC LIMIT 15""", w=12, h=8,
        description="Bulk mail classification and SaaS-usage visibility (graymail/spam/shadow IT) -- real "
                     "volume, not inherently malicious. Kept visible so it isn't just dropped from the data.")
    b.table("Recent High+ email events", f"""
        SELECT created_at AS "Time", event_type AS "Type", severity AS "Severity", state AS "State",
               site_label AS "Site", sender AS "Sender", recipient_domain AS "Recipient domain",
               action_taken AS "Action", link AS "Link"
        FROM email_events WHERE site_label IN ($site) AND severity IN ('critical','high') AND {rng_ts('created_at')}
        ORDER BY created_at DESC LIMIT 200""", h=9, overrides=[sev_cell()], links={"Link": "${__value.raw}"})

    b.row("DMARC (parsedmarc)", note="Aggregate reports from receiving mail servers about mail claiming to be "
          "from our domains. Low pass rates are usually a misconfigured legitimate sender, not spoofing.")
    b.stat("Messages reported (range)", f"SELECT sum(messages) FROM dmarc_daily WHERE site_label IN ($site) "
           f"AND {rng_d('report_date')}", thresholds=NEUTRAL)
    b.stat("DMARC pass", f"SELECT round(100.0 * sum(dmarc_pass) / NULLIF(sum(messages),0), 1) FROM dmarc_daily "
           f"WHERE site_label IN ($site) AND {rng_d('report_date')}", unit="percent", thresholds=GOOD_PCT, decimals=1)
    b.stat("SPF aligned", f"SELECT round(100.0 * sum(spf_aligned) / NULLIF(sum(messages),0), 1) FROM dmarc_daily "
           f"WHERE site_label IN ($site) AND {rng_d('report_date')}", unit="percent", thresholds=GOOD_PCT, decimals=1)
    b.stat("DKIM aligned", f"SELECT round(100.0 * sum(dkim_aligned) / NULLIF(sum(messages),0), 1) FROM dmarc_daily "
           f"WHERE site_label IN ($site) AND {rng_d('report_date')}", unit="percent", thresholds=GOOD_PCT, decimals=1)
    b.stat("Failed DMARC (range)", f"SELECT sum(messages - dmarc_pass) FROM dmarc_daily WHERE site_label IN ($site) "
           f"AND {rng_d('report_date')}", thresholds=NEUTRAL,
           description="Spoofing attempts AND your own misconfigured senders -- the source table below separates them.")
    b.stat("Rejected / quarantined", f"SELECT sum(rejected + quarantined) FROM dmarc_daily WHERE site_label IN ($site) "
           f"AND {rng_d('report_date')}", thresholds=NEUTRAL)
    b.ts("DMARC pass rate by domain", f"""
        SELECT report_date::timestamp AS time, header_from AS metric,
               round(100.0 * sum(dmarc_pass) / NULLIF(sum(messages),0), 1) AS value
        FROM dmarc_daily WHERE site_label IN ($site) AND {rng_d('report_date')}
        GROUP BY 1, 2 ORDER BY 1""", unit="percent")
    b.table("Domains", f"""
        SELECT header_from AS "Domain", site_label AS "Site", sum(messages) AS "Messages",
               round(100.0 * sum(dmarc_pass) / NULLIF(sum(messages),0), 1) AS "DMARC %",
               round(100.0 * sum(spf_aligned) / NULLIF(sum(messages),0), 1) AS "SPF %",
               round(100.0 * sum(dkim_aligned) / NULLIF(sum(messages),0), 1) AS "DKIM %",
               sum(rejected) AS "Rejected", sum(quarantined) AS "Quarantined", count(DISTINCT source_ip) AS "Sources"
        FROM dmarc_daily WHERE site_label IN ($site) AND {rng_d('report_date')}
        GROUP BY 1, 2 ORDER BY 3 DESC""", w=12, h=8,
            overrides=[thresh_bg("DMARC %", GOOD_PCT), thresh_bg("SPF %", GOOD_PCT), thresh_bg("DKIM %", GOOD_PCT)])
    b.table("Top failing sources", f"""
        SELECT source_ip AS "Source IP", coalesce(source_name, source_base_domain) AS "Sender",
               source_country AS "Country", string_agg(DISTINCT header_from, ', ') AS "Claimed domains",
               sum(messages - dmarc_pass) AS "Failed msgs", sum(messages) AS "Total msgs",
               bool_or(spf_aligned > 0 OR dkim_aligned > 0) AS "Partly aligned"
        FROM dmarc_daily WHERE site_label IN ($site) AND {rng_d('report_date')} AND messages > dmarc_pass
        GROUP BY 1, 2, 3 ORDER BY 5 DESC LIMIT 50""", w=12, h=8,
            description="'Partly aligned' sources are usually legitimate senders missing SPF/DKIM setup, not spoofers.")

    b.row("External attack surface (Hadrian)", note="What Hadrian sees from the internet. **Confirmed** = "
          "verified, unpatched-technology or infected-device risks; the rest are unverified detections.")
    b.stat("External assets", "SELECT count(*) FROM external_assets WHERE NOT retired AND site_label IN ($site)",
           thresholds=NEUTRAL)
    b.stat("Open external risks", "SELECT count(*) FROM fact_vuln_findings_current WHERE source = 'hadrian' "
           "AND site_label IN ($site)", thresholds=NEUTRAL)
    b.stat("Critical + High", "SELECT count(*) FROM fact_vuln_findings_current WHERE source = 'hadrian' "
           "AND severity IN ('critical','high') AND site_label IN ($site)", thresholds=BAD_UP)
    b.stat("KEV on the internet", "SELECT count(*) FROM fact_vuln_findings_current WHERE source = 'hadrian' "
           "AND has_kev AND site_label IN ($site)", thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
    b.stat("SLA breaches", "SELECT count(*) FROM fact_vuln_findings_current WHERE source = 'hadrian' "
           "AND sla_breach AND site_label IN ($site)", thresholds=BAD_UP)
    b.stat("Fixed (range)", f"SELECT count(*) FROM vuln_findings WHERE source = 'hadrian' AND state = 'FIXED' "
           f"AND site_label IN ($site) AND {rng_ts('last_fixed')}",
           thresholds=[{"color": "green", "value": None}])
    b.ts("External risks trend", f"""
        SELECT snapshot_date::timestamp AS time, sum(crit) AS "Critical", sum(high) AS "High",
               sum(medium) AS "Medium", sum(low) AS "Low"
        FROM daily_source_metrics WHERE source = 'hadrian' AND site_label IN ($site) AND {rng_d('snapshot_date')}
        GROUP BY 1 ORDER BY 1""", colors=SEV_COLORS, stack=True)
    b.table("Open external risks", """
        SELECT severity AS "Severity", title AS "Risk", hostname AS "Asset", site_label AS "Site",
               plugin_family AS "Category", CASE WHEN has_kev THEN 'KEV' END AS "KEV",
               round(age_days::numeric, 0) AS "Age (days)", sla_breach AS "SLA breach", solution AS "Fix"
        FROM fact_vuln_findings_current WHERE source = 'hadrian' AND site_label IN ($site)
        ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, age_days DESC
        LIMIT 300""", w=12, h=8, overrides=[sev_cell(), bg("Age (days)")])
    b.table("External asset inventory", """
        SELECT name AS "Asset", site_label AS "Site", asset_type AS "Type", array_to_string(ips, ', ') AS "IPs",
               array_to_string(ports, ', ') AS "Ports", array_to_string(technologies, ', ') AS "Technologies",
               last_seen AS "Last seen",
               (SELECT count(*) FROM fact_vuln_findings_current f WHERE f.source = 'hadrian'
                  AND f.source_asset_id = external_assets.asset_id) AS "Open risks"
        FROM external_assets WHERE NOT retired AND site_label IN ($site)
        ORDER BY "Open risks" DESC, name LIMIT 500""", h=9, overrides=[bg("Open risks")])
    return dashboard("secops-email-external", "Email & External Exposure",
                     "Check Point HEC email threats, DMARC alignment from parsedmarc, and Hadrian external attack surface.", b,
                     help=EMAIL_EXTERNAL_HELP)


# =====================================================================
#  4. SecOps Cyber Team Worklist
# =====================================================================
# "Assessed" = Falcon has ever returned a vulnerability record (any status)
# for the host. A fully patched, assessed host with no history would read
# as unassessed -- rare enough on this estate to be a fair proxy, and the
# API has no "assessed, zero findings" signal to do better with.
ACTIVE_HOSTS = ("SELECT * FROM assets WHERE source = 'falcon' AND NOT retired "
                "AND last_seen > now() - interval '7 days'")
# "Falcon has returned vulnerability data for this host", as an index probe on
# vuln_findings (source, source_asset_id, ...) per host: IN / NOT IN (SELECT DISTINCT
# ...) read the whole multi-GB table and took 2-45 s depending on what was cached.
ASSESSED_A = ("EXISTS (SELECT 1 FROM vuln_findings v WHERE v.source = 'falcon_spotlight' "
              "AND v.source_asset_id = a.source_asset_id)")
CONFIRMED = "('Verified','UnpatchedTechnology','InfectedDevice')"


WORKLIST_HELP = {
    "Active managed hosts (7d)": "Hosts with a Falcon sensor that checked in within 7 days.",
    "Active hosts not assessed": "Active hosts Falcon has returned no vulnerability data for: blind spots in the "
                                 "vulnerability figures.",
    "Coverage by site": "Per site: active hosts, how many are assessed, stale sensors and named machines missing a "
                        "sensor. Worst coverage first.",
    "Network devices by MAC vendor": "Sensorless devices seen only on the network, grouped by network-card maker -- "
                                     "a quick way to spot printers, phones, VMs and IoT.",
    "Confirmed risks open": "Open Hadrian risks that are verified, unpatched technology or infected devices.",
    "Infostealer infections": "Open Hadrian infostealer findings: credentials of ours seen in malware logs.",
    "External assets: not tag-matched or not recently seen": "Hadrian assets with no site tag (site guessed from "
                                                             "the domain) or not seen recently.",
    "Extra access accounts (enabled)": "Enabled second accounts in the shared domain used only for VPN or remote "
                                       "apps.",
    "Legacy (no VPN or remote-app group)": "Enabled shared-domain access accounts in neither a VPN nor a remote-app "
                                           "group: confirm and remove.",
    "By site": "Shared-domain access accounts per home site, by what they're used for.",
    "Accounts": "Every shared-domain access account; enabled and stale ones first.",
    "DMARC pass rate by sending domain (range)": "Per From domain in the range: volume, pass rate and failures.",
    "Identity: high": "Open Falcon Identity Protection detections rated critical or high.",
    "Identity: medium": "Open Falcon Identity Protection detections rated medium.",
    "Identity: low": "Open low-severity identity detections -- mostly unusual logins and bad-reputation IPs; "
                     "review in bulk rather than one by one.",
    "OverWatch open": "Open alerts from CrowdStrike's OverWatch threat hunters, any severity.",
    "Open identity detections by type": "Open identity detections (low and up) by detection name.",
    "Detections to triage": "Open identity detections rated medium and up, plus OverWatch alerts, oldest first. "
                            "Close them in the Falcon console; the next nightly pull clears them here.",
}

def worklist():
    b = Builder()
    b.text("Coverage gaps, data-quality problems and triage queues: the things to fix so every other dashboard "
           "and report tells the truth. Point-in-time (the time picker doesn't apply). Start with **Feed health**. "
           f"{HOVER}", h=2)

    b.row("Feed health")
    b.table("Collectors (latest run each)", """
        SELECT DISTINCT ON (collector) collector AS "Collector", status AS "Status",
               started_at AS "Last run", round(EXTRACT(EPOCH FROM finished_at - started_at))::int AS "Seconds",
               (SELECT max(started_at) FROM collector_runs c2 WHERE c2.collector = r.collector AND c2.status = 'ok')
                   AS "Last success",
               left(error, 200) AS "Error"
        FROM collector_runs r ORDER BY collector, started_at DESC""", h=7, overrides=[
        {"matcher": {"id": "byName", "options": "Status"},
         "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background"}},
                        {"id": "mappings", "value": [{"type": "value", "options": {
                            "ok": {"color": "green", "index": 0}, "partial": {"color": "orange", "index": 1},
                            "error": {"color": "red", "index": 2}, "running": {"color": "blue", "index": 3}}}]}]}],
        description="Disabled feeds keep their last run here. An 'error' row for a feed you rely on means its "
                    "panels and report figures are stale since 'Last success'.")

    open_det = "status IS DISTINCT FROM 'closed' AND site_label IN ($site)"
    b.row("Detections awaiting triage", note="Identity Protection detections live in the **child CID's** console, "
          "so they pile up unseen from the parent. Triage there (and OverWatch in the parent); the nightly digest "
          "on Pushover lists new ones.")
    b.stat("Identity: high", f"SELECT count(*) FROM security_alerts WHERE product = 'idp' "
           f"AND severity IN ('critical','high') AND {open_det}", w=6, thresholds=BAD_UP)
    b.stat("Identity: medium", f"SELECT count(*) FROM security_alerts WHERE product = 'idp' AND severity = 'medium' "
           f"AND {open_det}", w=6, thresholds=BAD_UP)
    b.stat("Identity: low", f"SELECT count(*) FROM security_alerts WHERE product = 'idp' AND severity = 'low' "
           f"AND {open_det}", w=6, thresholds=NEUTRAL)
    b.stat("OverWatch open", f"SELECT count(*) FROM security_alerts WHERE product = 'overwatch' AND {open_det}",
           w=6, thresholds=BAD_UP)
    b.table("Detections to triage", f"""
        SELECT created_at AS "Raised", severity AS "Severity",
               CASE product WHEN 'idp' THEN 'Identity' WHEN 'overwatch' THEN 'OverWatch' ELSE product END AS "From",
               name AS "Detection", user_name AS "User", hostname AS "Host", site_label AS "Site",
               floor(EXTRACT(EPOCH FROM now() - created_at) / 86400)::int AS "Days open", link AS "Link"
        FROM security_alerts
        WHERE {open_det} AND ((product = 'idp' AND severity IN ('critical','high','medium')) OR product = 'overwatch')
        ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END, created_at
        LIMIT 300""", w=16, h=9, overrides=[sev_cell(), bg("Days open")], links={"Link": "${__value.raw}"})
    b.bars("Open identity detections by type", f"""
        SELECT name AS "Detection", count(*) AS "Open" FROM security_alerts
        WHERE product = 'idp' AND severity <> 'info' AND {open_det} GROUP BY 1 ORDER BY 2 DESC LIMIT 12""",
           w=8, h=9, thresholds=[{"color": "orange", "value": None}])

    b.row("Endpoint coverage", note="**Active** = sensor seen in the last 7 days. **Assessed** = Falcon has "
          "returned vulnerability data for it. The gap is estate the vulnerability figures can't see.")
    b.stat("Active managed hosts (7d)", f"SELECT count(*) FROM ({ACTIVE_HOSTS}) a WHERE site_label IN ($site)",
           thresholds=NEUTRAL)
    b.stat("Vulnerability assessment coverage", f"""
        SELECT 100.0 * count(*) FILTER (WHERE {ASSESSED_A}) / NULLIF(count(*), 0)
        FROM ({ACTIVE_HOSTS}) a WHERE a.site_label IN ($site)""", unit="percent", decimals=1,
           thresholds=GOOD_PCT,
           description="Active managed hosts Falcon has returned vulnerability data for. Everything below 100% is "
                       "estate the vuln figures can't see.")
    b.stat("Active hosts not assessed", f"""
        SELECT count(*) FROM ({ACTIVE_HOSTS}) a
        WHERE a.site_label IN ($site) AND NOT {ASSESSED_A}""", thresholds=BAD_UP)
    b.stat("Stale sensors", """
        SELECT count(*) FROM assets WHERE source = 'falcon' AND NOT retired AND site_label IN ($site)
          AND last_seen <= now() - interval '7 days'""", thresholds=BAD_UP,
           description="Managed hosts silent for 7+ days: unprotected, unassessed, or decommissioned but not "
                       "removed from Falcon.")
    b.stat("Named machines missing a sensor", f"""
        SELECT count(*) FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND site_label IN ($site)
          AND discovery_class IN {dc.sql_in(dc.NAMED_MACHINES)}""", thresholds=BAD_UP,
           description="AD computer accounts in active use (servers, workstations, DCs) with no Falcon sensor -- "
                       "Discover's unmanaged list minus duplicates, service accounts, appliances and stale objects. "
                       "Network-only devices are counted separately below.")
    b.stat("Hosts in Ungrouped", """
        SELECT count(*) FROM assets WHERE NOT retired AND site_label = 'Ungrouped'""", thresholds=BAD_UP,
           description="Managed + unmanaged hosts no site rule matched (ignores the Site filter). Fix with "
                       "falcon_groups / ou_contains / hostname_regex in config.yaml.")
    b.table("Coverage by site", f"""
        SELECT s.site_label AS "Site", COALESCE(a.active,0) AS "Active hosts",
               COALESCE(a.assessed,0) AS "Assessed",
               round(100.0 * COALESCE(a.assessed,0) / NULLIF(a.active,0), 1) AS "% assessed",
               COALESCE(st.n,0) AS "Stale sensors", COALESCE(u.n,0) AS "Missing a sensor"
        FROM dim_site s
        LEFT JOIN (SELECT site_label, count(*) AS active,
                          count(*) FILTER (WHERE {ASSESSED_A}) AS assessed
                   FROM ({ACTIVE_HOSTS}) a GROUP BY 1) a ON a.site_label = s.site_label
        LEFT JOIN (SELECT site_label, count(*) n FROM assets WHERE source = 'falcon' AND NOT retired
                     AND last_seen <= now() - interval '7 days' GROUP BY 1) st ON st.site_label = s.site_label
        LEFT JOIN (SELECT site_label, count(*) n FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired
                     AND discovery_class IN {dc.sql_in(dc.NAMED_MACHINES)} GROUP BY 1) u ON u.site_label = s.site_label
        WHERE s.site_label IN ($site)
        ORDER BY "% assessed" NULLS LAST, "Active hosts" DESC""", w=10, h=10,
            overrides=[thresh_bg("% assessed", GOOD_PCT)])
    b.table("Active hosts with no vulnerability data", f"""
        SELECT a.hostname AS "Hostname", a.site_label AS "Site", a.product_type AS "Type",
               a.os_version AS "OS", a.sensor_version AS "Sensor", a.last_seen AS "Last seen",
               array_to_string(a.groups, ', ') AS "Host groups"
        FROM ({ACTIVE_HOSTS}) a
        WHERE a.site_label IN ($site) AND NOT {ASSESSED_A}
        ORDER BY a.site_label, a.hostname""", w=14, h=10,
            description="Compare sensor version, host groups and policy against assessed hosts to find what "
                        "Exposure Management isn't covering.")

    b.row("Missing endpoints")
    b.table("Stale sensors (silent 7+ days)", """
        SELECT hostname AS "Hostname", site_label AS "Site", product_type AS "Type", os_version AS "OS",
               last_seen AS "Last seen", (now()::date - last_seen::date) AS "Days silent",
               sensor_version AS "Sensor", array_to_string(ous, ' / ') AS "OU"
        FROM assets WHERE source = 'falcon' AND NOT retired AND site_label IN ($site)
          AND last_seen <= now() - interval '7 days'
        ORDER BY last_seen""", w=12, h=10, overrides=[bg("Days silent", "continuous-YlRd")],
            description="Decommissioned: remove from Falcon. Still in use: fix the sensor.")
    b.table("Unmanaged assets by class", f"""
        SELECT {dc.sql_case()} AS "Class", count(*) AS "Assets",
               CASE WHEN discovery_class IN {dc.sql_in(dc.ACTIONABLE)} THEN 'Yes' ELSE 'No' END AS "Needs a sensor?",
               {dc.sql_case(part=1)} AS "What to do"
        FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND site_label IN ($site)
        GROUP BY discovery_class
        ORDER BY "Needs a sensor?" DESC, "Assets" DESC""", w=12, h=10,
            description="Discover's unmanaged list, sorted into real machines without a sensor vs records that "
                        "aren't missing endpoints at all. Classified by collectors/falcon_hosts.py.")

    b.row("Missing sensors: named machines")
    b.table("Servers, DCs and workstations with no sensor (AD accounts in use)", f"""
        SELECT hostname AS "Hostname", {dc.sql_case()} AS "Class", site_label AS "Site",
               os_version AS "OS", last_seen AS "Last AD logon", description AS "AD description",
               ad_created::date AS "AD account created", domain AS "Domain"
        FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND site_label IN ($site)
          AND discovery_class IN {dc.sql_in(dc.NAMED_MACHINES)}
        ORDER BY CASE discovery_class WHEN 'domain_controller_no_sensor' THEN 1 WHEN 'server_no_sensor' THEN 2
                                      WHEN 'cloud_no_sensor' THEN 3 ELSE 4 END,
                 site_label, hostname""", h=12,
            description="Real, in-use Windows machines Falcon knows from AD but that have no sensor. Install one, "
                        "or record why not (vendor-supported clinical systems). A workstation here can also be a "
                        "renamed managed host -- check the name in Falcon first.")

    b.row("Missing sensors: devices seen on the network")
    b.table("Network devices with no sensor (passive discovery)", f"""
        SELECT COALESCE(hostname, '(no hostname)') AS "Hostname", {dc.sql_case()} AS "Class",
               COALESCE(mac_vendor, '?') AS "MAC vendor", array_to_string(ips, ', ') AS "IPs",
               array_to_string(mac_addresses, ', ') AS "MACs", site_label AS "Site", last_seen AS "Last seen"
        FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND site_label IN ($site)
          AND discovery_class IN ('vmware_nic', 'network_device')
        ORDER BY mac_vendor NULLS LAST, site_label, ips""", w=16, h=12,
            description="Seen talking on the network by managed sensors, no AD account. VMware MACs are VMs "
                        "without a sensor or ESXi management interfaces; Dell/Intel/HP/Lenovo NICs are often PCs; "
                        "printers, phones and IoT can't take a sensor.")
    b.table("Network devices by MAC vendor", """
        SELECT COALESCE(mac_vendor, '(unknown)') AS "MAC vendor", count(*) AS "Devices",
               count(*) FILTER (WHERE hostname IS NOT NULL) AS "With hostname"
        FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND site_label IN ($site)
          AND discovery_class IN ('vmware_nic', 'network_device')
        GROUP BY 1 ORDER BY 2 DESC""", w=8, h=12)

    b.row("Not missing endpoints (AD cleanup)", collapsed=True)
    b.table("Discover records that aren't unsensored machines", f"""
        SELECT hostname AS "Hostname", {dc.sql_case()} AS "Class", managed_twin AS "Managed host",
               site_label AS "Site", os_version AS "OS", ad_enabled AS "AD enabled", last_seen AS "Last AD logon",
               description AS "AD description"
        FROM assets WHERE source = 'falcon_unmanaged' AND NOT retired AND site_label IN ($site)
          AND discovery_class NOT IN {dc.sql_in(dc.ACTIONABLE)}
        ORDER BY discovery_class, hostname""", h=12,
            description="Duplicates of managed hosts (Falcon didn't link the AD object), service accounts, "
                        "appliances, cluster/listener names, disabled or stale AD accounts. No sensor needed; "
                        "disabled/stale ones are AD cleanup.")

    b.row("External attack surface (Hadrian) hygiene", note="Keeping Hadrian's picture accurate: assets "
          "without a site tag, and assets it hasn't seen lately (gone, or moved?).")
    b.stat("Potential risks to triage", f"""
        SELECT count(*) FROM vuln_findings WHERE source = 'hadrian' AND state IN ('OPEN','REOPENED')
          AND risk_type = 'Potential' AND site_label IN ($site)""", thresholds=BAD_UP,
           description="Unverified detections: confirm (promote) or dismiss in Hadrian.")
    b.stat("Confirmed risks open", f"""
        SELECT count(*) FROM vuln_findings WHERE source = 'hadrian' AND state IN ('OPEN','REOPENED')
          AND risk_type IN {CONFIRMED} AND site_label IN ($site)""", thresholds=BAD_UP)
    b.stat("Infostealer infections", """
        SELECT count(*) FROM vuln_findings WHERE source = 'hadrian' AND state IN ('OPEN','REOPENED')
          AND risk_type = 'InfectedDevice' AND site_label IN ($site)""", thresholds=BAD_UP)
    b.stat("Assets not matched by tag", """
        SELECT count(*) FROM external_assets WHERE source = 'hadrian' AND NOT retired
          AND site_matched_by <> 'hadrian_tag' AND site_label IN ($site)""", thresholds=BAD_UP,
           description="Tag these in Hadrian -- the collector also writes them to reports/hadrian-suggested-tags.csv.")
    b.stat("Assets not seen in 30 days", """
        SELECT count(*) FROM external_assets WHERE source = 'hadrian' AND NOT retired AND site_label IN ($site)
          AND (last_seen IS NULL OR last_seen < now() - interval '30 days')""", thresholds=BAD_UP,
           description="Hadrian hasn't observed these recently: gone, moved, or no longer reachable. Archive "
                       "(zzArchive) if abandoned.")
    b.stat("Reopened risks", """
        SELECT count(*) FROM vuln_findings WHERE source = 'hadrian' AND state = 'REOPENED'
          AND site_label IN ($site)""", thresholds=BAD_UP,
           description="Risks marked fixed that Hadrian found again -- the fix didn't hold.")
    b.table("Triage queue: potential risks by title", """
        SELECT title AS "Risk", max(plugin_family) AS "Category", max(vendor_priority) AS "Severity",
               count(*) AS "Open", count(DISTINCT site_label) AS "Sites", min(first_found)::date AS "Oldest"
        FROM vuln_findings WHERE source = 'hadrian' AND state IN ('OPEN','REOPENED') AND risk_type = 'Potential'
          AND site_label IN ($site)
        GROUP BY title
        ORDER BY CASE max(vendor_priority) WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3
                                           WHEN 'Low' THEN 4 ELSE 5 END, count(*) DESC""", w=14, h=10,
            overrides=[sev_cell("Severity")],
            description="Grouped so one decision clears many: confirm or dismiss each title across its assets.")
    b.table("Infostealer infections", """
        SELECT title AS "Infection", site_label AS "Site", hostname AS "Asset", first_found::date AS "First seen",
               state AS "State"
        FROM vuln_findings WHERE source = 'hadrian' AND state IN ('OPEN','REOPENED')
          AND risk_type = 'InfectedDevice' AND site_label IN ($site)
        ORDER BY first_found""", w=10, h=10,
            description="Compromised credentials harvested from infected devices. Reset the named accounts and "
                        "find the device. Not masked here -- this dashboard is for the cyber team.")
    b.table("External assets: not tag-matched or not recently seen", """
        SELECT name AS "Asset", asset_type AS "Type", site_label AS "Site", site_matched_by AS "Site from",
               last_seen AS "Last seen by Hadrian"
        FROM external_assets WHERE source = 'hadrian' AND NOT retired AND site_label IN ($site)
          AND (site_matched_by <> 'hadrian_tag' OR last_seen IS NULL OR last_seen < now() - interval '30 days')
        ORDER BY last_seen NULLS FIRST""", h=8)

    b.row("Identity site mapping")
    b.table("Identities in Ungrouped, by domain and OU", """
        SELECT COALESCE(domain, '(none)') AS "Domain",
               COALESCE(NULLIF(split_part(ou, ',', 1), ''), '(none)') AS "OU (first part)",
               count(*) AS "Identities", count(*) FILTER (WHERE enabled) AS "Enabled"
        FROM identity_entities WHERE NOT retired AND site_label = 'Ungrouped'
        GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 200""", w=12, h=10,
            description="Ignores the Site filter. Each row is a mapping rule waiting to be written: add the "
                        "domain or OU fragment to the right site in config.yaml.")
    b.table("Identities per site", """
        SELECT s.site_label AS "Site", count(e.entity_id) AS "Identities",
               count(e.entity_id) FILTER (WHERE e.enabled) AS "Enabled"
        FROM dim_site s LEFT JOIN identity_entities e ON e.site_label = s.site_label AND NOT e.retired
        GROUP BY 1 ORDER BY 2 DESC""", w=12, h=10,
            description="A site with far fewer identities than staff is a sign its accounts are landing in "
                        "Ungrouped (or another site).")

    b.row("Shared-domain access accounts (VPN / remote apps)")
    b.text("Second accounts other sites' staff have in the shared domain only for **VPN** (SSL-VPN groups) or "
           "**remote apps** (MANAD over RDS). **Legacy** = in neither kind of group: older provisioning to confirm "
           "and remove. Enabled + stale = unused: disable now. The rest go when VPN moves to Azure authentication. "
           "Rules: collectors.falcon_identity.access_domain.", h=3)
    ACC = "access_account IS NOT NULL AND NOT retired AND site_label IN ($site)"
    STALE = ("EXISTS (SELECT 1 FROM identity_risk_factors f WHERE f.source = e.source AND f.entity_id = e.entity_id "
             "AND f.factor_type = 'STALE_ACCOUNT')")
    b.stat("Extra access accounts (enabled)", f"SELECT count(*) FROM identity_entities e WHERE {ACC} AND enabled IS NOT FALSE",
           thresholds=BAD_UP)
    b.stat("Enabled but unused (stale)", f"SELECT count(*) FROM identity_entities e WHERE {ACC} AND enabled IS NOT FALSE "
           f"AND {STALE}", thresholds=BAD_UP, description="Quick win: nobody is using these -- disable.")
    b.stat("Legacy (no VPN or remote-app group)", f"SELECT count(*) FROM identity_entities e WHERE {ACC} "
           "AND enabled IS NOT FALSE AND access_account = 'legacy'", thresholds=BAD_UP)
    b.newline()
    b.table("By site", f"""
        SELECT site_label AS "Site",
               count(*) FILTER (WHERE access_account = 'vpn') AS "VPN",
               count(*) FILTER (WHERE access_account = 'rds') AS "Remote apps",
               count(*) FILTER (WHERE access_account = 'vpn+rds') AS "VPN + remote apps",
               count(*) FILTER (WHERE access_account = 'legacy') AS "Legacy",
               count(*) FILTER (WHERE enabled IS NOT FALSE) AS "Enabled",
               count(*) FILTER (WHERE enabled IS NOT FALSE AND {STALE}) AS "Enabled + stale"
        FROM identity_entities e WHERE {ACC}
        GROUP BY 1 ORDER BY "Enabled" DESC""", w=10, h=10, overrides=[bg("Enabled + stale", "continuous-YlRd")])
    b.table("Accounts", f"""
        SELECT display_name AS "Name", sam_account_name AS "Account", site_label AS "Site",
               access_account AS "Used for", CASE WHEN enabled IS FALSE THEN 'No' ELSE 'Yes' END AS "Enabled",
               CASE WHEN {STALE} THEN 'Yes' ELSE '' END AS "Stale",
               array_to_string(ARRAY(SELECT g FROM unnest(ad_groups) g
                                     WHERE g ~* '(vpn|manad|remote|terminal|rds|rdp)'), ', ') AS "Access groups"
        FROM identity_entities e WHERE {ACC}
        ORDER BY enabled IS FALSE, NOT {STALE}, site_label, display_name""", w=14, h=10)

    b.row("DMARC (parsedmarc)", collapsed=True)
    b.text("Populates once the **dmarc** collector is enabled and can reach the parsedmarc OpenSearch "
           "(`collectors.dmarc.opensearch_url` in config.yaml). Until then these panels are empty -- check "
           "**Feed health** above for its last error.", h=3)
    b.table("DMARC pass rate by sending domain (range)", f"""
        SELECT header_from AS "From domain", sum(messages) AS "Messages",
               round(100.0 * sum(dmarc_pass) / NULLIF(sum(messages), 0), 1) AS "Pass %",
               sum(quarantined) AS "Quarantined", sum(rejected) AS "Rejected"
        FROM dmarc_daily WHERE site_label IN ($site) AND {rng_d('report_date')}
        GROUP BY 1 ORDER BY "Pass %" NULLS LAST, 2 DESC""", w=12, h=9, overrides=[thresh_bg("Pass %", GOOD_PCT)])
    b.table("Top failing sources (range)", f"""
        SELECT header_from AS "From domain", COALESCE(source_name, source_base_domain, source_ip) AS "Source",
               source_country AS "Country", sum(messages - dmarc_pass) AS "Failing messages",
               bool_or(spf_aligned > 0) AS "Any SPF aligned", bool_or(dkim_aligned > 0) AS "Any DKIM aligned"
        FROM dmarc_daily WHERE site_label IN ($site) AND {rng_d('report_date')}
        GROUP BY 1, 2, 3 HAVING sum(messages - dmarc_pass) > 0 ORDER BY 4 DESC LIMIT 50""", w=12, h=9,
            description="Legitimate senders failing here need SPF/DKIM set up; unknown ones are spoofing.")

    return dashboard("secops-worklist", "SecOps Cyber Team Worklist",
                     "Coverage gaps, data quality and triage queues for the cyber team", b, help=WORKLIST_HELP)

# =====================================================================
#  5. Vulnerability Management
# =====================================================================
NIGHTLY = "As at the last nightly run (pre-computed by rollup_daily_metrics.py)."
CVSS_BG = thresh_bg("CVSS", [{"color": "yellow", "value": None}, {"color": "dark-yellow", "value": 4},
                             {"color": "orange", "value": 7}, {"color": "red", "value": 9}])
NVD_LINK = {"CVE": "https://nvd.nist.gov/vuln/detail/${__value.text}"}
SEV4 = {"Critical": "red", "High": "orange", "Medium": "dark-yellow", "Low": "yellow"}
SITE_SUMMARY = "FROM dash_vuln_site_summary WHERE site_label IN ($site)"


def week_change(table, expr):
    """Latest daily snapshot of `expr` minus the one 7 days before it (same days for every site)."""
    return f"""
        WITH latest AS (SELECT max(snapshot_date) AS d FROM {table}),
             hist AS (SELECT max(snapshot_date) AS d FROM {table}, latest WHERE snapshot_date::date <= latest.d::date - 7),
             now_v AS (SELECT {expr} AS v FROM {table}, latest WHERE site_label IN ($site) AND snapshot_date = latest.d),
             then_v AS (SELECT {expr} AS v FROM {table}, hist WHERE site_label IN ($site) AND snapshot_date = hist.d)
        SELECT (now_v.v - then_v.v) AS delta FROM now_v, then_v"""


VULN_HELP = {
    "Open findings": f"Open vulnerability findings (one per CVE per device, plus Hadrian's external risks). {NIGHTLY}",
    "Critical + high open": f"Open findings rated critical or high. {NIGHTLY}",
    "SLA breach rate": "Share of open findings older than their severity's SLA. Drops sharply whenever coverage "
                       f"expands, because new findings start at age zero -- read it with the breach count. {NIGHTLY}",
    "Share on CISA KEV": f"Share of open findings whose CVE CISA lists as actively exploited. {NIGHTLY}",
    "Remote + no-auth critical/high": "Open critical/high findings exploitable over the network with no credentials "
                                      f"and no user interaction: reachable by an attacker starting from nothing. {NIGHTLY}",
    "Remote + no-auth critical/high trend": "The same count per day, from the nightly snapshot.",
    "Open findings by severity": "Open findings per day by severity, from the nightly snapshot. Step changes are "
                                 "usually coverage (more devices assessed), not risk.",
    "Net change (opened − fixed)": "Findings opened minus fixed in the selected range, by the day each happened "
                                   "(as the exec reports count them; expired records and findings on newly assessed "
                                   "hosts aren't 'opened'). Positive = backlog growing.",
    "Opened vs remediated per day": "Findings first detected (up) and fixed (down) per day, from the nightly rollup. "
                                    "Opened = new findings on hosts already being assessed; newly assessed hosts = "
                                    "everything found on a host's first day of assessment (coverage, not new vulns).",
    "Open findings: change over 7 days": "Open findings now minus 7 days ago. Any rise is red.",
    "Critical + high: change over 7 days": "Open critical + high findings now minus 7 days ago.",
    "SLA breaches: change over 7 days": "Findings past SLA now minus 7 days ago: the count behind the rate, which "
                                        "can fall while breaches rise when coverage grows.",
    "SLA breach rate: change over 7 days": "Breach rate now minus 7 days ago, in percentage points: 10% -> 12% is "
                                           "+2 pts (not +20%).",
    "KEV share: change over 7 days": "Share of open findings on CISA KEV now minus 7 days ago, in percentage points.",
    "Critical SLA (days)": "Days a critical finding may stay open before it breaches (current policy).",
    "High SLA (days)": "Days a high finding may stay open before it breaches.",
    "Medium SLA (days)": "Days a medium finding may stay open before it breaches.",
    "Low SLA (days)": "Days a low finding may stay open before it breaches.",
    "SLA breaches by site and risk (latest snapshot)": "Per site and risk band: open findings, how many are past SLA, "
                                                       "and the rate. Worst rate first.",
    "SLA breach rate by risk band": "Breach rate per day for each risk band, from the nightly snapshot.",
    "Open KEV findings": "Open findings whose CVE is on CISA's Known Exploited list (latest snapshot).",
    "Ransomware-linked": "Open KEV findings CISA notes are used in ransomware campaigns.",
    "Past CISA due date": "Open KEV findings past the remediation date CISA set when listing them.",
    "Open KEV trend": "Open KEV and ransomware-linked findings per day.",
    "Open KEV findings by CVE (soonest due first)": "One row per KEV CVE: what it's in, how many findings, devices "
                                                    f"and sites, and the oldest. CVE links to NVD. {NIGHTLY}",
    "High EPSS, not yet KEV": "Open findings with EPSS of 50% or more (likely to be exploited within 30 days) that "
                              "aren't on KEV yet (latest snapshot).",
    "Average / max EPSS": "Average and highest EPSS across open findings per day.",
    "NVD enrichment coverage": "Open CVE-backed findings with a CVSS vector (from the vendor, or looked up from NVD "
                               f"when the vendor gave none). {NIGHTLY}",
    "Likely next: high EPSS, not yet KEV (by CVE)": "One row per CVE with EPSS 50%+ not yet on KEV. Priority = "
                                                    "severity-weighted findings, scaled up by EPSS, plus remote/no-auth "
                                                    f"exposure. {NIGHTLY}",
    "Worst devices (by risk score)": "Devices ranked by severity counts plus KEV and remote/no-auth bonuses. A "
                                     f"ranking, not a unit. {NIGHTLY}",
    "Top 10 patches to deploy (all sites)": "One row per fix (e.g. one browser update, or one Hadrian risk). Priority "
                                            "= devices affected + severity + remote/no-auth + KEV + EPSS: the single "
                                            f"fixes that close the most, worst risk. Not filtered by Site. {NIGHTLY}",
    "Average days to remediate by severity": "Average days from first detected to fixed, for findings fixed each "
                                             "day.",
    "Fixed within SLA by severity (range)": "Share of findings fixed in the range that were fixed within their SLA.",
    "Top products by open findings (latest snapshot)": "Open findings per product, by severity.",
}


def vuln():
    b = Builder()
    b.text("Endpoint (Falcon Exposure Management) and external (Hadrian) vulnerabilities. Current figures are as at "
           f"the last nightly run; trends come from the daily snapshots. {HOVER}", h=2)

    b.row("Executive summary", note="Severity runs red (critical) to orange (high) to amber (medium) to yellow (low); "
          "green only ever means good news. A coverage jump raises counts and lowers rates for a few weeks.")
    b.stat("Open findings", f'SELECT COALESCE(sum(n), 0) AS "Open Findings" {SITE_SUMMARY}', w=6,
           thresholds=NEUTRAL)
    b.stat("Critical + high open", "SELECT COALESCE(sum(n) FILTER (WHERE severity IN ('critical','high')), 0) "
           f'AS "Critical + High" {SITE_SUMMARY}', w=6,
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}, {"color": "red", "value": 25}])
    b.stat("SLA breach rate", "SELECT round(100.0 * sum(n) FILTER (WHERE sla_breach) / NULLIF(sum(n),0), 1) "
           f'AS "SLA Breach Rate" {SITE_SUMMARY}', w=6, unit="percent",
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 10}, {"color": "red", "value": 25}])
    b.stat("Share on CISA KEV", "SELECT round(100.0 * sum(n) FILTER (WHERE has_kev) / NULLIF(sum(n),0), 2) "
           f'AS "Active KEV %" {SITE_SUMMARY}', w=6, unit="percent", decimals=2,
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 5}, {"color": "red", "value": 15}])
    b.stat("Remote + no-auth critical/high", "SELECT COALESCE(sum(n) FILTER (WHERE severity IN ('critical','high') "
           f'AND is_remote_no_auth), 0) AS "Remote+NoAuth Crit/High" {SITE_SUMMARY}', w=6, h=8,
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}, {"color": "red", "value": 25}])
    b.ts("Remote + no-auth critical/high trend", f"""
        SELECT snapshot_date::timestamp AS time, sum(remote_crit) AS "Remote Critical", sum(remote_high) AS "Remote High"
        FROM daily_site_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date::date')}
        GROUP BY snapshot_date ORDER BY time""", w=18, colors={"Remote Critical": "red", "Remote High": "orange"})
    b.ts("Open findings by severity", f"""
        SELECT snapshot_date::timestamp AS time, sum(crit) AS "Critical", sum(high) AS "High",
               sum(medium) AS "Medium", sum(low) AS "Low"
        FROM daily_site_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date::date')}
        GROUP BY snapshot_date ORDER BY time""", w=24, colors=SEV4, stack=True)
    b.stat("Net change (opened − fixed)", f"""
        SELECT (COALESCE(sum(opened - opened_new_host),0) - COALESCE(sum(fixed),0))::int AS "Net Change"
        FROM daily_vuln_flow_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date')}""", w=6, h=8,
           thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
    b.ts("Opened vs remediated per day", f"""
        SELECT snapshot_date::timestamp AS time, sum(opened - opened_new_host) AS "Opened",
               sum(opened_new_host) AS "Newly assessed hosts", -sum(fixed) AS "Closed"
        FROM daily_vuln_flow_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date')}
        GROUP BY 1 ORDER BY 1""", w=18, bars=True, stack=True,
         colors={"Opened": "red", "Newly assessed hosts": "blue", "Closed": "green"})

    b.row("Change over 7 days", collapsed=True, note="Today's figure minus the figure 7 days ago. Rates are in "
          "percentage points (**pts**): 10% -> 12% is +2 pts, not +20%. Any rise is red. Straight after a coverage "
          "jump, trust the counts over the rates.")
    b.delta("Open findings: change over 7 days", week_change("daily_site_metrics", "coalesce(sum(total),0)"), w=5)
    b.delta("Critical + high: change over 7 days",
            week_change("daily_site_metrics", "coalesce(sum(crit)+sum(high),0)"), w=5)
    b.delta("SLA breaches: change over 7 days", week_change("daily_sla_metrics", "coalesce(sum(sla_breaches),0)"), w=5)
    b.delta("SLA breach rate: change over 7 days", week_change(
        "daily_sla_metrics", "round(100.0*sum(sla_breaches)/NULLIF(sum(total_vulns),0),1)"), w=5, suffix=" pts",
        decimals=1)
    b.delta("KEV share: change over 7 days", week_change(
        "daily_kev_metrics", "round(100.0*sum(kev_open_total)/NULLIF(sum(kev_open_total)+sum(non_kev_open_total),0),2)"),
        w=4, suffix=" pts", decimals=2)

    b.row("SLA compliance", collapsed=True, note="A finding breaches once its age since first detected exceeds its "
          "severity's SLA -- the policy is in the four tiles below, so check them rather than assuming.")
    for sev, color in (("critical", "red"), ("high", "orange"), ("medium", "dark-yellow"), ("low", "yellow")):
        b.stat(f"{sev.title()} SLA (days)", f"SELECT threshold_days AS \"SLA (days)\" FROM sla_policy WHERE severity = '{sev}'",
               w=6, h=3, color=color)
    b.table("SLA breaches by site and risk (latest snapshot)", """
        SELECT site_label AS "Site", risk AS "Risk", total_vulns AS "Total", sla_breaches AS "Breaches",
               round(100.0 * sla_breaches / NULLIF(total_vulns,0), 1) AS "Breach Rate %"
        FROM daily_sla_metrics WHERE site_label IN ($site)
          AND snapshot_date = (SELECT max(snapshot_date) FROM daily_sla_metrics)
        ORDER BY "Breach Rate %" DESC""", w=12, h=8)
    b.ts("SLA breach rate by risk band", f"""
        SELECT snapshot_date::timestamp AS time, risk AS metric,
               round(100.0 * sum(sla_breaches) / NULLIF(sum(total_vulns),0), 1) AS value
        FROM daily_sla_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date::date')}
        GROUP BY snapshot_date, risk ORDER BY time""", unit="percent", colors=SEV4)

    b.row("CISA KEV exposure", collapsed=True, note="**KEV** = CISA has confirmed the CVE is being exploited in the "
          "wild right now: the highest-priority signal here. **Past due** = beyond the fix-by date CISA set.")
    latest_kev = "snapshot_date = (SELECT max(snapshot_date) FROM daily_kev_metrics)"
    for title, col, alias in (("Open KEV findings", "kev_open_total", "Open KEV"),
                              ("Ransomware-linked", "kev_ransomware_total", "Ransomware-Flagged"),
                              ("Past CISA due date", "kev_past_due_total", "Past Due")):
        b.stat(title, f'SELECT sum({col}) AS "{alias}" FROM daily_kev_metrics WHERE site_label IN ($site) AND {latest_kev}',
               w=8, thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
    b.ts("Open KEV trend", f"""
        SELECT snapshot_date::timestamp AS time, sum(kev_open_total) AS "Open KEV",
               sum(kev_ransomware_total) AS "Ransomware-Flagged"
        FROM daily_kev_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date::date')}
        GROUP BY snapshot_date ORDER BY time""", w=24, colors={"Open KEV": "red", "Ransomware-Flagged": "dark-red"})
    b.table("Open KEV findings by CVE (soonest due first)", """
        SELECT kev_cve_id AS "CVE",
               mode() WITHIN GROUP (ORDER BY product_family) FILTER (WHERE product_family IS NOT NULL) AS "Application",
               round(max(cvss_score)::numeric,1) AS "CVSS", max(kev_due_date) AS "KEV Due",
               max(kev_ransomware_use) AS "Ransomware Use", count(*) AS "Findings",
               count(DISTINCT source_asset_id) AS "Assets", count(DISTINCT site_label) AS "Sites",
               count(*) FILTER (WHERE severity='critical') AS "Crit", count(*) FILTER (WHERE severity='high') AS "High",
               count(*) FILTER (WHERE severity='medium') AS "Med", count(*) FILTER (WHERE severity='low') AS "Low",
               round(max(age_days)::numeric,1) AS "Oldest (days)"
        FROM dash_vuln_kev_epss WHERE has_kev AND site_label IN ($site)
        GROUP BY kev_cve_id ORDER BY "KEV Due" ASC NULLS LAST, "Crit" DESC LIMIT 100""", h=10,
            overrides=[CVSS_BG], links=NVD_LINK)

    b.row("Predictive risk (EPSS)", collapsed=True, note="**EPSS** (FIRST.org) = the probability a CVE is exploited "
          "in the next 30 days, updated daily. Predictive, the complement to KEV: high EPSS but not yet KEV is the "
          "'likely next' list.")
    b.stat("High EPSS, not yet KEV", """
        SELECT sum(high_epss_non_kev_total) AS "High-EPSS Not Yet KEV" FROM daily_epss_metrics
        WHERE site_label IN ($site) AND snapshot_date = (SELECT max(snapshot_date) FROM daily_epss_metrics)""", w=6, h=8,
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}, {"color": "red", "value": 25}])
    b.ts("Average / max EPSS", f"""
        SELECT snapshot_date::timestamp AS time, avg(avg_epss) AS "Avg EPSS", max(max_epss) AS "Max EPSS"
        FROM daily_epss_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date::date')}
        GROUP BY snapshot_date ORDER BY time""", w=18, unit="percentunit", minmax=(0, 1))
    b.table("NVD enrichment coverage", "SELECT * FROM dash_nvd_coverage", h=4)
    b.table("Likely next: high EPSS, not yet KEV (by CVE)", """
        SELECT epss_cve_id AS "CVE",
               mode() WITHIN GROUP (ORDER BY product_family) FILTER (WHERE product_family IS NOT NULL) AS "Application",
               round(max(cvss_score)::numeric,1) AS "CVSS", round((epss_score*100)::numeric,1) AS "EPSS %",
               round((epss_percentile*100)::numeric,1) AS "Percentile", count(*) AS "Findings",
               count(DISTINCT source_asset_id) AS "Assets", count(DISTINCT site_label) AS "Sites",
               count(*) FILTER (WHERE severity='critical') AS "Crit", count(*) FILTER (WHERE severity='high') AS "High",
               count(*) FILTER (WHERE severity='medium') AS "Med", count(*) FILTER (WHERE severity='low') AS "Low",
               count(*) FILTER (WHERE is_remote_no_auth) AS "Remote/No-Auth",
               round(max(age_days)::numeric,1) AS "Oldest (days)",
               ((count(*) FILTER (WHERE severity='critical')*10 + count(*) FILTER (WHERE severity='high')*5
                 + count(*) FILTER (WHERE severity='medium')*2 + count(*) FILTER (WHERE severity='low')*1)
                + ROUND((count(*) FILTER (WHERE severity='critical')*10 + count(*) FILTER (WHERE severity='high')*5
                         + count(*) FILTER (WHERE severity='medium')*2 + count(*) FILTER (WHERE severity='low')*1)
                        * epss_score)
                + (count(*) FILTER (WHERE is_remote_no_auth) * 5))::int AS "Priority"
        FROM dash_vuln_kev_epss WHERE site_label IN ($site) AND epss_score >= 0.5 AND NOT has_kev
        GROUP BY epss_cve_id, epss_score, epss_percentile ORDER BY "Priority" DESC LIMIT 100""", h=10,
            overrides=[CVSS_BG], links=NVD_LINK)

    b.row("Worst devices", collapsed=True, note="Devices ranked by risk score: severity counts plus a KEV bonus plus "
          "a remote/no-auth bonus. A ranking tool, not an absolute unit.")
    b.table("Worst devices (by risk score)", """
        SELECT hostname AS "Host", site_label AS "Site",
               CASE source WHEN 'hadrian' THEN 'External' ELSE 'Endpoint' END AS "Source", asset_type AS "Type",
               open_critical AS "Crit", open_high AS "High", open_medium AS "Med", open_low AS "Low",
               open_kev_count AS "KEV", open_remote_no_auth AS "Remote/No-Auth",
               round(oldest_open_finding_age_days::numeric,1) AS "Oldest (days)", risk_score AS "Risk Score"
        FROM dash_asset_risk WHERE site_label IN ($site) ORDER BY risk_score DESC LIMIT 25""", h=10,
            overrides=[bg("Risk Score")])

    b.row("Top patches to deploy", collapsed=True, note="Which single fixes close the most, worst risk across the "
          "region -- not the same as the biggest raw counts. Not filtered by Site.")
    b.table("Top 10 patches to deploy (all sites)", """
        SELECT title AS "Fix", CASE source WHEN 'hadrian' THEN 'External' ELSE 'Endpoint' END AS "Source",
               affected_sites AS "Sites", product_family AS "Product Family", affected_assets AS "Assets",
               open_findings AS "Findings", crit AS "Crit", high AS "High", medium AS "Med", low AS "Low",
               remote_no_auth_count AS "Remote/No-Auth", CASE WHEN has_kev THEN 'Yes' ELSE 'No' END AS "KEV",
               round((COALESCE(max_epss,0)*100)::numeric,1) AS "Max EPSS %", priority_score AS "Priority"
        FROM dash_patch_impact ORDER BY priority_score DESC LIMIT 10""", h=10, overrides=[bg("Priority")])

    b.row("Time to remediate", collapsed=True, note="How long fixes take: days from first detected to fixed, for "
          "findings fixed in the period, and the share fixed inside their SLA.")
    b.ts("Average days to remediate by severity", f"""
        SELECT snapshot_date::timestamp AS time, severity AS metric, avg(avg_remediation_days) AS value
        FROM daily_mttr_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date::date')}
        GROUP BY snapshot_date, severity ORDER BY time""", w=14, unit="d",
         colors={"critical": "red", "high": "orange", "medium": "dark-yellow", "low": "yellow"})
    b.bars("Fixed within SLA by severity (range)", f"""
        SELECT severity AS "Severity", round(100.0 * sum(sla_compliant_count) / NULLIF(sum(fixed_count),0), 1)
               AS "SLA Compliance %"
        FROM daily_mttr_metrics WHERE site_label IN ($site) AND {rng_d('snapshot_date::date')}
        GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END""",
           w=10, unit="percent", minmax=(0, 100),
           thresholds=[{"color": "red", "value": None}, {"color": "orange", "value": 60}, {"color": "green", "value": 85}])

    b.row("Products", collapsed=True, note="Open findings by product from the latest snapshot -- where the backlog "
          "actually sits.")
    b.table("Top products by open findings (latest snapshot)", """
        SELECT product AS "Product", vendor AS "Vendor", product_family AS "Family", sum(open_crit) AS "Crit",
               sum(open_high) AS "High", sum(open_medium) AS "Med", sum(open_low) AS "Low", sum(open_total) AS "Total"
        FROM daily_product_metrics WHERE site_label IN ($site)
          AND snapshot_date = (SELECT max(snapshot_date) FROM daily_product_metrics)
        GROUP BY product, vendor, product_family ORDER BY "Total" DESC LIMIT 15""", h=10)
    return dashboard("vuln-mgmt-core", "Vulnerability Management",
                     "Site/severity trending, SLA compliance, CISA KEV exposure, worst-devices hit list and MTTR across "
                     "every vulnerability source in vuln_findings (Falcon Exposure Management endpoints + Hadrian "
                     "external).", b, help=VULN_HELP, tags=("kev", "mttr", "vuln-management"), time_from="now-90d")


def main():
    for fname, fn in (("secops-overview.json", overview),
                      ("secops-endpoint-identity.json", endpoint_identity),
                      ("secops-email-external.json", email_external),
                      ("secops-worklist.json", worklist),
                      ("vuln-dashboard.json", vuln)):
        path = os.path.join(HERE, fname)
        with open(path, "w") as f:
            json.dump(fn(), f, indent=2)
            f.write("\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
