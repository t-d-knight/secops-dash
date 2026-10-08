#!/usr/bin/env python3
"""
Dashboard-as-code for the four non-vuln SecOps dashboards. Edit the panel
definitions here and re-run; the generated JSON is committed alongside so it
can be imported without running anything.

  python3 grafana/build_dashboards.py          # writes grafana/secops-*.json

Every dashboard shares the `secops` tag (they link to each other, keeping
$site and the time range) and the same conventions as vuln-dashboard.json:
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

    def row(self, title, collapsed=False):
        self.newline()
        r = {"id": self._id(), "type": "row", "title": title, "collapsed": collapsed,
             "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1}, "panels": []}
        self.panels.append(r)
        self.current_row = r
        self.y += 1
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

    def stat(self, title, sql, w=4, h=4, unit="short", thresholds=None, description=None, decimals=None):
        d = {"unit": unit}
        if decimals is not None:
            d["decimals"] = decimals
        if thresholds:
            d["thresholds"] = {"mode": "absolute", "steps": thresholds}
            d["color"] = {"mode": "thresholds"}
        return self._panel("stat", title, sql, w, h, defaults=d, description=description,
                           options={"reduceOptions": {"calcs": ["lastNotNull"]},
                                    "colorMode": "value" if thresholds else "none", "graphMode": "none"})

    def ts(self, title, sql, w=12, h=8, unit="short", colors=None, stack=False, bars=False, description=None):
        custom = {"fillOpacity": 15}
        if stack:
            custom["stacking"] = {"mode": "normal"}
        if bars:
            custom.update({"drawStyle": "bars", "fillOpacity": 80})
        ov = [{"matcher": {"id": "byName", "options": n},
               "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]}
              for n, c in (colors or {}).items()]
        return self._panel("timeseries", title, sql, w, h, fmt="time_series",
                           defaults={"unit": unit, "custom": custom}, overrides=ov, description=description,
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


def dashboard(uid, title, description, b: Builder):
    return {
        "__inputs": [{"name": "DS_POSTGRESQL", "label": "PostgreSQL",
                      "description": "Postgres datasource pointing at the secops_dashboard database",
                      "type": "datasource", "pluginId": "postgres", "pluginName": "PostgreSQL"}],
        "__requires": [{"type": "grafana", "id": "grafana", "name": "Grafana", "version": "10.0.0"},
                       {"type": "datasource", "id": "postgres", "name": "PostgreSQL", "version": "1.0.0"}],
        "id": None, "uid": uid, "title": title, "description": description,
        "tags": ["secops"], "timezone": "browser", "schemaVersion": 39, "version": 1,
        "editable": True, "graphTooltip": 1, "refresh": "1h",
        "time": {"from": "now-30d", "to": "now"}, "timepicker": {},
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


# =====================================================================
#  1. SecOps Overview
# =====================================================================
def overview():
    b = Builder()
    b.text(
        "### SecOps Overview\n"
        "One row per site across every feed. **Vulns** = Falcon Exposure Management (endpoints) + Hadrian "
        "(external), open and seen in the last 30 days. **Alerts** = Falcon detections not yet closed. "
        "**Identity** = Falcon Identity Protection high-risk accounts + Entra ID users at risk. "
        "**Email** = Check Point HEC threats in the selected range. **DMARC** = share of mail claiming the "
        "site's domains that passed DMARC. Drill into the linked dashboards (top right) for detail. "
        "If a number looks too good, check **Data freshness** at the bottom first.", h=4)

    b.row("Posture at a glance")
    b.stat("Open Crit + High vulns",
           "SELECT count(*) FROM fact_vuln_findings_current WHERE site_label IN ($site) "
           "AND severity IN ('critical','high') AND last_found >= now() - interval '30 days'",
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}, {"color": "red", "value": 500}])
    b.stat("Open KEV findings",
           "SELECT count(*) FROM fact_vuln_findings_current WHERE site_label IN ($site) AND has_kev "
           "AND last_found >= now() - interval '30 days'", thresholds=BAD_UP)
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

    b.row("Site scorecard")
    b.table("Site scorecard", """
        WITH v AS (
            SELECT site_label,
                   count(*) FILTER (WHERE severity IN ('critical','high') AND source <> 'hadrian') AS ep_ch,
                   count(*) FILTER (WHERE severity IN ('critical','high') AND source = 'hadrian') AS ext_ch,
                   count(*) FILTER (WHERE has_kev) AS kev,
                   count(*) FILTER (WHERE sla_breach) AS sla
            FROM fact_vuln_findings_current WHERE last_found >= now() - interval '30 days' GROUP BY 1),
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

    b.row("Trends")
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

    b.row("Data freshness & site mapping", collapsed=False)
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
                     "Cross-feed security posture per site: vulns, detections, identity, email, DMARC, coverage.", b)


# =====================================================================
#  2. Endpoint & Identity
# =====================================================================
def endpoint_identity():
    b = Builder()
    b.row("Endpoint coverage (Falcon)")
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

    b.row("Detections (Falcon alerts)")
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

    b.row("Identity risk (Falcon Identity Protection)")
    b.stat("High-risk accounts", "SELECT count(*) FROM identity_entities WHERE NOT retired AND risk_severity = 'high' "
           "AND site_label IN ($site)", thresholds=BAD_UP)
    b.stat("Medium-risk accounts", "SELECT count(*) FROM identity_entities WHERE NOT retired AND risk_severity = 'medium' "
           "AND site_label IN ($site)", thresholds=NEUTRAL)
    b.stat("Enabled, password > 1 year", "SELECT count(*) FROM identity_entities WHERE NOT retired AND enabled "
           "AND password_last_change < now() - interval '365 days' AND site_label IN ($site)", thresholds=BAD_UP)
    b.bars("Accounts by risk factor", """
        SELECT f.factor_type AS "Factor", count(DISTINCT f.entity_id) AS "Accounts"
        FROM identity_risk_factors f JOIN identity_entities e ON e.source = f.source AND e.entity_id = f.entity_id
        WHERE NOT e.retired AND e.site_label IN ($site) GROUP BY 1 ORDER BY 2 DESC LIMIT 15""", w=12, h=8,
           thresholds=[{"color": "orange", "value": None}])
    b.ts("Risk factor trend", f"""
        SELECT snapshot_date::timestamp AS time, replace(metric, 'factor:', '') AS metric, sum(value) AS value
        FROM daily_identity_metrics WHERE metric LIKE 'factor:%' AND site_label IN ($site) AND {rng_d('snapshot_date')}
        GROUP BY 1, 2 ORDER BY 1""", w=12)
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

    b.row("Entra ID")
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
                     "Falcon sensor coverage and detections, Falcon Identity Protection risk, Entra ID risk/MFA and sign-in activity.", b)


# =====================================================================
#  3. Email & External exposure
# =====================================================================
def email_external():
    b = Builder()
    # event_type is split into genuine threats vs bulk mail classification
    # (see email_types.py) -- on real data, graymail+spam alone was ~97% of
    # all HEC events, which was swamping "Top sending domains (threats)"
    # with legitimate bulk senders (LinkedIn, Zoom, Canva notification
    # traffic) instead of actual phishing/malware senders.
    b.row("Email threats (Check Point HEC)")
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

    b.row("DMARC (parsedmarc)")
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

    b.row("External attack surface (Hadrian)")
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
                     "Check Point HEC email threats, DMARC alignment from parsedmarc, and Hadrian external attack surface.", b)


# =====================================================================
#  4. SecOps Cyber Team Worklist
# =====================================================================
# "Assessed" = Falcon has ever returned a vulnerability record (any status)
# for the host. A fully patched, assessed host with no history would read
# as unassessed -- rare enough on this estate to be a fair proxy, and the
# API has no "assessed, zero findings" signal to do better with.
ACTIVE_HOSTS = ("SELECT * FROM assets WHERE source = 'falcon' AND NOT retired "
                "AND last_seen > now() - interval '7 days'")
ASSESSED = "SELECT DISTINCT source_asset_id FROM vuln_findings WHERE source = 'falcon_spotlight'"
CONFIRMED = "('Verified','UnpatchedTechnology','InfectedDevice')"


def worklist():
    b = Builder()
    b.text(
        "### Cyber Team Worklist\n"
        "Coverage gaps, data-quality problems and triage queues -- the things to fix so every other "
        "dashboard and report is telling the truth. Point-in-time (the time picker doesn't apply), "
        "filtered by **Site**. Start with **Feed health**: a failing feed makes everything downstream stale.",
        h=3)

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

    b.row("Endpoint coverage")
    b.stat("Active managed hosts (7d)", f"SELECT count(*) FROM ({ACTIVE_HOSTS}) a WHERE site_label IN ($site)",
           thresholds=NEUTRAL)
    b.stat("Vulnerability assessment coverage", f"""
        SELECT 100.0 * count(*) FILTER (WHERE a.source_asset_id IN ({ASSESSED})) / NULLIF(count(*), 0)
        FROM ({ACTIVE_HOSTS}) a WHERE a.site_label IN ($site)""", unit="percent", decimals=1,
           thresholds=GOOD_PCT,
           description="Active managed hosts Falcon has returned vulnerability data for. Everything below 100% is "
                       "estate the vuln figures can't see.")
    b.stat("Active hosts not assessed", f"""
        SELECT count(*) FROM ({ACTIVE_HOSTS}) a
        WHERE a.site_label IN ($site) AND a.source_asset_id NOT IN ({ASSESSED})""", thresholds=BAD_UP)
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
                          count(*) FILTER (WHERE source_asset_id IN ({ASSESSED})) AS assessed
                   FROM ({ACTIVE_HOSTS}) x GROUP BY 1) a ON a.site_label = s.site_label
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
        WHERE a.site_label IN ($site) AND a.source_asset_id NOT IN ({ASSESSED})
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

    b.row("External attack surface (Hadrian) hygiene")
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
                     "Coverage gaps, data quality and triage queues for the cyber team", b)


def main():
    for fname, fn in (("secops-overview.json", overview),
                      ("secops-endpoint-identity.json", endpoint_identity),
                      ("secops-email-external.json", email_external),
                      ("secops-worklist.json", worklist)):
        path = os.path.join(HERE, fname)
        with open(path, "w") as f:
            json.dump(fn(), f, indent=2)
            f.write("\n")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
