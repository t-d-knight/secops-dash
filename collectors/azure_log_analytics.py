#!/usr/bin/env python3
"""
Azure Monitor Log Analytics (Sentinel / diagnostic-settings workspaces)
-> azure_log_metrics.

Rather than copying millions of raw sign-in rows into Postgres, each
configured KQL query aggregates server-side and returns a small table with
this contract:

    day        datetime   -- bucket (startofday)
    key        string     -- what to resolve a site from (see key_type)
    dimension  string     -- optional breakdown, e.g. "success"/"failure"
    value      real/long  -- the number

key_type tells the resolver what `key` is: email_domain | upn | ip |
hostname | ad_domain. Values are summed per (day, query, site, dimension),
and every run recomputes the whole lookback window, so late-arriving logs
are picked up. Add any query you like in config.yaml -- no code change.

Permissions: the app needs "Log Analytics Reader" (or Reader) on each
workspace. {lookback_days} in a query is substituted.
"""
import datetime as dt
from collections import defaultdict
from typing import Any, Dict

from collectors.base import RunContext, parse_ts
from collectors.msgraph import AzureApp
from http_client import raise_for_status
from site_resolver import SiteContext, email_domain

NAME = "azure_log_analytics"
SCOPE = "https://api.loganalytics.io/.default"


def _ctx_for(key: str, key_type: str) -> SiteContext:
    key = (key or "").strip()
    if key_type == "upn":
        d = email_domain(key)
        return SiteContext(email_domains=[d] if d else [])
    if key_type == "email_domain":
        return SiteContext(email_domains=[key])
    if key_type == "ip":
        return SiteContext(ips=[key])
    if key_type == "hostname":
        return SiteContext(hostnames=[key])
    if key_type == "ad_domain":
        return SiteContext(ad_domains=[key])
    return SiteContext()


def run(ctx: RunContext) -> Dict[str, Any]:
    tenants = {t.get("name") or t.get("tenant_id"): t
               for t in (ctx.ccfg.get("tenants") or (ctx.cfg.get("collectors") or {}).get("entra", {}).get("tenants") or [])}
    workspaces = ctx.ccfg.get("workspaces") or []
    queries = ctx.ccfg.get("queries") or []
    if not workspaces or not queries:
        raise RuntimeError("collectors.azure_log_analytics needs workspaces and queries")
    days = int(ctx.ccfg.get("lookback_days", 7))

    apps: Dict[str, AzureApp] = {}
    agg: Dict[tuple, float] = defaultdict(float)
    stats: Dict[str, Any] = {}
    window_start = (ctx.run_started - dt.timedelta(days=days)).date()

    for ws in workspaces:
        tname = ws.get("tenant") or next(iter(tenants), None)
        if tname not in tenants:
            raise RuntimeError(f"workspace {ws.get('workspace_id')}: unknown tenant '{tname}'")
        app = apps.setdefault(tname, AzureApp(tenants[tname], SCOPE))
        for q in queries:
            kql = q["kql"].replace("{lookback_days}", str(days))
            r = app.s.post(
                f"{app.la_base}/workspaces/{ws['workspace_id']}/query",
                headers=app.headers(), json={"query": kql, "timespan": f"P{days + 1}D"},
            )
            raise_for_status(r, f"Log Analytics [{q['name']}]")
            tables = r.json().get("tables") or []
            if not tables:
                continue
            cols = [c["name"] for c in tables[0]["columns"]]
            n = 0
            for row in tables[0]["rows"]:
                rec = dict(zip(cols, row))
                day = parse_ts(rec.get("day"))
                if not day:
                    continue
                m = ctx.resolver.resolve(_ctx_for(str(rec.get("key") or ""), q.get("key_type", "upn")))
                dim = str(rec.get("dimension") or "all")
                agg[(day.date(), q["name"], m.label, m.key, dim)] += float(rec.get("value") or 0)
                n += 1
            stats[f"{ws.get('name', ws['workspace_id'])}.{q['name']}"] = n

    cur = ctx.conn.cursor()
    cur.execute(
        "DELETE FROM azure_log_metrics WHERE snapshot_date >= %s AND query_name = ANY(%s)",
        (window_start, [q["name"] for q in queries]),
    )
    for (day, qn, label, key, dim), v in agg.items():
        if day < window_start:
            continue
        cur.execute(
            "INSERT INTO azure_log_metrics (snapshot_date, query_name, site_label, site_tag, dimension, value) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (day, qn, label, key, dim, v),
        )
    ctx.conn.commit()
    stats["rows"] = len(agg)
    return stats
