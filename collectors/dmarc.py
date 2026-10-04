#!/usr/bin/env python3
"""
DMARC aggregate reports from the existing parsedmarc -> OpenSearch pipeline
(cyber-dmarc) -> dmarc_daily.

parsedmarc maps header_from / source_* as `text` with no keyword sub-field,
so OpenSearch can't terms-aggregate them. Instead this scrolls the raw
aggregate-report records for the window (low thousands per day -- cheap) and
aggregates here. Each run recomputes the whole lookback window because
reporters send aggregate reports a day or more late.

Site = the header_from domain, via the sites' email_domains.
"""
import datetime as dt
from collections import defaultdict
from typing import Any, Dict

from collectors.base import RunContext, parse_ts
from http_client import make_session, raise_for_status
from site_resolver import SiteContext

NAME = "dmarc"
FIELDS = ["date_begin", "header_from", "source_ip_address", "source_base_domain", "source_name",
          "source_country", "message_count", "passed_dmarc", "spf_aligned", "dkim_aligned",
          "disposition", "org_name"]


def _truthy(v: Any) -> bool:
    return v is True or str(v).lower() == "true"


def run(ctx: RunContext) -> Dict[str, Any]:
    c = ctx.ccfg
    url = c.get("opensearch_url", "https://localhost:9200").rstrip("/")
    index = c.get("index", "dmarc_aggregate*")
    days = int(c.get("lookback_days", 10))
    verify = c.get("ca_file") or c.get("verify_tls", True)
    s = make_session(timeout=120, verify=verify)
    if c.get("username"):
        s.auth = (c["username"], c.get("password", ""))
    if c.get("api_key"):
        s.headers["Authorization"] = f"ApiKey {c['api_key']}"

    window_start = (ctx.run_started - dt.timedelta(days=days)).date()
    body = {
        "size": 2000,
        "_source": FIELDS,
        "query": {"range": {"date_begin": {"gte": window_start.isoformat()}}},
        "sort": ["_doc"],
    }
    r = s.post(f"{url}/{index}/_search", params={"scroll": "2m"}, json=body)
    raise_for_status(r, "OpenSearch search")
    j = r.json()
    scroll_id = j.get("_scroll_id")

    agg: Dict[tuple, Dict[str, Any]] = defaultdict(lambda: {
        "messages": 0, "dmarc_pass": 0, "spf_aligned": 0, "dkim_aligned": 0,
        "quarantined": 0, "rejected": 0, "reporters": set()})
    meta: Dict[tuple, Dict[str, Any]] = {}
    docs = 0
    try:
        while True:
            hits = (j.get("hits") or {}).get("hits") or []
            if not hits:
                break
            for h in hits:
                d = h.get("_source") or {}
                day = parse_ts(d.get("date_begin"))
                hf = str(d.get("header_from") or "").strip().lower()
                if not day or not hf:
                    continue
                ip = str(d.get("source_ip_address") or "")
                k = (day.date(), hf, ip)
                cnt = int(d.get("message_count") or 0)
                a = agg[k]
                a["messages"] += cnt
                if _truthy(d.get("passed_dmarc")):
                    a["dmarc_pass"] += cnt
                if _truthy(d.get("spf_aligned")):
                    a["spf_aligned"] += cnt
                if _truthy(d.get("dkim_aligned")):
                    a["dkim_aligned"] += cnt
                disp = str(d.get("disposition") or "").lower()
                if disp == "quarantine":
                    a["quarantined"] += cnt
                elif disp == "reject":
                    a["rejected"] += cnt
                if d.get("org_name"):
                    a["reporters"].add(str(d["org_name"]))
                meta.setdefault(k, {
                    "source_base_domain": d.get("source_base_domain"),
                    "source_name": d.get("source_name"),
                    "source_country": d.get("source_country"),
                })
                docs += 1
            if not scroll_id:
                break
            r = s.post(f"{url}/_search/scroll", json={"scroll": "2m", "scroll_id": scroll_id})
            raise_for_status(r, "OpenSearch scroll")
            j = r.json()
            scroll_id = j.get("_scroll_id") or scroll_id
    finally:
        if scroll_id:
            try:
                s.delete(f"{url}/_search/scroll", json={"scroll_id": scroll_id})
            except Exception:
                pass

    cur = ctx.conn.cursor()
    cur.execute("DELETE FROM dmarc_daily WHERE report_date >= %s", (window_start,))
    site_cache: Dict[str, Any] = {}
    for (day, hf, ip), a in agg.items():
        if hf not in site_cache:
            site_cache[hf] = ctx.resolver.resolve(SiteContext(email_domains=[hf]))
        m = site_cache[hf]
        md = meta.get((day, hf, ip), {})
        cur.execute(
            """INSERT INTO dmarc_daily (report_date, header_from, source_ip, source_base_domain, source_name,
                   source_country, messages, dmarc_pass, spf_aligned, dkim_aligned, quarantined, rejected,
                   reporters, site_label, site_tag, site_matched_by)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (day, hf, ip, md.get("source_base_domain"), md.get("source_name"), md.get("source_country"),
             a["messages"], a["dmarc_pass"], a["spf_aligned"], a["dkim_aligned"], a["quarantined"],
             a["rejected"], sorted(a["reporters"]), m.label, m.key, m.matched_by),
        )
    ctx.conn.commit()
    return {"docs": docs, "rows": len(agg), "window_start": window_start.isoformat()}
