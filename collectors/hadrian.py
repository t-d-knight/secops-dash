#!/usr/bin/env python3
"""
Hadrian Atlas (external attack surface) -> external_assets + vuln_findings
(source='hadrian', asset_type='internet').

External risks deliberately go into the SAME vuln_findings table as
endpoint vulns: SLA, KEV, EPSS, MTTR and the per-site rollups then apply to
the internet-facing estate for free, and the dashboard can still split on
source.

Hadrian's REST API reference sits behind the customer login, so endpoint
paths, pagination style and field names are ALL config-driven
(collectors.hadrian in config.yaml) rather than hardcoded. Defaults are
placeholders -- copy the real ones from the API docs in the Hadrian
console. `mode: csv` ingests the platform's CSV exports instead, using the
same field map against column names, which works today with zero API
wrangling.
"""
import csv
import datetime as dt
import os
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urlparse

import cvss
from collectors.base import RunContext, as_list, dig, norm_severity, parse_ts, upsert_rows, TextArray
from findings_store import FindingsWriter, NormalizedFinding, expire_unseen
from http_client import make_session, raise_for_status
from site_resolver import SiteContext

NAME = "hadrian"
SOURCE = "hadrian"

DEFAULT_OPEN = {"open", "new", "active", "in_progress", "triaged", "reopened", "unresolved"}
DEFAULT_FIXED = {"resolved", "fixed", "closed", "remediated", "mitigated"}
DEFAULT_SUPPRESSED = {"accepted", "risk_accepted", "false_positive", "ignored", "dismissed", "wont_fix"}


# ---------------------------------------------------------------- fetching
def _iter_api(ctx: RunContext, s, feed: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    base = ctx.ccfg["base_url"].rstrip("/")
    url = base + feed["path"]
    items_key = feed.get("items_key", "data")
    pg = feed.get("pagination") or {"type": "page"}
    ptype = pg.get("type", "page")
    size = int(pg.get("size", 500))
    params = dict(feed.get("params") or {})
    if pg.get("size_param", "page_size"):
        params[pg.get("size_param", "page_size")] = size

    page = int(pg.get("start", 1))
    offset = 0
    cursor = None
    guard = 0
    while True:
        p = dict(params)
        if ptype == "page":
            p[pg.get("param", "page")] = page
        elif ptype == "offset":
            p[pg.get("param", "offset")] = offset
        elif ptype == "cursor" and cursor:
            p[pg.get("cursor_param", "cursor")] = cursor
        r = s.get(url, params=p)
        raise_for_status(r, "Hadrian")
        j = r.json()
        items = j if isinstance(j, list) else dig(j, items_key, []) or []
        yield from items
        guard += 1
        if not items or guard > 100000:
            break
        if ptype == "page":
            total_pages = dig(j, pg["total_pages_path"]) if pg.get("total_pages_path") else None
            if total_pages is not None and page >= int(total_pages):
                break
            if len(items) < size:
                break
            page += 1
        elif ptype == "offset":
            offset += len(items)
            if len(items) < size:
                break
        elif ptype == "cursor":
            cursor = dig(j, pg.get("cursor_path", "next_cursor"))
            if not cursor:
                break
        else:
            break  # 'none': single response


def _iter_csv(ctx: RunContext, path: str) -> Iterator[Dict[str, Any]]:
    path = path if os.path.isabs(path) else os.path.join(ctx.cfg.get("_config_dir", "."), path)
    with open(path, newline="", encoding="utf-8-sig") as f:
        yield from csv.DictReader(f)


def _session(ctx: RunContext):
    s = make_session()
    key = ctx.ccfg.get("api_key")
    if not key:
        raise RuntimeError("collectors.hadrian.api_key missing from secrets.yaml")
    header = ctx.ccfg.get("auth_header", "Authorization")
    scheme = ctx.ccfg.get("auth_scheme", "Bearer")
    s.headers[header] = f"{scheme} {key}".strip() if scheme else key
    s.headers["Accept"] = "application/json"
    return s


def _records(ctx: RunContext, s, feed_name: str) -> Iterator[Dict[str, Any]]:
    feed = ctx.ccfg.get(feed_name) or {}
    if ctx.ccfg.get("mode", "api") == "csv":
        path = (ctx.ccfg.get("csv") or {}).get(f"{feed_name}_path")
        if not path:
            return iter(())
        return _iter_csv(ctx, path)
    if not feed.get("path"):
        return iter(())
    return _iter_api(ctx, s, feed)


# ---------------------------------------------------------------- mapping
def _f(rec: Dict[str, Any], fields: Dict[str, str], name: str, default: Any = None) -> Any:
    path = fields.get(name)
    if not path:
        return default
    if path in rec:            # flat CSV column / top-level key, even if it contains dots
        v = rec[path]
    else:
        v = dig(rec, path)
    return default if v in (None, "") else v


def _host_of(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    n = str(name).strip()
    if "://" in n:
        n = urlparse(n).hostname or n
    return n.split(":")[0].lower()


def _site(ctx: RunContext, host: Optional[str], ips: List[str]):
    doms = []
    if host and "." in host and not host.replace(".", "").isdigit():
        doms.append(host)
    return ctx.resolver.resolve(SiteContext(hostnames=[host] if host else [], ips=ips, email_domains=doms))


def _cves(v: Any) -> List[str]:
    out = []
    for x in as_list(v):
        if isinstance(x, dict):
            x = x.get("id") or x.get("cve")
        for part in str(x or "").replace(";", ",").split(","):
            p = part.strip().upper()
            if p.startswith("CVE-"):
                out.append(p)
    return out


def run(ctx: RunContext) -> Dict[str, Any]:
    s = _session(ctx) if ctx.ccfg.get("mode", "api") == "api" else None
    stats: Dict[str, Any] = {}

    # ---- assets
    af = (ctx.ccfg.get("assets") or {}).get("fields") or {}
    rows = []
    for rec in _records(ctx, s, "assets"):
        aid = _f(rec, af, "id")
        if not aid:
            continue
        host = _host_of(_f(rec, af, "name"))
        ips = [str(x) for x in as_list(_f(rec, af, "ip"))]
        m = _site(ctx, host, ips)
        rows.append({
            "source": SOURCE,
            "asset_id": str(aid),
            "name": host or _f(rec, af, "name"),
            "asset_type": _f(rec, af, "type"),
            "ips": TextArray(ips),
            "ports": TextArray([str(x) for x in as_list(_f(rec, af, "ports"))]),
            "technologies": TextArray([str(x if not isinstance(x, dict) else x.get("name")) for x in as_list(_f(rec, af, "technologies"))]),
            "first_seen": parse_ts(_f(rec, af, "first_seen")),
            "last_seen": parse_ts(_f(rec, af, "last_seen")),
            "site_label": m.label,
            "site_tag": m.key,
            "site_matched_by": m.matched_by,
            "collected_at": ctx.run_started,
            "retired": False,
        })
    stats["assets"] = upsert_rows(ctx.conn, "external_assets", rows, ["source", "asset_id"])
    if rows:
        cur = ctx.conn.cursor()
        cur.execute("UPDATE external_assets SET retired = TRUE WHERE source = %s AND collected_at < %s",
                    (SOURCE, ctx.run_started))
        ctx.conn.commit()
    asset_sites = {r["asset_id"]: r for r in rows}

    # ---- risks -> vuln_findings
    rcfg = ctx.ccfg.get("risks") or {}
    rf = rcfg.get("fields") or {}
    open_s = {x.lower() for x in rcfg.get("open_statuses", DEFAULT_OPEN)}
    fixed_s = {x.lower() for x in rcfg.get("fixed_statuses", DEFAULT_FIXED)}
    supp_s = {x.lower() for x in rcfg.get("suppressed_statuses", DEFAULT_SUPPRESSED)}
    require_exploit = ctx.cfg.get("reporting", {}).get("require_exploit_for_remote_no_auth", True)
    now = ctx.run_started
    w = FindingsWriter(ctx.conn)
    n = 0
    for rec in _records(ctx, s, "risks"):
        rid = _f(rec, rf, "id")
        if not rid:
            continue
        status = str(_f(rec, rf, "status", "open")).lower().replace(" ", "_")
        state = ("FIXED" if status in fixed_s else "SUPPRESSED" if status in supp_s
                 else "OPEN" if status in open_s else "OPEN")
        asset_id = str(_f(rec, rf, "asset_id") or _f(rec, rf, "asset_name") or "unknown")
        host = _host_of(_f(rec, rf, "asset_name")) or (asset_sites.get(asset_id) or {}).get("name")
        ips = [str(x) for x in as_list(_f(rec, rf, "ip"))]
        a = asset_sites.get(asset_id)
        if a:
            label, key, by = a["site_label"], a["site_tag"], a["site_matched_by"]
        else:
            m = _site(ctx, host, ips)
            label, key, by = m.label, m.key, m.matched_by
        score = _f(rec, rf, "cvss")
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None
        sev_raw = _f(rec, rf, "severity")
        sev = norm_severity(sev_raw, "") or cvss.severity_band_from_score(score) or "low"
        if sev == "info":
            sev = "low"
        vector = _f(rec, rf, "cvss_vector")
        exploit = _f(rec, rf, "exploit_available")
        exploit = str(exploit).lower() in ("true", "1", "yes") if exploit is not None else None
        first = parse_ts(_f(rec, rf, "first_seen")) or now
        last = parse_ts(_f(rec, rf, "last_seen")) or now
        w.add(NormalizedFinding(
            source=SOURCE,
            source_asset_id=asset_id,
            source_rule_id=str(rid),
            state=state,
            severity=sev,
            first_found=first,
            # External assets have no "sensor check-in"; Hadrian re-observes
            # continuously, so an open risk returned today was seen today.
            last_found=now if state == "OPEN" else last,
            last_fixed=(parse_ts(_f(rec, rf, "resolved_at")) or last) if state == "FIXED" else None,
            site_label=label, site_tag=key, site_matched_by=by,
            cvss_score=score, cvss_vector=vector,
            title=_f(rec, rf, "title"),
            plugin_family=_f(rec, rf, "category"),
            synopsis=(str(_f(rec, rf, "description", "")) or "")[:2000] or None,
            solution=_f(rec, rf, "remediation"),
            is_remote_no_auth=cvss.is_remote_no_auth(vector, exploit_available=exploit,
                                                     require_exploit=require_exploit),
            exploit_available=exploit,
            asset_type="internet",
            hostname=host,
            fix_id=f"hadrian:{_f(rec, rf, 'title')}",
            fix_title=_f(rec, rf, "title"),
            vendor_priority=str(sev_raw) if sev_raw is not None else None,
            cves=_cves(_f(rec, rf, "cves")),
        ))
        n += 1
    w.flush()
    stats["risks"] = n
    if n and rcfg.get("full_pull", True):
        stats["expired"] = expire_unseen(ctx.conn, SOURCE, ctx.run_started)
    return stats
