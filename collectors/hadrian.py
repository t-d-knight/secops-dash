#!/usr/bin/env python3
"""
Hadrian Atlas (external attack surface) -> external_assets + vuln_findings
(source='hadrian', asset_type='internet').

External risks deliberately go into the SAME vuln_findings table as
endpoint vulns, so SLA and the per-site rollups apply to the internet-facing
estate too; everything downstream can still split on source (the exec
report does -- endpoint figures exclude Hadrian, which gets its own page).

Both endpoints are confirmed against the live API (2026-10-06 probe):
  - GET /organizations/{id}/assets  -- tags carry the site key (see _HadrianSites)
  - GET /organizations/{id}/risks   -- id, title, riskSeverity, activityStatus,
    status, riskType, riskVisibility, created, lastSeen, resolvedOn,
    primaryCategory.id. No asset, CVE or CVSS fields: the asset comes from
    GET /risks/{id} (relatedAssets), and with no CVEs Hadrian risks don't
    join to KEV/EPSS.
Paths, pagination and field names are config-driven (collectors.hadrian in
config.yaml) so a contract change doesn't need a code change. `mode: csv`
ingests the platform's CSV exports instead, using the same field map
against column names (no risk details, so no asset link, in that mode).
"""
import collections
import csv
import datetime as dt
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urlparse

from collectors.base import RunContext, as_list, dig, norm_severity, parse_ts, upsert_rows, TextArray
from findings_store import FindingsWriter, NormalizedFinding, expire_unseen
from http_client import make_session, raise_for_status
from site_resolver import SiteContext

NAME = "hadrian"
SOURCE = "hadrian"



# ---------------------------------------------------------------- fetching
def _iter_api(ctx: RunContext, s, feed: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
    base = ctx.ccfg["base_url"].rstrip("/")
    org_id = ctx.ccfg.get("organization_id")
    if not org_id:
        raise RuntimeError("collectors.hadrian.organization_id missing from config.yaml "
                            "(find it in the console URL, or GET /users/me/organizations)")
    url = base + feed["path"].format(organization_id=org_id)
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
    header = ctx.ccfg.get("auth_header", "X-Api-Key")
    scheme = ctx.ccfg.get("auth_scheme", "")
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


# ------------------------------------------------------------------ sites
# Hadrian asset tags ARE the site keys (SITE-A, SITE-B, ...), applied in the
# Hadrian console. Untagged domains inherit the site of their apex domain,
# learned from tagged domains plus each site's email_domains. Bare IPs fall
# back to the normal resolver (cidrs). Archive tags (zzArchive = abandoned
# domains pending removal) drop the asset and its risks entirely.

# Second-level public suffixes in use here, so the apex of
# foo.site-a.example.org.au is site-a.example.org.au, not org.au. Anything
# under a state gov suffix keeps one more label (x.vic.gov.au).
_SL_SUFFIXES = {"com.au", "org.au", "net.au", "gov.au", "edu.au", "asn.au", "id.au", "co.uk", "org.uk", "co.nz"}
_STATE_GOV = {"vic.gov.au", "nsw.gov.au", "qld.gov.au", "sa.gov.au", "wa.gov.au", "tas.gov.au", "act.gov.au", "nt.gov.au"}


def _apex(host: Optional[str]) -> Optional[str]:
    if not host or "." not in host or host.replace(".", "").isdigit():
        return None
    parts = host.lower().strip(".").lstrip("*.").split(".")
    keep = 2
    if ".".join(parts[-3:]) in _STATE_GOV:
        keep = 4
    elif ".".join(parts[-2:]) in _SL_SUFFIXES:
        keep = 3
    return ".".join(parts[-keep:]) if len(parts) >= keep else None


class _HadrianSites:
    def __init__(self, ctx: RunContext):
        self.ctx = ctx
        self.by_key = {s["key"].upper(): (s["label"], s["key"]) for s in ctx.cfg.get("sites", [])}
        self.aliases = {k.upper(): v.upper() for k, v in (ctx.ccfg.get("tag_aliases") or {}).items()}
        self.archive = {t.lower() for t in ctx.ccfg.get("archive_tags", ["zzArchive"])}
        self.apex_site: Dict[str, Any] = {}
        for s in ctx.cfg.get("sites", []):
            for d in (s.get("match") or {}).get("email_domains") or []:
                self.apex_site.setdefault(_apex(d) or d, (s["label"], s["key"]))

    def tag_names(self, rec: Dict[str, Any]) -> List[str]:
        return [str(t.get("name") or "") for t in as_list(rec.get("tags")) if isinstance(t, dict)]

    def archived(self, rec: Dict[str, Any]) -> bool:
        return any(t.lower() in self.archive for t in self.tag_names(rec))

    def from_tags(self, rec: Dict[str, Any]):
        for t in self.tag_names(rec):
            k = self.aliases.get(t.upper(), t.upper())
            if k in self.by_key:
                return self.by_key[k]
        return None

    def learn(self, host: Optional[str], site) -> None:
        """A tagged domain teaches its apex -> site (first tag seen wins;
        email_domains seeded above take precedence)."""
        a = _apex(host)
        if a and site:
            self.apex_site.setdefault(a, site)

    def resolve(self, rec: Dict[str, Any], host: Optional[str], ips: List[str]):
        site = self.from_tags(rec)
        if site:
            return site[0], site[1], "hadrian_tag"
        a = _apex(host)
        if a and a in self.apex_site:
            label, key = self.apex_site[a]
            return label, key, "hadrian_apex"
        m = _site(self.ctx, host, ips)
        return m.label, m.key, m.matched_by


def _write_suggestions(ctx: RunContext, rows: List[Dict[str, Any]]) -> Optional[str]:
    """Untagged assets whose site was inferred -- tag these in the Hadrian
    console so its own views agree with the dashboard."""
    out = ctx.ccfg.get("suggested_tags_out")
    if not out:
        return None
    path = out if os.path.isabs(out) else os.path.join(ctx.cfg.get("_config_dir", "."), out)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["asset", "asset_type", "suggested_tag", "how"])
        for r in sorted(rows, key=lambda r: (r["site_tag"], r["name"] or "")):
            w.writerow([r["name"], r["asset_type"], r["site_tag"], r["site_matched_by"]])
    return path


# ------------------------------------------------------------------ risks
def _risk_state(activity: str, status: str, visibility: str) -> str:
    """activityStatus Open/Closed is the real lifecycle; status refines it
    (New / Reopened / Resolved / NotFound -- NotFound means a rescan no
    longer sees it, which is how Hadrian closes most risks: counted as
    fixed). Hidden/ignored risks are suppressed."""
    if visibility and visibility.lower() not in ("visible", ""):
        return "SUPPRESSED"
    if activity.lower() == "closed":
        return "FIXED"
    return "REOPENED" if status.lower() == "reopened" else "OPEN"


def _details(ctx: RunContext, s, ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """GET /risks/{id} for each risk -- the list response doesn't say which
    asset a risk is on; the detail's relatedAssets does. Idempotent GETs,
    retried/backed off by the session; a few in parallel."""
    tmpl = ctx.ccfg["base_url"].rstrip("/") + (ctx.ccfg.get("risks") or {}).get(
        "detail_path", "/organizations/{organization_id}/risks/{id}")
    org = ctx.ccfg.get("organization_id")

    def one(rid: str):
        r = s.get(tmpl.format(organization_id=org, id=rid))
        raise_for_status(r, "Hadrian risk detail")
        return rid, r.json()

    with ThreadPoolExecutor(max_workers=int(ctx.ccfg.get("detail_workers", 4))) as ex:
        return dict(ex.map(one, ids))


def run(ctx: RunContext) -> Dict[str, Any]:
    api = ctx.ccfg.get("mode", "api") == "api"
    s = _session(ctx) if api else None
    stats: Dict[str, Any] = {}
    sites = _HadrianSites(ctx)

    # ---- assets
    af = (ctx.ccfg.get("assets") or {}).get("fields") or {}
    parsed = []
    archived_ids = set()
    for rec in _records(ctx, s, "assets"):
        aid = _f(rec, af, "id")
        if not aid:
            continue
        if sites.archived(rec):
            archived_ids.add(str(aid))
            continue
        value = _f(rec, af, "name")
        platform_type = _f(rec, af, "type") or ""
        services = as_list(rec.get("services"))
        ips = []
        if platform_type in ("StaticIp", "DynamicIp") and value:
            ips.append(str(value))
        ips.extend(str(ip) for svc in services
                   if (ip := ((svc or {}).get("ipAsset") or {}).get("value")))
        # A bare IP asset has no hostname; only Domain/Service-style values are one.
        host = _host_of(value) if platform_type not in ("StaticIp", "DynamicIp") else None
        ports = sorted({str(svc.get("port")) for svc in services if (svc or {}).get("port") is not None})
        sites.learn(host, sites.from_tags(rec))
        parsed.append((rec, aid, value, platform_type, ips, host, ports))

    rows = []
    for rec, aid, value, platform_type, ips, host, ports in parsed:   # 2nd pass: apex map now complete
        label, key, by = sites.resolve(rec, host, ips)
        rows.append({
            "source": SOURCE,
            "asset_id": str(aid),
            "name": host or value,
            "asset_type": platform_type,
            "ips": TextArray(ips),
            "ports": TextArray(ports),
            # Not in the list-assets response; only the single-asset GET
            # endpoint reportedly carries it, which isn't documented here yet.
            "technologies": TextArray([]),
            "first_seen": parse_ts(_f(rec, af, "first_seen")),
            "last_seen": parse_ts(_f(rec, af, "last_seen")),
            "site_label": label,
            "site_tag": key,
            "site_matched_by": by,
            "collected_at": ctx.run_started,
            "retired": False,
        })
    stats["assets"] = upsert_rows(ctx.conn, "external_assets", rows, ["source", "asset_id"])
    stats["assets_archived_skipped"] = len(archived_ids)
    stats["assets_by_match"] = dict(collections.Counter(r["site_matched_by"] for r in rows))
    if rows:
        cur = ctx.conn.cursor()
        # also retires anything since archived in Hadrian (not upserted this run)
        cur.execute("UPDATE external_assets SET retired = TRUE WHERE source = %s AND collected_at < %s",
                    (SOURCE, ctx.run_started))
        ctx.conn.commit()
    sugg = _write_suggestions(ctx, [r for r in rows if r["site_matched_by"] != "hadrian_tag"
                                    and r["site_tag"] != "UNGROUPED"])
    if sugg:
        stats["suggested_tags_file"] = sugg
    asset_by_id = {r["asset_id"]: r for r in rows}

    # ---- risks -> vuln_findings
    rcfg = ctx.ccfg.get("risks") or {}
    rf = rcfg.get("fields") or {}
    risks = [r for r in _records(ctx, s, "risks") if _f(r, rf, "id")]
    details = _details(ctx, s, [str(_f(r, rf, "id")) for r in risks]) if api else {}
    now = ctx.run_started
    w = FindingsWriter(ctx.conn)
    n = skipped = 0
    for rec in risks:
        rid = str(_f(rec, rf, "id"))
        d = details.get(rid) or {}
        related = [a for a in as_list(d.get("relatedAssets")) if isinstance(a, dict)]
        live = [a for a in related if str(a.get("assetId")) not in archived_ids and not sites.archived(a)]
        if related and not live:
            skipped += 1          # only on archived assets: pending removal, not a live risk
            continue
        ra = live[0] if live else {}
        asset_id = str(ra.get("assetId") or _f(rec, rf, "asset_id") or "unknown")
        a = asset_by_id.get(asset_id)
        host = (a or {}).get("name") or _host_of(ra.get("value") or _f(rec, rf, "asset_name"))
        if a:
            label, key, by = a["site_label"], a["site_tag"], a["site_matched_by"]
        else:
            label, key, by = sites.resolve(ra, host, [])
        sev_raw = _f(rec, rf, "severity")
        # vuln_findings has no 'info' band; Info is kept verbatim in
        # vendor_priority for anything that needs to tell it apart.
        sev = norm_severity(sev_raw, "low")
        if sev not in ("critical", "high", "medium", "low"):
            sev = "low"
        state = _risk_state(str(_f(rec, rf, "activity", "Open")), str(_f(rec, rf, "status", "")),
                            str(_f(rec, rf, "visibility", "Visible")))
        first = parse_ts(_f(rec, rf, "first_seen")) or now
        last = parse_ts(_f(rec, rf, "last_seen")) or now
        w.add(NormalizedFinding(
            source=SOURCE,
            source_asset_id=asset_id,
            source_rule_id=rid,
            state=state,
            severity=sev,
            first_found=first,
            # External assets have no "sensor check-in"; Hadrian re-observes
            # continuously, so an open risk returned today was seen today.
            last_found=now if state in ("OPEN", "REOPENED") else last,
            last_fixed=(parse_ts(_f(rec, rf, "resolved_at")) or last) if state == "FIXED" else None,
            site_label=label, site_tag=key, site_matched_by=by,
            title=_f(rec, rf, "title"),
            plugin_family=_f(rec, rf, "category"),
            synopsis=(str(d.get("description") or "") or "")[:2000] or None,
            solution=d.get("remediation"),
            # No CVSS/CVE/exploit fields in Hadrian's risk schema, so these
            # don't join to KEV/EPSS; reported on their own.
            asset_type="internet",
            hostname=host,
            fix_id=f"hadrian:{_f(rec, rf, 'title')}",
            fix_title=_f(rec, rf, "title"),
            vendor_priority=str(sev_raw) if sev_raw is not None else None,
            risk_type=_f(rec, rf, "risk_type"),
            cves=_cves(d.get("relatedIssues")),
        ))
        n += 1
    w.flush()
    stats["risks"] = n
    stats["risks_archived_skipped"] = skipped
    if n and rcfg.get("full_pull", True):
        stats["expired"] = expire_unseen(ctx.conn, SOURCE, ctx.run_started)
    return stats
