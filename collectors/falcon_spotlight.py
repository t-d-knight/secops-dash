#!/usr/bin/env python3
"""
Falcon Exposure Management / Spotlight vulnerabilities -> vuln_findings
(source='falcon_spotlight'). Replaces the Tenable export adapter.

Each run:
  1. Pulls EVERY open/reopened vuln (full, so anything that vanished can be
     detected) with the cve / host_info / remediation facets.
  2. Pulls closed/expired vulns updated since the last good run (incremental),
     which is what feeds MTTR.
  3. Marks rows that were open last time but absent from (1) as EXPIRED.
  4. Sets last_found from the host's sensor last_seen, so the rollups'
     days_last_seen staleness rule means "host checked in recently" exactly
     as it did for Tenable -- Spotlight's own updated_timestamp only moves
     when the vuln changes, which would wrongly age out long-standing vulns.

Suppressed vulns (accepted risk / compensating control / false positive)
land as state SUPPRESSED: visible, but excluded from open counts and SLA.
"""
import datetime as dt
from typing import Any, Dict, Optional

import cvss
from collectors.base import RunContext, as_list, parse_ts
from collectors.falcon_client import FalconClient
from collectors.falcon_hosts import host_site_map
from findings_store import FindingsWriter, NormalizedFinding, expire_unseen
from product_classify import classify_product
from site_resolver import SiteContext

NAME = "falcon_spotlight"
SOURCE = "falcon_spotlight"
PATH = "/spotlight/combined/vulnerabilities/v1"
FACETS = ["cve", "host_info", "remediation"]

_STATE = {"open": "OPEN", "reopen": "REOPENED", "closed": "FIXED", "expired": "EXPIRED"}


def _severity(cve: Dict[str, Any]) -> str:
    s = (cve.get("severity") or "").lower()
    if s in ("critical", "high", "medium", "low"):
        return s
    return cvss.severity_band_from_score(cve.get("base_score")) or "low"


def _asset_type(hi: Dict[str, Any], cached: Optional[str]) -> str:
    if str(hi.get("internet_exposure") or "").lower() == "yes":
        return "internet"
    d = (hi.get("product_type_desc") or "").lower()
    if "domain controller" in d:
        return "domain_controller"
    if "server" in d:
        return "server"
    if "workstation" in d:
        return "workstation"
    return cached or "unknown"


def _product_key(app: Dict[str, Any]) -> Optional[str]:
    v = (app.get("vendor_normalized") or "").strip().lower().replace(" ", "_")
    p = (app.get("product_name_normalized") or "").strip().lower().replace(" ", "_")
    if v and p:
        return f"{v}:{p}"
    return (app.get("product_name_version") or None)


def to_finding(rec: Dict[str, Any], hosts, fc: FalconClient, resolver, require_exploit: bool) -> NormalizedFinding:
    cve = rec.get("cve") or {}
    hi = rec.get("host_info") or {}
    aid = rec.get("aid") or ""
    apps = rec.get("apps") or []
    app = apps[0] if apps else {}
    rem = rec.get("remediation") or {}
    ents = rem.get("entities") or []
    supp = (rec.get("suppression_info") or {}).get("is_suppressed")

    state = _STATE.get((rec.get("status") or "").lower(), "OPEN")
    if supp and state in ("OPEN", "REOPENED"):
        state = "SUPPRESSED"

    cached = hosts.get(aid)
    if cached:
        site_label, site_tag, matched_by, extra = cached
    else:
        m = resolver.resolve(SiteContext(
            falcon_tags=as_list(hi.get("tags")),
            falcon_groups=fc.group_labels(as_list(hi.get("groups"))),
            ous=as_list(hi.get("ou")),
            ad_sites=as_list(hi.get("site_name")),
            ad_domains=as_list(hi.get("machine_domain")),
            hostnames=as_list(hi.get("hostname")),
            ips=as_list(hi.get("local_ip")),
        ))
        site_label, site_tag, matched_by, extra = m.label, m.key, m.matched_by, {}

    exploit_status = cve.get("exploit_status")
    try:
        exploit_status = int(exploit_status) if exploit_status is not None else None
    except (TypeError, ValueError):
        exploit_status = None
    exploit_available = exploit_status is not None and exploit_status >= 30
    vector = cve.get("vector")

    pk = _product_key(app)
    fam = classify_product(pk)["family"] if pk else None
    vendor = pk.split(":", 1)[0] if pk and ":" in pk else None
    cve_id = cve.get("id") or rec.get("vulnerability_id")
    created = parse_ts(rec.get("created_timestamp")) or dt.datetime.now(dt.timezone.utc)
    updated = parse_ts(rec.get("updated_timestamp")) or created

    fix = ents[0] if ents else {}
    return NormalizedFinding(
        source=SOURCE,
        source_asset_id=aid,
        source_rule_id=rec.get("id") or f"{aid}_{cve_id}",
        state=state,
        severity=_severity(cve),
        first_found=created,
        last_found=updated,
        last_fixed=parse_ts(rec.get("closed_timestamp")) if state == "FIXED" else None,
        site_label=site_label,
        site_tag=site_tag,
        site_matched_by=matched_by,
        cvss_score=cve.get("base_score"),
        cvss_vector=vector,
        title=" ".join(x for x in (cve_id, app.get("product_name_version")) if x),
        plugin_family=", ".join(as_list(cve.get("types"))) or None,
        synopsis=(cve.get("description") or "")[:2000] or None,
        solution=fix.get("action") or fix.get("title"),
        is_remote_no_auth=cvss.is_remote_no_auth(vector, exploit_available=exploit_available,
                                                 require_exploit=require_exploit),
        exploit_available=exploit_available,
        exploited_by_malware=(exploit_status is not None and exploit_status >= 90),
        has_patch=bool(ents) or (cve.get("remediation_level") == "O"),
        product_key=pk,
        product_vendor=vendor,
        product_family=fam,
        asset_type=_asset_type(hi, extra.get("product_type")),
        hostname=hi.get("hostname") or extra.get("hostname"),
        fix_id=fix.get("id"),
        fix_title=fix.get("title") or fix.get("action"),
        vendor_priority=(cve.get("exprt_rating") or None),
        cves=[cve_id] if cve_id and str(cve_id).upper().startswith("CVE-") else [],
    )


def run(ctx: RunContext) -> Dict[str, Any]:
    fc = FalconClient(ctx.cfg, ctx.ccfg)
    hosts = host_site_map(ctx.conn)
    require_exploit = ctx.cfg.get("reporting", {}).get("require_exploit_for_remote_no_auth", True)
    page = int(ctx.ccfg.get("page_size", 1000))
    extra = ctx.ccfg.get("filter")  # optional extra FQL ANDed onto both pulls
    w = FindingsWriter(ctx.conn)

    def pull(fql: str, label: str) -> int:
        if extra:
            fql = f"{fql}+{extra}"
        n = 0
        for rec in fc.iter_after(PATH, {"filter": fql, "facet": FACETS, "limit": page}):
            w.add(to_finding(rec, hosts, fc, ctx.resolver, require_exploit))
            n += 1
            if n % 50000 == 0:
                ctx.log(f"{label}: {n} records...")
        w.flush()
        ctx.log(f"{label}: {n} records")
        return n

    open_n = pull("status:['open','reopen']", "open")
    expired = expire_unseen(ctx.conn, SOURCE, ctx.run_started)

    since = ctx.since(NAME, default_days=int(ctx.ccfg.get("closed_lookback_days", 30)))
    closed_n = pull(
        f"status:['closed','expired']+updated_timestamp:>'{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'",
        "closed",
    )

    cur = ctx.conn.cursor()
    cur.execute(
        """
        UPDATE vuln_findings vf SET last_found = a.last_seen
        FROM assets a
        WHERE vf.source = %s AND a.source = 'falcon'
          AND a.source_asset_id = vf.source_asset_id
          AND vf.state IN ('OPEN','REOPENED','SUPPRESSED')
          AND a.last_seen IS NOT NULL AND a.last_seen > vf.last_found
        """,
        (SOURCE,),
    )
    ctx.conn.commit()
    return {"open": open_n, "closed": closed_n, "expired": expired, "rows": w.written}
