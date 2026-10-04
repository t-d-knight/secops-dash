#!/usr/bin/env python3
"""
Falcon host inventory -> assets (source='falcon').

Runs FIRST among the Falcon collectors: it resolves each host's site once,
and Spotlight/alerts reuse that answer by agent ID (host_site_map) so one
host can never land in two different sites depending on which feed you
look at.

Optionally also pulls Exposure Management / Discover *unmanaged* assets
(devices seen on the network by sensors but with no sensor of their own) as
source='falcon_unmanaged' -- the "what's on the wire that we can't see"
coverage gap per site.
"""
from typing import Any, Dict, List, Tuple

from collectors.base import RunContext, TextArray, as_list, parse_ts, upsert_rows
from collectors.falcon_client import FalconClient
from site_resolver import SiteContext

NAME = "falcon_hosts"


def _product_type(desc: Any) -> str:
    d = (desc or "").lower()
    if "domain controller" in d:
        return "domain_controller"
    if "server" in d:
        return "server"
    if "workstation" in d:
        return "workstation"
    return "unknown"


def _ctx_for_host(fc: FalconClient, d: Dict[str, Any]) -> SiteContext:
    return SiteContext(
        falcon_tags=as_list(d.get("tags")),
        falcon_groups=fc.group_labels(as_list(d.get("groups"))),
        ous=as_list(d.get("ou")),
        ad_sites=as_list(d.get("site_name")),
        ad_domains=as_list(d.get("machine_domain")),
        hostnames=as_list(d.get("hostname")),
        ips=as_list(d.get("local_ip")) + as_list(d.get("external_ip")),
    )


def run(ctx: RunContext) -> Dict[str, Any]:
    fc = FalconClient(ctx.cfg, ctx.ccfg)
    fql = ctx.ccfg.get("filter")  # e.g. "last_seen:>='now-90d'"
    params = {"filter": fql} if fql else {}

    ids = list(fc.iter_scroll_ids("/devices/queries/devices-scroll/v1", params, limit=5000))
    ctx.log(f"{len(ids)} managed hosts")

    rows: List[Dict[str, Any]] = []
    for i in range(0, len(ids), 5000):
        j = fc.post("/devices/entities/devices/v2", {"ids": ids[i:i + 5000]})
        for d in j.get("resources") or []:
            m = ctx.resolver.resolve(_ctx_for_host(fc, d))
            ou = as_list(d.get("ou"))
            rows.append({
                "source": "falcon",
                "source_asset_id": d.get("device_id"),
                "hostname": d.get("hostname"),
                "domain": d.get("machine_domain"),
                "ous": TextArray([str(x) for x in ou]),
                "ad_site": d.get("site_name"),
                "platform": d.get("platform_name"),
                "os_version": d.get("os_version"),
                "product_type": _product_type(d.get("product_type_desc")),
                "managed": True,
                "internet_exposure": None,
                "sensor_version": d.get("agent_version"),
                "rfm": d.get("reduced_functionality_mode"),
                "containment": d.get("status"),
                "prevention_policy": ((d.get("device_policies") or {}).get("prevention") or {}).get("policy_id"),
                "ips": TextArray([str(x) for x in as_list(d.get("local_ip"))]),
                "external_ip": d.get("external_ip"),
                "groups": TextArray(fc.group_labels(as_list(d.get("groups")))),
                "tags": TextArray([str(x) for x in as_list(d.get("tags"))]),
                "first_seen": parse_ts(d.get("first_seen")),
                "last_seen": parse_ts(d.get("last_seen")),
                "site_label": m.label,
                "site_tag": m.key,
                "site_matched_by": m.matched_by,
                "collected_at": ctx.run_started,
            })
    n = upsert_rows(ctx.conn, "assets", rows, ["source", "source_asset_id"])
    stats = {"managed_hosts": n}
    pulled = ["falcon"]

    if ctx.ccfg.get("include_unmanaged", True):
        try:
            stats["unmanaged_assets"] = _pull_unmanaged(ctx, fc)
            pulled.append("falcon_unmanaged")
        except Exception as e:  # Discover scope not granted / not licensed -> don't fail the hosts pull
            ctx.log(f"unmanaged asset pull skipped: {e}")
            stats["unmanaged_error"] = str(e)[:300]

    # Hosts no longer returned at all (sensor removed, host hidden) -> flag,
    # don't delete. Only for sources that were pulled completely this run.
    cur = ctx.conn.cursor()
    cur.execute(
        "UPDATE assets SET retired = (collected_at < %s) WHERE source = ANY(%s)",
        (ctx.run_started, pulled))
    ctx.conn.commit()
    return stats


def _pull_unmanaged(ctx: RunContext, fc: FalconClient) -> int:
    flt = ctx.ccfg.get("unmanaged_filter", "entity_type:'unmanaged'")
    ids = list(fc.iter_offset_ids("/discover/queries/hosts/v1", {"filter": flt}, limit=100))
    rows = []
    for i in range(0, len(ids), 100):
        j = fc.get("/discover/entities/hosts/v1", {"ids": ids[i:i + 100]})
        for d in j.get("resources") or []:
            ips = as_list(d.get("current_local_ip")) + as_list(d.get("local_ip_addresses"))
            sc = SiteContext(
                ad_domains=as_list(d.get("machine_domain")),
                ous=as_list(d.get("ou")),
                ad_sites=as_list(d.get("site_name")),
                hostnames=as_list(d.get("hostname")),
                ips=ips,
            )
            m = ctx.resolver.resolve(sc)
            rows.append({
                "source": "falcon_unmanaged",
                "source_asset_id": d.get("id"),
                "hostname": d.get("hostname"),
                "domain": d.get("machine_domain"),
                "ous": TextArray([]),
                "ad_site": d.get("site_name"),
                "platform": d.get("platform_name"),
                "os_version": d.get("os_version"),
                "product_type": _product_type(d.get("product_type_desc")),
                "managed": False,
                "internet_exposure": d.get("internet_exposure"),
                "sensor_version": None,
                "rfm": None,
                "containment": None,
                "prevention_policy": None,
                "ips": TextArray(sorted({str(x) for x in ips if x})),
                "external_ip": d.get("external_ip"),
                "groups": TextArray([]),
                "tags": TextArray([str(x) for x in as_list(d.get("tags"))]),
                "first_seen": parse_ts(d.get("first_seen_timestamp")),
                "last_seen": parse_ts(d.get("last_seen_timestamp")),
                "site_label": m.label,
                "site_tag": m.key,
                "site_matched_by": m.matched_by,
                "collected_at": ctx.run_started,
            })
    return upsert_rows(ctx.conn, "assets", rows, ["source", "source_asset_id"])


def host_site_map(conn) -> Dict[str, Tuple[str, str, str, Dict[str, Any]]]:
    """aid -> (site_label, site_tag, matched_by, extras) from the last hosts pull."""
    cur = conn.cursor()
    cur.execute(
        "SELECT source_asset_id, site_label, site_tag, site_matched_by, product_type, hostname "
        "FROM assets WHERE source = 'falcon'"
    )
    return {r[0]: (r[1], r[2], r[3], {"product_type": r[4], "hostname": r[5]}) for r in cur.fetchall()}
