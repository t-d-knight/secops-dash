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
import datetime as dt
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from collectors.base import RunContext, TextArray, as_list, parse_ts, upsert_rows
from collectors.falcon_client import FalconClient
from discovery_classes import DISCOVERY_CLASSES  # noqa: F401 (re-exported for callers)
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
                "mac_addresses": TextArray([m for m in (_mac(x) for x in as_list(d.get("mac_address"))) if m]),
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
            stats["unmanaged_assets"], stats["unmanaged_by_class"] = _pull_unmanaged(ctx, fc, rows)
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


# ---------------------------------------------------------------- unmanaged
# Discover's "unmanaged" list mixes real machines with no sensor and a lot
# of things that aren't missing endpoints at all. Classified from what
# Discover itself provides (2026-10-06, 1,298 records): data provider (AD
# computer object vs passively seen on the wire), AD userAccountControl and
# enabled flag, OS, MAC + vendor, description. Discover's own
# ad_virtual_server flag was "No" on every record, so it isn't used.
_SERVICE_ACCT = re.compile(r"(G?MSA|_MSA)$|^AZUREADSSOACC", re.I)
# Only applied to AD accounts with no OS, so a loose match can't swallow a
# real machine: EXDAG01, BHPSQLAG05, SQL-LSNR, FILE-CLUSTER...
_CLUSTER_NAME = re.compile(r"(^|[-_])(LSNR|LISTENER|CLUS(TER)?|CNO)([-_]|\d|$)|DAG\d*$|SQLAG\d*$|[-_]AG\d*$", re.I)
UAC_DISABLED, UAC_SERVER_TRUST = 0x2, 0x2000


def _mac(v: Any) -> Optional[str]:
    h = re.sub(r"[^0-9a-f]", "", str(v or "").lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else None


def classify_unmanaged(d: Dict[str, Any], managed_names: Set[str], managed_macs: Set[str],
                       now: dt.datetime, out_of_scope_ous: Optional[Set[str]] = None) -> Tuple[str, Optional[str]]:
    """-> (discovery_class, managed twin hostname or None). Order matters:
    "is this really something we already manage / not a machine" first,
    then "what kind of machine is missing a sensor"."""
    providers = [str(p) for p in as_list(d.get("data_providers"))]
    name = (d.get("hostname") or "").rstrip("$").upper()
    if name and name in managed_names:
        return "duplicate_of_managed", name
    macs = {m for m in (_mac(x) for x in as_list(d.get("mac_addresses"))) if m}
    if macs & managed_macs:
        return "secondary_ip_of_managed", None
    # Services in a shared AD that run their own Falcon tenant, or have left
    # the organisation: their computer accounts have no sensor *here* by
    # design. Matched on an exact OU segment name.
    if out_of_scope_ous and {str(o).lower() for o in as_list(d.get("ous"))} & out_of_scope_ous:
        return "out_of_scope", None
    if "Active Directory" in providers:
        try:
            uac = int(d.get("ad_user_account_control") or 0)
        except (TypeError, ValueError):
            uac = 0
        os_ver = d.get("os_version") or ""
        if uac & UAC_DISABLED or str(d.get("account_enabled")).lower() == "no":
            return "disabled_ad_account", None
        last = parse_ts(d.get("last_seen_timestamp"))
        if last and (now - last).days > 60:
            return "stale_ad_account", None
        if not os_ver:
            if _SERVICE_ACCT.search(name):
                return "service_account", None
            if _CLUSTER_NAME.search(name):
                return "cluster_name", None
            return "appliance_ad_account", None
        if uac & UAC_SERVER_TRUST:
            return "domain_controller_no_sensor", None
        return ("server_no_sensor" if "server" in os_ver.lower() else "workstation_no_sensor"), None
    if any("cloud" in p.lower() for p in providers) or d.get("cloud_provider"):
        return "cloud_no_sensor", None
    if "vmware" in str(d.get("system_manufacturer") or "").lower():
        return "vmware_nic", None
    return "network_device", None


def _pull_unmanaged(ctx: RunContext, fc: FalconClient, managed_rows: List[Dict[str, Any]]) -> Tuple[int, Dict[str, int]]:
    flt = ctx.ccfg.get("unmanaged_filter", "entity_type:'unmanaged'")
    managed_names = {str(r["hostname"]).upper() for r in managed_rows if r.get("hostname")}
    # aid -> (label, key) of the managed hosts from this same run: a device
    # only seen on the wire has no AD/OU data, but the sensors that
    # discovered it sit on the same network, so their site is its site.
    managed_site = {r["source_asset_id"]: (r["site_label"], r["site_tag"]) for r in managed_rows}
    ungrouped = ctx.cfg.get("ungrouped_label", "Ungrouped")
    out_of_scope = {str(o).lower() for o in (ctx.ccfg.get("out_of_scope_ous") or {})}
    managed_macs = {m for r in managed_rows for m in (r.get("mac_addresses") or [])}
    now = dt.datetime.now(dt.timezone.utc)
    by_class: Dict[str, int] = {}
    ids = list(fc.iter_offset_ids("/discover/queries/hosts/v1", {"filter": flt}, limit=100))
    rows = []
    for i in range(0, len(ids), 100):
        j = fc.get("/discover/entities/hosts/v1", {"ids": ids[i:i + 100]})
        for d in j.get("resources") or []:
            ips = as_list(d.get("current_local_ip")) + as_list(d.get("local_ip_addresses"))
            # `ous` is the OU segment list (["SITE-A Servers", "SITE-A"]), the same
            # shape managed hosts' `ou` has; `ou` here is the full DN string.
            ous = [str(x) for x in as_list(d.get("ous"))] or [str(x) for x in as_list(d.get("ou"))]
            sc = SiteContext(
                ad_domains=as_list(d.get("machine_domain")),
                ous=ous,
                ad_sites=as_list(d.get("site_name")),
                hostnames=as_list(d.get("hostname")),
                ips=ips,
            )
            m = ctx.resolver.resolve(sc)
            label, key, by = m.label, m.key, m.matched_by
            if label == ungrouped:
                votes: Dict[Tuple[str, str], int] = {}
                for aid in as_list(d.get("discoverer_aids")):
                    st = managed_site.get(aid)
                    if st and st[0] != ungrouped:
                        votes[st] = votes.get(st, 0) + 1
                if votes:
                    (label, key), _ = max(votes.items(), key=lambda kv: kv[1])
                    by = "discoverer"
            cls, twin = classify_unmanaged(d, managed_names, managed_macs, now, out_of_scope)
            by_class[cls] = by_class.get(cls, 0) + 1
            try:
                uac = int(d["ad_user_account_control"]) if d.get("ad_user_account_control") is not None else None
            except (TypeError, ValueError):
                uac = None
            enabled = str(d.get("account_enabled")).lower()
            rows.append({
                "source": "falcon_unmanaged",
                "source_asset_id": d.get("id"),
                "hostname": d.get("hostname"),
                "domain": d.get("machine_domain"),
                "ous": TextArray(ous),
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
                "mac_addresses": TextArray(sorted({m for m in (_mac(x) for x in as_list(d.get("mac_addresses"))) if m})),
                "mac_vendor": d.get("system_manufacturer"),
                "data_providers": TextArray([str(x) for x in as_list(d.get("data_providers"))]),
                "ad_uac": uac,
                "ad_enabled": True if enabled == "yes" else False if enabled == "no" else None,
                "ad_created": parse_ts(d.get("creation_timestamp")),
                "description": "; ".join(str(x) for x in as_list(d.get("descriptions")))[:500] or None,
                "discovery_class": cls,
                "managed_twin": twin,
                "first_seen": parse_ts(d.get("first_seen_timestamp")),
                "last_seen": parse_ts(d.get("last_seen_timestamp")),
                "site_label": label,
                "site_tag": key,
                "site_matched_by": by,
                "collected_at": ctx.run_started,
            })
    return upsert_rows(ctx.conn, "assets", rows, ["source", "source_asset_id"]), by_class


def host_site_map(conn) -> Dict[str, Tuple[str, str, str, Dict[str, Any]]]:
    """aid -> (site_label, site_tag, matched_by, extras) from the last hosts pull."""
    cur = conn.cursor()
    cur.execute(
        "SELECT source_asset_id, site_label, site_tag, site_matched_by, product_type, hostname "
        "FROM assets WHERE source = 'falcon'"
    )
    return {r[0]: (r[1], r[2], r[3], {"product_type": r[4], "hostname": r[5]}) for r in cur.fetchall()}
