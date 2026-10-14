#!/usr/bin/env python3
"""
Patch status and server load from Falcon, for the Servers dashboard:

  host_patch_status  every managed host, from Spotlight's installed-patches
                     view (GET /spotlight/combined/installed-patches/v1 --
                     the console's Exposure Management > Patches page):
                     last patch confirmed, pending / active patch counts,
                     reboot required, the installed patch list.
  host_insights      servers and DCs only, from Discover's system insights:
                     disk used, CPU and memory load (Falcon's averages),
                     Falcon's computed roles (web, backup, database, ...),
                     criticality, end-of-life OS, form factor.

Both are "right now" tables replaced each run; hosts no longer returned are
removed. Scopes: Spotlight vulnerabilities read (same as falcon_spotlight),
Falcon Discover read.
"""
from typing import Any, Dict, List

from collectors.base import RunContext, TextArray, as_list, parse_ts, upsert_rows
from collectors.falcon_client import FalconClient

NAME = "falcon_patches"
SERVERS = "entity_type:'managed'+product_type_desc:['Server','Domain Controller']"


def _num(v: Any):
    try:
        return float(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def _yes(v: Any):
    return None if v is None else str(v).strip().lower() in ("yes", "true", "1")


def run(ctx: RunContext) -> Dict[str, Any]:
    fc = FalconClient(ctx.cfg, ctx.ccfg)
    cur = ctx.conn.cursor()
    stats: Dict[str, Any] = {}

    rows: List[Dict[str, Any]] = []
    for r in fc.iter_after("/spotlight/combined/installed-patches/v1",
                           {"limit": int(ctx.ccfg.get("page_size", 400))}):
        if not r.get("aid"):
            continue
        rows.append({
            "aid": r["aid"],
            "hostname": r.get("hostname"),
            "device_type": r.get("device_type"),
            "reboot_required": r.get("reboot_required"),
            "active_patches": r.get("active_patches"),
            "pending_patches": r.get("pending_patches"),
            "last_patch_confirmed": parse_ts(r.get("last_patch_confirmed")),
            "installed_patches": [{"id": p.get("id"), "status": p.get("status")}
                                  for p in as_list(r.get("installed_patches")) if isinstance(p, dict)],
            "collected_at": ctx.run_started,
        })
    stats["patch_hosts"] = upsert_rows(ctx.conn, "host_patch_status", rows, ["aid"])
    if rows:   # a complete pull: drop hosts it no longer returns
        cur.execute("DELETE FROM host_patch_status WHERE collected_at < %s", (ctx.run_started,))
        stats["patch_hosts_removed"] = cur.rowcount
    ctx.log(f"{len(rows)} hosts with patch status")

    if ctx.ccfg.get("server_insights", True):
        ins: List[Dict[str, Any]] = []
        try:
            for d in fc.iter_after("/discover/combined/hosts/v1",
                                   {"filter": SERVERS, "limit": 100,
                                    "facet": ["system_insights", "risk_factors"]}):   # roles come with risk_factors
                if not d.get("aid"):
                    continue
                ins.append({
                    "aid": d["aid"],
                    "disk_used_pct": _num(d.get("used_disk_space_pct")),
                    "disk_total_gb": _num(d.get("total_disk_space")),
                    "disk_free_gb": _num(d.get("available_disk_space")),
                    "cpu_avg_pct": _num(d.get("average_processor_usage")),
                    "cpu_max_pct": _num(d.get("max_processor_usage")),
                    "mem_avg_pct": _num(d.get("average_memory_usage_pct")),
                    "mem_max_pct": _num(d.get("max_memory_usage_pct")),
                    "mem_total_mb": _num(d.get("total_memory")),
                    "asset_roles": TextArray([str(x) for x in as_list(d.get("computed_asset_roles"))
                                              if x != "Server by behavior"]),
                    "criticality": d.get("criticality"),
                    "os_is_eol": _yes(d.get("os_is_eol")),
                    "internet_exposure": d.get("computed_internet_exposure") or d.get("internet_exposure"),
                    "encryption_status": d.get("encryption_status"),
                    "form_factor": d.get("form_factor"),
                    "collected_at": ctx.run_started,
                })
            stats["server_insights"] = upsert_rows(ctx.conn, "host_insights", ins, ["aid"])
            if ins:
                cur.execute("DELETE FROM host_insights WHERE collected_at < %s", (ctx.run_started,))
            ctx.log(f"{len(ins)} servers with system insights")
        except Exception as e:   # Discover scope missing -> keep the patch half
            ctx.log(f"server insights skipped: {e}")
            stats["server_insights_error"] = str(e)[:300]
    ctx.conn.commit()
    return stats
