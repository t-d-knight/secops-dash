#!/usr/bin/env python3
"""
LogicMonitor device inventory -> lm_devices (one row per monitored device).

What it's for: which servers sit in which patch tier / group, and when that
group's current SCCM deployment starts and must be done by. Joined to the
Falcon `assets` table by short hostname (lm_devices.host_key), so a server
still missing patches after its group's deadline, or a server in no patch
group at all, can be told apart from one that simply hasn't been scheduled.

API (confirmed against a live portal, 2026-11-16 probe):
  GET https://<company>.logicmonitor.com/santaba/rest/device/devices
      ?size=&offset=  (X-Version: 3)  -> {total, items: [...], searchId, isMin}
  Each device carries systemProperties / autoProperties / customProperties /
  inheritedProperties as [{name, value}]. The patch schedule is pushed into
  custom properties by an SCCM sync:
      sccm.updateGroup           e.g. "<group name> (Tier 2 - Group B)"
      sccm.deploymentStartRaw    e.g. "11/19/2026 19:00:00", month first, no zone
      sccm.deploymentDeadlineRaw same format
  Property names, the time format and zone are config (collectors.logicmonitor).

Auth is LMv1: HMAC-SHA256 over verb + epoch-ms + body + resource path, hex
digest, base64'd. Read-only: this collector only ever issues GETs.

Credential properties (wmi.pass, snmp.community, ssh.*, ...) come back on
every device, masked by LogicMonitor. They are never stored: only the
properties named in `keep_properties` are kept, and any name that looks like
a credential is dropped even if it's listed there.
"""
import base64
import collections
import datetime as dt
import hashlib
import hmac
import re
import time
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import requests

from collectors.base import RunContext, TextArray, upsert_rows
from http_client import make_session, raise_for_status
from site_resolver import SiteContext

NAME = "logicmonitor"

FIELDS = ("id,displayName,name,deviceType,hostStatus,createdOn,updatedOn,lastDataTime,"
          "systemProperties,autoProperties,customProperties,inheritedProperties")
PROP_KINDS = ("systemProperties", "autoProperties", "inheritedProperties", "customProperties")  # later wins

# Never stored, whatever keep_properties says.
SECRETISH = re.compile(r"(pass|secret|community|token|key|cred|auth|\.user$|username)", re.I)

DEFAULTS = {
    "page_size": 1000,
    "patch_group_property": "sccm.updateGroup",
    "patch_start_property": "sccm.deploymentStartRaw",
    "patch_deadline_property": "sccm.deploymentDeadlineRaw",
    "patch_time_format": "%m/%d/%Y %H:%M:%S",
    "patch_tier_regex": r"Tier\s*(\d+)",
    "patch_subgroup_regex": r"Group\s+([A-Za-z0-9]+)",
}


class LMv1Auth(requests.auth.AuthBase):
    """Signs each request as it's sent (fresh timestamp on every retry)."""

    def __init__(self, access_id: str, access_key: str, prefix: str):
        self.access_id, self.access_key, self.prefix = access_id, access_key, prefix

    def __call__(self, r):
        path = urlparse(r.url).path
        resource = path[len(self.prefix):] if path.startswith(self.prefix) else path
        ts = str(int(time.time() * 1000))
        body = r.body or b""
        body = body.decode() if isinstance(body, bytes) else body
        digest = hmac.new(self.access_key.encode(), (r.method + ts + body + resource).encode(),
                          hashlib.sha256).hexdigest()
        sig = base64.b64encode(digest.encode()).decode()
        r.headers["Authorization"] = f"LMv1 {self.access_id}:{sig}:{ts}"
        return r


def _base_url(c: Dict[str, Any]) -> str:
    if c.get("base_url"):
        return c["base_url"].rstrip("/")
    if not c.get("company"):
        raise RuntimeError("collectors.logicmonitor.company (the portal name in "
                           "https://<company>.logicmonitor.com) missing from config/secrets")
    return f"https://{c['company']}.logicmonitor.com/santaba/rest"


def _session(c: Dict[str, Any], base: str):
    if not c.get("access_id") or not c.get("access_key"):
        raise RuntimeError("collectors.logicmonitor.access_id / access_key missing from secrets.yaml")
    s = make_session()
    s.auth = LMv1Auth(c["access_id"], c["access_key"], urlparse(base).path)
    s.headers.update({"X-Version": "3", "Accept": "application/json"})
    return s


def iter_devices(s, base: str, page_size: int) -> Iterator[Dict[str, Any]]:
    offset, total = 0, None
    while True:
        r = s.get(base + "/device/devices", params={"size": page_size, "offset": offset, "fields": FIELDS})
        raise_for_status(r, "LogicMonitor")
        j = r.json()
        if "items" not in j:    # v1-style envelope {status, errmsg, data} = auth/permission problem
            raise RuntimeError(f"LogicMonitor: unexpected response {str(j)[:300]}")
        items = j.get("items") or []
        total = j.get("total", total)
        yield from items
        offset += len(items)
        if not items or (total is not None and offset >= int(total)):
            break


# ---------------------------------------------------------------- mapping
def props_of(dev: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for kind in PROP_KINDS:
        for p in dev.get(kind) or []:
            if p.get("name"):
                out[p["name"]] = p.get("value")
    return out


def host_key(name: Optional[str]) -> Optional[str]:
    """Short, lower-case hostname: how lm_devices joins to assets.hostname."""
    if not name:
        return None
    n = str(name).strip().lower()
    if not n or re.fullmatch(r"[\d.]+", n) or ":" in n:   # an IP, not a name
        return None
    return n.split(".")[0] or None


def parse_patch(group: Optional[str], cfg: Dict[str, Any]):
    """(tier, subgroup) from the update group name; None where absent."""
    if not group:
        return None, None
    t = re.search(cfg["patch_tier_regex"], group, re.I)
    g = re.search(cfg["patch_subgroup_regex"], group, re.I)
    return (int(t.group(1)) if t else None), (g.group(1).upper() if g else None)


def parse_local(v: Optional[str], fmt: str, tz: dt.tzinfo) -> Optional[dt.datetime]:
    if not v:
        return None
    try:
        return dt.datetime.strptime(str(v).strip(), fmt).replace(tzinfo=tz)
    except ValueError:
        return None


def _epoch(v: Any) -> Optional[dt.datetime]:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    if x <= 0:
        return None
    return dt.datetime.fromtimestamp(x / 1000.0 if x > 1e12 else x, tz=dt.timezone.utc)


def _split(v: Any) -> List[str]:
    return [x.strip() for x in str(v or "").split(",") if x.strip()]


def _db_tz(conn) -> ZoneInfo:
    cur = conn.cursor()
    cur.execute("SHOW timezone")
    return ZoneInfo(cur.fetchone()[0])


def _falcon_sites(conn) -> Dict[str, tuple]:
    """host_key -> (site_label, site_tag) from managed Falcon hosts: the sensor's
    site (tags/groups/OU) is a better signal than anything LogicMonitor has."""
    cur = conn.cursor()
    cur.execute("""SELECT lower(split_part(hostname, '.', 1)), site_label, site_tag FROM assets
                   WHERE source = 'falcon' AND NOT retired AND hostname IS NOT NULL
                   ORDER BY last_seen NULLS FIRST""")
    return {k: (label, tag) for k, label, tag in cur.fetchall() if k}


def to_row(ctx: RunContext, dev: Dict[str, Any], cfg: Dict[str, Any], tz: dt.tzinfo,
           keep: List[str], falcon: Dict[str, tuple]) -> Dict[str, Any]:
    p = props_of(dev)
    hostname = p.get("system.hostname") or dev.get("name")
    sysname = p.get("system.sysname") or p.get("auto.os.computer_name")
    hk = host_key(sysname) or host_key(hostname) or host_key(dev.get("displayName"))
    ips = _split(p.get("system.ips"))
    domain = p.get("auto.os.domain") or p.get("system.domain")
    group = p.get(cfg["patch_group_property"]) or None
    tier, sub = parse_patch(group, cfg)

    if hk and hk in falcon:
        label, tag = falcon[hk]
        by = "falcon_asset"
    else:
        names = [n for n in (hostname, sysname, dev.get("displayName")) if n]
        m = ctx.resolver.resolve(SiteContext(hostnames=names, ips=ips,
                                             ad_domains=[domain] if domain else []))
        label, tag, by = m.label, m.key, m.matched_by

    return {
        "device_id": int(dev["id"]),
        "display_name": dev.get("displayName"),
        "hostname": hostname,
        "host_key": hk,
        "domain": domain,
        "ips": TextArray(ips),
        "device_type": dev.get("deviceType"),
        "host_status": dev.get("hostStatus"),
        "os": (p.get("auto.os.version.description")
               or (p.get("system.sysinfo") or "").split("\n")[0][:200] or None),
        "model": p.get("system.model"),
        "categories": TextArray(_split(p.get("system.categories"))),
        "properties": {k: p[k] for k in keep if k in p and not SECRETISH.search(k)},
        "patch_group": group,
        "patch_tier": tier,
        "patch_subgroup": sub,
        "patch_window_start": parse_local(p.get(cfg["patch_start_property"]), cfg["patch_time_format"], tz),
        "patch_deadline": parse_local(p.get(cfg["patch_deadline_property"]), cfg["patch_time_format"], tz),
        "created_on": _epoch(dev.get("createdOn")),
        "last_data_at": _epoch(dev.get("lastDataTime")),
        "site_label": label,
        "site_tag": tag,
        "site_matched_by": by,
        "retired": False,
        "collected_at": ctx.run_started,
    }


def run(ctx: RunContext) -> Dict[str, Any]:
    cfg = dict(DEFAULTS, **{k: v for k, v in ctx.ccfg.items() if v is not None})
    base = _base_url(cfg)
    s = _session(cfg, base)
    tz = ZoneInfo(cfg["patch_timezone"]) if cfg.get("patch_timezone") else _db_tz(ctx.conn)
    keep = list(cfg.get("keep_properties") or [])
    dropped = [k for k in keep if SECRETISH.search(k)]
    if dropped:
        ctx.log(f"not storing credential-like properties listed in keep_properties: {dropped}")
    falcon = _falcon_sites(ctx.conn)

    rows = [to_row(ctx, d, cfg, tz, keep, falcon) for d in iter_devices(s, base, int(cfg["page_size"]))]
    n = upsert_rows(ctx.conn, "lm_devices", rows, ["device_id"])
    if rows:   # a complete pull: anything not seen this run has left LogicMonitor
        cur = ctx.conn.cursor()
        cur.execute("UPDATE lm_devices SET retired = TRUE WHERE collected_at < %s AND NOT retired",
                    (ctx.run_started,))
        retired = cur.rowcount
        ctx.conn.commit()
    else:
        retired = 0

    with_group = [r for r in rows if r["patch_group"]]
    return {
        "rows": n,
        "retired": retired,
        "with_patch_group": len(with_group),
        "patch_group_unparsed_tier": sum(1 for r in with_group if r["patch_tier"] is None),
        "patch_dates_unparsed": sum(1 for r in with_group
                                    if r["patch_window_start"] is None or r["patch_deadline"] is None),
        "by_tier": dict(collections.Counter(str(r["patch_tier"]) for r in with_group)),
        "by_match": dict(collections.Counter(r["site_matched_by"] for r in rows)),
    }
