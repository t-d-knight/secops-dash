#!/usr/bin/env python3
"""
Removable media (USB) activity from Falcon, per site:

  usb_file_writes_daily  files written to USB/removable drives, rolled up per
                         day x PC x user x USB device x top folder x category
                         (files, bytes, sample file names). Source: NG-SIEM
                         search (collectors/queries/usb_file_writes.cql), or
                         console CSV exports of that query (`mode: csv`).
  usb_scans              on-demand scans Falcon starts when a USB drive is
                         plugged in (ODS initiated_from = auto_usb): what was
                         scanned, what was malicious, what was quarantined.

Detections from those scans are Falcon alerts (type 'ods') and land in
security_alerts via falcon_alerts, which keeps their scan_id -- reports join
them to usb_scans to tell USB-insertion detections from scheduled scans.

Why rolled up: one person copying a portable app onto a stick writes hundreds
of icons and config files in a minute. Per-folder, per-category rows keep
that to one line while still showing which documents, spreadsheets or
mailbox exports left on which device. Office lock/temp files and recycle-bin
stubs are dropped.

Days are the server's local calendar days. Each run re-pulls the last
`overlap_days` whole days (late events from PCs that were offline) and
replaces them; --full goes back `lookback_days`.

Scopes: NGSIEM read+write (starting a search is a write in CrowdStrike's
model; the collector only reads), NGSIEM Lookup Files read (user names /
titles from falconUserIdentityContext.csv), On-demand scans (ODS) read.
"""
import csv
import datetime as dt
import glob
import io
import os
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import usb_categories as uc
from collectors.base import RunContext, TextArray, as_list, parse_ts, upsert_rows
from collectors.falcon_client import FalconClient
from collectors.falcon_hosts import host_site_map
from site_resolver import SiteContext

NAME = "falcon_usb"
QUERY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "queries", "usb_file_writes.cql")
SAMPLES = 10            # file names kept per rolled-up row
ODS_PAGE_CAP = 9000     # ODS offset paging errors out near 10k; busier windows are split


# ------------------------------------------------------------ file writes
def _query() -> str:
    with open(QUERY_FILE) as f:
        return "\n".join(line for line in f if not line.lstrip().startswith("//"))


def _search_day(fc: FalconClient, repo: str, query: str, lo: dt.datetime, hi: dt.datetime,
                timeout_s: int) -> List[Dict[str, Any]]:
    path = f"/humio/api/v1/repositories/{repo}/queryjobs"
    job = fc.post(path, {"queryString": query, "start": int(lo.timestamp() * 1000),
                         "end": int(hi.timestamp() * 1000), "isLive": False})
    jid = job["id"]
    try:
        deadline = time.time() + timeout_s
        while True:
            res = fc.get(f"{path}/{jid}")
            if res.get("cancelled"):
                raise RuntimeError(f"search cancelled by NG-SIEM: {res.get('messages')}")
            if res.get("done"):
                return res.get("events") or []
            if time.time() > deadline:
                raise RuntimeError(f"search still running after {timeout_s}s")
            time.sleep(2)
    finally:
        try:
            fc.s.delete(f"{fc.base}{path}/{jid}", headers=fc._h())
        except Exception:
            pass


def _iter_csv(paths: Iterable[str]) -> Iterator[Dict[str, Any]]:
    for pattern in paths:
        for p in sorted(glob.glob(pattern)):
            with open(p, newline="", encoding="utf-8-sig") as f:
                yield from csv.DictReader(f)


def _identity_lookup(fc: FalconClient, ctx: RunContext, repo: str) -> Dict[str, Tuple[str, str, str]]:
    """lower(sAMAccountName) -> (full name, title, department) from Falcon's
    user identity lookup file. Optional: without it rows keep the bare username."""
    name = ctx.ccfg.get("identity_lookup", "falconUserIdentityContext.csv")
    if not name:
        return {}
    try:
        text = fc.download(f"/humio/api/v1/repositories/{repo}/files/{name}")
    except Exception as e:
        ctx.log(f"identity lookup {name} unavailable ({e}); usernames only")
        return {}
    out: Dict[str, Tuple[str, str, str]] = {}
    for r in csv.DictReader(io.StringIO(text)):
        sam = (r.get("user.active_directory.samaccountname") or "").strip().lower()
        if not sam:
            continue
        enabled = (r.get("user.active_directory.is_enabled") or "").lower() == "true"
        if sam in out and not enabled:   # same sAM in two domains: prefer the enabled account
            continue
        out[sam] = ((r.get("user.full_name") or r.get("displayName") or "").strip(),
                    (r.get("user.title") or "").strip(), (r.get("user.department") or "").strip())
    return out


def _bare_user(u: Optional[str]) -> str:
    u = (u or "").strip()
    if u in ("--", "-"):
        return ""
    return u.rsplit("\\", 1)[-1]


def _rollup(ctx: RunContext, events: Iterable[Dict[str, Any]],
            hosts: Dict[str, Tuple], people: Dict[str, Tuple[str, str, str]]) -> Tuple[List[Dict[str, Any]], int, int]:
    groups: Dict[Tuple, Dict[str, Any]] = {}
    seen = noise = 0
    for e in events:
        seen += 1
        name = (e.get("FileName") or "").strip()
        if uc.is_noise(name, e.get("FilePath")):
            noise += 1
            continue
        ts = parse_ts(e.get("@timestamp"))
        if ts is None:
            continue
        aid = (e.get("aid") or "").strip()
        user = _bare_user(e.get("UserName"))
        serial = (e.get("DeviceSerialNumber") or "").strip()
        serial = "" if serial in ("--", "NA") else serial
        cat = uc.categorise(name, e.get("writtenFileType"))
        key = (ts.astimezone().date(), aid, user.lower(), serial, uc.folder(e.get("FilePath")), cat)
        g = groups.get(key)
        if g is None:
            host = (e.get("ComputerName") or "").strip()
            if aid in hosts:
                label, tag, by, extra = hosts[aid]
                host = host or (extra or {}).get("hostname") or ""
            else:
                m = ctx.resolver.resolve(SiteContext(hostnames=as_list(host or None)))
                label, tag, by = m.label, m.key, m.matched_by
            full, title, dept = people.get(user.lower(), ("", "", ""))
            make = (e.get("DeviceManufacturer") or "").strip()
            model = (e.get("DeviceProduct") or "").strip()
            g = groups[key] = {
                "day": key[0], "aid": aid, "user_name": user, "user_key": key[2], "device_serial": serial,
                "folder": key[4],
                "category": cat, "hostname": host, "display_name": full or None, "title": title or None,
                "department": dept or None, "device_make": None if make in ("", "NA") else make,
                "device_model": None if model in ("", "NA") else model,
                "connection_type": e.get("ConnectionType") or None, "platform": e.get("event_platform") or None,
                "files": 0, "bytes": 0, "first_write": ts, "last_write": ts, "_samples": {}, "_types": set(),
                "site_label": label, "site_tag": tag, "site_matched_by": by,
            }
        g["files"] += 1
        try:
            size = int(float(e.get("Size") or 0))
        except ValueError:
            size = 0
        g["bytes"] += size
        g["first_write"] = min(g["first_write"], ts)
        g["last_write"] = max(g["last_write"], ts)
        if name:
            g["_samples"][name] = max(size, g["_samples"].get(name, 0))
        ext = uc.extension(name)
        if ext:
            g["_types"].add(ext)
    rows = []
    for g in groups.values():
        biggest = sorted(g.pop("_samples").items(), key=lambda kv: -kv[1])[:SAMPLES]
        g["sample_files"] = TextArray(n for n, _ in biggest)
        g["file_types"] = TextArray(sorted(g.pop("_types")))
        rows.append(g)
    return rows, seen, noise


def _replace_days(ctx: RunContext, days: List[dt.date], rows: List[Dict[str, Any]]) -> None:
    cur = ctx.conn.cursor()
    cur.execute("DELETE FROM usb_file_writes_daily WHERE day = ANY(%s::date[])", (days,))
    ctx.conn.commit()
    upsert_rows(ctx.conn, "usb_file_writes_daily", rows,
                ["day", "aid", "user_key", "device_serial", "folder", "category"])


def collect_writes(ctx: RunContext, fc: Optional[FalconClient], hosts: Dict[str, Tuple]) -> Dict[str, Any]:
    repo = ctx.ccfg.get("repository", "search-all")
    people = _identity_lookup(fc, ctx, repo) if fc else {}
    stats: Dict[str, Any] = {}
    if ctx.ccfg.get("mode", "api") == "csv":
        paths = as_list((ctx.ccfg.get("csv") or {}).get("paths"))
        rows, seen, noise = _rollup(ctx, _iter_csv(paths), hosts, people)
        days = sorted({r["day"] for r in rows})
        if days:
            _replace_days(ctx, days, rows)
        ctx.log(f"csv: {seen} file writes ({noise} temp files dropped) -> {len(rows)} rows over {len(days)} days")
        return {"write_events": seen, "write_rows": len(rows), "write_days": len(days)}

    query = _query()
    timeout_s = int(ctx.ccfg.get("search_timeout_s", 600))
    today = ctx.run_started.astimezone().date()
    overlap = int(ctx.ccfg.get("overlap_days", 2))
    start = ctx.since(NAME, default_days=int(ctx.ccfg.get("lookback_days", 30)),
                      overlap_hours=24 * overlap).astimezone().date()
    total_seen = total_rows = 0
    day = start
    while day <= today:
        lo = dt.datetime.combine(day, dt.time.min).astimezone()
        hi = min(dt.datetime.combine(day + dt.timedelta(days=1), dt.time.min).astimezone(),
                 ctx.run_started.astimezone())
        events = _search_day(fc, repo, query, lo, hi, timeout_s)
        rows, seen, noise = _rollup(ctx, events, hosts, people)
        # a day's events can include ones the sensor stamped just outside it;
        # keep only the day being replaced so neighbouring days stay intact
        rows = [r for r in rows if r["day"] == day]
        _replace_days(ctx, [day], rows)
        ctx.log(f"{day}: {seen} file writes ({noise} temp files dropped) -> {len(rows)} rows")
        total_seen += seen
        total_rows += len(rows)
        day += dt.timedelta(days=1)
    stats.update(write_events=total_seen, write_rows=total_rows, write_days=(today - start).days + 1)
    return stats


# ------------------------------------------------------------- USB scans
def _scan_ids(fc: FalconClient, base_filter: str, lo: dt.datetime, hi: dt.datetime) -> List[str]:
    """IDs of USB-triggered scans updated in [lo, hi), splitting the window
    while it holds more than ODS offset paging can reach."""
    fql = (f"{base_filter}+last_updated:>='{lo.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
           f"+last_updated:<'{hi.strftime('%Y-%m-%dT%H:%M:%SZ')}'")
    j = fc.get("/ods/queries/scans/v1", {"filter": fql, "limit": 1})
    total = (j.get("meta", {}).get("pagination") or {}).get("total") or 0
    if total > ODS_PAGE_CAP and hi - lo > dt.timedelta(minutes=10):
        mid = lo + (hi - lo) / 2
        return _scan_ids(fc, base_filter, lo, mid) + _scan_ids(fc, base_filter, mid, hi)
    return list(fc.iter_offset_ids("/ods/queries/scans/v1", {"filter": fql, "sort": "last_updated|asc"}, limit=500))


def collect_scans(ctx: RunContext, fc: FalconClient, hosts: Dict[str, Tuple]) -> Dict[str, Any]:
    since = ctx.since(NAME, default_days=int(ctx.ccfg.get("lookback_days", 30)))
    hi = ctx.run_started
    ids = _scan_ids(fc, "initiated_from:'auto_usb'", since.astimezone(dt.timezone.utc), hi.astimezone(dt.timezone.utc))
    rows = []
    for i in range(0, len(ids), 100):
        for s in fc.get("/ods/entities/scans/v2", {"ids": ids[i:i + 100]}).get("resources") or []:
            aid = next(iter(as_list(s.get("hosts"))), None)
            fcnt = s.get("filecount") or {}
            if aid in hosts:
                label, tag, by, extra = hosts[aid]
                hostname = (extra or {}).get("hostname")
            else:
                m = ctx.resolver.resolve(SiteContext())
                label, tag, by, hostname = m.label, m.key, m.matched_by, None
            rows.append({
                "scan_id": s["id"], "aid": aid, "hostname": hostname,
                "created_on": parse_ts(s.get("created_on")), "completed_on": parse_ts(s.get("scan_completed_on")),
                "last_updated": parse_ts(s.get("last_updated")), "status": s.get("status"),
                "drives": TextArray(as_list(s.get("scan_inclusions") or s.get("file_paths"))),
                "files_traversed": fcnt.get("traversed"), "files_scanned": fcnt.get("scanned"),
                "files_malicious": fcnt.get("malicious"), "files_quarantined": fcnt.get("quarantined"),
                "site_label": label, "site_tag": tag, "site_matched_by": by,
            })
    n = upsert_rows(ctx.conn, "usb_scans", rows, ["scan_id"])
    ctx.log(f"{n} USB-insertion scans updated since {since:%Y-%m-%d %H:%M}")
    return {"scans": n}


def run(ctx: RunContext) -> Dict[str, Any]:
    hosts = host_site_map(ctx.conn)
    csv_only = ctx.ccfg.get("mode", "api") == "csv" and not ctx.cfg.get("crowdstrike", {}).get("client_id")
    fc = None if csv_only else FalconClient(ctx.cfg, ctx.ccfg)
    stats: Dict[str, Any] = {}
    errors = []
    # each half is independent: a missing NG-SIEM scope mustn't stop the scan feed
    for part, fn in (("file writes", lambda: collect_writes(ctx, fc, hosts)),
                     ("USB scans", lambda: collect_scans(ctx, fc, hosts) if fc else {})):
        if part == "USB scans" and not ctx.ccfg.get("scans", True):
            continue
        try:
            stats.update(fn())
        except Exception as e:
            ctx.conn.rollback()
            errors.append(f"{part}: {type(e).__name__}: {e}")
            ctx.log(f"{part} FAILED: {e}")
    if errors and not stats:
        raise RuntimeError("; ".join(errors))
    if errors:
        stats.update(partial=True, errors=errors)
    return stats
