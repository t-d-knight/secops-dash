#!/usr/bin/env python3
"""
Falcon Exposure Management / Spotlight vulnerabilities -> vuln_findings
(source='falcon_spotlight'). Replaces the Tenable export adapter.

Each run:
  1. Pulls open/reopened vulns with the cve / host_info / remediation facets:
     EVERY one on a full pull (so anything that vanished can be detected), or
     only those updated since the last good run on an incremental one (see
     open_pull below).
  2. Pulls closed/expired vulns updated since the last good run (incremental),
     which is what feeds MTTR.
  3. Full pulls only: marks rows that were open last time but absent from (1)
     as EXPIRED.
  4. Sets last_found from the host's sensor last_seen, so the rollups'
     days_last_seen staleness rule means "host checked in recently" exactly
     as it did for Tenable -- Spotlight's own updated_timestamp only moves
     when the vuln changes, which would wrongly age out long-standing vulns.

open_pull (config): "full" (default) pulls every open vuln every run. At
~1.45M records/hour that grows with the estate's open count (11M+ after the
Oct 2026 Patch Tuesday = 7-8 h, and a cursor expiring part-way doubles it).
"incremental" pulls only what changed, with a full pull on full_pull_weekdays
(default Saturday) or whenever the last good full pull is over 8 days old --
that full pull is what catches vulns that vanish without being closed or
expired. --full always does a full pull.

A full pull is split into created_timestamp windows (full_pull_chunk_days,
default 1 day), each its own short-lived cursor. Falcon expires a search
context part-way through a long pull ("Search context expired, 'after' key
no longer valid"), and from Nov 2026 it did so on most full pulls of the
whole estate; a window that loses its cursor is halved and pulled again, so
a drop costs minutes, not the whole pull. Vanished vulns are only EXPIRED
when every window came back and the total matches Falcon's own count.

If a full pull still can't finish, the run falls back to an incremental pull
(so the night's changes and fixes still land), skips expiring, and reports
'partial' (a Pushover message; the catch-up doesn't retry it). The next
night tries the full pull again, because the last good one is still old.
A --catch-up run never does a full pull: it would hold the collector lock
for hours while the reports and publish wait on it.

Suppressed vulns (accepted risk / compensating control / false positive)
land as state SUPPRESSED: visible, but excluded from open counts and SLA.
"""
import datetime as dt
from typing import Any, Dict, Optional

import cvss
from collectors.base import RunContext, as_list, parse_ts
from collectors.falcon_client import CursorExpired, FalconClient
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
        cve_description=(cve.get("description") or "")[:2000] or None,   # -> cve_descriptions, once per CVE
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


EPOCH = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)


def _fql_ts(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _windows(now: dt.datetime, chunk_days: float, span_days: float):
    """created_timestamp windows [lo, hi) covering everything: one catch-all for
    anything older than span_days, then chunk_days steps up to tomorrow (nothing
    can be created after that during this run). Whole seconds, so FQL's
    >= / < bounds neither overlap nor leave gaps."""
    end = (now + dt.timedelta(days=1)).replace(microsecond=0)
    start = end - dt.timedelta(days=span_days)
    step = dt.timedelta(days=chunk_days)
    out, t = [(EPOCH, start)], start
    while t < end:
        out.append((t, min(t + step, end)))
        t += step
    return out


def _full_open_pull(ctx: RunContext) -> bool:
    if ctx.full:
        return True
    if ctx.catch_up:
        return False
    if str(ctx.ccfg.get("open_pull", "full")).lower() != "incremental":
        return True
    if ctx.run_started.astimezone().weekday() in [int(d) for d in ctx.ccfg.get("full_pull_weekdays", [5])]:
        return True
    cur = ctx.conn.cursor()
    cur.execute("""SELECT max(started_at) FROM collector_runs WHERE collector = %s AND status = 'ok'
                   AND COALESCE(stats->>'open_pull', 'full') = 'full'""", (NAME,))
    last_full = cur.fetchone()[0]
    return last_full is None or ctx.run_started - last_full > dt.timedelta(days=8)


def run(ctx: RunContext) -> Dict[str, Any]:
    fc = FalconClient(ctx.cfg, ctx.ccfg)
    hosts = host_site_map(ctx.conn)
    require_exploit = ctx.cfg.get("reporting", {}).get("require_exploit_for_remote_no_auth", True)
    page = int(ctx.ccfg.get("page_size", 1000))
    extra = ctx.ccfg.get("filter")  # optional extra FQL ANDed onto both pulls
    w = FindingsWriter(ctx.conn)

    seen = {"n": 0}   # records written this run, for the progress log

    def drain(fql: str, label: str) -> int:
        """One pass over a cursor. Raises CursorExpired if Falcon drops it."""
        if extra:
            fql = f"{fql}+{extra}"
        n = 0
        try:
            for rec in fc.iter_after(PATH, {"filter": fql, "facet": FACETS, "limit": page}):
                w.add(to_finding(rec, hosts, fc, ctx.resolver, require_exploit))
                n += 1
                seen["n"] += 1
                if seen["n"] % 50000 == 0:
                    ctx.log(f"{label}: {seen['n']} records...")
        except CursorExpired:
            w.flush()   # what did arrive is kept (upserts); a re-pull rewrites nothing unchanged
            raise
        w.flush()
        return n

    def pull(fql: str, label: str) -> int:
        """Incremental / closed pulls (short): if the cursor drops, start again once."""
        seen["n"] = 0
        for attempt in (1, 2):
            try:
                n = drain(fql, label)
                ctx.log(f"{label}: {n} records")
                return n
            except CursorExpired as e:
                if attempt == 2:
                    raise
                ctx.log(f"{label}: cursor dropped ({e}) -- restarting the pull")
        return 0

    def total(fql: str) -> Optional[int]:
        """Falcon's own count for a filter (one record fetched), or None."""
        if extra:
            fql = f"{fql}+{extra}"
        try:
            j = fc.get(PATH, {"filter": fql, "facet": FACETS, "limit": 1})
            t = (j.get("meta", {}).get("pagination") or {}).get("total")
            return int(t) if t is not None else None
        except Exception as e:   # the count is a cross-check, not worth failing the run over
            ctx.log(f"open: couldn't get Falcon's total ({type(e).__name__}: {str(e)[:200]})")
            return None

    def full_pull(fql: str) -> Dict[str, Any]:
        """Every open vuln, window by window. A window whose cursor drops is
        halved and both halves pulled; one already at the minimum width, or
        running out of splits, raises CursorExpired."""
        chunk_days = float(ctx.ccfg.get("full_pull_chunk_days", 1))
        span_days = float(ctx.ccfg.get("full_pull_span_days", 400))
        min_win = dt.timedelta(minutes=float(ctx.ccfg.get("full_pull_min_window_minutes", 60)))
        max_splits = int(ctx.ccfg.get("full_pull_max_splits", 200))
        wins = _windows(ctx.run_started, chunk_days, span_days)
        todo = list(reversed(wins))
        got, splits = 0, 0
        seen["n"] = 0
        ctx.log(f"open: full pull in {len(wins)} created_timestamp windows")
        while todo:
            lo, hi = todo.pop()
            wfql = f"{fql}+created_timestamp:>='{_fql_ts(lo)}'+created_timestamp:<'{_fql_ts(hi)}'"
            before = seen["n"]
            try:
                got += drain(wfql, "open")
            except CursorExpired as e:
                span = f"{_fql_ts(lo)}..{_fql_ts(hi)}"
                if hi - lo <= min_win or splits >= max_splits:
                    raise CursorExpired(f"window {span} still failing after {splits} splits: {e}") from e
                splits += 1
                mid = lo + dt.timedelta(seconds=int((hi - lo).total_seconds() // 2))
                ctx.log(f"open: cursor dropped in window {span} after {seen['n'] - before} records "
                        f"-- splitting it ({splits}/{max_splits})")
                todo.extend([(mid, hi), (lo, mid)])   # lo half next
        ctx.log(f"open: {got} records ({len(wins)} windows, {splits} splits)")
        return {"open": got, "full_pull_windows": len(wins), "full_pull_splits": splits}

    since = ctx.since(NAME, default_days=int(ctx.ccfg.get("closed_lookback_days", 30)))
    since_fql = since.strftime('%Y-%m-%dT%H:%M:%SZ')
    incr_fql = f"status:['open','reopen']+updated_timestamp:>'{since_fql}'"
    stats: Dict[str, Any] = {}
    full = _full_open_pull(ctx)
    expired = 0
    if full:
        open_fql = "status:['open','reopen']"
        t0 = total(open_fql)
        try:
            stats.update(full_pull(open_fql))
        except CursorExpired as e:
            # Keep the night useful: what the windows did pull is stored; pick up
            # the rest of the changes incrementally, don't expire anything.
            full = False
            stats["full_pull.error"] = str(e)[:300]
            ctx.log(f"open: full pull failed ({str(e)[:300]}) -- falling back to an incremental pull, "
                    f"nothing expired this run")
            ctx.log(f"open: incremental, updated since {since_fql}")
            stats["open"] = pull(incr_fql, "open")
        else:
            t1 = total(open_fql)
            # vulns closed during a long pull lower the count, so compare with the smaller one
            counts = [t for t in (t0, t1) if t is not None]
            want = min(counts) if counts else None
            tol = float(ctx.ccfg.get("full_pull_total_tolerance", 0.05))
            stats["falcon_total"] = want
            if want is not None and stats["open"] < want * (1 - tol):
                stats["expire.error"] = (f"pulled {stats['open']} open vulns but Falcon counts {want}: "
                                         f"windows may be missing some, so nothing expired")
                ctx.log(f"open: {stats['expire.error']}")
            else:
                expired = expire_unseen(ctx.conn, SOURCE, ctx.run_started)
    else:
        ctx.log(f"open: incremental{' (catch-up)' if ctx.catch_up else ''}, updated since {since_fql}")
        stats["open"] = pull(incr_fql, "open")
    closed_n = pull(
        f"status:['closed','expired']+updated_timestamp:>'{since_fql}'",
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
          AND a.last_seen IS NOT NULL AND a.last_seen > vf.last_found + interval '7 days'
        """,
        (SOURCE,),
    )
    ctx.conn.commit()
    stats.update({"open_pull": "full" if full else "incremental", "closed": closed_n, "expired": expired,
                  "rows": w.written, "changed": w.changed})
    if any(k.endswith(".error") for k in stats):
        stats["partial"] = True   # -> 'partial': alerted, not retried by the catch-up
    return stats
