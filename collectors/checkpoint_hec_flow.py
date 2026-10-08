#!/usr/bin/env python3
"""
Check Point Harmony Email & Collaboration (HEC) mail-flow funnel ->
daily_email_flow_metrics: how much inbound mail the systems handle and what
each layer does with it, per site per day.

  Microsoft layer   entityPayload.saasSpamVerdict = Microsoft's spam
                    confidence level (SCL) on the message: 5-6 -> junk,
                    7-9 -> quarantined; everything else -> inbox.
  Check Point layer entitySecurityResult.combinedVerdict.ap = clean /
                    graymail / spam / phishing / suspicious_phishing /
                    malware; entityPayload.isQuarantined = Check Point
                    quarantined it.
  Admin actions     isRestoreRequested / isRestored / isRestoreDeclined.
Each is counted twice: for incoming mail and (as internal_<metric>) for
internal mail, which Check Point's own "Inbound" figure includes.

Uses the Smart API *entity search* (/v1.0/search/query: emails, not the
security events checkpoint_hec.py collects -- clean mail never raises an
event). Nothing is downloaded: each figure is a filtered query's
responseEnvelope.recordsNumber, which is an exact count below 10,000 and
capped at 10,000 above it -- so a capped window is re-counted hour by hour
(and a capped hour by quarter-hour). Confirmed against the live tenant
2026-10-06/08: counts exact below the cap, filters AND together, `isNot`
works on boolean fields but not on SCL (so SCL is counted per value).

Sites are per recipient domain (entityPayload.origRecipient contains
@<domain>, from each site's email_domains); Ungrouped = region total minus
the sites, so summing every site gives the region.

Credentials are checkpoint_hec's (same API key). Days are local days in the
database's timezone. The last `lookback_days` days are recomputed each run,
since verdicts and restores keep changing after delivery.
"""
import datetime as dt
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

from collectors.base import RunContext
from collectors.checkpoint_hec import HecClient

NAME = "checkpoint_hec_flow"
CAP = 10000

Filter = Tuple[str, str, str]
INCOMING: Filter = ("entityPayload.isIncoming", "is", "true")
# Internal (staff-to-staff) mail, made disjoint from incoming: Check Point's
# own "Inbound emails" figure counts both (2026-10-08 check: incoming 699.9K
# + internal 228.1K - 1.9K both ~= the console's 903K over 14 days), so the
# funnel does too. Stored as internal_<metric>.
INTERNAL: List[Filter] = [("entityPayload.isInternal", "is", "true"), ("entityPayload.isIncoming", "isNot", "true")]
DIRECTIONS: Dict[str, List[Filter]] = {"": [INCOMING], "internal_": INTERNAL}
NOT_CP_QUARANTINED: Filter = ("entityPayload.isQuarantined", "isNot", "true")


def _scl(v: str) -> Filter:
    return ("entityPayload.saasSpamVerdict", "is", v)


def _ap(v: str) -> Filter:
    return ("entitySecurityResult.combinedVerdict.ap", "is", v)


# metric -> filter sets whose counts are summed (each ANDed with the direction's filter)
METRICS: Dict[str, List[List[Filter]]] = {
    "incoming": [[]],
    "ms_junk": [[_scl("5")], [_scl("6")]],
    "ms_quarantine": [[_scl("7")], [_scl("8")], [_scl("9")]],
    # Microsoft-quarantined that Check Point didn't also quarantine, so
    # "delivered" = not CP-quarantined minus these never double-subtracts
    "ms_quarantine_not_cp": [[_scl(v), NOT_CP_QUARANTINED] for v in ("7", "8", "9")],
    "not_cp_quarantined": [[NOT_CP_QUARANTINED]],
    "cp_clean": [[_ap("clean")]],
    "cp_graymail": [[_ap("graymail")]],
    "cp_spam": [[_ap("spam")]],
    "cp_phishing": [[_ap("phishing")]],
    "cp_suspicious_phishing": [[_ap("suspicious_phishing")]],
    "cp_malware": [[_ap("malware")]],
    "cp_quarantined": [[("entityPayload.isQuarantined", "is", "true")]],
    "restore_requested": [[("entityPayload.isRestoreRequested", "is", "true")]],
    "restored": [[("entityPayload.isRestored", "is", "true")]],
    "restore_declined": [[("entityPayload.isRestoreDeclined", "is", "true")]],
    "monitor_mode": [[("entityPayload.mode", "is", "monitor")]],
}


STORED = [prefix + m for prefix in DIRECTIONS for m in METRICS]


class _Search:
    def __init__(self, hec: HecClient):
        self.h = hec
        self.url = f"{hec.gw}/app/hec-api/v1.0/search/query"
        self.queries = 0

    @staticmethod
    def _fmt(t: dt.datetime) -> str:
        return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _count(self, start: dt.datetime, end: dt.datetime, filters: List[Filter]) -> int:
        rd = {"entityFilter": {"saas": "office365_emails", "startDate": self._fmt(start), "endDate": self._fmt(end)},
              "entityExtendedFilter": [{"saasAttrName": a, "saasAttrOp": o, "saasAttrValue": v} for a, o, v in filters]}
        for attempt in (1, 2):
            hd = {"Authorization": f"Bearer {self.h.tok.get()}", "x-av-req-id": str(uuid.uuid4()),
                  "Content-Type": "application/json"}
            r = self.h.s.post(self.url, json={"requestData": rd}, headers=hd)
            self.queries += 1
            if r.status_code == 401 and attempt == 1:
                self.h.tok.invalidate()
                continue
            if r.status_code != 200:
                raise RuntimeError(f"HEC search HTTP {r.status_code}: {r.text[:300]}")
            n = (r.json().get("responseEnvelope") or {}).get("recordsNumber")
            if n is None:
                raise RuntimeError(f"HEC search returned no recordsNumber: {r.text[:300]}")
            return int(n)
        raise RuntimeError("HEC search: auth failed twice")

    def count(self, start: dt.datetime, end: dt.datetime, filters: List[Filter]) -> int:
        """Exact count over [start, end): one query if under the cap, else
        re-counted in hours, and a capped hour in quarter-hours. Each query
        ends one second early so a message on a boundary isn't counted twice."""
        n = self._count(start, end - dt.timedelta(seconds=1), filters)
        if n < CAP:
            return n
        span = end - start
        step = (dt.timedelta(hours=1) if span > dt.timedelta(hours=1)
                else dt.timedelta(minutes=15) if span > dt.timedelta(minutes=15) else None)
        if step is None:
            return n   # 10k+ in 15 minutes: report the cap rather than recurse forever
        total, t = 0, start
        while t < end:
            total += self.count(t, min(t + step, end), filters)
            t += step
        return total


def _db_tz(conn) -> ZoneInfo:
    cur = conn.cursor()
    cur.execute("SHOW timezone")
    return ZoneInfo(cur.fetchone()[0])


def run(ctx: RunContext) -> Dict[str, Any]:
    hec_cfg = dict((ctx.cfg.get("collectors") or {}).get("checkpoint_hec") or {})
    hec_cfg.update({k: v for k, v in ctx.ccfg.items() if k in ("gateway", "client_id", "access_key")})
    search = _Search(HecClient(hec_cfg))
    tz = _db_tz(ctx.conn)
    today = dt.datetime.now(tz).date()
    lookback = int(ctx.ccfg.get("backfill_days", 14) if ctx.full else ctx.ccfg.get("lookback_days", 3))
    days = [today - dt.timedelta(days=i) for i in range(lookback, -1, -1)]   # incl. today so far
    workers = int(ctx.ccfg.get("workers", 4))
    ungrouped = ctx.cfg.get("ungrouped_label", "Ungrouped")

    # scope -> recipient filter; None = region (no recipient filter)
    scopes: List[Tuple[Optional[str], Optional[Filter]]] = [(None, None)]
    for s in ctx.cfg.get("sites", []):
        for d in (s.get("match") or {}).get("email_domains") or []:
            scopes.append((s["label"], ("entityPayload.origRecipient", "contains", "@" + d.lower())))

    def day_bounds(d: dt.date) -> Tuple[dt.datetime, dt.datetime]:
        start = dt.datetime.combine(d, dt.time(), tz)
        end = min(dt.datetime.combine(d + dt.timedelta(days=1), dt.time(), tz), dt.datetime.now(tz))
        return start, end

    def scope_day(job: Tuple[dt.date, Optional[str], Optional[Filter]]) -> Tuple[dt.date, Optional[str], Dict[str, int]]:
        d, label, rcpt = job
        start, end = day_bounds(d)
        out: Dict[str, int] = {}
        for prefix, direction in DIRECTIONS.items():
            base = direction + ([rcpt] if rcpt else [])
            total = search.count(start, end, base)
            out[prefix + "incoming"] = total
            if total:   # quiet domains/days cost one query, not seventeen
                for metric, sets in METRICS.items():
                    if metric != "incoming":
                        out[prefix + metric] = sum(search.count(start, end, base + fs) for fs in sets)
        ctx.log(f"{d} {label or 'region'}: {out.get('incoming', 0)} incoming, {out.get('internal_incoming', 0)} internal")
        return d, label, out

    from psycopg2.extras import execute_values
    cur = ctx.conn.cursor()
    rows_total, region_in = 0, 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        # A day at a time, saved as soon as it's counted: a long backfill
        # fills in progressively, and an interruption only loses that day.
        for d in days:
            results = list(ex.map(scope_day, [(d, label, rcpt) for label, rcpt in scopes]))
            # Fold domains into sites; Ungrouped = region minus the sites.
            bucket: Dict[str, Dict[str, int]] = {}
            for _, label, vals in results:
                tgt = bucket.setdefault(label or "__region__", {})
                for m, v in vals.items():
                    tgt[m] = tgt.get(m, 0) + v
            region = bucket.pop("__region__", {})
            for m in STORED:
                rest = region.get(m, 0) - sum(v.get(m, 0) for v in bucket.values())
                bucket.setdefault(ungrouped, {})[m] = max(rest, 0)
            rows = [(d, label, m, vals.get(m, 0)) for label, vals in bucket.items() for m in STORED]
            cur.execute("DELETE FROM daily_email_flow_metrics WHERE snapshot_date = %s", (d,))
            execute_values(cur, "INSERT INTO daily_email_flow_metrics (snapshot_date, site_label, metric, value) "
                                "VALUES %s", rows, page_size=1000)
            ctx.conn.commit()
            rows_total += len(rows)
            region_in += region.get("incoming", 0) + region.get("internal_incoming", 0)
    return {"days": f"{days[0]}..{days[-1]}", "queries": search.queries, "inbound_incl_internal": region_in,
            "rows": rows_total}
