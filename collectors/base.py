#!/usr/bin/env python3
"""
Collector contract. Each module in collectors/ exposes:

    NAME = "falcon_hosts"
    def run(ctx: RunContext) -> dict      # returns stats, e.g. {"rows": 1234}

collect.py builds the RunContext, runs each enabled collector in its own
try/except (one dead API never takes the rest of the run down), and records
the outcome in collector_runs -- which Grafana's "Data freshness" panel
reads, so a silently-failing feed shows up as stale rather than as a
suspiciously good-looking week.
"""
import datetime as dt
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from psycopg2.extras import Json, execute_values

from site_resolver import SiteResolver


@dataclass
class RunContext:
    cfg: Dict[str, Any]
    ccfg: Dict[str, Any]                 # this collector's config block
    conn: Any
    resolver: SiteResolver
    run_started: dt.datetime
    full: bool = False                   # --full: ignore incremental watermarks
    stats: Dict[str, Any] = field(default_factory=dict)

    def log(self, msg: str) -> None:
        print(f"[{self.ccfg.get('_name', '?')}] {msg}", flush=True)

    # ---- incremental watermarks ---------------------------------------
    def last_success(self, collector: str) -> Optional[dt.datetime]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT max(started_at) FROM collector_runs WHERE collector = %s AND status IN ('ok','partial')",
            (collector,),
        )
        row = cur.fetchone()
        return row[0] if row else None

    def since(self, collector: str, default_days: int, overlap_hours: int = 6) -> dt.datetime:
        """Start of the incremental window: last good run minus an overlap,
        capped at `default_days` back. --full forces the cap."""
        floor = self.run_started - dt.timedelta(days=default_days)
        if self.full:
            return floor
        last = self.last_success(collector)
        if not last:
            return floor
        return max(floor, last - dt.timedelta(hours=overlap_hours))


def parse_ts(v: Any) -> Optional[dt.datetime]:
    """Parse the ISO-ish timestamps every vendor emits slightly differently."""
    if v is None or v == "":
        return None
    if isinstance(v, dt.datetime):
        return v if v.tzinfo else v.replace(tzinfo=dt.timezone.utc)
    if isinstance(v, (int, float)):
        # epoch seconds or ms
        x = float(v)
        if x > 1e12:
            x /= 1000.0
        return dt.datetime.fromtimestamp(x, tz=dt.timezone.utc)
    s = str(v).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # trim sub-microsecond precision (e.g. .1234567) that fromisoformat rejects
    if "." in s:
        head, _, rest = s.partition(".")
        frac = ""
        i = 0
        while i < len(rest) and rest[i].isdigit():
            frac += rest[i]
            i += 1
        s = f"{head}.{frac[:6].ljust(6, '0')}{rest[i:]}" if frac else head + rest[i:]
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        try:
            d = dt.datetime.strptime(s[:10], "%Y-%m-%d")
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, (list, tuple, set)):
        return list(v)
    return [v]


def dig(obj: Any, path: str, default: Any = None) -> Any:
    """dig(d, "a.b.0.c") -- tolerant dotted lookup used by config-driven field maps."""
    cur = obj
    for part in path.split("."):
        if cur is None:
            return default
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return default
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return default
    return default if cur is None else cur


SEVERITY_WORDS = {
    "critical": "critical", "crit": "critical", "p1": "critical", "very_high": "critical",
    "high": "high", "p2": "high",
    "medium": "medium", "moderate": "medium", "med": "medium", "p3": "medium",
    "low": "low", "p4": "low",
    "informational": "info", "info": "info", "none": "info", "p5": "info",
}


def norm_severity(v: Any, default: str = "low") -> str:
    if v is None:
        return default
    s = str(v).strip().lower().replace(" ", "_")
    return SEVERITY_WORDS.get(s, default)


def upsert_rows(conn, table: str, rows: Iterable[Dict[str, Any]], key_cols: List[str],
                page_size: int = 2000) -> int:
    """Generic bulk upsert for the simple per-collector tables. dict/list
    values are stored as JSONB."""
    rows = list(rows)
    if not rows:
        return 0
    cols = list(rows[0].keys())
    upd = [c for c in cols if c not in key_cols]
    # de-dup on key (ON CONFLICT can't touch the same row twice per statement)
    dedup = {}
    for r in rows:
        dedup[tuple(r[k] for k in key_cols)] = r
    rows = list(dedup.values())

    def adapt(v):
        return Json(v) if isinstance(v, (dict, list)) and not _is_text_array(v) else v

    sql = (
        f"INSERT INTO {table} ({', '.join(cols)}) VALUES %s "
        f"ON CONFLICT ({', '.join(key_cols)}) DO "
        + (f"UPDATE SET {', '.join(f'{c} = EXCLUDED.{c}' for c in upd)}" if upd else "NOTHING")
    )
    cur = conn.cursor()
    for i in range(0, len(rows), page_size):
        chunk = rows[i:i + page_size]
        execute_values(cur, sql, [tuple(adapt(r[c]) for c in cols) for r in chunk], page_size=page_size)
    conn.commit()
    return len(rows)


class TextArray(list):
    """Marker: store this list as a Postgres text[] rather than JSONB."""


def _is_text_array(v: Any) -> bool:
    return isinstance(v, TextArray)


def jdump(v: Any) -> str:
    return json.dumps(v, default=str)
