#!/usr/bin/env python3
"""
The vendor-agnostic vulnerability findings seam. Any collector that
produces vulnerability-shaped data (Falcon Spotlight/Exposure Management,
Hadrian external risks, ...) yields NormalizedFinding rows and hands them to
FindingsWriter, which bulk-upserts into vuln_findings / vuln_finding_cves.
Everything downstream (SLA, KEV, EPSS, MTTR, rollups, Grafana) only ever
reads vuln_findings, so it doesn't care which vendor a row came from.
"""
import datetime as dt
from dataclasses import dataclass, field
from typing import List, Optional

from psycopg2.extras import execute_values


@dataclass
class NormalizedFinding:
    source: str                    # 'falcon_spotlight' | 'hadrian' | ...
    source_asset_id: str
    source_rule_id: str
    state: str                     # 'OPEN' | 'REOPENED' | 'FIXED' | 'EXPIRED' | 'SUPPRESSED'
    severity: str                  # 'critical' | 'high' | 'medium' | 'low'
    first_found: dt.datetime
    last_found: dt.datetime
    site_label: str

    port: int = 0
    protocol: str = ""

    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    title: Optional[str] = None
    plugin_family: Optional[str] = None     # vendor category (Spotlight cve.types, Hadrian category)
    synopsis: Optional[str] = None
    solution: Optional[str] = None

    is_remote_no_auth: bool = False
    exploit_available: Optional[bool] = None
    exploited_by_malware: Optional[bool] = None
    has_patch: Optional[bool] = None
    patch_published: Optional[dt.datetime] = None

    product_key: Optional[str] = None
    product_vendor: Optional[str] = None
    product_family: Optional[str] = None

    site_tag: Optional[str] = None
    site_matched_by: Optional[str] = None
    asset_type: Optional[str] = None        # 'internet' | 'server' | 'workstation' | 'domain_controller' | 'unknown'
    hostname: Optional[str] = None

    fix_id: Optional[str] = None            # groups findings closed by one remediation action
    fix_title: Optional[str] = None
    vendor_priority: Optional[str] = None   # e.g. Falcon ExPRT rating, Hadrian priority

    last_fixed: Optional[dt.datetime] = None
    risk_type: Optional[str] = None         # Hadrian riskType (Potential/Verified/...)
    # Stored once per CVE in cve_descriptions, not per finding: the same
    # ~1.9 KB NVD text repeated across millions of Spotlight rows was most
    # of vuln_findings' 20 GB. Not a vuln_findings column.
    cve_description: Optional[str] = None
    cves: List[str] = field(default_factory=list)


_COLS = [
    "source", "source_asset_id", "source_rule_id", "port", "protocol",
    "state", "severity", "cvss_score", "cvss_vector",
    "title", "plugin_family", "synopsis", "solution",
    "is_remote_no_auth", "exploit_available", "exploited_by_malware",
    "has_patch", "patch_published",
    "product_key", "product_vendor", "product_family",
    "site_label", "site_tag", "site_matched_by", "asset_type", "hostname",
    "fix_id", "fix_title", "vendor_priority",
    "first_found", "last_found", "last_fixed", "risk_type",
]

_UPDATABLE = [c for c in _COLS if c not in (
    "source", "source_asset_id", "source_rule_id", "port", "protocol", "first_found")]

# Only rewrite a row when something meaningful changed. Every vendor pull
# re-sends every open finding, and rewriting all of them nightly (4.5M rows
# once Spotlight covered the estate) cost hours and doubled the table on
# disk. last_found moves almost daily for every finding, so it alone only
# triggers a write once it has advanced LAST_FOUND_SLACK -- the rollups use
# it against a 30-day staleness window, so a week's precision is plenty.
LAST_FOUND_SLACK = "7 days"
_COMPARED = [c for c in _UPDATABLE if c != "last_found"]
NATURAL_KEY = ("source", "source_asset_id", "source_rule_id", "port", "protocol")

UPSERT_SQL = f"""
INSERT INTO vuln_findings ({", ".join(_COLS)}, last_seen_in_export, updated_at)
VALUES %s
ON CONFLICT ({", ".join(NATURAL_KEY)})
DO UPDATE SET
    {", ".join(f"{c} = EXCLUDED.{c}" for c in _UPDATABLE if c != "last_found")},
    last_found = GREATEST(vuln_findings.last_found, EXCLUDED.last_found),   -- never backwards
    first_found = LEAST(vuln_findings.first_found, EXCLUDED.first_found),
    last_seen_in_export = now(),
    updated_at = now()
WHERE ({", ".join(f"vuln_findings.{c}" for c in _COMPARED)})
          IS DISTINCT FROM ({", ".join(f"EXCLUDED.{c}" for c in _COMPARED)})
   OR EXCLUDED.first_found < vuln_findings.first_found
   OR EXCLUDED.last_found > vuln_findings.last_found + interval '{LAST_FOUND_SLACK}'
RETURNING id, {", ".join(NATURAL_KEY)}
"""

# Which findings this run's pull returned (changed or not), per session, so
# expire_unseen can find the ones that vanished without every unchanged row
# having to be rewritten just to bump a timestamp.
SEEN_DDL = """
CREATE TEMP TABLE IF NOT EXISTS findings_seen (
    source text, source_asset_id text, source_rule_id text, port integer, protocol text
)"""

_TEMPLATE = "(" + ", ".join(f"%({c})s" for c in _COLS) + ", now(), now())"


class FindingsWriter:
    """Buffers NormalizedFindings and flushes them in batches."""

    def __init__(self, conn, batch_size: int = 2000):
        self.conn = conn
        self.batch_size = batch_size
        self._buf: List[NormalizedFinding] = []
        self.written = 0      # rows the pull returned
        self.changed = 0      # rows actually inserted/updated

    def add(self, nf: NormalizedFinding) -> None:
        self._buf.append(nf)
        if len(self._buf) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if not self._buf:
            return
        # Same natural key twice in one batch makes ON CONFLICT error out
        # ("cannot affect row a second time"); last one wins.
        dedup = {}
        for nf in self._buf:
            dedup[(nf.source, nf.source_asset_id, nf.source_rule_id, nf.port, nf.protocol)] = nf
        rows = list(dedup.values())
        self._buf = []

        cur = self.conn.cursor()
        cur.execute(SEEN_DDL)
        execute_values(cur, "INSERT INTO findings_seen VALUES %s",
                       [(nf.source, nf.source_asset_id, nf.source_rule_id, nf.port, nf.protocol) for nf in rows],
                       page_size=5000)
        # RETURNING only yields rows actually inserted/updated, so map back by
        # natural key rather than by position.
        changed = execute_values(
            cur, UPSERT_SQL, [{c: getattr(nf, c) for c in _COLS} for nf in rows],
            template=_TEMPLATE, page_size=len(rows), fetch=True,
        )
        by_key = {(nf.source, nf.source_asset_id, nf.source_rule_id, nf.port, nf.protocol): nf for nf in rows}
        touched = [(r[0], by_key[tuple(r[1:])]) for r in changed]
        if touched:
            cur.execute("DELETE FROM vuln_finding_cves WHERE finding_id = ANY(%s)", ([fid for fid, _ in touched],))
            cve_rows = [(fid, cve.strip().upper()) for fid, nf in touched for cve in set(nf.cves or []) if cve and cve.strip()]
            if cve_rows:
                execute_values(cur, "INSERT INTO vuln_finding_cves (finding_id, cve) VALUES %s ON CONFLICT DO NOTHING",
                               cve_rows, page_size=5000)
        descs = {cve.strip().upper(): nf.cve_description for nf in rows if nf.cve_description
                 for cve in (nf.cves or []) if cve and cve.strip()}
        if descs:
            execute_values(cur, """
                INSERT INTO cve_descriptions (cve_id, description) VALUES %s
                ON CONFLICT (cve_id) DO UPDATE SET description = EXCLUDED.description, updated_at = now()
                WHERE cve_descriptions.description IS DISTINCT FROM EXCLUDED.description""",
                           list(descs.items()), page_size=5000)
        self.changed += len(touched)
        self.conn.commit()
        self.written += len(rows)


def expire_unseen(conn, source: str, run_started: dt.datetime, *, scope_sql: str = "TRUE") -> int:
    """
    After a COMPLETE pull of a source's open findings, any row of that
    source still marked OPEN/REOPENED/SUPPRESSED that this pull didn't
    return has vanished vendor-side (host aged out, asset retired). Mark it
    EXPIRED so it stops counting as open -- but NOT as FIXED, which would
    fake MTTR. Only call this after a full open-findings pull succeeded, on
    the same connection the FindingsWriter used (the seen-set is a
    session temp table). run_started is kept for callers' compatibility.
    """
    cur = conn.cursor()
    cur.execute(SEEN_DDL)
    cur.execute("SELECT count(*) FROM findings_seen WHERE source = %s", (source,))
    if not cur.fetchone()[0]:
        # an empty pull would otherwise expire every open finding
        conn.commit()
        return 0
    cur.execute("ANALYZE findings_seen")
    cur.execute(
        f"""
        UPDATE vuln_findings vf SET state = 'EXPIRED', updated_at = now()
        WHERE vf.source = %s AND vf.state IN ('OPEN','REOPENED','SUPPRESSED') AND ({scope_sql})
          AND NOT EXISTS (SELECT 1 FROM findings_seen s
                          WHERE s.source = vf.source AND s.source_asset_id = vf.source_asset_id
                            AND s.source_rule_id = vf.source_rule_id AND s.port = vf.port
                            AND s.protocol = vf.protocol)
        """,
        (source,),
    )
    n = cur.rowcount
    conn.commit()
    return n
