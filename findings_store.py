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
    "first_found", "last_found", "last_fixed",
]

_UPDATABLE = [c for c in _COLS if c not in (
    "source", "source_asset_id", "source_rule_id", "port", "protocol", "first_found")]

UPSERT_SQL = f"""
INSERT INTO vuln_findings ({", ".join(_COLS)}, last_seen_in_export, updated_at)
VALUES %s
ON CONFLICT (source, source_asset_id, source_rule_id, port, protocol)
DO UPDATE SET
    {", ".join(f"{c} = EXCLUDED.{c}" for c in _UPDATABLE)},
    first_found = LEAST(vuln_findings.first_found, EXCLUDED.first_found),
    last_seen_in_export = now(),
    updated_at = now()
RETURNING id
"""

_TEMPLATE = "(" + ", ".join(f"%({c})s" for c in _COLS) + ", now(), now())"


class FindingsWriter:
    """Buffers NormalizedFindings and flushes them in batches."""

    def __init__(self, conn, batch_size: int = 2000):
        self.conn = conn
        self.batch_size = batch_size
        self._buf: List[NormalizedFinding] = []
        self.written = 0

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
        ids = execute_values(
            cur, UPSERT_SQL, [{c: getattr(nf, c) for c in _COLS} for nf in rows],
            template=_TEMPLATE, page_size=len(rows), fetch=True,
        )
        id_list = [r[0] for r in ids]
        cur.execute("DELETE FROM vuln_finding_cves WHERE finding_id = ANY(%s)", (id_list,))
        cve_rows = [
            (fid, cve.strip().upper())
            for fid, nf in zip(id_list, rows)
            for cve in set(nf.cves or [])
            if cve and cve.strip()
        ]
        if cve_rows:
            execute_values(
                cur,
                "INSERT INTO vuln_finding_cves (finding_id, cve) VALUES %s ON CONFLICT DO NOTHING",
                cve_rows, page_size=5000,
            )
        self.conn.commit()
        self.written += len(rows)


def expire_unseen(conn, source: str, run_started: dt.datetime, *, scope_sql: str = "TRUE") -> int:
    """
    After a COMPLETE pull of a source's open findings, any row of that
    source still marked OPEN/REOPENED that this pull didn't touch has
    vanished vendor-side (host aged out, asset retired). Mark it EXPIRED so
    it stops counting as open -- but NOT as FIXED, which would fake MTTR.
    Only call this after a full open-findings pull succeeded.
    """
    cur = conn.cursor()
    cur.execute(
        f"""
        UPDATE vuln_findings SET state = 'EXPIRED', updated_at = now()
        WHERE source = %s AND state IN ('OPEN','REOPENED','SUPPRESSED')
          AND last_seen_in_export < %s AND ({scope_sql})
        """,
        (source, run_started),
    )
    n = cur.rowcount
    conn.commit()
    return n
