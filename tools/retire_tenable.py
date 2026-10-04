#!/usr/bin/env python3
"""
One-off cleanup when pointing this at an existing tenable-vuln-dashboard
database (instead of starting from an empty one).

Removes the Tenable *current-state* data that would otherwise sit in the
open-findings views forever (nothing refreshes it any more):
  - vuln_findings rows with source = 'tenable' (and their CVE links)
  - plugin_metadata / plugin_cves (Tenable plugin catalog)
  - the asset_inventory schema (Tenable <-> CrowdStrike hostname matching)

KEEPS all daily_* snapshot history, so trend lines show an honest step at
cutover rather than losing the past. Dry run unless --confirm.

  python3 tools/retire_tenable.py --config config.yaml            # show what would go
  python3 tools/retire_tenable.py --config config.yaml --confirm  # do it
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as config_mod
from db import pg_connect


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--confirm", action="store_true")
    args = ap.parse_args()

    conn = pg_connect(config_mod.load_config(args.config))
    cur = conn.cursor()

    def exists(rel):
        cur.execute("SELECT to_regclass(%s) IS NOT NULL", (rel,))
        return cur.fetchone()[0]

    cur.execute("SELECT count(*), count(*) FILTER (WHERE state IN ('OPEN','REOPENED')) "
                "FROM vuln_findings WHERE source = 'tenable'")
    total, open_ = cur.fetchone()
    print(f"vuln_findings source='tenable': {total} rows ({open_} open)")
    for rel in ("plugin_metadata", "plugin_cves"):
        print(f"{rel}: {'present' if exists(rel) else 'absent'}")
    cur.execute("SELECT count(*) FROM information_schema.schemata WHERE schema_name = 'asset_inventory'")
    has_schema = cur.fetchone()[0] > 0
    print(f"asset_inventory schema: {'present' if has_schema else 'absent'}")

    if not args.confirm:
        print("\nDry run. Re-run with --confirm to delete the above. daily_* history is kept either way.")
        return

    cur.execute("DELETE FROM vuln_findings WHERE source = 'tenable'")  # CVE links cascade
    cur.execute("DROP TABLE IF EXISTS plugin_cves, plugin_metadata")
    cur.execute("DROP SCHEMA IF EXISTS asset_inventory CASCADE")
    conn.commit()
    print("Done. Run rollup_daily_metrics.py so today's snapshot reflects the new sources only.")


if __name__ == "__main__":
    main()
