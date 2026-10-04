#!/usr/bin/env python3
"""
Runs every enabled collector (config.yaml `collectors:`), each isolated: a
failing vendor API is logged to collector_runs and the run moves on. Exits
non-zero if anything failed, so cron/systemd still notices.

  python3 collect.py --config config.yaml                 # all enabled
  python3 collect.py --config config.yaml --only falcon_hosts,falcon_spotlight
  python3 collect.py --config config.yaml --full          # ignore incremental watermarks
  python3 collect.py --config config.yaml --list
"""
import argparse
import datetime as dt
import sys
import traceback

from psycopg2.extras import Json

import config as config_mod
import db_schema
from collectors import REGISTRY
from collectors.base import RunContext
from db import pg_connect
from site_resolver import SiteResolver


def main() -> int:
    ap = argparse.ArgumentParser(description="Run security data collectors")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--only", help="comma-separated collector names (runs them even if disabled)")
    ap.add_argument("--full", action="store_true", help="ignore incremental watermarks")
    ap.add_argument("--list", action="store_true", help="list collectors and whether they're enabled")
    args = ap.parse_args()

    cfg = config_mod.load_config(args.config)
    ccfgs = cfg.get("collectors") or {}

    if args.list:
        for name in REGISTRY:
            print(f"{name:22s} {'enabled' if (ccfgs.get(name) or {}).get('enabled') else 'disabled'}")
        return 0

    if args.only:
        names = [n.strip() for n in args.only.split(",") if n.strip()]
        unknown = [n for n in names if n not in REGISTRY]
        if unknown:
            print(f"Unknown collector(s): {unknown}. Known: {list(REGISTRY)}")
            return 2
    else:
        names = [n for n in REGISTRY if (ccfgs.get(n) or {}).get("enabled")]

    db_schema.ensure_schema(cfg)
    resolver = SiteResolver(cfg)
    conn = pg_connect(cfg)
    failures = []

    for name in names:
        mod = REGISTRY[name]
        ccfg = dict(ccfgs.get(name) or {}, _name=name)
        started = dt.datetime.now(dt.timezone.utc)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO collector_runs (collector, started_at, status) VALUES (%s, %s, 'running') RETURNING id",
            (name, started),
        )
        run_id = cur.fetchone()[0]
        conn.commit()
        print(f"=== {name} ===", flush=True)
        ctx = RunContext(cfg=cfg, ccfg=ccfg, conn=conn, resolver=resolver, run_started=started, full=args.full)
        try:
            stats = mod.run(ctx) or {}
            status = "partial" if stats.get("partial") else "ok"
            err = None
        except Exception as e:
            conn.rollback()
            stats, status, err = {}, "error", f"{type(e).__name__}: {e}"
            failures.append(name)
            print(f"[{name}] FAILED: {err}", flush=True)
            traceback.print_exc()
        cur = conn.cursor()
        cur.execute(
            "UPDATE collector_runs SET finished_at = now(), status = %s, stats = %s, error = %s WHERE id = %s",
            (status, Json(stats, dumps=lambda o: __import__("json").dumps(o, default=str)), err and err[:4000], run_id),
        )
        conn.commit()
        print(f"[{name}] {status} {stats}", flush=True)

    conn.close()
    if failures:
        print(f"Collectors failed: {failures}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
