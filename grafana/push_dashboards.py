#!/usr/bin/env python3
"""
Push the generated dashboards (grafana/*.json) to Grafana through its HTTP API,
overwriting the live copy by uid and keeping whatever folder it's in.

  python3 grafana/push_dashboards.py --config config.yaml                  # all five
  python3 grafana/push_dashboards.py --config config.yaml secops-worklist  # just one

Needs grafana.url (config.yaml) and grafana.api_token (secrets.yaml): a service
account token with the Editor role. The ${DS_POSTGRESQL} placeholder is
replaced with the Postgres data source's uid (the only one, or --datasource).
"""
import argparse
import glob
import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load_config

HERE = os.path.dirname(os.path.abspath(__file__))
PG_TYPES = ("postgres", "grafana-postgresql-datasource")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--datasource", help="Postgres data source uid, if Grafana has more than one")
    ap.add_argument("--message", default="pushed by push_dashboards.py", help="version history note")
    ap.add_argument("names", nargs="*", help="dashboard file names without .json (default: all)")
    args = ap.parse_args()

    g = load_config(args.config).get("grafana") or {}
    if not g.get("url") or not g.get("api_token"):
        print("grafana.url (config.yaml) and grafana.api_token (secrets.yaml) are both needed", file=sys.stderr)
        return 2
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {g['api_token']}"
    base = g["url"].rstrip("/")

    ds_uid = args.datasource
    if not ds_uid:
        r = s.get(f"{base}/api/datasources", timeout=30)
        r.raise_for_status()
        pgs = [d for d in r.json() if d.get("type") in PG_TYPES]
        if len(pgs) != 1:
            print(f"found {len(pgs)} Postgres data sources ({', '.join(d['name'] + '=' + d['uid'] for d in pgs)}); "
                  f"pick one with --datasource", file=sys.stderr)
            return 2
        ds_uid = pgs[0]["uid"]

    paths = ([os.path.join(HERE, f"{n}.json") for n in args.names] if args.names
             else sorted(glob.glob(os.path.join(HERE, "*.json"))))
    failed = 0
    for path in paths:
        with open(path) as f:
            dash = json.loads(f.read().replace("${DS_POSTGRESQL}", ds_uid))
        for k in ("__inputs", "__requires"):
            dash.pop(k, None)
        dash["id"] = None
        cur = s.get(f"{base}/api/dashboards/uid/{dash['uid']}", timeout=30)
        folder = cur.json().get("meta", {}).get("folderUid") if cur.ok else None
        r = s.post(f"{base}/api/dashboards/db", timeout=60, json={
            "dashboard": dash, "overwrite": True, "message": args.message, **({"folderUid": folder} if folder else {})})
        if r.ok:
            b = r.json()
            print(f"[grafana] {os.path.basename(path)} -> {b.get('url')} (v{b.get('version')}, "
                  f"{'updated' if cur.ok else 'created'})")
        else:
            failed += 1
            print(f"[grafana] {os.path.basename(path)} FAILED {r.status_code}: {r.text[:300]}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
