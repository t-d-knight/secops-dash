#!/usr/bin/env python3
"""
Push the generated dashboards (grafana/*.json) to Grafana through its HTTP API,
overwriting the live copy by uid and keeping whatever folder it's in.

  python3 grafana/push_dashboards.py --config config.yaml                  # all of them
  python3 grafana/push_dashboards.py --config config.yaml secops-worklist  # just one

Needs grafana.url (config.yaml) and grafana.api_token (secrets.yaml): a service
account token with the Editor role. The ${DS_POSTGRESQL} placeholder is
replaced with the org's Postgres data source uid (the only one, or --datasource).

With grafana.remediation_api_token (secrets.yaml) set too, the dashboards in
remediation_access.DASHBOARDS also go to the Remediation org: service accounts
belong to one org, so that's a token from a service account created in it.
"""
import argparse
import glob
import json
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import remediation_access  # noqa: E402
from config import load_config  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
PG_TYPES = ("postgres", "grafana-postgresql-datasource")


def find_datasource(s: requests.Session, base: str, label: str) -> str:
    """The org's only Postgres data source (a token belongs to one org, so this is that org's)."""
    r = s.get(f"{base}/api/datasources", timeout=30)
    r.raise_for_status()
    pgs = [d for d in r.json() if d.get("type") in PG_TYPES]
    if len(pgs) != 1:
        raise SystemExit(f"{label}: found {len(pgs)} Postgres data sources "
                         f"({', '.join(d['name'] + '=' + d['uid'] for d in pgs)}); pick one with --datasource")
    return pgs[0]["uid"]


def push_org(base: str, token: str, paths, ds_uid, message: str, label: str) -> int:
    """Push `paths` into the org `token` belongs to. Returns the number that failed."""
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    ds_uid = ds_uid or find_datasource(s, base, label)
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
            "dashboard": dash, "overwrite": True, "message": message, **({"folderUid": folder} if folder else {})})
        if r.ok:
            b = r.json()
            print(f"[grafana:{label}] {os.path.basename(path)} -> {b.get('url')} (v{b.get('version')}, "
                  f"{'updated' if cur.ok else 'created'})")
        else:
            failed += 1
            print(f"[grafana:{label}] {os.path.basename(path)} FAILED {r.status_code}: {r.text[:300]}", file=sys.stderr)
    return failed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--datasource", help="Postgres data source uid in the main org, if it has more than one")
    ap.add_argument("--remediation-datasource", help="the same, in the Remediation org")
    ap.add_argument("--message", default="pushed by push_dashboards.py", help="version history note")
    ap.add_argument("names", nargs="*", help="dashboard file names without .json (default: all)")
    args = ap.parse_args()

    g = load_config(args.config).get("grafana") or {}
    if not g.get("url") or not g.get("api_token"):
        print("grafana.url (config.yaml) and grafana.api_token (secrets.yaml) are both needed", file=sys.stderr)
        return 2
    base = g["url"].rstrip("/")
    names = args.names or sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(HERE, "*.json")))
    path = lambda n: os.path.join(HERE, f"{n}.json")  # noqa: E731
    failed = push_org(base, g["api_token"], [path(n) for n in names], args.datasource, args.message, "main")

    # Remediation org (knowledge-base/grafana-access.md): only its dashboards, with its own token
    rem = [n for n in names if n in remediation_access.DASHBOARDS]
    if g.get("remediation_api_token") and rem:
        failed += push_org(base, g["remediation_api_token"], [path(n) for n in rem], args.remediation_datasource,
                           args.message, "remediation")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
