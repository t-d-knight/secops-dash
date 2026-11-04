#!/usr/bin/env python3
"""
Diagnose the entra collector without writing anything.

For each configured tenant: gets a token, shows which Graph application
permissions (roles) it actually carries, runs each feed's real query with
$top=1, and prints the status and Graph's error code. Then lists the recent
entra rows in collector_runs. Never prints the secret or the token.

  venv/bin/python3 tools/entra_probe.py --config config.yaml
"""
import argparse
import base64
import datetime as dt
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.msgraph import AzureApp  # noqa: E402
from collectors.entra import SCOPE, FEED_QUERIES, FEED_ROLES  # noqa: E402
from config import collector_cfg, load_config  # noqa: E402


def _claims(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def probe_tenant(t: dict) -> None:
    name = t.get("name") or t.get("tenant_id")
    print(f"\n== tenant {name} ({t.get('tenant_id')}) ==")
    try:
        app = AzureApp(t, SCOPE)
        c = _claims(app.tok.get())
    except Exception as e:
        print(f"  token: FAILED {e}")
        return
    roles = sorted(c.get("roles") or [])
    print(f"  token ok: app '{c.get('app_displayname')}' appid {c.get('appid')} tid {c.get('tid')}")
    print(f"  roles: {', '.join(roles) or '(none -- nothing admin-consented)'}")
    for feed, (path, params) in FEED_QUERIES.items():
        need = FEED_ROLES[feed]
        have = "yes" if need in roles else "MISSING"
        since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        p = dict(params(since) if callable(params) else (params or {}))
        p["$top"] = 1
        r = app.s.get(f"{app.graph_base}{path}", headers=app.headers(), params=p)
        if r.status_code < 400:
            n = len((r.json() or {}).get("value") or [])
            print(f"  {feed:17} role {need} {have}: HTTP {r.status_code}, {n} row(s) on first page")
        else:
            try:
                err = r.json().get("error") or {}
                msg = f"{err.get('code')}: {err.get('message')}"
            except ValueError:
                msg = (r.text or "")[:300]
            print(f"  {feed:17} role {need} {have}: HTTP {r.status_code} {msg[:300]}")
            print(f"  {'':17} request-id {r.headers.get('request-id')} date {r.headers.get('Date')}")


def recent_runs(cfg: dict) -> None:
    try:
        from db import pg_connect
        conn = pg_connect(cfg)
    except Exception as e:
        print(f"\n(no database: {e})")
        return
    cur = conn.cursor()
    cur.execute("""SELECT started_at, finished_at - started_at, status, stats, error
                   FROM collector_runs WHERE collector = 'entra' ORDER BY started_at DESC LIMIT 15""")
    print("\n== recent entra runs ==")
    for started, took, status, stats, error in cur.fetchall():
        print(f"  {started:%Y-%m-%d %H:%M} {status:8} {took}")
        for k, v in sorted((stats or {}).items()):
            print(f"      {k}: {v}")
        if error:
            print(f"      error: {error[:500]}")
    conn.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()
    cfg = load_config(args.config)
    ccfg = collector_cfg(cfg, "entra")
    print(f"entra enabled: {ccfg.get('enabled')}  feeds: {ccfg.get('feeds')}")
    for t in ccfg.get("tenants") or []:
        missing = [k for k in ("tenant_id", "client_id", "client_secret") if not t.get(k)]
        if missing:
            print(f"\n== tenant {t.get('name')} == missing {', '.join(missing)} (check the name matches secrets.yaml)")
            continue
        probe_tenant(t)
    recent_runs(cfg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
