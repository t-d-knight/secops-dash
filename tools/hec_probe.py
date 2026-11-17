#!/usr/bin/env python3
"""
Diagnose the Check Point HEC collectors without writing anything, and print
what Check Point support asks for when the API is blocked.

Prints this host's egress IP, gets a token from <gateway>/auth/external, then
runs a one-hour event/query the same way the collector does (same HTTP
session and User-Agent). On a failure it prints the request sent (method,
URL, headers, body) and the full response (status, every header, the whole
body). An HTML 403 means something in front of the API refused the request;
a JSON one is the API itself.

Never prints the access key or the token: the Authorization header is shown
as "Bearer <redacted>". Output is safe to paste into a support ticket, but
it does include this host's public IP and the gateway URL.

  venv/bin/python3 tools/hec_probe.py --config config.yaml
  venv/bin/python3 tools/hec_probe.py --config config.yaml --hours 130 --like-collector

--hours sets the query's time range (default 1). --like-collector also adds
the collector's configured event_types / saas filters, so the request body
matches what checkpoint_hec.py sends for that range.
"""
import argparse
import datetime as dt
import json
import os
import sys
import uuid

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import collector_cfg, load_config  # noqa: E402
from http_client import make_session  # noqa: E402

REDACT = {"authorization": "Bearer <redacted>"}


def show_exchange(r: requests.Response) -> None:
    """The request as sent and the response in full, secrets redacted."""
    req = r.request
    print("\n--- request ---")
    print(f"{req.method} {req.url}")
    for k, v in req.headers.items():
        print(f"{k}: {REDACT.get(k.lower(), v)}")
    if req.body:
        body = req.body.decode() if isinstance(req.body, bytes) else req.body
        try:
            body = json.dumps(json.loads(body), indent=2)
        except ValueError:
            pass
        print("\n" + body)
    print("\n--- response ---")
    print(f"HTTP {r.status_code} {r.reason}")
    for k, v in r.headers.items():
        print(f"{k}: {v}")
    print("\n" + (r.text or "(empty body)"))
    print("--- end ---")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--hours", type=float, default=1, help="event/query time range in hours (default 1)")
    ap.add_argument("--like-collector", action="store_true",
                    help="add the collector's event_types / saas filters from config")
    args = ap.parse_args()

    c = collector_cfg(load_config(args.config), "checkpoint_hec")
    gw = c.get("gateway", "https://cloudinfra-gw.portal.checkpoint.com").rstrip("/")
    if not c.get("client_id") or not c.get("access_key"):
        print("collectors.checkpoint_hec.client_id / access_key missing from secrets.yaml")
        return 2
    s = make_session(timeout=120)
    print("time (UTC):", dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    print("gateway:   ", gw)
    try:
        print("egress IP: ", requests.get("https://api.ipify.org", timeout=10).text.strip())
    except requests.RequestException as e:
        print("egress IP:  unknown (%s)" % e)

    r = s.post(gw + "/auth/external", json={"clientId": c["client_id"], "accessKey": c["access_key"]})
    print("\n[1] auth:", r.status_code, r.headers.get("content-type"))
    tok = None
    if r.ok:
        try:
            tok = ((r.json() or {}).get("data") or {}).get("token")
        except ValueError:
            pass
    if not tok:
        # the request body holds the access key: show only the response
        print(f"POST {gw}/auth/external (body: clientId + accessKey, not shown)")
        print(f"HTTP {r.status_code} {r.reason}")
        for k, v in r.headers.items():
            print(f"{k}: {v}")
        print("\n" + (r.text or "(empty body)"))
        print("\n=> auth failed: the API key itself (expired/revoked/regenerated?), or blocked (HTML)")
        return 1
    print("    token OK (len %d)" % len(tok))

    now = dt.datetime.now(dt.timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    rd = {"startDate": (now - dt.timedelta(hours=args.hours)).strftime(fmt), "endDate": now.strftime(fmt)}
    if args.like_collector:
        if c.get("event_types"):
            rd["eventTypes"] = c["event_types"]
        if c.get("saas"):
            rd["saas"] = c["saas"]
    body = {"requestData": rd}
    r = s.post(gw + "/app/hec-api/v1.0/event/query", json=body,
               headers={"Authorization": "Bearer " + tok, "x-av-req-id": str(uuid.uuid4()),
                        "Content-Type": "application/json"})
    ctype = r.headers.get("content-type") or ""
    print("\n[2] event/query:", r.status_code, ctype, f"({args.hours:g} h{', collector filters' if args.like_collector else ''})")

    if r.ok:
        print("\n=> OK: credentials and API both fine; re-run the collector")
        return 0
    show_exchange(r)
    if "html" in ctype.lower():
        print("\n=> blocked in front of the API (HTML). Try from another network: "
              "works there = this IP is blocked; fails there too = Check Point side or key scope")
    else:
        print("\n=> the API rejected it (JSON): read the message above, usually key scope/permissions")
    return 1


if __name__ == "__main__":
    sys.exit(main())
