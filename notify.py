#!/usr/bin/env python3
"""
Notifications: Pushover messages when something needs a look, plus an
optional dead-man's-switch ping (healthchecks.io or anything with the same
URL scheme) so a box that's off or hung -- which can't report itself --
still gets noticed: the service alerts when the nightly ping doesn't arrive.

Quiet by design: nothing is sent when a run is healthy. What does send:
  run-end   a collector failed or a feed has had no successful run in
            notify.stale_hours, the run exited non-zero or ran longer than
            notify.max_run_hours, or the disk is over notify.disk_warn_pct
  publish   reports published (low priority), or publishing failed (high)
  identity-digest
            new open Falcon Identity Protection detections (critical/high/
            medium) and OverWatch alerts since the last digest -- identity
            detections live in the child CID's console, which nobody watches
  send      anything else, e.g. a crontab line's `|| notify.py send ...`

Config (config.yaml `notify:`, keys in secrets.yaml):
  notify:
    enabled: true
    healthcheck_url: "https://hc-ping.com/<uuid>"   # optional
    pushover: {app_token: ..., user_key: ...}       # secrets.yaml

    python3 notify.py --config config.yaml send --title "Test" --message "Hello"
    python3 notify.py --config config.yaml run-start
    python3 notify.py --config config.yaml run-end --rc 0 --started 2026-10-13T02:00:00+11:00

Never raises and always exits 0: a notification problem must not turn a good
run into a failed one. Problems sending are printed to the calling job's log.
"""
import argparse
import datetime as dt
import json
import os
import shutil
import socket
import sys
from typing import Any, Dict, List, Optional

import config as config_mod
from http_client import make_session

ROOT = os.path.dirname(os.path.abspath(__file__))
PUSHOVER_URL = "https://api.pushover.net/1/messages.json"
# Pushover priorities: -1 quiet (no sound), 0 normal, 1 high (bypasses quiet hours).
# 2 (emergency) needs retry/expire handling and isn't used.
QUIET, NORMAL, HIGH = -1, 0, 1


def _cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return cfg.get("notify") or {}


def send(cfg: Dict[str, Any], title: str, message: str, priority: int = NORMAL) -> bool:
    n = _cfg(cfg)
    po = n.get("pushover") or {}
    if not n.get("enabled") or not po.get("app_token") or not po.get("user_key"):
        return False
    host = n.get("host_label") or socket.gethostname().split(".")[0]
    try:
        r = make_session(timeout=20, retries=3).post(po.get("api_url") or PUSHOVER_URL, data={
            "token": po["app_token"], "user": po["user_key"], "priority": max(QUIET, min(priority, HIGH)),
            "title": f"secops-dash ({host}): {title}"[:250], "message": message[:1024]})
        if r.status_code != 200:
            print(f"[notify] Pushover returned {r.status_code}: {r.text[:200]}", file=sys.stderr)
            return False
        return True
    except Exception as e:
        print(f"[notify] Pushover send failed: {type(e).__name__}: {e}", file=sys.stderr)
        return False


def ping(cfg: Dict[str, Any], suffix: str = "") -> None:
    """Dead-man's switch: `url` = success, `url/start`, `url/<exit code>`."""
    url = _cfg(cfg).get("healthcheck_url")
    if not _cfg(cfg).get("enabled") or not url:
        return
    try:
        make_session(timeout=10, retries=3).get(url.rstrip("/") + (f"/{suffix}" if suffix else ""))
    except Exception as e:
        print(f"[notify] health-check ping failed: {type(e).__name__}: {e}", file=sys.stderr)


def enabled_collectors(cfg: Dict[str, Any]) -> List[str]:
    return [name for name, c in (cfg.get("collectors") or {}).items() if isinstance(c, dict) and c.get("enabled")]


def run_problems(cfg: Dict[str, Any], rc: int, started: dt.datetime) -> List[tuple]:
    """(priority, line) for everything wrong with the run that started at `started`."""
    from db import pg_connect
    n = _cfg(cfg)
    out: List[tuple] = []
    conn = pg_connect(cfg)
    try:
        cur = conn.cursor()
        cur.execute("""SELECT collector, status, left(COALESCE(error, ''), 160) FROM collector_runs
                       WHERE started_at >= %s AND status NOT IN ('ok', 'partial') ORDER BY started_at""", (started,))
        for name, status, err in cur.fetchall():
            if status == "running":   # still 'running' after the run ended: the process was killed
                status, err = "never finished", err or "killed? (power loss, OOM, reboot)"
            out.append((HIGH, f"{name}: {status}" + (f" -- {err}" if err else "")))
        stale_h = float(n.get("stale_hours", 36))
        cur.execute("SELECT collector, last_success FROM collector_freshness")
        last_ok = dict(cur.fetchall())
        now = dt.datetime.now(dt.timezone.utc)
        for name in enabled_collectors(cfg):
            ts = last_ok.get(name)
            if ts is None or (now - ts).total_seconds() > stale_h * 3600:
                when = ts.astimezone().strftime("%d %b %H:%M") if ts else "never"
                out.append((HIGH, f"{name}: no successful run since {when}"))
    finally:
        conn.close()
    hours = (dt.datetime.now(dt.timezone.utc) - started).total_seconds() / 3600
    if hours > float(n.get("max_run_hours", 6)):
        out.append((NORMAL, f"run took {hours:.1f} h (limit {n.get('max_run_hours', 6)} h)"))
    if rc != 0:   # always say so: a step that died (e.g. database restarted) isn't a collector row
        out.append((NORMAL, f"run exited {rc} -- a step failed, see logs/collector.log"))
    out += disk_problems(cfg)
    return out


def disk_problems(cfg: Dict[str, Any]) -> List[tuple]:
    pct = float(_cfg(cfg).get("disk_warn_pct", 85))
    u = shutil.disk_usage(ROOT)
    used = 100.0 * u.used / u.total
    return [(NORMAL, f"disk {used:.0f}% full ({u.free / 2**30:.0f} GB free)")] if used > pct else []


def notify_published(cfg: Dict[str, Any], published: List[str], failed: List[str],
                     error: Optional[str] = None) -> None:
    """Called by publish.py. A quiet note when reports go out, a loud one when they don't."""
    if error:
        send(cfg, "publish failed", f"Couldn't reach the destination: {error}", HIGH)
        return
    if failed:
        send(cfg, f"publish: {len(failed)} file(s) failed",
             "\n".join(failed[:10]) + ("\n..." if len(failed) > 10 else ""), HIGH)
    if published:
        lines, parts = published_summary(published)
        send(cfg, "published " + ", ".join(parts), "\n".join(lines), QUIET)


def _sites(n: int) -> str:
    return f"{n} site{'s' if n != 1 else ''}"


def published_summary(published: List[str]):
    """Batch publish.py's destination paths ("<Site>/Weekly/2026-W41 <Site> Security
    Report.pdf") into one line per set: "Weekly 2026-W41: 18 Security Reports (PDF,
    18 sites)", plus short title parts ("18 weekly reports")."""
    groups: Dict[tuple, set] = {}
    for p in published:
        site, folder, fname = (p.split("/") + ["", "", ""])[:3]
        stem, ext = os.path.splitext(fname)
        period = stem.split(" ", 1)[0]
        kind = ("Action Pack" if stem.endswith("Action Pack") else
                "Servers Report" if stem.endswith("Servers Report") else
                "Impact Report" if stem.endswith("Impact Report") else "Security Report")
        groups.setdefault((folder, period, kind, ext.lstrip(".").upper()), set()).add(site)
    lines, parts = [], []
    for (folder, period, kind, ext), sites in sorted(groups.items()):
        n = len(sites)
        lines.append(f"{folder} {period}: {n} {kind}{'s' if n != 1 else ''} ({ext}, "
                     f"{'region + ' if 'Region' in sites else ''}{_sites(n - ('Region' in sites))})")
        parts.append(f"{n} {folder.lower()} {kind.lower() if kind != 'Security Report' else 'report'}{'s' if n != 1 else ''}")
    return lines, parts


DIGEST_STATE = os.path.join(ROOT, "logs", ".identity-digest.json")
DIGEST_KEEP_DAYS = 90


def identity_digest(cfg: Dict[str, Any]) -> None:
    """One message listing open identity detections (critical/high/medium) and
    OverWatch alerts not yet notified. The first run reports the existing
    backlog. Detection names and sites only -- no account names off the box.
    Notified ids are remembered (logs/.identity-digest.json) only once the
    message has gone, so a failed send is retried next run."""
    from db import pg_connect
    try:
        with open(DIGEST_STATE) as fh:
            seen: Dict[str, str] = json.load(fh)
    except (OSError, ValueError):
        seen = {}
    conn = pg_connect(cfg)
    try:
        cur = conn.cursor()
        cur.execute("""SELECT source || ':' || alert_id, product, severity, COALESCE(name, '(unnamed)'), site_label
                       FROM security_alerts
                       WHERE status IS DISTINCT FROM 'closed'
                         AND ((product = 'idp' AND severity IN ('critical', 'high', 'medium'))
                              OR product = 'overwatch')""")
        new = [r for r in cur.fetchall() if r[0] not in seen]
    finally:
        conn.close()
    if not new:
        return
    order = {"critical": 0, "high": 1, "medium": 2}
    groups: Dict[tuple, set] = {}
    counts: Dict[tuple, int] = {}
    for _, product, sev, name, site in new:
        k = ("OverWatch" if product == "overwatch" else sev, name)
        groups.setdefault(k, set()).add(site)
        counts[k] = counts.get(k, 0) + 1
    keys = sorted(counts, key=lambda k: (k[0] != "OverWatch", order.get(k[0], 9), -counts[k]))
    lines = [f"{counts[k]} x {k[1]} ({k[0]}) -- {', '.join(sorted(groups[k]))}" for k in keys[:12]]
    if len(keys) > 12:
        lines.append(f"... and {len(keys) - 12} more kinds")
    url = _cfg(cfg).get("identity_console_url")
    lines.append("Triage in the Identity Protection console (child CID)" + (f": {url}" if url else "") +
                 "; open list on the Worklist dashboard.")
    n_hi = sum(1 for _, product, sev, _, _ in new if product == "overwatch" or sev in ("critical", "high"))
    title = (f"{len(new)} identity detection{'s' if len(new) != 1 else ''} to triage"
             + (f" ({n_hi} high/OverWatch)" if n_hi else "") + (" -- current backlog" if not seen else ""))
    if send(cfg, title, "\n".join(lines), HIGH if n_hi else NORMAL):
        today = dt.date.today()
        seen.update({r[0]: today.isoformat() for r in new})
        cutoff = (today - dt.timedelta(days=DIGEST_KEEP_DAYS)).isoformat()
        seen = {k: v for k, v in seen.items() if v >= cutoff}
        tmp = DIGEST_STATE + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(seen, fh)
        os.replace(tmp, DIGEST_STATE)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", default="config.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("send", help="send one message")
    s.add_argument("--title", required=True)
    s.add_argument("--message", required=True)
    s.add_argument("--priority", type=int, default=NORMAL)
    sub.add_parser("run-start", help="dead-man's switch: nightly run started")
    sub.add_parser("run-skipped", help="nightly run skipped because the previous one still holds the lock")
    sub.add_parser("identity-digest", help="new identity / OverWatch detections since the last digest")
    e = sub.add_parser("run-end", help="check the run that just finished; alert on problems, ping the switch")
    e.add_argument("--rc", type=int, required=True)
    e.add_argument("--started", required=True, help="run start time, ISO 8601 with offset")
    args = ap.parse_args()

    try:
        cfg = config_mod.load_config(args.config)
        if args.cmd == "send":
            send(cfg, args.title, args.message, args.priority)
        elif args.cmd == "run-start":
            ping(cfg, "start")
        elif args.cmd == "identity-digest":
            identity_digest(cfg)
        elif args.cmd == "run-skipped":
            send(cfg, "nightly run skipped", "The previous run still holds the collector lock -- "
                 "it's still going, or hung. Check logs/collector.log.", HIGH)
        elif args.cmd == "run-end":
            started = dt.datetime.fromisoformat(args.started)
            try:
                problems = run_problems(cfg, args.rc, started)
            except Exception as ex:      # e.g. the database is down -- that's itself worth knowing
                problems = [(HIGH, f"couldn't check the run: {type(ex).__name__}: {ex}")]
            if problems:
                send(cfg, "nightly run needs a look", "\n".join(line for _, line in problems),
                     max(p for p, _ in problems))
            # the switch only hears "ok" when nothing needed a look, so its own
            # alert also covers a run that never finished
            ping(cfg, str(args.rc if args.rc else (1 if any(p == HIGH for p, _ in problems) else 0)))
    except Exception as ex:
        print(f"[notify] {type(ex).__name__}: {ex}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
