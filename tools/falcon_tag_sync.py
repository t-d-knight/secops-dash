#!/usr/bin/env python3
"""
Keep Falcon grouping tags on servers in step with LogicMonitor: which SCCM
patch group a server is in, and which team manages it.

    FalconGroupingTags/Patch-T1        Tier 1
    FalconGroupingTags/Patch-T2-B      Tier 2, Group B
    FalconGroupingTags/Patch-<Name>    an update group with no tier in its name
    FalconGroupingTags/Patch-None      monitored in LogicMonitor, in no update group
    FalconGroupingTags/Team-<Name>     lm_devices.team (collectors.logicmonitor.team_property;
                                       falcon_tag_sync.team_property still works as a fallback)

THE ONE PLACE THIS REPO WRITES TO A VENDOR (see AGENTS.md rule 4). Limits:
  - Only managed Falcon hosts whose type is server or domain controller.
  - Only tags under the managed prefixes (Patch-, Team-) are ever added or
    removed. Every other tag (Owner-*, PilotGroup, ...) is left alone.
  - Dry run by default: prints the plan and writes it to a CSV. --apply sends it.
  - Refuses to run on stale LogicMonitor data, and stops if the plan changes
    more hosts than --max-changes (a mass change is more likely a bug or a bad
    LogicMonitor pull than a real reorganisation).
  - Uses its own API client (falcon_tag_sync.client_id / client_secret in
    secrets.yaml, scope Hosts: Write), never the collectors' read-only one.
  - A server seen as several LogicMonitor devices takes the SCCM group from the
    entry that has one, and every team listed ("Applications, Database" is two
    Team tags). Two DIFFERENT groups is a conflict: that server is skipped.
  - Patch-None means LogicMonitor holds no SCCM group for the server. That can
    be "not in any update group" or the SCCM sync not matching it; check before
    treating it as unpatched.

Reads the current tags from the assets table (last night's falcon_hosts run),
so run it after the nightly collection. Changes show up in the database after
the next run.

  venv/bin/python3 tools/falcon_tag_sync.py --config config.yaml           # plan only
  venv/bin/python3 tools/falcon_tag_sync.py --config config.yaml --apply --host SRV01 --host SRV02  # pilot
  venv/bin/python3 tools/falcon_tag_sync.py --config config.yaml --apply   # send it

Every run is a differential: it compares what each server should carry with
what it carries now and sends only the difference, so a daily run with nothing
changed in LogicMonitor or SCCM sends nothing.
"""
import argparse
import collections
import csv
import datetime as dt
import os
import re
import sys
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as config_mod  # noqa: E402
from collectors.falcon_client import FalconClient  # noqa: E402
from db import pg_connect  # noqa: E402

PREFIX = "FalconGroupingTags/"
MANAGED = ("Patch-", "Team-")
TAG_PATH = "/devices/entities/devices/tags/v1"
BATCH = 100


def slug(v: Optional[str]) -> Optional[str]:
    """'Power BI' -> 'PowerBI'; Falcon tags allow letters, digits, - and _ only."""
    if not v:
        return None
    v = re.sub(r"\(.*?\)", " ", str(v))
    words = re.findall(r"[A-Za-z0-9]+", v)
    s = "".join(w[:1].upper() + w[1:] for w in words)
    return s[:60] or None


def patch_tag(in_lm: bool, group: Optional[str], tier: Optional[int], sub: Optional[str]) -> Optional[str]:
    if not in_lm:
        return None                       # not monitored: we know nothing, so say nothing
    if tier is not None:
        return f"Patch-T{tier}" + (f"-{sub}" if sub else "")
    if group:
        return f"Patch-{slug(group) or 'Unnamed'}"
    return "Patch-None"


def team_tags(v: Optional[str]) -> Set[str]:
    """'Applications, Database' -> {Team-Applications, Team-Database}."""
    return {f"Team-{s}" for s in (slug(p) for p in re.split(r"[,;/&]", v or "")) if s}


def is_managed(tag: str) -> bool:
    t = tag[len(PREFIX):] if tag.lower().startswith(PREFIX.lower()) else None
    return bool(t) and any(t.lower().startswith(m.lower()) for m in MANAGED)


def build_plan(conn, team_property: Optional[str]):
    cur = conn.cursor()
    cur.execute("""
        SELECT a.source_asset_id, a.hostname, coalesce(a.tags, '{}'),
               l.device_id, l.patch_group, l.patch_tier, l.patch_subgroup,
               coalesce(l.team, CASE WHEN %(tp)s IS NULL THEN NULL ELSE l.properties ->> %(tp)s END)
        FROM assets a
        LEFT JOIN lm_devices l
               ON NOT l.retired AND l.host_key = lower(split_part(a.hostname, '.', 1))
        WHERE a.source = 'falcon' AND NOT a.retired
          AND a.product_type IN ('server', 'domain_controller')
    """, {"tp": team_property})
    hosts: Dict[str, dict] = {}
    for aid, host, tags, dev, group, tier, sub, team in cur.fetchall():
        h = hosts.setdefault(aid, {"hostname": host, "tags": list(tags), "patch": set(), "teams": set()})
        p = patch_tag(dev is not None, group, tier, sub)
        if p:
            h["patch"].add(p)
        h["teams"].update(team_tags(team))

    plan, skipped = [], []
    for aid, h in sorted(hosts.items(), key=lambda kv: (kv[1]["hostname"] or "", kv[0])):
        # One server seen as several LogicMonitor devices (cluster name, IP-monitored
        # duplicate...): the entry that carries an SCCM group wins over one that doesn't,
        # teams are combined, and two DIFFERENT groups is a conflict we leave alone.
        patch = h["patch"] - {"Patch-None"} or h["patch"]
        if len(patch) > 1:
            skipped.append((aid, h["hostname"], "LogicMonitor devices disagree: " + ", ".join(sorted(patch))))
            continue
        want = {PREFIX + t for t in patch | h["teams"]}
        have = {t for t in h["tags"] if is_managed(t)}
        have_l = {t.lower() for t in have}
        add = sorted(t for t in want if t.lower() not in have_l)
        want_l = {t.lower() for t in want}
        remove = sorted(t for t in have if t.lower() not in want_l)
        if add or remove:
            plan.append((aid, h["hostname"], add, remove))
    return plan, skipped, len(hosts)


def lm_freshness(conn) -> Tuple[int, Optional[dt.datetime]]:
    cur = conn.cursor()
    cur.execute("SELECT count(*), max(collected_at) FROM lm_devices WHERE NOT retired")
    return cur.fetchone()


def write_csv(path: str, plan, skipped) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["aid", "hostname", "add", "remove", "skipped_reason"])
        for aid, host, add, rem in plan:
            w.writerow([aid, host, " ".join(add), " ".join(rem), ""])
        for aid, host, why in skipped:
            w.writerow([aid, host, "", "", why])


def apply_plan(fc: FalconClient, plan) -> List[str]:
    by_change: Dict[Tuple[str, str], List[str]] = collections.defaultdict(list)
    for aid, _, add, rem in plan:
        for t in add:
            by_change[("add", t)].append(aid)
        for t in rem:
            by_change[("remove", t)].append(aid)
    errors = []
    for (action, tag), aids in sorted(by_change.items()):
        for i in range(0, len(aids), BATCH):
            chunk = aids[i:i + BATCH]
            j = fc.patch(TAG_PATH, {"action": action, "device_ids": chunk, "tags": [tag]})
            for r in j.get("resources") or []:
                if r.get("code") not in (None, 200) or r.get("error"):
                    errors.append(f"{action} {tag} on {r.get('device_id')}: {r.get('code')} {r.get('error')}")
            for e in j.get("errors") or []:
                errors.append(f"{action} {tag}: {e}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--apply", action="store_true", help="send the changes (default: plan only)")
    ap.add_argument("--max-changes", type=int, help="stop if more hosts would change (default from config, else 100)")
    ap.add_argument("--out", help="plan CSV (default reports/falcon-tag-plan.csv)")
    ap.add_argument("--host", action="append", default=[],
                    help="only these servers (short hostname, repeatable): for a pilot run")
    args = ap.parse_args()

    cfg = config_mod.load_config(args.config)
    tcfg = cfg.get("falcon_tag_sync") or {}
    max_changes = args.max_changes if args.max_changes is not None else int(tcfg.get("max_changes", 100))
    max_age_h = float(tcfg.get("max_lm_age_hours", 36))
    out = args.out or tcfg.get("plan_out") or os.path.join(cfg.get("_config_dir", "."), "reports",
                                                           "falcon-tag-plan.csv")
    conn = pg_connect(cfg)

    n_lm, last = lm_freshness(conn)
    if not n_lm or not last or dt.datetime.now(dt.timezone.utc) - last > dt.timedelta(hours=max_age_h):
        print(f"LogicMonitor data missing or older than {max_age_h:g}h (devices={n_lm}, last pull={last}). "
              "Run the logicmonitor collector first.")
        return 2

    plan, skipped, n_servers = build_plan(conn, tcfg.get("team_property"))
    if args.host:
        only = {h.strip().lower().split(".")[0] for h in args.host if h.strip()}
        keep = lambda host: (host or "").lower().split(".")[0] in only  # noqa: E731
        plan = [x for x in plan if keep(x[1])]
        skipped = [x for x in skipped if keep(x[1])]
        print(f"limited to --host {sorted(only)}: {len(plan)} to change")
    write_csv(out, plan, skipped)
    adds = collections.Counter(t for _, _, a, _ in plan for t in a)
    rems = collections.Counter(t for _, _, _, r in plan for t in r)
    print(f"servers considered: {n_servers}; hosts to change: {len(plan)}; skipped (conflicts): {len(skipped)}")
    for t, n in sorted(adds.items()):
        print(f"  add    {t[len(PREFIX):]:<30} {n}")
    for t, n in sorted(rems.items()):
        print(f"  remove {t[len(PREFIX):]:<30} {n}")
    print(f"plan written to {out}")

    if not args.apply:
        print("dry run: nothing sent (use --apply)")
        return 0
    if len(plan) > max_changes:
        print(f"refusing: {len(plan)} hosts would change, over --max-changes {max_changes}. "
              "Check the plan, then rerun with a higher limit if it's right.")
        return 3
    if not plan:
        return 0
    if not tcfg.get("client_id") or not tcfg.get("client_secret"):
        print("falcon_tag_sync.client_id / client_secret missing from secrets.yaml "
              "(a separate API client with Hosts: Write; the collectors' client stays read-only)")
        return 2
    fc = FalconClient(cfg, {k: tcfg[k] for k in ("client_id", "client_secret", "base_url") if k in tcfg})
    errors = apply_plan(fc, plan)
    for e in errors:
        print("  ERROR", e)
    print(f"applied: {len(plan)} hosts, {sum(adds.values())} adds, {sum(rems.values())} removes, {len(errors)} errors")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
