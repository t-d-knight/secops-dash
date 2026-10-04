#!/usr/bin/env python3
"""
Run this before wiring the dashboards (grafana/*.json) into a live Grafana instance.
Checks that everything the dashboard's panels query actually exists and
has data, so a broken import shows up here instead of as a wall of "No
data" panels in Grafana.

Usage:
  python3 grafana/preflight_check.py --config config.yaml
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load_config
from db import pg_connect

# (name, kind, empty_is_fatal, empty_hint)
REQUIRED_RELATIONS = [
    ("vuln_findings", "table", True, "Run collect.py with falcon_spotlight (or hadrian) enabled."),
    ("vuln_finding_cves", "table", False, "Empty until findings with CVEs are ingested -- OK if vuln_findings is also empty."),
    ("sla_policy", "table", True, "Run any script that calls db_schema.ensure_schema() (e.g. collect.py)."),
    ("sites", "table", True, "Run collect.py (ensure_schema syncs config.yaml sites into it)."),
    ("collector_runs", "table", True, "Run collect.py at least once."),
    ("cisa_kev", "table", True, "Run kev_sync.py first (CISA KEV feed sync)."),
    ("epss_scores", "table", True, "Run epss_sync.py first (FIRST.org EPSS feed sync)."),
    ("nvd_cvss_cache", "table", False, "Empty until nvd_enrich.py has looked up at least one CVE -- not fatal early on."),
    ("daily_site_metrics", "table", True, "Run rollup_daily_metrics.py first."),
    ("daily_sla_metrics", "table", True, "Run rollup_daily_metrics.py first."),
    ("daily_product_metrics", "table", True, "Run rollup_daily_metrics.py first."),
    ("daily_kev_metrics", "table", True, "Run rollup_daily_metrics.py first."),
    ("daily_epss_metrics", "table", True, "Run rollup_daily_metrics.py first."),
    ("daily_mttr_metrics", "table", False, "Empty until findings have actually been fixed -- not fatal early on."),
    ("daily_source_metrics", "table", False, "Run rollup_daily_metrics.py."),
    ("daily_asset_metrics", "table", True, "Run rollup_daily_metrics.py."),
    ("daily_alert_metrics", "table", True, "Run rollup_daily_metrics.py."),
    ("daily_identity_metrics", "table", False, "Empty until falcon_identity or entra has data."),
    ("daily_email_metrics", "table", False, "Empty until checkpoint_hec has events."),
    # per-feed tables: empty is only a warning (that collector may not be enabled)
    ("assets", "table", False, "falcon_hosts collector."),
    ("security_alerts", "table", False, "falcon_alerts collector (empty is fine if there were no alerts)."),
    ("identity_entities", "table", False, "falcon_identity collector."),
    ("external_assets", "table", False, "hadrian collector."),
    ("email_events", "table", False, "checkpoint_hec collector."),
    ("entra_mfa_registration", "table", False, "entra collector (mfa_registration feed)."),
    ("dmarc_daily", "table", False, "dmarc collector."),
    ("azure_log_metrics", "table", False, "azure_log_analytics collector."),
    ("fact_vuln_findings_current", "view", True, "Run db_schema.ensure_schema() (collect.py / rollup_daily_metrics.py do this)."),
    ("dim_site", "view", True, "Same as above."),
    ("dim_product", "view", False, "Empty until findings have a classified product_key."),
    ("asset_risk_summary", "view", True, "Same as fact_vuln_findings_current."),
    ("patch_impact_summary", "view", False, "Empty until there are open findings."),
    ("collector_freshness", "view", True, "Run collect.py at least once."),
]


def check_relation_exists(cur, name: str) -> bool:
    cur.execute("SELECT to_regclass(%s) IS NOT NULL", (f"public.{name}",))
    return bool(cur.fetchone()[0])


def check_row_count(cur, name: str) -> int:
    cur.execute(f"SELECT count(*) FROM {name}")  # nosec: name is from our own fixed allowlist above
    return cur.fetchone()[0]


def check_grafana_service_local() -> None:
    """
    Best-effort check for a local grafana-server systemd unit. Only
    meaningful if this script runs on the same host as Grafana (or is
    meant to) -- purely informational, never fatal, since Grafana may
    legitimately live elsewhere or run some other way (container, etc).
    """
    import shutil
    import subprocess

    if not shutil.which("systemctl"):
        print("[SKIP] Local grafana-server service check -- systemctl not available on this host.")
        return

    try:
        result = subprocess.run(
            ["systemctl", "is-active", "grafana-server"],
            capture_output=True, text=True, timeout=5,
        )
        state = result.stdout.strip()
        if state == "active":
            print("[PASS] grafana-server systemd service is active on this host.")
        elif state in ("inactive", "failed"):
            print(f"[WARN] grafana-server systemd service is installed but {state} -- "
                  f"start it with: sudo systemctl enable --now grafana-server")
        else:
            print("[INFO] grafana-server systemd service not found on this host "
                  "(status: not-found) -- Grafana isn't installed here yet, or runs elsewhere.")
    except Exception as e:
        print(f"[SKIP] Local grafana-server service check failed: {e}")


def check_grafana_reachable(cfg) -> bool:
    """Returns True only if Grafana was actually confirmed reachable and healthy."""
    grafana_cfg = cfg.get("grafana") or {}
    url = grafana_cfg.get("url")
    guessed = False
    if not url:
        url = "http://127.0.0.1:3000"
        guessed = True
        print(f"[INFO] No `grafana.url` set in config.yaml -- guessing {url} (default Grafana port on this host).")
        print("       Set `grafana: {url: 'http://your-grafana-host:3000'}` in config.yaml once you know the real address.")

    try:
        import requests
    except ImportError:
        print("[SKIP] Grafana HTTP reachability -- `requests` not installed.")
        return False

    try:
        resp = requests.get(f"{url.rstrip('/')}/api/health", timeout=5)
        if resp.status_code == 200:
            print(f"[PASS] Grafana reachable at {url}")
            return True
        print(f"[WARN] Grafana at {url} responded with status {resp.status_code}")
        return False
    except requests.RequestException as e:
        level = "INFO" if guessed else "FAIL"
        print(f"[{level}] Could not reach Grafana at {url}: {e}")
        if guessed:
            print("       This is expected if Grafana isn't installed on this host yet -- "
                  "see the README's Grafana install steps.")
        return False


def main():
    parser = argparse.ArgumentParser(description="Preflight check before importing the dashboards into Grafana")
    parser.add_argument("--config", default="config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)

    print("=== Postgres connectivity ===")
    try:
        conn = pg_connect(cfg)
    except Exception as e:
        print(f"[FAIL] Could not connect to Postgres: {e}")
        sys.exit(1)
    print("[PASS] Connected to Postgres.")

    cur = conn.cursor()
    fatal_failures = 0

    print("\n=== Required tables/views ===")
    for name, kind, empty_is_fatal, hint in REQUIRED_RELATIONS:
        if not check_relation_exists(cur, name):
            print(f"[FAIL] {kind} '{name}' does not exist. {hint}")
            fatal_failures += 1
            continue

        count = check_row_count(cur, name)
        if count == 0:
            level = "FAIL" if empty_is_fatal else "WARN"
            print(f"[{level}] {kind} '{name}' exists but has 0 rows. {hint}")
            if empty_is_fatal:
                fatal_failures += 1
        else:
            print(f"[PASS] {kind} '{name}' exists, {count} row(s).")

    print("\n=== Collector freshness ===")
    enabled = [n for n, c in (cfg.get("collectors") or {}).items() if (c or {}).get("enabled")]
    if check_relation_exists(cur, "collector_freshness"):
        cur.execute("SELECT collector, status, last_success, error FROM collector_freshness")
        fresh = {r[0]: r[1:] for r in cur.fetchall()}
        for name in enabled:
            st = fresh.get(name)
            if not st:
                print(f"[WARN] {name}: enabled but has never run -- run collect.py.")
            elif st[1] is None:
                print(f"[FAIL] {name}: has never succeeded. Last error: {(st[2] or '')[:300]}")
                fatal_failures += 1
            elif st[0] == "error":
                print(f"[WARN] {name}: last run failed ({(st[2] or '')[:200]}); last success {st[1]:%Y-%m-%d %H:%M}.")
            else:
                print(f"[PASS] {name}: {st[0]}, last success {st[1]:%Y-%m-%d %H:%M}.")

    print("\n=== Site coverage ===")
    configured_sites = {s.get("label", s["key"]) for s in cfg.get("sites", [])}
    if check_relation_exists(cur, "assets"):
        cur.execute(
            "SELECT site_label FROM assets WHERE NOT retired UNION "
            "SELECT site_label FROM vuln_findings UNION SELECT site_label FROM identity_entities")
        seen_sites = {r[0] for r in cur.fetchall()}
        missing = configured_sites - seen_sites
        if not configured_sites:
            print("[WARN] No sites configured in config.yaml -- everything will land in Ungrouped.")
        elif missing:
            print(f"[WARN] Configured sites with no hosts/findings/identities mapped yet: {sorted(missing)}. "
                  f"Check their match rules; the overview's 'Site mapping gaps' panel shows what fell through.")
        else:
            print(f"[PASS] All {len(configured_sites)} configured sites have data mapped to them.")

    print("\n=== Grafana ===")
    check_grafana_service_local()
    grafana_up = check_grafana_reachable(cfg)

    conn.close()

    print("\n=== Summary ===")
    if fatal_failures:
        print(f"{fatal_failures} fatal issue(s) found. Fix these before importing the dashboards.")
        sys.exit(1)
    else:
        print("All required tables/views are present and populated -- the data side is ready.")
        if grafana_up:
            print("Grafana is reachable. Remaining manual steps: add a PostgreSQL datasource pointing at this "
                  "database, then Import Dashboard -> upload each grafana/*.json -> select that datasource "
                  "for DS_POSTGRESQL.")
        else:
            print("Grafana itself is NOT confirmed reachable -- install/start it first (see the README's Grafana section) "
                  "before the datasource + dashboard import steps will make sense.")


if __name__ == "__main__":
    main()
