#!/usr/bin/env python3
"""
End-to-end test: every collector against the mock vendor APIs, into a
throwaway Postgres database, then the rollups, then every SQL query in the
Grafana dashboards. Exits non-zero on any failure.

  PGHOST=127.0.0.1 PGUSER=postgres python3 tests/run_e2e.py

Needs a Postgres it may DROP/CREATE the database `secops_e2e` on.
"""
import csv
import datetime as dt
import glob
import json
import os
import re
import subprocess
import sys
import tempfile

import psycopg2

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import mock_vendors  # noqa: E402

PG = dict(host=os.environ.get("PGHOST", "127.0.0.1"), port=int(os.environ.get("PGPORT", 5432)),
          user=os.environ.get("PGUSER", "postgres"), password=os.environ.get("PGPASSWORD"))
DB = "secops_e2e"
PORT = 8999
M = f"http://127.0.0.1:{PORT}"

CONFIG = f"""
crowdstrike: {{base_url: "{M}/falcon"}}
reporting: {{days_last_seen: 30, require_exploit_for_remote_no_auth: true, stale_sensor_days: 7,
            sla_days: {{critical: 2, high: 14, medium: 30, low: 60}}}}
sites:
  - key: RVH
    label: Riverside Health
    match: {{falcon_groups: ["RVH Workstations"], ad_domains: ["rvh.local"], email_domains: ["riversidehealth.test"],
            cidrs: ["10.1.0.0/16", "203.0.113.0/28"]}}
  - key: LKH
    label: Lakeside Health
    match: {{falcon_tags: ["SensorGroupingTags/LKH"], ou_contains: ["ou=lakeside"],
            email_domains: ["lakesidehealth.test"], hostname_regex: ["^LKH-"]}}
ungrouped_label: Ungrouped
database: {{host: "{PG['host']}", port: {PG['port']}, name: {DB}, user: "{PG['user']}"}}
secrets_file: secrets.yaml
collectors:
  falcon_hosts: {{enabled: true, out_of_scope_ous: {{"Departed Service": "left the alliance"}}}}
  falcon_spotlight: {{enabled: true, page_size: 2, cursor_retry_wait: 0}}
  falcon_alerts: {{enabled: true}}
  falcon_identity: {{enabled: true, access_domain: {{domain: "shared.local", native_sites: ["Lakeside Health"]}}}}
  falcon_usb: {{enabled: true, lookback_days: 5}}
  hadrian:
    enabled: true
    base_url: "{M}/hadrian"
    organization_id: "org1"
    tag_aliases: {{OLDRVH: RVH}}
    archive_tags: ["zzArchive"]
    suggested_tags_out: "hadrian-suggested-tags.csv"
    detail_workers: 2
    assets: {{path: "/organizations/{{organization_id}}/assets", items_key: items,
             pagination: {{type: page, param: offset, size_param: pageSize, size: 1, start: 0}},
             fields: {{id: assetId, name: value, type: platformAssetType,
                      first_seen: detectedOnUtc, last_seen: lastSeenAtUtc}}}}
    risks: {{path: "/organizations/{{organization_id}}/risks", detail_path: "/organizations/{{organization_id}}/risks/{{id}}",
            items_key: items, pagination: {{type: page, param: offset, size_param: pageSize, size: 1, start: 0}},
            fields: {{id: id, title: title, severity: riskSeverity, activity: activityStatus, status: status,
                     visibility: riskVisibility, risk_type: riskType, category: primaryCategory.id,
                     first_seen: created, last_seen: lastSeen, resolved_at: resolvedOn}}}}
  logicmonitor:
    enabled: true
    base_url: "{M}/lm/santaba/rest"
    page_size: 2
    patch_timezone: "Asia/Tokyo"
    team_property: org.managedBy
    keep_properties: ["org.class", "org.managedBy", "snmp.community"]
  checkpoint_hec: {{enabled: true, gateway: "{M}/hec", block_marker: "BLOCK_MARKER"}}
  checkpoint_hec_flow: {{enabled: true, lookback_days: 1}}
  entra:
    enabled: true
    tenants: [{{name: main, tenant_id: t1, login_base: "{M}/login", graph_base: "{M}/graph",
               loganalytics_base: "{M}/la"}}]
  azure_log_analytics:
    enabled: true
    workspaces: [{{name: ws, tenant: main, workspace_id: w1}}]
    queries: [{{name: signins, key_type: upn, kql: "SigninLogs | take 1"}}]
  dmarc: {{enabled: true, opensearch_url: "{M}/os", username: u}}
falcon_tag_sync: {{max_changes: 5}}
notify: {{enabled: true, host_label: e2e, healthcheck_url: "{M}/hc/abc",
          pushover: {{api_url: "{M}/pushover/1/messages.json"}}}}
"""
SECRETS = """
database: {password: null}
crowdstrike: {client_id: cid, client_secret: sec}
collectors:
  hadrian: {api_key: hk}
  logicmonitor: {access_id: lid, access_key: lk}
  checkpoint_hec: {client_id: hc, access_key: hk}
  entra: {tenants: [{name: main, client_id: ac, client_secret: as}]}
  dmarc: {password: p}
notify: {pushover: {app_token: at, user_key: uk}}
falcon_tag_sync: {client_id: tcid, client_secret: tsec}
"""

failures = []


SITE_VALS = "'Riverside Health','Lakeside Health','Ungrouped'"


def dash_sql(sql):
    """Dashboard SQL with Grafana's variables and macros substituted, runnable in plain Postgres."""
    sql = (sql.replace("$site", SITE_VALS).replace("${site:sqlstring}", SITE_VALS)
           .replace("$team", "'Systems','Cyber','Power BI','(no team)'")
           .replace("$source", "'falcon_spotlight','hadrian'")
           .replace("$__timeFilter(", "TRUE OR (").replace("$__timeFrom()", "now()-interval '30 days'")
           .replace("$__timeTo()", "now()")
           .replace("${__from:date}", (dt.date.today() - dt.timedelta(days=30)).isoformat())
           .replace("${__to:date}", dt.date.today().isoformat())
           # patch compliance drill-down variables (textbox, quoted by Grafana's :sqlstring)
           .replace("${pgroup:sqlstring}", "'Tier 1'").replace("${focus:sqlstring}", "'Overdue'")
           .replace("${pfix:sqlstring}", "''").replace("${dkey:sqlstring}", "'x'"))
    sql = re.sub(r"\$__timeGroupAlias\(([^,]+),[^)]+\)", r"date_trunc('day', \1) AS time", sql)
    sql = re.sub(r"\$__timeGroup\(([^,]+),[^)]+\)", r"date_trunc('day', \1)", sql)
    return sql


def check(cond, msg):
    print(("  PASS " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def q(cur, sql, *a):
    cur.execute(sql, a)
    return cur.fetchall()


def main() -> int:
    admin = psycopg2.connect(dbname="postgres", **PG)
    admin.autocommit = True
    admin.cursor().execute(f"DROP DATABASE IF EXISTS {DB}")
    admin.cursor().execute(f"CREATE DATABASE {DB}")

    tmp = tempfile.mkdtemp()
    marker = os.path.join(tmp, "hec-blocked")
    open(os.path.join(tmp, "config.yaml"), "w").write(CONFIG.replace("BLOCK_MARKER", marker))
    open(os.path.join(tmp, "secrets.yaml"), "w").write(SECRETS)
    cfgp = os.path.join(tmp, "config.yaml")
    srv = mock_vendors.start(PORT)

    def run(*args):
        r = subprocess.run([sys.executable, *args, "--config", cfgp], cwd=ROOT, capture_output=True, text=True)
        print(r.stdout[-4000:])
        if r.returncode != 0:
            print(r.stderr[-4000:])
        return r.returncode

    # schema first, then seed KEV/EPSS and a stale open row that must get EXPIRED
    import config as config_mod
    import db_schema
    cfg = config_mod.load_config(cfgp)
    db_schema.ensure_schema(cfg)
    conn = psycopg2.connect(dbname=DB, **PG)
    cur = conn.cursor()
    cur.execute("INSERT INTO cisa_kev (cve_id, date_added, due_date, known_ransomware_campaign_use) "
                "VALUES ('CVE-2021-44228', '2021-12-10', '2021-12-24', 'Known')")
    cur.execute("INSERT INTO epss_scores (cve_id, epss, percentile) VALUES ('CVE-2024-0001', 0.71, 0.99)")
    cur.execute("""INSERT INTO vuln_findings (source, source_asset_id, source_rule_id, state, severity, first_found,
                   last_found, site_label, last_seen_in_export)
                   VALUES ('falcon_spotlight','aid9','gone','OPEN','high', now()-interval '50 days',
                           now()-interval '1 day','Ungrouped', now()-interval '1 day')""")
    conn.commit()

    print("== collect.py (all collectors)")
    rc = run("collect.py")
    check(rc == 0, "collect.py exited 0")
    print("== collect.py second run (idempotency / incremental)")
    check(run("collect.py") == 0, "second collect.py run exited 0")
    # incremental open pull: only changed vulns asked for, and nothing expired (the pull isn't complete)
    cfg_inc = os.path.join(tmp, "config-incremental.yaml")
    open(cfg_inc, "w").write(CONFIG.replace("falcon_spotlight: {enabled: true, page_size: 2,",
                                            "falcon_spotlight: {enabled: true, page_size: 2, open_pull: incremental, "
                                            "full_pull_weekdays: [],"))
    cur.execute("""INSERT INTO vuln_findings (source, source_asset_id, source_rule_id, state, severity, first_found,
                   last_found, site_label, last_seen_in_export)
                   VALUES ('falcon_spotlight','aid9','gone2','OPEN','high', now()-interval '50 days',
                           now()-interval '1 day','Ungrouped', now()-interval '1 day')""")
    conn.commit()
    n_calls = len(mock_vendors.CALLS)
    r = subprocess.run([sys.executable, "collect.py", "--config", cfg_inc, "--only", "falcon_spotlight"],
                       cwd=ROOT, capture_output=True, text=True)
    check(r.returncode == 0, "incremental Spotlight run exited 0")
    if r.returncode != 0:
        print(r.stdout[-2000:], r.stderr[-2000:])
    flts = [c[2].get("filter", [""])[0] for c in mock_vendors.CALLS[n_calls:]
            if c[1] == "/falcon/spotlight/combined/vulnerabilities/v1" and "after" not in c[2]]
    check(len(flts) == 2 and all("updated_timestamp:>" in f for f in flts),
          f"incremental run asks only for updated open + closed vulns: {flts}")
    mode = q(cur, "SELECT stats->>'open_pull' FROM collector_runs WHERE collector = 'falcon_spotlight' "
                  "ORDER BY started_at DESC LIMIT 1")[0][0]
    st2 = q(cur, "SELECT state FROM vuln_findings WHERE source_rule_id = 'gone2'")[0][0]
    check(mode == "incremental" and st2 == "OPEN", f"incremental pull expires nothing ({mode}, gone2 {st2})")
    cur.execute("DELETE FROM vuln_findings WHERE source_rule_id = 'gone2'")
    conn.commit()
    print("== rollup_daily_metrics.py")
    check(run("rollup_daily_metrics.py") == 0, "rollup exited 0")

    print("== notifications")
    # form-encoded, so the mock parses each field to a list
    pushes = lambda: [{k: v[0] for k, v in c[2].items()} for c in mock_vendors.CALLS
                      if c[1] == "/pushover/1/messages.json"]
    pings = lambda: [c[1] for c in mock_vendors.CALLS if c[1].startswith("/hc/")]
    started = (dt.datetime.now().astimezone() - dt.timedelta(minutes=5)).isoformat(timespec="seconds")
    subprocess.run([sys.executable, "notify.py", "--config", cfgp, "run-start"], cwd=ROOT)
    subprocess.run([sys.executable, "notify.py", "--config", cfgp, "run-end", "--rc", "0", "--started", started], cwd=ROOT)
    check(pings() == ["/hc/abc/start", "/hc/abc/0"] and not pushes(),
          f"healthy run: start + success pings, no Pushover message ({pings()}, {len(pushes())} pushes)")
    cur.execute("INSERT INTO collector_runs (collector, started_at, finished_at, status, error) "
                "VALUES ('falcon_alerts', now(), now(), 'error', 'HTTP 403 from vendor')")
    conn.commit()
    subprocess.run([sys.executable, "notify.py", "--config", cfgp, "run-end", "--rc", "1", "--started", started], cwd=ROOT)
    p = pushes()
    check(len(p) == 1 and "falcon_alerts: error -- HTTP 403" in p[0].get("message", "")
          and p[0].get("priority") == "1" and pings()[-1] == "/hc/abc/1",
          f"failed collector: one high-priority push naming it, failure ping ({p}, {pings()[-1:]})")
    cur.execute("DELETE FROM collector_runs WHERE error = 'HTTP 403 from vendor'")
    # source gone quiet: the collector still succeeds, but its newest data is a week old
    cur.execute("UPDATE dmarc_daily SET report_date = current_date - 7")
    conn.commit()
    subprocess.run([sys.executable, "notify.py", "--config", cfgp, "run-end", "--rc", "0", "--started", started], cwd=ROOT)
    p = pushes()
    check(len(p) == 2 and "dmarc: runs OK but newest data is" in p[1].get("message", "")
          and p[1].get("priority") == "0" and pings()[-1] == "/hc/abc/0",
          f"quiet feed: normal-priority push naming it, success ping ({p[1:]}, {pings()[-1:]})")
    srv.shutdown()
    srv.server_close()

    cur = conn.cursor()
    print("== collector_runs")
    rows = q(cur, "SELECT collector, status, error FROM collector_freshness ORDER BY 1")
    for r in rows:
        check(r[1] == "ok", f"collector {r[0]} status ok ({r[2] or ''})")
    check(len(rows) == 12, f"12 collectors ran (got {len(rows)})")

    print("== site resolution")
    sites = dict(q(cur, "SELECT source_asset_id, site_label || '/' || site_matched_by FROM assets"))
    check(sites.get("aid1") == "Riverside Health/falcon_groups", f"aid1 via host group: {sites.get('aid1')}")
    check(sites.get("aid2") == "Lakeside Health/falcon_tags", f"aid2 via tag: {sites.get('aid2')}")
    check(sites.get("aid3") == "Riverside Health/ad_domains", f"aid3 via AD domain: {sites.get('aid3')}")
    check(sites.get("aid4") == "Ungrouped/none", f"aid4 ungrouped: {sites.get('aid4')}")
    check(sites.get("u1") == "Riverside Health/cidrs", f"unmanaged u1 via CIDR: {sites.get('u1')}")
    check(sites.get("u5") == "Lakeside Health/discoverer", f"network-only u5 via its discoverer's site: {sites.get('u5')}")
    cls = dict(q(cur, "SELECT source_asset_id, discovery_class FROM assets WHERE source = 'falcon_unmanaged'"))
    check(cls == {"u1": "network_device", "u2": "workstation_no_sensor", "u3": "service_account",
                  "u4": "duplicate_of_managed", "u5": "vmware_nic", "u6": "out_of_scope",
                  "u7": "secondary_ip_of_managed", "u8": "duplicate_of_managed"}, f"Discover classes {cls}")
    twin = q(cur, "SELECT managed_twin FROM assets WHERE source_asset_id = 'u4'")[0][0]
    check(twin == "RVH-WS01", f"duplicate linked to its managed host: {twin}")

    print("== vulnerabilities")
    st = dict(q(cur, "SELECT source_rule_id, state FROM vuln_findings"))
    check(st.get("v1") == "OPEN" and st.get("v2") == "REOPENED", "open/reopen mapped")
    check(st.get("v3") == "SUPPRESSED", "suppressed vuln -> SUPPRESSED")
    check(st.get("v5") == "FIXED", "closed vuln -> FIXED")
    check(st.get("gone") == "EXPIRED", "vanished open vuln -> EXPIRED (not FIXED)")
    check((st.get("r1"), st.get("r2"), st.get("r3")) == ("OPEN", "FIXED", "REOPENED"),
          f"Hadrian activity/status -> OPEN/FIXED(NotFound)/REOPENED: {st.get('r1'), st.get('r2'), st.get('r3')}")
    check("r4" not in st, "risk only on a zzArchive asset skipped")
    r5 = q(cur, "SELECT state, last_fixed::date = (now() - interval '18 days')::date FROM vuln_findings "
                "WHERE source = 'hadrian' AND source_rule_id = 'r5'")[0]
    check(r5 == ("FIXED", True), f"Hadrian Ignored + rescan NotFound -> FIXED, dated resolvedOn: {r5}")
    from collectors.hadrian import _risk_state
    check(_risk_state("Ignored", "New", "Visible") == "SUPPRESSED",
          "Hadrian Ignored but still detected -> SUPPRESSED (accepted risk, not fixed)")
    check(_risk_state("Snoozed", "New", "Visible") == "OPEN",
          "unknown Hadrian activityStatus stays OPEN (never hidden on a guess)")
    rt = dict(q(cur, "SELECT source_rule_id, risk_type FROM vuln_findings WHERE source = 'hadrian'"))
    check(rt.get("r1") == "UnpatchedTechnology" and rt.get("r3") == "InfectedDevice", f"risk_type stored: {rt}")
    xa = dict(q(cur, "SELECT asset_id, site_label || '/' || site_matched_by FROM external_assets"))
    check(xa == {"a1": "Riverside Health/hadrian_tag", "a2": "Lakeside Health/hadrian_apex"},
          f"external asset sites (tag, apex; archived skipped): {xa}")
    v1 = q(cur, "SELECT is_remote_no_auth, exploit_available, product_key, fix_id, site_label FROM vuln_findings WHERE source_rule_id='v1'")[0]
    check(v1 == (True, True, "google:chrome", "R1", "Riverside Health"), f"v1 enrichment {v1}")
    v2r = q(cur, "SELECT is_remote_no_auth FROM vuln_findings WHERE source_rule_id='v2'")[0][0]
    check(v2r is False, "no vector -> not remote/no-auth (old cvss bug fixed)")
    lf = q(cur, "SELECT last_found > now() - interval '1 day' FROM vuln_findings WHERE source_rule_id='v1'")[0][0]
    check(lf, "last_found taken from host last_seen")
    runs = q(cur, "SELECT stats->>'rows', stats->>'changed' FROM collector_runs WHERE collector = 'falcon_spotlight' "
                  "AND stats->>'open_pull' = 'full' ORDER BY started_at")
    check(len(runs) == 2 and runs[1][1] == "0" and runs[1][0] != "0",
          f"second identical pull rewrites no findings (rows, changed per run: {runs})")
    desc = q(cur, "SELECT count(*) FROM cve_descriptions")[0][0]
    syn = q(cur, "SELECT count(*) FROM vuln_findings WHERE source = 'falcon_spotlight' AND synopsis IS NOT NULL")[0][0]
    check(desc >= 4 and syn == 0, f"CVE descriptions stored once per CVE ({desc}), not per finding ({syn})")
    kev = q(cur, "SELECT count(*) FROM fact_vuln_findings_current WHERE has_kev")[0][0]
    check(kev == 1, f"KEV joins Spotlight log4j; Hadrian risks carry no CVEs (got {kev})")
    patch = q(cur, "SELECT title, open_findings, affected_assets FROM patch_impact_summary WHERE fix_key='R1'")
    check(patch and patch[0][1] == 2, f"R1 patch groups both Chrome CVEs: {patch}")
    ext = q(cur, "SELECT site_label, asset_type FROM vuln_findings WHERE source='hadrian' AND source_rule_id='r1'")[0]
    check(ext == ("Riverside Health", "internet"), f"Hadrian risk site/type {ext}")

    print("== falcon_spotlight: chunked full pull, dropped cursors, fallback, catch-up")
    srv = mock_vendors.start(PORT)   # stopped after the collector runs above
    SP = "/falcon/spotlight/combined/vulnerabilities/v1"

    def spotlight(extra_cfg, *args, seed=None):
        """One Spotlight-only run with extra config; seeds a stale open row `seed` first."""
        conn.commit()   # don't hold a read lock that collect.py's schema check would wait on
        if seed:
            cur.execute("""INSERT INTO vuln_findings (source, source_asset_id, source_rule_id, state, severity,
                           first_found, last_found, site_label, last_seen_in_export)
                           VALUES ('falcon_spotlight','aid9',%s,'OPEN','high', now()-interval '50 days',
                                   now()-interval '1 day','Ungrouped', now()-interval '1 day')""", (seed,))
            conn.commit()
        path = os.path.join(tmp, "config-spotlight.yaml")
        open(path, "w").write(CONFIG.replace("falcon_spotlight: {enabled: true, page_size: 2,",
                                             f"falcon_spotlight: {{enabled: true, page_size: 2, {extra_cfg},"))
        n0 = len(mock_vendors.CALLS)
        r = subprocess.run([sys.executable, "collect.py", "--config", path, "--only", "falcon_spotlight", *args],
                           cwd=ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            print(r.stdout[-3000:], r.stderr[-3000:])
        row = q(cur, "SELECT status, stats FROM collector_runs WHERE collector = 'falcon_spotlight' "
                     "ORDER BY started_at DESC LIMIT 1")[0]
        st = q(cur, "SELECT state FROM vuln_findings WHERE source_rule_id = %s", seed)[0][0] if seed else None
        if seed:
            cur.execute("DELETE FROM vuln_findings WHERE source_rule_id = %s", (seed,))
            conn.commit()
        calls = [c[2] for c in mock_vendors.CALLS[n0:] if c[1] == SP]
        return r.returncode, row[0], row[1] or {}, st, calls, r.stdout

    # 1. normal full pull: every open request is a created_timestamp window; vanished rows expire
    rc, status, stats, st, calls, _ = spotlight("full_pull_chunk_days: 30, full_pull_span_days: 60", seed="gone3")
    opens = [c.get("filter", [""])[0] for c in calls if "closed" not in c.get("filter", [""])[0]
             and "after" not in c and c.get("limit") != ["1"]]
    check(rc == 0 and status == "ok" and stats.get("open_pull") == "full" and stats.get("open") == 4
          and stats.get("full_pull_windows") == 3 and st == "EXPIRED",
          f"chunked full pull: 3 windows (catch-all + 2 x 30 days), all 4 open vulns, vanished row expired ({status}, {stats}, {st})")
    check(opens and all("created_timestamp:>='" in f and "created_timestamp:<'" in f for f in opens),
          f"every full-pull page asks for one created_timestamp window ({len(opens)} requests)")

    # 2. Falcon drops the cursor on wide windows: only that window is split, the pull still completes
    mock_vendors.SPOTLIGHT_DROP_WIDER_THAN_H = 12
    rc, status, stats, st, _, out = spotlight("full_pull_chunk_days: 30, full_pull_span_days: 60", seed="gone4")
    check(rc == 0 and status == "ok" and stats.get("open") == 4 and stats.get("full_pull_splits", 0) > 0
          and st == "EXPIRED" and "splitting it" in out,
          f"dropped cursor: window halved until it fits, pull completes and expires ({status}, {stats}, {st})")

    # 3. a window still failing at the minimum width: incremental fallback, nothing expired, 'partial'
    mock_vendors.SPOTLIGHT_DROP_WIDER_THAN_H = 0
    rc, status, stats, st, calls, _ = spotlight("full_pull_chunk_days: 30, full_pull_span_days: 60", seed="gone5")
    closed_pulled = any("closed" in c.get("filter", [""])[0] for c in calls)
    check(rc == 0 and status == "partial" and "full_pull.error" in stats and stats.get("open_pull") == "incremental"
          and st == "OPEN" and closed_pulled,
          f"full pull can't finish: partial, incremental + closed pulls still run, nothing expired "
          f"({rc}, {status}, {sorted(stats)}, {st}, closed pulled {closed_pulled})")
    mock_vendors.SPOTLIGHT_DROP_WIDER_THAN_H = None

    # 4. windows return fewer than Falcon's own total: don't expire
    mock_vendors.SPOTLIGHT_TOTAL_EXTRA = 100
    rc, status, stats, st, _, _ = spotlight("full_pull_chunk_days: 30, full_pull_span_days: 60", seed="gone6")
    check(rc == 0 and status == "partial" and "expire.error" in stats and st == "OPEN",
          f"short of Falcon's total: nothing expired, partial ({status}, {stats.get('expire.error')}, {st})")
    mock_vendors.SPOTLIGHT_TOTAL_EXTRA = 0

    # 5. catch-up never does a full pull, even on a full-pull weekday; the same config without it does
    every_day = "open_pull: incremental, full_pull_weekdays: [0, 1, 2, 3, 4, 5, 6]"
    rc, status, stats, st, calls, _ = spotlight(every_day, "--catch-up", seed="gone7")
    flts = [c.get("filter", [""])[0] for c in calls if "after" not in c]
    check(rc == 0 and stats.get("open_pull") == "incremental" and st == "OPEN"
          and all("updated_timestamp:>" in f for f in flts),
          f"--catch-up: incremental only, nothing expired ({stats.get('open_pull')}, {st}, {flts})")
    rc, status, stats, st, _, _ = spotlight(every_day, seed="gone8")
    check(stats.get("open_pull") == "full" and st == "EXPIRED",
          f"same config, nightly run: full pull on a full-pull weekday ({stats.get('open_pull')}, {st})")
    srv.shutdown()
    srv.server_close()

    print("== logicmonitor")
    conn.commit()
    lm = {r[0]: r[1:] for r in q(cur, """SELECT device_id, host_key, site_label, site_matched_by, patch_tier,
                                                patch_subgroup, patch_window_start, patch_deadline, properties
                                         FROM lm_devices""")}
    check(sorted(lm) == [101, 102, 103, 104, 105], f"all LogicMonitor devices across pages: {sorted(lm)}")
    check(lm[101][:5] == ("lkh-srv01", "Lakeside Health", "falcon_asset", 1, None),
          f"sysname -> host_key, site taken from the matching Falcon host, Tier 1: {lm[101][:5]}")
    check(lm[101][5].isoformat() == "2026-11-11T10:00:00+00:00" and lm[101][6].isoformat() == "2026-11-12T22:00:00+00:00",
          f"SCCM local times read in patch_timezone: {lm[101][5]}, {lm[101][6]}")
    check(lm[102][1:5] == ("Riverside Health", "ad_domains", 2, "B") and lm[102][6] is None,
          f"no Falcon twin -> resolver; Tier 2 Group B; bad date -> NULL: {lm[102][1:7]}")
    check(lm[103][0] is None and lm[103][3] is None, f"IP-only device has no host key or tier: {lm[103][:4]}")
    check(lm[104][3] is None and lm[104][5] is not None, f"group with no tier keeps its schedule: {lm[104][3:6]}")
    leaked = [k for v in lm.values() for k in (v[7] or {}) if k not in ("org.class", "org.managedBy")]
    check(lm[101][7] == {"org.class": "Server Endpoints", "org.managedBy": "Power BI"} and not leaked,
          f"only keep_properties stored, credential-like ones dropped even if listed: {lm[101][7]}, {leaked}")
    view = q(cur, "SELECT device_id, falcon_aid, in_patch_group FROM lm_device_patch ORDER BY 1")
    check(view == [(101, "aid2", True), (102, None, True), (103, None, False), (104, None, True), (105, "aid2", False)],
          f"lm_device_patch joins Falcon by short hostname: {view}")
    cur.execute("INSERT INTO lm_devices (device_id, site_label, collected_at) VALUES (999, 'Ungrouped', now() - interval '2 days')")
    conn.commit()   # also ends this connection's read transaction: collect.py's schema step needs the locks
    srv.server_close()
    srv = mock_vendors.start(PORT)   # the mocks were stopped after the collector runs above
    check(run("collect.py", "--only", "logicmonitor") == 0, "logicmonitor re-run exited 0")
    ret = dict(q(cur, "SELECT device_id, retired FROM lm_devices WHERE device_id IN (101, 999)"))
    check(ret == {101: False, 999: True}, f"device gone from LogicMonitor is retired: {ret}")

    print("== Check Point edge block")
    def hec_calls():
        return [c[1] for c in mock_vendors.CALLS if c[1].startswith("/hec/")]
    def last_errors():
        r = dict(q(cur, """SELECT DISTINCT ON (collector) collector, COALESCE(error, status) FROM collector_runs
                           WHERE collector LIKE 'checkpoint_hec%%' ORDER BY collector, started_at DESC"""))
        conn.commit()
        return r
    conn.commit()   # end this connection's read transaction: collect.py's schema step needs the locks
    mock_vendors.HEC_EDGE_BLOCK = True
    del mock_vendors.CALLS[:]
    rc = run("collect.py", "--only", "checkpoint_hec,checkpoint_hec_flow")
    conn.commit()
    lines = open(marker).read().splitlines() if os.path.exists(marker) else []
    errs = last_errors()
    check(rc == 1 and lines[:1] == [dt.date.today().isoformat()] and "mockCfId123==" in " ".join(lines),
          f"HTML 403: both collectors fail, marker has today's date and the CloudFront request ID ({rc}, {lines})")
    check(hec_calls() == ["/hec/auth/external", "/hec/app/hec-api/v1.0/event/query"],
          f"first block stops it: one event query, flow collector sends nothing ({hec_calls()})")
    check(all(e.startswith("EdgeBlocked: Check Point blocked this IP") for e in errs.values()),
          f"error says it was blocked, short enough for the alert's first line: {errs}")
    os.remove(marker)
    del mock_vendors.CALLS[:]
    run("collect.py", "--only", "checkpoint_hec_flow")
    queries = [c for c in hec_calls() if c.startswith("/hec/app/")]
    check(1 <= len(queries) <= 4 and os.path.exists(marker),
          f"flow collector: other workers stop at the first block (queries sent: {len(queries)} of 4 workers)")
    del mock_vendors.CALLS[:]
    mock_vendors.HEC_EDGE_BLOCK = False
    rc = run("collect.py", "--only", "checkpoint_hec,checkpoint_hec_flow")
    check(rc == 1 and not hec_calls(), f"same day, block lifted: still nothing sent (catch-up stays quiet) ({hec_calls()})")
    open(marker, "w").write(f"{dt.date.today() - dt.timedelta(days=1)}\nyesterday\n")
    rc = run("collect.py", "--only", "checkpoint_hec,checkpoint_hec_flow")
    conn.commit()
    check(rc == 0 and hec_calls() and not os.path.exists(marker) and set(last_errors().values()) == {"ok"},
          f"next day: tries again, works, clears the marker (rc {rc}, {last_errors()})")

    print("== falcon tag sync")
    def tag_calls():
        return [c for c in mock_vendors.CALLS if c[0] == "PATCH"]
    r = subprocess.run([sys.executable, "tools/falcon_tag_sync.py", "--config", cfgp], cwd=ROOT,
                       capture_output=True, text=True)
    print(r.stdout[-2000:], r.stderr[-2000:])
    plan = {row["aid"]: (row["add"], row["remove"]) for row in
            csv.DictReader(open(os.path.join(tmp, "reports", "falcon-tag-plan.csv")))}
    check(r.returncode == 0 and not tag_calls(), "tag sync dry run exits 0 and sends nothing")
    check(plan == {"aid2": ("FalconGroupingTags/Patch-T1 FalconGroupingTags/Team-Cyber "
                            "FalconGroupingTags/Team-PowerBI FalconGroupingTags/Team-Systems", ""),
                   "aid4": ("", "FalconGroupingTags/Patch-T9")},
          f"servers only; duplicate LM entry: SCCM group wins, teams combined and split; stale managed tag removed; Owner-/sensor tags untouched: {plan}")
    r = subprocess.run([sys.executable, "tools/falcon_tag_sync.py", "--config", cfgp, "--apply", "--max-changes", "1"],
                       cwd=ROOT, capture_output=True, text=True)
    check(r.returncode == 3 and not tag_calls(), f"over --max-changes: refuses, sends nothing (rc {r.returncode})")
    r = subprocess.run([sys.executable, "tools/falcon_tag_sync.py", "--config", cfgp, "--apply", "--host", "mystery"],
                       cwd=ROOT, capture_output=True, text=True)
    pilot = [(c[2]["action"], c[2]["tags"][0], tuple(c[2]["device_ids"])) for c in tag_calls()]
    check(r.returncode == 0 and pilot == [("remove", "FalconGroupingTags/Patch-T9", ("aid4",))],
          f"--host pilot touches only that server: {pilot}")
    del mock_vendors.CALLS[:]
    r = subprocess.run([sys.executable, "tools/falcon_tag_sync.py", "--config", cfgp, "--apply"], cwd=ROOT,
                       capture_output=True, text=True)
    sent = sorted((c[2]["action"], c[2]["tags"][0], tuple(c[2]["device_ids"])) for c in tag_calls())
    check(r.returncode == 0 and sent == [("add", "FalconGroupingTags/Patch-T1", ("aid2",)),
                                         ("add", "FalconGroupingTags/Team-Cyber", ("aid2",)),
                                         ("add", "FalconGroupingTags/Team-PowerBI", ("aid2",)),
                                         ("add", "FalconGroupingTags/Team-Systems", ("aid2",)),
                                         ("remove", "FalconGroupingTags/Patch-T9", ("aid4",))],
          f"--apply sends one call per tag change: {sent} (rc {r.returncode}) {r.stdout[-300:]}")
    cur.execute("UPDATE lm_devices SET collected_at = now() - interval '3 days'")
    conn.commit()
    r = subprocess.run([sys.executable, "tools/falcon_tag_sync.py", "--config", cfgp], cwd=ROOT,
                       capture_output=True, text=True)
    check(r.returncode == 2, f"stale LogicMonitor data: refuses to plan (rc {r.returncode})")
    srv.shutdown()
    srv.server_close()

    print("== server patch compliance")
    teams = dict(q(cur, "SELECT device_id, team FROM lm_devices WHERE device_id IN (101, 105)"))
    check(teams == {101: "Power BI", 105: "Systems, Cyber"}, f"team_property stored, several teams normalised: {teams}")
    cur.execute("UPDATE lm_devices SET patch_window_start = now() - interval '5 days', "
                "patch_deadline = now() - interval '2 days' WHERE device_id = 101")
    cur.execute("INSERT INTO host_patch_status (aid, hostname, reboot_required, last_patch_confirmed) VALUES "
                "('aid2', 'LKH-SRV01', FALSE, now() - interval '10 days'), "
                "('aid4', 'MYSTERY', FALSE, now() - interval '50 days')")
    conn.commit()
    def pc():
        return {r[0]: r[1:] for r in q(cur, "SELECT aid, schedule_state, status, team, schedule FROM server_patch_compliance")}
    v = pc()
    check(sorted(v) == ["aid2", "aid4"], f"servers and DCs only, workstations left out: {sorted(v)}")
    check(v["aid2"] == ("Past deadline", "Overdue: past deadline", "Cyber, Power BI, Systems", "Tier 1"),
          f"deadline passed, last patch before the window -> overdue; duplicate LM entry's teams combined: {v['aid2']}")
    check(v["aid4"][:3] == ("Not in LogicMonitor", "Behind: 35+ days", "(no team)"),
          f"no schedule, 50 days since patched -> behind: {v['aid4']}")
    cur.execute("UPDATE host_patch_status SET last_patch_confirmed = now() - interval '1 day', reboot_required = TRUE "
                "WHERE aid = 'aid2'")
    conn.commit()
    check(pc()["aid2"][1] == "Patched, reboot pending", f"patched since the window, restart outstanding: {pc()['aid2']}")
    cur.execute("UPDATE lm_devices SET patch_deadline = now() + interval '2 days' WHERE device_id = 101")
    cur.execute("UPDATE host_patch_status SET last_patch_confirmed = now() - interval '8 days', reboot_required = FALSE "
                "WHERE aid = 'aid2'")
    conn.commit()
    check(pc()["aid2"][:2] == ("In window", "Not patched yet (in window)"), f"inside the window: not judged yet: {pc()['aid2']}")
    cur.execute("UPDATE lm_devices SET patch_window_start = now() - interval '60 days', "
                "patch_deadline = now() - interval '50 days' WHERE device_id = 101")
    conn.commit()
    check(pc()["aid2"][:2] == ("Stale deployment", "Patched within 35 days"),
          f"window opened 45+ days ago -> judged on the 35-day rule: {pc()['aid2']}")
    judged = dict(q(cur, "SELECT status, judged FROM server_patch_compliance_status"))
    known = {r[0] for r in q(cur, "SELECT DISTINCT status FROM server_patch_compliance")}
    check(known <= set(judged), f"every status has a sort order / on-track entry: {known - set(judged)}")

    print("== servers report per owner team")
    cur.execute("UPDATE assets SET tags = tags || ARRAY['FalconGroupingTags/Team-Cyber', 'FalconGroupingTags/Team-PowerBI'] "
                "WHERE source = 'falcon' AND source_asset_id = 'aid2'")
    conn.commit()
    srv_out = os.path.join(tmp, "reports", "servers-2026-11-16")
    check(run("server_report.py", "--out-dir", srv_out, "--no-pdf") == 0, "server_report.py exited 0")
    import openpyxl
    def listed(folder):
        wb = openpyxl.load_workbook(os.path.join(folder, "Servers.xlsx"), read_only=True)
        return sorted(r[0] for r in wb["All servers"].iter_rows(min_row=2, values_only=True) if r[0]), wb.sheetnames
    owners = os.path.join(srv_out, "owners")
    got = {t: listed(os.path.join(owners, t))[0] for t in sorted(os.listdir(owners))}
    check(got == {"Cyber": ["LKH-SRV01"], "PowerBI": ["LKH-SRV01"], "Unassigned": ["MYSTERY"]},
          f"one folder per Team- tag + Unassigned; a two-team server in both; untagged DC unassigned: {got}")
    region, region_tabs = listed(srv_out)
    team_tabs = listed(os.path.join(owners, "Cyber"))[1]
    team_html = open(os.path.join(owners, "Cyber", "Servers.html")).read()
    check(region == ["LKH-SRV01", "MYSTERY"] and "No sensor" in region_tabs and "No sensor" not in team_tabs,
          f"region report unchanged (both servers, No sensor tab); team copies have no No sensor tab: {region}, {team_tabs}")
    check("Team Cyber" in team_html and "3 of 3" in team_html and "4 of" not in team_html
          and "Team-Cyber" in team_html, "team PDF: titled for the team, three pages, footer names the tag")
    import publish
    for t in ("Cyber", "Unassigned"):
        open(os.path.join(owners, t, "Servers.pdf"), "w").close()
    dest = sorted(d for _, d in publish.candidates(os.path.join(tmp, "reports")))
    check(dest == ["Servers/Owners/Cyber/2026-11-16 Cyber Servers Report.pdf",
                   "Servers/Owners/Cyber/2026-11-16 Cyber Servers Report.xlsx",
                   "Servers/Owners/PowerBI/2026-11-16 PowerBI Servers Report.xlsx",
                   "Servers/Owners/Unassigned/2026-11-16 Unassigned Servers Report.pdf",
                   "Servers/Owners/Unassigned/2026-11-16 Unassigned Servers Report.xlsx",
                   "Servers/Weekly/2026-11-16 Servers Report.xlsx"],
          f"publish: Servers/Owners/<Team>/ beside the region report, no HTML: {dest}")
    r = subprocess.run([sys.executable, "publish.py", "--config", cfgp, "--dry-run", "--sets", "servers"],
                       cwd=ROOT, capture_output=True, text=True)
    check(r.returncode == 0 and "would publish Servers/Owners/PowerBI/" in r.stdout and "6 file(s)" in r.stdout,
          f"publish --sets servers includes the owner folders: {r.stdout[-300:]}")

    print("== other domains")
    check(q(cur, "SELECT count(*) FROM security_alerts")[0][0] == 3, "3 alerts")
    al2 = q(cur, "SELECT site_label, closed_at IS NOT NULL FROM security_alerts WHERE alert_id='al2'")[0]
    check(al2 == ("Lakeside Health", True), f"user-only alert -> site via UPN, closed_at set: {al2}")
    al2d = q(cur, "SELECT status, disposition FROM security_alerts WHERE alert_id='al2'")[0]
    check(al2d == ("closed", "false_positive"),
          f"disposition preserved under collapsed status: {al2d}")
    ids = dict(q(cur, "SELECT entity_id, site_label FROM identity_entities"))
    check(ids == {"e1": "Riverside Health", "e2": "Lakeside Health", "e3": "Ungrouped", "e4": "Riverside Health",
                  "e5": "Lakeside Health"}, f"identity sites {ids}")
    en = dict(q(cur, "SELECT entity_id, (enabled, last_activity IS NOT NULL) FROM identity_entities "
                     "WHERE entity_id IN ('e3', 'e5')"))
    check(en == {"e3": "(,f)", "e5": "(f,t)"}, f"cloud-only account takes enabled/activity from Entra: {en}")
    ros = {r[0]: r[1:] for r in q(cur, "SELECT entity_id, title, department, account_expires IS NOT NULL, "
                                       "password_never_expires FROM identity_entities WHERE entity_id IN ('e1','e2')")}
    check(ros == {"e1": (None, None, False, True), "e2": ("Registered Nurse", "Ward 3", True, False)},
          f"roster fields: title, department, expiry, password-never-expires flag: {ros}")
    acc = dict(q(cur, "SELECT entity_id, access_account FROM identity_entities WHERE access_account IS NOT NULL"))
    check(acc == {"e4": "vpn"}, f"shared-domain VPN-only account tagged: {acc}")
    kinds = dict(q(cur, "SELECT entity_id, account_kind FROM identity_entities"))
    check(kinds.get("e1") == "service" and kinds.get("e2") == "human", f"account kinds (svc_ name -> service): {kinds}")
    check(q(cur, "SELECT count(*) FROM identity_risk_factors")[0][0] == 3, "3 identity risk factors (not doubled on rerun)")
    hec = dict(q(cur, "SELECT event_id, site_label FROM email_events"))
    check(hec == {"h1": "Riverside Health", "h2": "Lakeside Health", "h3": "Ungrouped"}, f"HEC recipient sites {hec}")
    dirs = dict(q(cur, "SELECT event_id, direction FROM email_events"))
    check(dirs == {"h1": "inbound", "h2": "inbound", "h3": "outbound"}, f"HEC direction classified: {dirs}")
    check(q(cur, "SELECT count(*) FROM entra_risky_users")[0][0] == 2, "2 risky users (paged via nextLink)")
    check(q(cur, "SELECT count(*) FROM entra_mfa_registration")[0][0] == 2, "guests excluded from MFA stats")
    la = dict(q(cur, "SELECT site_label, value FROM azure_log_metrics WHERE dimension='failure'"))
    check(la.get("Riverside Health") == 15, f"Log Analytics values summed per site: {la}")
    dm = q(cur, "SELECT sum(messages), sum(dmarc_pass), count(DISTINCT site_label) FROM dmarc_daily")[0]
    check(tuple(map(int, dm)) == (1537, 1500, 2), f"DMARC aggregates across scroll pages: {dm}")

    print("== removable media")
    usb = {(r[0], r[1]): r[2:] for r in q(cur, """SELECT user_key, category, files, bytes, site_label, folder,
                                                          display_name, device_serial FROM usb_file_writes_daily""")}
    check(sum(v[0] for v in usb.values()) == 6, f"6 USB file writes kept, Office lock file dropped: {usb}")
    check(usb.get(("jnurse", "email"), (0,))[0] == 1 and usb.get(("jnurse", "data"), (0,))[0] == 1,
          ".pst -> email, .xlsx -> data (extension beats the sensor's Generic label)")
    icons = usb.get(("jnurse", "images"))
    check(icons and icons[0] == 2 and icons[3] == "App\\Portable", f"program copy rolled up to one folder row: {icons}")
    check(usb.get(("jnurse", "data"), (0,) * 6)[2:4] == ("Riverside Health", "Ward\\Exports")
          and usb[("jnurse", "data")][4] == "Jo Nurse", "site by aid, folder, name from the enabled lookup row")
    nouser = usb.get(("", "archives"))
    check(nouser and nouser[2] == "Lakeside Health" and nouser[5] == "", f"no user / unknown drive kept: {nouser}")
    runs = q(cur, "SELECT stats->>'write_rows' FROM collector_runs WHERE collector = 'falcon_usb' ORDER BY started_at")
    check(len(runs) == 2 and runs[0] == runs[1], f"re-pull replaces days rather than doubling: {runs}")
    sc = dict(q(cur, "SELECT scan_id, site_label FROM usb_scans"))
    check(sc == {"sc_usb1": "Riverside Health", "sc_usb2": "Lakeside Health"}, f"USB-insertion scans by host site: {sc}")
    det = q(cur, """SELECT a.file_name, a.quarantined FROM security_alerts a
                    JOIN usb_scans u ON u.scan_id = a.scan_id""")
    check(det == [("setup.exe", True)], f"ODS detection linked to its USB scan: {det}")

    print("== mail-flow funnel")
    fl = {(r[0], r[1]): int(r[2]) for r in q(cur, "SELECT site_label, metric, sum(value) FROM daily_email_flow_metrics "
                                                 "GROUP BY 1, 2")}
    check((fl.get(("Riverside Health", "incoming")), fl.get(("Lakeside Health", "incoming")),
           fl.get(("Ungrouped", "incoming"))) == (4, 1, 1), f"incoming per site by recipient domain, rest Ungrouped: {fl}")
    check(fl.get(("Lakeside Health", "internal_incoming")) == 1 and fl.get(("Lakeside Health", "incoming")) == 1,
          "internal mail counted separately from incoming")
    check((fl.get(("Riverside Health", "ms_junk")), fl.get(("Riverside Health", "ms_quarantine")),
           fl.get(("Riverside Health", "cp_quarantined")), fl.get(("Riverside Health", "restored"))) == (1, 1, 3, 1),
          "Microsoft junk/quarantine, Check Point quarantine and restores counted")

    print("== rollups")
    am = dict(q(cur, "SELECT site_label, stale_sensors FROM daily_asset_metrics WHERE snapshot_date=CURRENT_DATE"))
    check(am.get("Riverside Health") == 1, f"stale sensor counted (aid3): {am}")
    sil = {r[0]: r[1:] for r in q(cur, "SELECT site_label, silent_sensors, silent_in_use FROM daily_asset_metrics "
                                       "WHERE snapshot_date = CURRENT_DATE")}
    # aid3: workstation silent 20 days -- inside the 30-day limit, but still logging on (u8), so not reporting;
    # aid2 (server, 2 days) and aid4 (DC, 1 day) are inside their limits
    check(sil.get("Riverside Health") == (1, 1) and sil.get("Lakeside Health") == (0, 0)
          and sil.get("Ungrouped") == (0, 0),
          f"sensors not reporting: per-type limits, broken sensor on a machine in use counted: {sil}")
    src = q(cur, "SELECT count(DISTINCT source) FROM daily_source_metrics")[0][0]
    check(src == 2, "daily_source_metrics splits spotlight vs hadrian")
    idm = dict(q(cur, "SELECT metric, value FROM daily_identity_metrics WHERE site_label='Riverside Health'"))
    check(idm.get("factor:WEAK_PASSWORD") == 1 and idm.get("mfa_registered") == 1, f"identity metrics {idm}")
    check((idm.get("cat:stale_accounts"), idm.get("cat:weak_passwords"), idm.get("cat:access_accounts"),
           idm.get("catgroup:exposure")) == (1, 1, 1, 2),
          "identity categories count distinct enabled accounts (stale + weak on one account = 1 in the group)")
    check((idm.get("total:enabled_accounts"), idm.get("total:enabled_people")) == (2, 0),
          f"enabled-account totals: service + VPN account, neither a person's main account: {idm}")

    print("== reports")
    out = os.path.join(tmp, "out")
    since = (dt.date.today() - dt.timedelta(days=6)).isoformat()
    check(run("exec_report.py", "--since", since, "--until", dt.date.today().isoformat(),
              "--out", os.path.join(out, "exec-region.html")) == 0, "exec_report.py region exited 0")
    check(run("exec_report.py", "--since", since, "--until", dt.date.today().isoformat(),
              "--site", "Riverside Health", "--out", os.path.join(out, "exec-site.html")) == 0,
          "exec_report.py single site exited 0")
    html_ = open(os.path.join(out, "exec-region.html")).read() if os.path.exists(os.path.join(out, "exec-region.html")) else ""
    check(html_.count('class="page"') == 6, "exec report has 6 pages")
    check("Removable Media (USB)" in html_ and "Business data written" in html_ and "medical images" in html_,
          "exec report has the removable-media page")
    site_html = open(os.path.join(out, "exec-site.html")).read() if os.path.exists(os.path.join(out, "exec-site.html")) else ""
    check("jnurse" not in site_html and "j*****" in site_html and "Ward 3" in site_html,
          "USB people masked in the site report, department shown")
    check("Most business data written" not in html_ and "j*****" not in html_, "region report has no per-person USB table")
    import exec_report
    if exec_report.find_chromium():
        pdf = os.path.join(out, "exec-region.pdf")
        check(os.path.exists(pdf) and open(pdf, "rb").read(5) == b"%PDF-", "exec report also rendered to PDF")
    else:
        print("  SKIP PDF check -- no Chromium on this machine")
    check("What we're protecting" in html_ and "Operating systems" in html_, "exec report has the estate page")
    check("someone@riversidehealth.test" not in html_ and "Infostealer" not in html_,
          "low-severity infostealer risk left out of the external table, account never shown unmasked")
    check("Inbound + internal emails" in html_ and "Delivered to users" in html_, "exec report has the mail-flow funnel")
    check("Indicators of compromise or attack" in html_ and "Reused passwords" in html_ and "WATCHED" not in html_,
          "exec report shows the identity categories, not raw factors")
    check(run("action_pack.py", "--out-dir", out, "--since", since, "--until", dt.date.today().isoformat()) == 0,
          "action_pack.py exited 0")
    packs = sorted(os.listdir(out)) if os.path.isdir(out) else []
    check(sum(f.endswith(".xlsx") for f in packs) == 4, f"action pack per site + region: {packs}")
    region_xlsx = next((os.path.join(out, f) for f in packs if f.startswith("region-")), None)
    if region_xlsx:
        from openpyxl import load_workbook
        wb = load_workbook(region_xlsx)
        check({"USB file writes", "USB drives", "USB malware"} <= set(wb.sheetnames), f"USB tabs: {wb.sheetnames}")
        ws = wb["USB file writes"]
        hdr = [c.value for c in ws[1]]
        top = dict(zip(hdr, [c.value for c in ws[2]]))
        check(top.get("Person") == "Jo Nurse" and "Email / mailbox data" in (top.get("Flags") or "")
              and "Large volume" in top["Flags"] and "Patient list.xlsx" in (top.get("Largest business files") or ""),
              f"named person first, flagged, with file names: {top}")
        drives = {r[2]: r for r in wb["USB drives"].iter_rows(min_row=2, values_only=True)}
        check("Shared drive" in (drives.get("SER1") or ("",) * 14)[13], f"SER1 used by two people flagged shared: {drives}")
        check(wb["USB malware"].max_row == 2, "USB malware tab lists the detection")
        nr = [dict(zip([c.value for c in wb["Sensors not reporting"][1]], [c.value for c in r]))
              for r in wb["Sensors not reporting"].iter_rows(min_row=2)]
        check(len(nr) == 1 and nr[0]["Hostname"] == "RANDOM01" and nr[0]["Likely"].startswith("Sensor broken")
              and nr[0]["Machine last seen (AD / network)"] is not None,
              f"sensors-not-reporting tab: the broken sensor on a machine in use, with when it was last seen: {nr}")
        acc = [dict(zip([c.value for c in wb["All accounts"][1]], [c.value for c in r]))
               for r in wb["All accounts"].iter_rows(min_row=2)]
        check(acc and acc[0]["Display name"] == "Svc Backup" and acc[0]["Stale"] == "Yes"
              and acc[0]["Password never expires"] == "Yes"
              and any(a["Title"] == "Registered Nurse" and a["Department"] == "Ward 3" for a in acc)
              and all(a["Enabled"] != "No" for a in acc),
              f"All accounts tab: enabled accounts only, stale first, with title/department: {acc[:2]}")

    print("== scorecard")
    conn.commit()   # end this script's read transaction: impact.py's ensure_schema needs table locks
    check(run("impact.py", "--only", "metrics") == 0, "impact.py metrics exited 0")
    sc_out = os.path.join(tmp, "scorecard")
    check(run("scorecard.py", "--out-dir", sc_out, "--month", dt.date.today().strftime("%Y-%m"), "--no-pdf") == 0,
          "scorecard.py exited 0")
    cards = sorted(os.listdir(sc_out)) if os.path.isdir(sc_out) else []
    check(len(cards) == 4 and all("-scorecard-" in f and f.endswith(".html") for f in cards),
          f"scorecard per site + region: {cards}")
    reg = next((os.path.join(sc_out, f) for f in cards if f.startswith("region-")), None)
    reg_html = open(reg).read() if reg else ""
    check(reg_html.count('<section class="page') == 2 and 'class="page wide"' in reg_html
          and "By health service" in reg_html
          and "Servers patched in the last 35 days" in reg_html and "Riverside Health" in reg_html,
          "region scorecard: measures page + landscape by-service table")
    one = next((os.path.join(sc_out, f) for f in cards if f.startswith("Riverside")), None)
    one_html = open(one).read() if one else ""
    check(one_html.count('<section class="page') == 1 and "Lakeside Health" not in one_html,
          "a site's scorecard shows only that site")
    check("Too early" in one_html, "one day of snapshots: directions are 'too early', not invented")
    import publish
    os.makedirs(os.path.join(tmp, "monthly-2026-11"), exist_ok=True)
    for f in ("Riverside_Health-scorecard-2026-11.pdf", "Riverside_Health-scorecard-2026-11.html",
              "Riverside_Health-actions-2026-11.xlsx"):
        open(os.path.join(tmp, "monthly-2026-11", f), "w").close()
    dest = sorted(d for _, d in publish.candidates(tmp))
    check(dest == ["Riverside_Health/Monthly/2026-11 Riverside_Health Action Pack.xlsx",
                   "Riverside_Health/Monthly/2026-11 Riverside_Health Security Scorecard.pdf"],
          f"publish files the scorecard PDF (not the HTML) next to the action pack: {dest}")

    print("== impact action log outcomes")
    import impact_spec
    today = dt.date.today()
    cur.execute("DELETE FROM impact_actions")
    # (status, closed, ticket_ref, evidence, approved_by, review_date, owner_team) -> expected outcome
    cases = [
        (("Done", today, "SR-1", None, None, None, "Infra"), "remediated"),
        (("Done", today, None, "rescan clean", None, None, "Infra"), "remediated"),
        (("Done", today, "  ", None, None, None, "Infra"), "done_unverified"),       # blank ticket isn't evidence
        (("Done", None, "SR-2", None, None, None, "Infra"), "done_unverified"),      # no closed date
        (("Accepted risk", None, None, None, "CIO", today + dt.timedelta(days=30), "Infra"), "accepted"),
        (("Accepted risk", None, None, None, "CIO", today - dt.timedelta(days=1), "Infra"), "accepted_review"),
        (("Accepted risk", None, None, None, None, today + dt.timedelta(days=30), "Infra"), "accepted_review"),
        (("In progress", None, None, None, None, None, "Infra"), "open"),
        (("Open", None, None, None, None, None, None), "open"),
        ((None, None, None, None, None, None, None), "open"),
    ]
    for i, ((st, closed, tref, ev, appr, review, team), _) in enumerate(cases):
        cur.execute("""INSERT INTO impact_actions (row_no, found, what, severity, owner_team, status, closed,
                                                   ticket_ref, evidence, approved_by, review_date)
                       VALUES (%s, %s, %s, 'High', %s, %s, %s, %s, %s, %s, %s)""",
                    (i + 2, today, f"case {i}", team, st, closed, tref, ev, appr, review))
    got = dict(q(cur, f"SELECT row_no, {impact_spec.OUTCOME_SQL} FROM impact_actions"))
    bad = [(i, exp, got.get(i + 2)) for i, (_, exp) in enumerate(cases) if got.get(i + 2) != exp]
    check(not bad, f"action outcomes: Done needs a closed date + ticket/evidence, accepted risk needs an approver and "
                   f"an unexpired review date (case, expected, got): {bad}")
    conn.commit()
    imp_out = os.path.join(tmp, "impact")
    check(run("impact_report.py", "--out-dir", imp_out, "--no-pdf") == 0, "impact_report.py exited 0")
    imp_html = "".join(open(f).read() for f in glob.glob(os.path.join(imp_out, "*.html")))
    check("Resolved" not in imp_html and "Risk accepted" in imp_html and "Awaiting owner" in imp_html
          and "10 issues logged: 2 remediated, 3 accepted as risk, 3 still open and 2 marked Done with no evidence"
          in imp_html,
          "impact report keeps outcomes separate (no combined 'Resolved') and its headline reconciles to the log")

    print("== dashboard SQL")
    n = 0
    for path in sorted(glob.glob(os.path.join(ROOT, "grafana", "*.json"))):
        d = json.load(open(path))

        def walk(ps):
            for p in ps:
                yield p
                yield from walk(p.get("panels", []))
        for v in d.get("templating", {}).get("list", []):
            if v.get("type") == "query" and v.get("query"):
                try:
                    cur.execute(v["query"])
                    cur.fetchall()
                    n += 1
                except Exception as e:
                    conn.rollback()
                    check(False, f"{os.path.basename(path)} :: variable {v.get('name')} :: {e}".splitlines()[0])
        for p in walk(d.get("panels", [])):
            for t in p.get("targets", []):
                sql = t.get("rawSql")
                if not sql:
                    continue
                sql = dash_sql(sql)
                try:
                    cur.execute(sql)
                    cur.fetchall()
                    n += 1
                except Exception as e:
                    conn.rollback()
                    check(False, f"{os.path.basename(path)} :: {p.get('title')} :: {e}".splitlines()[0])
    check(n > 0, f"{n} dashboard queries executed cleanly")

    print("== remediation access (restricted Grafana login)")
    import remediation_access as ra
    conn.rollback()
    cur.execute("DROP SCHEMA IF EXISTS remediation CASCADE")
    cur.execute("DROP ROLE IF EXISTS e2e_remediation")
    cur.execute("CREATE ROLE e2e_remediation NOLOGIN")
    status = ra.ensure_views(cur, {"grafana": {"remediation_role": "e2e_remediation"}})
    conn.commit()
    check("views in schema remediation" in status, f"views created: {status}")
    # every script start runs ensure_schema, whose DDL drops views underneath; access must come back
    import db_schema as dbs
    dbs.ensure_schema(cfg)
    check("e2e_remediation" in ra.grantees(cur, "server_patch_compliance"),
          "ensure_schema keeps the restricted views and grants (set aside and rebuilt)")
    # the nightly dash_* swap must survive the views that depend on those tables, and keep the grants
    check(run("rollup_daily_metrics.py", "--dashboard-tables-only") == 0, "dash_* rebuild runs with remediation views in place")
    check("e2e_remediation" in ra.grantees(cur, "dash_asset_risk"), "rebuilt dash_* views keep the role's grant")
    conn.commit()

    def as_role(stmt):
        cur.execute("SET ROLE e2e_remediation")
        cur.execute("SET search_path = remediation, public")
        try:
            cur.execute(stmt)
            return cur.fetchall()
        finally:
            conn.rollback()
            cur.execute("RESET ROLE")
            cur.execute("RESET search_path")
    bad, ran = [], 0
    for name in ra.DASHBOARDS:
        d = json.load(open(os.path.join(ROOT, "grafana", name + ".json")))

        def walk2(ps):
            for p in ps:
                yield p
                yield from walk2(p.get("panels", []))
        stmts = [(v.get("name"), v["query"]) for v in d.get("templating", {}).get("list", [])
                 if v.get("type") == "query" and v.get("query")]
        stmts += [(p.get("title"), dash_sql(t["rawSql"])) for p in walk2(d.get("panels", []))
                  for t in p.get("targets", []) if t.get("rawSql")]
        for title, stmt in stmts:
            try:
                as_role(stmt)
                ran += 1
            except Exception as e:
                bad.append(f"{name} :: {title} :: {str(e).splitlines()[0]}")
    for b in bad[:5]:
        print("   ", b)
    check(ran > 0 and not bad, f"remediation dashboards run as the restricted role ({ran} queries, {len(bad)} failed)")
    for table in ("identity_entities", "security_alerts", "email_events", "impact_actions", "public.assets"):
        try:
            as_role(f"SELECT 1 FROM {table} LIMIT 1")
            check(False, f"restricted role can't read {table}")
        except Exception as e:
            check("permission denied" in str(e), f"restricted role can't read {table}")
    ws = as_role("SELECT count(*) FILTER (WHERE source = 'falcon' AND product_type = 'workstation'), "
                 "count(*) FILTER (WHERE source = 'falcon_unmanaged'), "
                 "count(*) FILTER (WHERE product_type IN ('server', 'domain_controller')) FROM assets")[0]
    check(ws[0] == 0 and ws[2] > 0, f"restricted assets: no managed workstations, servers kept {ws}")
    cur.execute("DROP SCHEMA remediation CASCADE")
    cur.execute("DROP ROLE e2e_remediation")
    conn.commit()

    print(f"\n{'ALL PASSED' if not failures else f'{len(failures)} FAILURE(S)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
