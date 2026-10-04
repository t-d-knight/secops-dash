#!/usr/bin/env python3
"""
End-to-end test: every collector against the mock vendor APIs, into a
throwaway Postgres database, then the rollups, then every SQL query in the
Grafana dashboards. Exits non-zero on any failure.

  PGHOST=127.0.0.1 PGUSER=postgres python3 tests/run_e2e.py

Needs a Postgres it may DROP/CREATE the database `secops_e2e` on.
"""
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
  - key: BH
    label: Bendigo Health
    match: {{falcon_groups: ["BH Workstations"], ad_domains: ["bh.local"], email_domains: ["bendigohealth.org.au"],
            cidrs: ["10.1.0.0/16", "203.0.113.0/28"]}}
  - key: CH
    label: Castlemaine Health
    match: {{falcon_tags: ["SensorGroupingTags/CH"], ou_contains: ["ou=castlemaine"],
            email_domains: ["castlemainehealth.org.au"], hostname_regex: ["^CH-"]}}
ungrouped_label: Ungrouped
database: {{host: "{PG['host']}", port: {PG['port']}, name: {DB}, user: "{PG['user']}"}}
secrets_file: secrets.yaml
collectors:
  falcon_hosts: {{enabled: true}}
  falcon_spotlight: {{enabled: true, page_size: 2}}
  falcon_alerts: {{enabled: true}}
  falcon_identity: {{enabled: true}}
  hadrian:
    enabled: true
    base_url: "{M}/hadrian"
    assets: {{path: /v1/assets, items_key: data, pagination: {{type: page, size: 1}},
             fields: {{id: id, name: name, type: type, ip: ip_addresses, ports: ports, technologies: technologies,
                      first_seen: first_seen, last_seen: last_seen}}}}
    risks: {{path: /v1/risks, items_key: data, pagination: {{type: page, size: 1}},
            fields: {{id: id, asset_id: asset.id, asset_name: asset.name, ip: asset.ip, title: title,
                     severity: severity, status: status, category: category, cves: cves, cvss: cvss_score,
                     first_seen: first_seen, last_seen: last_seen, resolved_at: resolved_at}}}}
  checkpoint_hec: {{enabled: true, gateway: "{M}/hec"}}
  entra:
    enabled: true
    tenants: [{{name: main, tenant_id: t1, login_base: "{M}/login", graph_base: "{M}/graph",
               loganalytics_base: "{M}/la"}}]
  azure_log_analytics:
    enabled: true
    workspaces: [{{name: ws, tenant: main, workspace_id: w1}}]
    queries: [{{name: signins, key_type: upn, kql: "SigninLogs | take 1"}}]
  dmarc: {{enabled: true, opensearch_url: "{M}/os", username: u}}
"""
SECRETS = """
database: {password: null}
crowdstrike: {client_id: cid, client_secret: sec}
collectors:
  hadrian: {api_key: hk}
  checkpoint_hec: {client_id: hc, access_key: hk}
  entra: {tenants: [{name: main, client_id: ac, client_secret: as}]}
  dmarc: {password: p}
"""

failures = []


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
    open(os.path.join(tmp, "config.yaml"), "w").write(CONFIG)
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
    print("== rollup_daily_metrics.py")
    check(run("rollup_daily_metrics.py") == 0, "rollup exited 0")
    srv.shutdown()

    cur = conn.cursor()
    print("== collector_runs")
    rows = q(cur, "SELECT collector, status, error FROM collector_freshness ORDER BY 1")
    for r in rows:
        check(r[1] == "ok", f"collector {r[0]} status ok ({r[2] or ''})")
    check(len(rows) == 9, f"9 collectors ran (got {len(rows)})")

    print("== site resolution")
    sites = dict(q(cur, "SELECT source_asset_id, site_label || '/' || site_matched_by FROM assets"))
    check(sites.get("aid1") == "Bendigo Health/falcon_groups", f"aid1 via host group: {sites.get('aid1')}")
    check(sites.get("aid2") == "Castlemaine Health/falcon_tags", f"aid2 via tag: {sites.get('aid2')}")
    check(sites.get("aid3") == "Bendigo Health/ad_domains", f"aid3 via AD domain: {sites.get('aid3')}")
    check(sites.get("aid4") == "Ungrouped/none", f"aid4 ungrouped: {sites.get('aid4')}")
    check(sites.get("u1") == "Bendigo Health/cidrs", f"unmanaged u1 via CIDR: {sites.get('u1')}")

    print("== vulnerabilities")
    st = dict(q(cur, "SELECT source_rule_id, state FROM vuln_findings"))
    check(st.get("v1") == "OPEN" and st.get("v2") == "REOPENED", "open/reopen mapped")
    check(st.get("v3") == "SUPPRESSED", "suppressed vuln -> SUPPRESSED")
    check(st.get("v5") == "FIXED", "closed vuln -> FIXED")
    check(st.get("gone") == "EXPIRED", "vanished open vuln -> EXPIRED (not FIXED)")
    check(st.get("r1") == "OPEN" and st.get("r2") == "FIXED", "Hadrian risks mapped open/fixed")
    v1 = q(cur, "SELECT is_remote_no_auth, exploit_available, product_key, fix_id, site_label FROM vuln_findings WHERE source_rule_id='v1'")[0]
    check(v1 == (True, True, "google:chrome", "R1", "Bendigo Health"), f"v1 enrichment {v1}")
    v2r = q(cur, "SELECT is_remote_no_auth FROM vuln_findings WHERE source_rule_id='v2'")[0][0]
    check(v2r is False, "no vector -> not remote/no-auth (old cvss bug fixed)")
    lf = q(cur, "SELECT last_found > now() - interval '1 day' FROM vuln_findings WHERE source_rule_id='v1'")[0][0]
    check(lf, "last_found taken from host last_seen")
    kev = q(cur, "SELECT count(*) FROM fact_vuln_findings_current WHERE has_kev")[0][0]
    check(kev == 2, f"KEV joins for Spotlight + Hadrian log4j (got {kev})")
    patch = q(cur, "SELECT title, open_findings, affected_assets FROM patch_impact_summary WHERE fix_key='R1'")
    check(patch and patch[0][1] == 2, f"R1 patch groups both Chrome CVEs: {patch}")
    ext = q(cur, "SELECT site_label, asset_type FROM vuln_findings WHERE source='hadrian' AND source_rule_id='r1'")[0]
    check(ext == ("Bendigo Health", "internet"), f"Hadrian risk site/type {ext}")

    print("== other domains")
    check(q(cur, "SELECT count(*) FROM security_alerts")[0][0] == 2, "2 alerts")
    al2 = q(cur, "SELECT site_label, closed_at IS NOT NULL FROM security_alerts WHERE alert_id='al2'")[0]
    check(al2 == ("Castlemaine Health", True), f"user-only alert -> site via UPN, closed_at set: {al2}")
    ids = dict(q(cur, "SELECT entity_id, site_label FROM identity_entities"))
    check(ids == {"e1": "Bendigo Health", "e2": "Castlemaine Health", "e3": "Ungrouped"}, f"identity sites {ids}")
    check(q(cur, "SELECT count(*) FROM identity_risk_factors")[0][0] == 3, "3 identity risk factors (not doubled on rerun)")
    hec = dict(q(cur, "SELECT event_id, site_label FROM email_events"))
    check(hec == {"h1": "Bendigo Health", "h2": "Castlemaine Health"}, f"HEC recipient sites {hec}")
    check(q(cur, "SELECT count(*) FROM entra_risky_users")[0][0] == 2, "2 risky users (paged via nextLink)")
    check(q(cur, "SELECT count(*) FROM entra_mfa_registration")[0][0] == 2, "guests excluded from MFA stats")
    la = dict(q(cur, "SELECT site_label, value FROM azure_log_metrics WHERE dimension='failure'"))
    check(la.get("Bendigo Health") == 15, f"Log Analytics values summed per site: {la}")
    dm = q(cur, "SELECT sum(messages), sum(dmarc_pass), count(DISTINCT site_label) FROM dmarc_daily")[0]
    check(tuple(map(int, dm)) == (1537, 1500, 2), f"DMARC aggregates across scroll pages: {dm}")

    print("== rollups")
    am = dict(q(cur, "SELECT site_label, stale_sensors FROM daily_asset_metrics WHERE snapshot_date=CURRENT_DATE"))
    check(am.get("Bendigo Health") == 1, f"stale sensor counted (aid3): {am}")
    src = q(cur, "SELECT count(DISTINCT source) FROM daily_source_metrics")[0][0]
    check(src == 2, "daily_source_metrics splits spotlight vs hadrian")
    idm = dict(q(cur, "SELECT metric, value FROM daily_identity_metrics WHERE site_label='Bendigo Health'"))
    check(idm.get("factor:WEAK_PASSWORD") == 1 and idm.get("mfa_registered") == 1, f"identity metrics {idm}")

    print("== dashboard SQL")
    n = 0
    for path in sorted(glob.glob(os.path.join(ROOT, "grafana", "*.json"))):
        d = json.load(open(path))

        def walk(ps):
            for p in ps:
                yield p
                yield from walk(p.get("panels", []))
        site_vals = "'Bendigo Health','Castlemaine Health','Ungrouped'"
        for p in walk(d.get("panels", [])):
            for t in p.get("targets", []):
                sql = t.get("rawSql")
                if not sql:
                    continue
                sql = (sql.replace("$site", site_vals).replace("${site:sqlstring}", site_vals)
                       .replace("$source", "'falcon_spotlight','hadrian'")
                       .replace("$__timeFilter(", "TRUE OR (").replace("$__timeFrom()", "now()-interval '30 days'")
                       .replace("$__timeTo()", "now()")
                       .replace("${__from:date}", (dt.date.today() - dt.timedelta(days=30)).isoformat())
                       .replace("${__to:date}", dt.date.today().isoformat()))
                sql = re.sub(r"\$__timeGroupAlias\(([^,]+),[^)]+\)", r"date_trunc('day', \1) AS time", sql)
                sql = re.sub(r"\$__timeGroup\(([^,]+),[^)]+\)", r"date_trunc('day', \1)", sql)
                try:
                    cur.execute(sql)
                    cur.fetchall()
                    n += 1
                except Exception as e:
                    conn.rollback()
                    check(False, f"{os.path.basename(path)} :: {p.get('title')} :: {e}".splitlines()[0])
    check(n > 0, f"{n} dashboard queries executed cleanly")

    print(f"\n{'ALL PASSED' if not failures else f'{len(failures)} FAILURE(S)'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
