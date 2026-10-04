# SecOps Dashboard

Pulls security data from the tools we actually run, maps every record to a **site**, and stores it in PostgreSQL for Grafana (and Power BI) dashboards that filter per site.

| Feed | Collector | What it gives the dashboards |
|---|---|---|
| CrowdStrike Falcon hosts + Exposure Management unmanaged assets | `falcon_hosts` | Sensor coverage, stale/RFM sensors, unmanaged devices per site |
| Falcon Exposure Management / Spotlight vulnerabilities | `falcon_spotlight` | Endpoint vulns → SLA, KEV, EPSS, MTTR, worst devices, top fixes |
| Falcon alerts (endpoint, identity, …) | `falcon_alerts` | Detections, open/unassigned, time to close |
| Falcon Identity Protection | `falcon_identity` | High-risk / stale / weak-password accounts, remediation list |
| Hadrian Atlas | `hadrian` | External attack surface: internet assets + external risks (same SLA/KEV treatment as endpoint vulns) |
| Check Point Harmony Email & Collaboration | `checkpoint_hec` | Phishing / malware / DLP events per recipient site |
| Microsoft Entra ID (Graph) | `entra` | Risky users, risk detections, MFA registration |
| Azure Log Analytics / Sentinel | `azure_log_analytics` | Sign-in failures, legacy auth, MFA denials, CA blocks (KQL you control) |
| DMARC via parsedmarc → OpenSearch | `dmarc` | Pass/SPF/DKIM alignment per domain, failing senders |
| CISA KEV, FIRST EPSS, NVD | `kev_sync.py`, `epss_sync.py`, `nvd_enrich.py` | Vendor-neutral exploit context for every CVE |

It grew out of the Tenable-only [tenable-vuln-dashboard](https://github.com/t-d-knight/tenable-vuln-dashboard) and keeps its vulnerability model (SLA, KEV, EPSS, MTTR), but it's a separate product with no Tenable dependency. To reuse an existing tenable-vuln-dashboard database, see [Coming from tenable-vuln-dashboard](#7-coming-from-tenable-vuln-dashboard).

---

## 1. How it fits together

```
 vendor APIs ──► collectors/<feed>.py ──► site_resolver ──► Postgres tables ──► rollup_daily_metrics.py ──► daily_* snapshots
                 (one per feed,            (one site per                          (trend history)                │
                  isolated failures)        record, + why)                                                       ▼
                                                                                           Grafana: 4 dashboards, $site filter
```

* **`collect.py`** runs every enabled collector in order. Each is wrapped on its own: if HEC's API is down, Falcon and DMARC still land. Every run is recorded in `collector_runs`, and the **Data freshness** panel shows any feed that's gone stale — so a dead feed shows up as *stale*, not as a suspiciously quiet week.
* **Vulnerability-shaped data** (Spotlight vulns and Hadrian external risks) goes into the one vendor-agnostic `vuln_findings` table, so SLA, KEV, EPSS, MTTR, the "worst devices" list and "top fixes" apply to both without any per-vendor logic.
* **Everything else** has its own table (`assets`, `security_alerts`, `identity_entities`, `email_events`, `dmarc_daily`, …). Every table carries `site_label`, `site_tag` and `site_matched_by`.
* **Incremental where it's safe**: alerts, HEC events, risk detections and closed vulns pull from the last good run (minus an overlap). Open vulns, identities, hosts and MFA state are pulled in full every run, because "what's still open" can only be known from a complete pull.

## 2. Install

Tested on Fedora Server; any modern distro works.

```bash
sudo dnf install -y python3 python3-pip git postgresql-server postgresql-contrib
git clone https://github.com/t-d-knight/secops-dashboard /opt/secops-dashboard
cd /opt/secops-dashboard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

PostgreSQL:

```bash
sudo postgresql-setup --initdb && sudo systemctl enable --now postgresql
sudo -u postgres psql <<'SQL'
CREATE DATABASE secops_dashboard;
CREATE USER secops_user WITH ENCRYPTED PASSWORD 'ChangeMe123!';
GRANT ALL PRIVILEGES ON DATABASE secops_dashboard TO secops_user;
\c secops_dashboard
GRANT ALL ON SCHEMA public TO secops_user;
-- read-only role for Grafana (don't give Grafana the collector's account)
CREATE USER grafana_reader WITH ENCRYPTED PASSWORD 'ChangeMe456!';
GRANT CONNECT ON DATABASE secops_dashboard TO grafana_reader;
GRANT USAGE ON SCHEMA public TO grafana_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE secops_user IN SCHEMA public GRANT SELECT ON TABLES TO grafana_reader;
SQL
```

Config:

```bash
cp config.yaml.example config.yaml     # sites, which collectors are on, non-secret settings
cp secrets.yaml.example secrets.yaml   # credentials only
chmod 600 secrets.yaml
```

Both are gitignored. Anything in `secrets.yaml` is deep-merged over the same path in `config.yaml` (lists of named items such as Entra tenants merge by `name`), so credentials never need to sit next to settings.

## 3. Site mapping

Each collector describes what it found with whatever signals it has, and `site_resolver.py` turns that into one site. Signal types are tried in `site_resolution.order` and **the first signal type that matches any site wins**:

| Matcher | Matches | Used by |
|---|---|---|
| `falcon_tags` | Falcon sensor/grouping tag (full tag or the part after the last `/`) | hosts, vulns, alerts |
| `falcon_groups` | Falcon host group **name** | hosts, vulns, alerts |
| `ou_contains` | substring of the AD OU / DN | hosts, identities |
| `ad_sites` | AD Sites & Services site (Falcon `site_name`) | hosts |
| `ad_domains` | AD domain (exact, or as a suffix) | hosts, identities, alerts |
| `hostname_regex` | regex on hostname | hosts, external assets |
| `cidrs` | IP in range (include public ranges for Hadrian) | hosts, unmanaged, external assets |
| `email_domains` | email/web domain or subdomain | DMARC, HEC, Entra, identities by UPN, Hadrian web assets |

Unmatched records land in `ungrouped_label`. **Tune it from data, not guesswork:** after the first run, the SecOps Overview's *Site mapping gaps* and *Unmapped examples* panels show how much fell through per feed and which signals those records carried. Add matchers and re-run; hosts re-resolve on every pull. (Sites removed from config disappear from the `$site` picker; historical rows keep their label.)

Falcon hosts are resolved once and the vulns/alerts collectors reuse the answer by agent ID, so a host can't land in two sites depending on which feed you look at.

## 4. Per-feed setup

### CrowdStrike Falcon (US-2)
One API client (Falcon console → Support and resources → API clients and keys) can serve all four Falcon collectors with these scopes:

| Scope | Access | Collector |
|---|---|---|
| Hosts, Host groups | Read | `falcon_hosts` |
| Assets (Discover / Exposure Management) | Read | `falcon_hosts` unmanaged assets — optional; if missing, managed hosts still load |
| Vulnerabilities | Read | `falcon_spotlight` |
| Alerts | Read | `falcon_alerts` |
| Identity Protection Entities | Read | `falcon_identity` |
| Identity Protection GraphQL | **Write** | `falcon_identity` (CrowdStrike's scope name for running GraphQL queries; the collector only reads) |

The Identity Protection query lives in `collectors/queries/identity_entities.graphql`. Add fields from the GraphQL explorer in the Falcon console without touching Python.

Suppressed Spotlight vulns (accepted risk, compensating control, false positive) are kept as `SUPPRESSED`: visible, but out of open counts and SLA. Vulns that disappear from the open pull without closing (host aged out) become `EXPIRED`, never `FIXED`, so they can't flatter MTTR.

### Hadrian Atlas ⚠️ confirm the API before enabling
Hadrian's API reference sits behind the customer login, so **paths, pagination style and field names are entirely config-driven** and the defaults in `config.yaml.example` are placeholders. Open the API docs in the Hadrian console and fill in `collectors.hadrian.assets` / `.risks` (`path`, `items_key`, `pagination`, `fields`). `fields` values are dotted paths into each record (`asset.id`). If the API takes a while to sort out, set `mode: csv` and point `csv.assets_path` / `csv.risks_path` at exported CSVs; the same field map is applied to column names.

External risks go into `vuln_findings` with `source='hadrian'`, `asset_type='internet'`, so KEV/SLA/MTTR work for them out of the box. Since we're on passive discovery for now, expect few validated risks until active scanning starts.

### Check Point Harmony Email & Collaboration
Infinity Portal → Global Settings → API Keys → New, service **Email & Collaboration**. Put Client ID / Secret Key in `secrets.yaml` (`collectors.checkpoint_hec.client_id` / `access_key`). Set `gateway` to the **Authentication URL shown when the key is created**. It's region-specific, and the global default in the example may not be ours. Site comes from the recipient address domain(s) found in each event.

### Microsoft Entra ID
App registration per tenant, **application** permissions, admin-consented:

| Feed | Permission | Licence |
|---|---|---|
| `risky_users` | `IdentityRiskyUser.Read.All` | Entra ID P2 |
| `risk_detections` | `IdentityRiskEvent.Read.All` | Entra ID P2 |
| `mfa_registration` | `AuditLog.Read.All` | Entra ID P1+ |

Feeds are independent: a 403 on one (e.g. no P2) is recorded and the rest still run; the run is marked `partial`. Drop unlicensed feeds from `feeds:` to stop the noise.

### Azure Log Analytics / Sentinel (optional)
Grant the same app **Log Analytics Reader** on each workspace. Each query in `collectors.azure_log_analytics.queries` aggregates *server-side* in KQL and must return `day`, `key`, `dimension`, `value`. `key_type` tells the resolver what `key` is (`upn`, `email_domain`, `ip`, `hostname`, `ad_domain`). The shipped queries cover sign-in success/failure, legacy auth, MFA denials, risky sign-ins and CA blocks. Add more by adding YAML; no code needed. The whole lookback window is recomputed each run, so late-arriving logs are counted.

### DMARC (parsedmarc on cyber-dmarc)
Create a read-only OpenSearch user with `read` on `dmarc_aggregate*`. Point `opensearch_url` at the cluster; use `ca_file` for the cluster CA rather than `verify_tls: false`. parsedmarc maps `header_from` and friends as `text` (not aggregatable), so the collector scrolls raw aggregate records for the window and aggregates them itself. That's a few thousand rows a day, so it's cheap. The window (default 10 days) is recomputed each run because reporters send late.

## 5. Running

```bash
./bootstrap.sh                          # first run: KEV/EPSS, all collectors (--full), NVD, rollups, preflight
./bootstrap.sh falcon_hosts,falcon_spotlight   # bring feeds online one at a time

python3 collect.py --config config.yaml --list            # what's enabled
python3 collect.py --config config.yaml --only entra      # one feed (even if disabled)
python3 collect.py --config config.yaml --full            # ignore incremental watermarks
python3 rollup_daily_metrics.py --config config.yaml [--dry-run]
```

Cron:

```cron
0 2 * * *  /opt/secops-dashboard/run_collector.sh >> /opt/secops-dashboard/logs/collector.log 2>&1
0 3 * * 0  /opt/secops-dashboard/maintenance.sh   >> /opt/secops-dashboard/logs/maintenance.log 2>&1
```

`run_collector.sh` takes a lock (no overlapping runs), runs everything even if a feed fails, and exits non-zero if anything did. For more frequent alert/email updates, add a second cron line that runs `collect.py --only falcon_alerts,checkpoint_hec` hourly. Those collectors are incremental.

## 6. Grafana

Install Grafana OSS (PostgreSQL datasource is built in):

```bash
sudo tee /etc/yum.repos.d/grafana.repo <<'EOF'
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF
sudo dnf install -y grafana && sudo systemctl enable --now grafana-server
```

1. `python3 grafana/preflight_check.py --config config.yaml`: fix any `[FAIL]` (it also checks every enabled feed has succeeded).
2. Connections → Data sources → PostgreSQL → the `secops_dashboard` DB as **`grafana_reader`**.
3. Dashboards → Import each file, selecting that datasource for `DS_POSTGRESQL`:

| File | Dashboard |
|---|---|
| `grafana/secops-overview.json` | **SecOps Overview**: site scorecard across every feed, trends, data freshness, site-mapping gaps |
| `grafana/vuln-dashboard.json` | **Vulnerability Management**: SLA, KEV, EPSS, worst devices, top fixes, MTTR (endpoint + external) |
| `grafana/secops-endpoint-identity.json` | **Endpoint & Identity**: sensor coverage, alerts, Identity Protection remediation list, Entra risk/MFA, sign-in activity |
| `grafana/secops-email-external.json` | **Email & External Exposure**: HEC threats, DMARC alignment and failing senders, Hadrian assets and risks |

All four share the `$site` variable and link to each other, carrying the site selection and time range. Severity is red → orange → amber → yellow everywhere and never green; green only ever means a good number.

The three `secops-*` dashboards are generated by `grafana/build_dashboards.py`. Edit panels there and re-run it, rather than hand-editing the JSON.

## 7. Coming from tenable-vuln-dashboard

A fresh database is the simplest start. To keep the old trend history instead, point `database.name` at the existing `tenable_trends` DB: `db_schema.ensure_schema()` upgrades it in place (additive: new columns, tables and rebuilt views). Then clear out the Tenable current-state data, which nothing refreshes any more:

```bash
python3 tools/retire_tenable.py --config config.yaml            # dry run: shows what goes
python3 tools/retire_tenable.py --config config.yaml --confirm  # removes source='tenable' findings, plugin catalog, asset_inventory schema
```

All `daily_*` history is kept, so trend lines show an honest step at cutover. Differences worth knowing:

* **`sites:`** keeps the old `key`/`label` shape. Add a `match:` block per site; a bare `key` still matches a Falcon tag of that value as a fallback.
* **`patch_impact_summary`** groups by remediation (one Falcon remediation action, e.g. a single Chrome update covering many CVEs) instead of Tenable plugin ID. Same columns, plus `fix_key`, `affected_sites`.
* **`dim_site`** comes from config (the `sites` table), so sites with no data yet still appear in the picker.
* **`cvss.is_remote_no_auth`** no longer treats a missing exploitability field as "exploit available". The old repo has that bug; it only stayed hidden because Tenable always sent the field.
* **Power BI:** `daily_site_metrics`, `daily_sla_metrics`, `daily_product_metrics` and the views keep their names and columns; the asset page that compared `cs_assets_raw` with `tn_assets_raw` should point at `assets` instead.

## 8. Per-site access for site contacts (next phase)

Not built yet, but the data is shaped for it: every table has `site_label`, and `sites.contacts` holds each site's contacts. The intended design is **Postgres row-level security**, not Grafana variables, because a locked dashboard variable can be edited out of the URL:

1. One login role per site (or one role plus `SET app.site = …`), and an RLS policy per table: `USING (site_label = current_setting('app.site'))` / `site_tag IN (SELECT … role mapping)`.
2. One Grafana datasource per site using that role, and one Grafana **team + folder** per site with dashboards bound to that datasource.
3. Site contacts sign in via Entra SSO, mapped to their team by group claim.

The views (`fact_vuln_findings_current` etc.) need `security_invoker = true` so RLS applies through them (PG 15+).

## 9. Testing

`tests/run_e2e.py` runs every collector against an in-process mock of each vendor API (multi-page pagination included), into a throwaway Postgres DB. It then runs the rollups and **executes every SQL query in every dashboard JSON**:

```bash
PGHOST=127.0.0.1 PGUSER=postgres python3 tests/run_e2e.py
```

It needs a Postgres where it can `DROP`/`CREATE` a database called `secops_e2e`. Run it after changing a collector, the schema or a dashboard.

## 10. Hit-by-a-bus notes

* `config.yaml`: sites, matchers, which feeds are on, retention. `secrets.yaml`: credentials. Neither is in git.
* Shared modules: `config.py`, `db.py`, `db_schema.py` (all DDL + views), `http_client.py` (timeouts/retries), `site_resolver.py`, `findings_store.py` (vuln upsert), `cvss.py`, `product_classify.py` + `product_groups.yaml`.
* Adding a feed: write `collectors/<name>.py` with `NAME` and `run(ctx)`, register it in `collectors/__init__.py`, add its tables to `db_schema.py` (with site columns), add a config block, add a mock to `tests/mock_vendors.py`. Vulnerability-shaped data should go through `FindingsWriter` instead of a new table.
* A feed looks wrong? Check the Data freshness panel, then `SELECT * FROM collector_runs WHERE collector='…' ORDER BY started_at DESC LIMIT 5;`. Each run stores its stats and full error.
* Dependencies: Python 3.9+, `requests`, `pyyaml`, `psycopg2-binary`, PostgreSQL 13+ (15+ for the RLS phase).
