#!/usr/bin/env python3
"""
Idempotent schema for everything the collectors and rollups write:

  core          sites, collector_runs, sla_policy
  vulns         vuln_findings (+cves), cisa_kev, epss_scores, nvd_cvss_cache
  assets        assets (Falcon managed/unmanaged), external_assets (Hadrian)
  detections    security_alerts (Falcon)
  identity      identity_entities, identity_risk_factors (Falcon IdP),
                entra_risky_users, entra_risk_detections, entra_mfa_registration
  email         email_events (Check Point HEC), dmarc_daily (parsedmarc)
  azure         azure_log_metrics (Log Analytics KQL rollups)
  daily_*       snapshot tables written by rollup_daily_metrics.py
  views         fact_vuln_findings_current, asset_risk_summary,
                patch_impact_summary, dim_site, dim_product, ...

Every per-entity table carries site_label / site_tag / site_matched_by so
the dashboard filters uniformly, and so per-site row-level security can be
layered on later without reshaping anything.

Safe to run repeatedly; existing (Tenable-era) databases are migrated in
place by the ALTER ... ADD COLUMN IF NOT EXISTS statements below.
"""
from typing import Any, Dict

import cvss
from db import pg_connect

DDL_STATEMENTS = [
    # SLA policy: single source of truth for the remediation-window CASE
    # logic that used to be hardcoded (identically, and separately) in this
    # file's views AND rollup_daily_metrics.py's queries. Synced from
    # config.yaml's reporting.sla_days by sync_sla_policy() below every
    # time ensure_schema() runs -- changing it only affects queries run
    # from that point on, not past daily_sla_metrics/daily_mttr_metrics rows.
    """
    CREATE TABLE IF NOT EXISTS sla_policy (
        severity        TEXT PRIMARY KEY,
        threshold_days  INTEGER NOT NULL,
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    # Legacy snapshot tables (previously created by tenable_trend_collector.py
    # and fill_daily_product_metrics.py, now superseded by rollup_daily_metrics.py
    # but kept with their existing shape/types so old Power BI reports don't break).
    """
    CREATE TABLE IF NOT EXISTS daily_site_metrics (
        snapshot_date TEXT NOT NULL,
        site_label    TEXT NOT NULL,
        site_tag      TEXT NOT NULL,
        crit          INTEGER NOT NULL,
        high          INTEGER NOT NULL,
        medium        INTEGER NOT NULL,
        low           INTEGER NOT NULL,
        total         INTEGER NOT NULL,
        remote_crit   INTEGER NOT NULL,
        remote_high   INTEGER NOT NULL,
        assets        INTEGER NOT NULL,
        PRIMARY KEY (snapshot_date, site_label)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS daily_sla_metrics (
        snapshot_date           TEXT NOT NULL,
        site_label              TEXT NOT NULL,
        site_tag                TEXT NOT NULL,
        risk                    TEXT NOT NULL,
        total_vulns             INTEGER NOT NULL,
        sla_breaches            INTEGER NOT NULL,
        remote_no_auth_vulns    INTEGER NOT NULL,
        remote_no_auth_breaches INTEGER NOT NULL,
        PRIMARY KEY (snapshot_date, site_label, risk)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS daily_product_metrics (
        snapshot_date date NOT NULL,
        site_label text NOT NULL,
        site_tag text,
        product text NOT NULL,
        open_crit integer NOT NULL DEFAULT 0,
        open_high integer NOT NULL DEFAULT 0,
        open_medium integer NOT NULL DEFAULT 0,
        open_low integer NOT NULL DEFAULT 0,
        open_total integer NOT NULL DEFAULT 0,
        new_crit integer NOT NULL DEFAULT 0,
        new_high integer NOT NULL DEFAULT 0,
        new_medium integer NOT NULL DEFAULT 0,
        new_low integer NOT NULL DEFAULT 0,
        new_total integer NOT NULL DEFAULT 0,
        fixed_crit integer NOT NULL DEFAULT 0,
        fixed_high integer NOT NULL DEFAULT 0,
        fixed_medium integer NOT NULL DEFAULT 0,
        fixed_low integer NOT NULL DEFAULT 0,
        fixed_total integer NOT NULL DEFAULT 0,
        vendor text,
        product_family text,
        PRIMARY KEY (snapshot_date, site_label, product)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS vuln_findings (
        id                   BIGSERIAL PRIMARY KEY,
        source               TEXT NOT NULL,
        source_asset_id      TEXT NOT NULL,
        source_rule_id       TEXT NOT NULL,
        port                 INTEGER NOT NULL DEFAULT 0,
        protocol             TEXT NOT NULL DEFAULT '',

        state                TEXT NOT NULL,
        severity             TEXT NOT NULL,
        cvss_score           NUMERIC(3,1),
        cvss_vector          TEXT,

        title                TEXT,
        plugin_family        TEXT,
        synopsis             TEXT,
        solution             TEXT,

        is_remote_no_auth    BOOLEAN NOT NULL DEFAULT FALSE,
        exploit_available    BOOLEAN,
        exploited_by_malware BOOLEAN,
        has_patch            BOOLEAN,
        patch_published      TIMESTAMPTZ,

        product_key          TEXT,
        product_vendor       TEXT,
        product_family       TEXT,

        site_label           TEXT NOT NULL,
        site_tag             TEXT,
        asset_type           TEXT,
        hostname             TEXT,

        first_found          TIMESTAMPTZ NOT NULL,
        last_found            TIMESTAMPTZ NOT NULL,
        last_fixed             TIMESTAMPTZ,

        unified_asset_id       BIGINT,
        last_seen_in_export    TIMESTAMPTZ NOT NULL DEFAULT now(),
        created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

        CONSTRAINT uq_vuln_findings_natural_key
            UNIQUE (source, source_asset_id, source_rule_id, port, protocol)
    );
    """,
    # --- v2 migration of the Tenable-era vuln_findings table -------------
    "ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS site_matched_by TEXT;",
    "ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS fix_id TEXT;",
    "ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS fix_title TEXT;",
    "ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS vendor_priority TEXT;",
    # One description per CVE (findings_store.FindingsWriter fills it from
    # NormalizedFinding.cve_description). Spotlight used to repeat the ~1.9 KB
    # text on every finding -- most of vuln_findings' size at 4.5M rows.
    """
    CREATE TABLE IF NOT EXISTS cve_descriptions (
        cve_id       TEXT PRIMARY KEY,
        description  TEXT,
        updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    # Hadrian riskType (Potential | Verified | UnpatchedTechnology |
    # InfectedDevice): separates confirmed external risks from unverified
    # "potential" ones. NULL for sources without the concept.
    "ALTER TABLE vuln_findings ADD COLUMN IF NOT EXISTS risk_type TEXT;",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_source_state ON vuln_findings (source, state);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_fix ON vuln_findings (source, fix_id) WHERE state IN ('OPEN','REOPENED');",
    # --- core ------------------------------------------------------------
    # Sites come from config.yaml (sync_sites below), not from whatever
    # labels happen to appear in data, so a site with zero findings still
    # shows in the $site picker -- and so a future per-site RLS policy has
    # one authoritative table to reference.
    """
    CREATE TABLE IF NOT EXISTS sites (
        site_tag    TEXT PRIMARY KEY,
        site_label  TEXT NOT NULL UNIQUE,
        contacts    TEXT[],
        synced_at   TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS collector_runs (
        id           BIGSERIAL PRIMARY KEY,
        collector    TEXT NOT NULL,
        started_at   TIMESTAMPTZ NOT NULL,
        finished_at  TIMESTAMPTZ,
        status       TEXT NOT NULL,            -- running | ok | partial | error
        stats        JSONB,
        error        TEXT
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_collector_runs_c ON collector_runs (collector, started_at DESC);",
    # --- assets ----------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS assets (
        source             TEXT NOT NULL,      -- falcon | falcon_unmanaged
        source_asset_id    TEXT NOT NULL,
        hostname           TEXT,
        domain             TEXT,
        ous                TEXT[],
        ad_site            TEXT,
        platform           TEXT,
        os_version         TEXT,
        product_type       TEXT,
        managed            BOOLEAN NOT NULL DEFAULT TRUE,
        internet_exposure  TEXT,
        sensor_version     TEXT,
        rfm                TEXT,
        containment        TEXT,
        prevention_policy  TEXT,
        ips                TEXT[],
        external_ip        TEXT,
        groups             TEXT[],
        tags               TEXT[],
        first_seen         TIMESTAMPTZ,
        last_seen          TIMESTAMPTZ,
        site_label         TEXT NOT NULL,
        site_tag           TEXT,
        site_matched_by    TEXT,
        retired            BOOLEAN NOT NULL DEFAULT FALSE,
        collected_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (source, source_asset_id)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_assets_site ON assets (site_label) WHERE NOT retired;",
    # Discover detail for telling real unsensored machines from noise (see
    # collectors/falcon_hosts.py classify_unmanaged). mac_addresses is also
    # filled for managed hosts (primary MAC) so an unmanaged record sharing a
    # managed host's MAC can be recognised as that host's secondary IP.
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS mac_addresses TEXT[];",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS mac_vendor TEXT;",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS data_providers TEXT[];",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS ad_uac INTEGER;",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS ad_enabled BOOLEAN;",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS ad_created TIMESTAMPTZ;",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS description TEXT;",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS discovery_class TEXT;",
    "ALTER TABLE assets ADD COLUMN IF NOT EXISTS managed_twin TEXT;",
    """
    CREATE TABLE IF NOT EXISTS external_assets (
        source           TEXT NOT NULL,
        asset_id         TEXT NOT NULL,
        name             TEXT,
        asset_type       TEXT,
        ips              TEXT[],
        ports            TEXT[],
        technologies     TEXT[],
        first_seen       TIMESTAMPTZ,
        last_seen        TIMESTAMPTZ,
        site_label       TEXT NOT NULL,
        site_tag         TEXT,
        site_matched_by  TEXT,
        retired          BOOLEAN NOT NULL DEFAULT FALSE,
        collected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (source, asset_id)
    );
    """,
    # --- detections ------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS security_alerts (
        source           TEXT NOT NULL,
        alert_id         TEXT NOT NULL,
        created_at       TIMESTAMPTZ,
        updated_at       TIMESTAMPTZ,
        closed_at        TIMESTAMPTZ,
        severity         TEXT NOT NULL,       -- critical | high | medium | low | info
        severity_score   INTEGER,
        status           TEXT,                -- new | in_progress | closed
        disposition      TEXT,                -- raw vendor verdict: new | in_progress | reopened |
                                               -- closed | true_positive | false_positive | ignored
        name             TEXT,
        tactic           TEXT,
        technique        TEXT,
        product          TEXT,                -- epp | idp | ...
        hostname         TEXT,
        user_name        TEXT,
        source_asset_id  TEXT,
        site_label       TEXT NOT NULL,
        site_tag         TEXT,
        site_matched_by  TEXT,
        link             TEXT,
        PRIMARY KEY (source, alert_id)
    );
    """,
    "ALTER TABLE security_alerts ADD COLUMN IF NOT EXISTS disposition TEXT;",
    "CREATE INDEX IF NOT EXISTS idx_alerts_created ON security_alerts (created_at);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_disposition ON security_alerts (source, disposition);",
    # --- identity --------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS identity_entities (
        source                TEXT NOT NULL,
        entity_id             TEXT NOT NULL,
        display_name          TEXT,
        upn                   TEXT,
        domain                TEXT,
        sam_account_name      TEXT,
        ou                    TEXT,
        enabled               BOOLEAN,
        entity_type           TEXT,
        risk_score            NUMERIC(6,3),
        risk_severity         TEXT,
        password_last_change  TIMESTAMPTZ,
        account_created       TIMESTAMPTZ,
        site_label            TEXT NOT NULL,
        site_tag              TEXT,
        site_matched_by       TEXT,
        retired               BOOLEAN NOT NULL DEFAULT FALSE,
        collected_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (source, entity_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS identity_risk_factors (
        source           TEXT NOT NULL,
        entity_id        TEXT NOT NULL,
        factor_type      TEXT NOT NULL,
        factor_severity  TEXT,
        PRIMARY KEY (source, entity_id, factor_type)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS entra_risky_users (
        tenant             TEXT NOT NULL,
        user_id            TEXT NOT NULL,
        upn                TEXT,
        display_name       TEXT,
        risk_level         TEXT,
        risk_state         TEXT,
        risk_detail        TEXT,
        risk_last_updated  TIMESTAMPTZ,
        site_label         TEXT NOT NULL,
        site_tag           TEXT,
        site_matched_by    TEXT,
        collected_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (tenant, user_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS entra_risk_detections (
        tenant           TEXT NOT NULL,
        detection_id     TEXT NOT NULL,
        upn              TEXT,
        risk_event_type  TEXT,
        risk_level       TEXT,
        risk_state       TEXT,
        detected_at      TIMESTAMPTZ,
        ip_address       TEXT,
        country          TEXT,
        city             TEXT,
        site_label       TEXT NOT NULL,
        site_tag         TEXT,
        site_matched_by  TEXT,
        PRIMARY KEY (tenant, detection_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS entra_mfa_registration (
        tenant                   TEXT NOT NULL,
        user_id                  TEXT NOT NULL,
        upn                      TEXT,
        is_admin                 BOOLEAN,
        is_mfa_capable           BOOLEAN,
        is_mfa_registered        BOOLEAN,
        is_passwordless_capable  BOOLEAN,
        methods                  TEXT[],
        site_label               TEXT NOT NULL,
        site_tag                 TEXT,
        site_matched_by          TEXT,
        collected_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (tenant, user_id)
    );
    """,
    # --- email -----------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS email_events (
        source            TEXT NOT NULL,
        event_id          TEXT NOT NULL,
        created_at        TIMESTAMPTZ,
        event_type        TEXT,
        severity          TEXT,
        state             TEXT,
        saas              TEXT,
        confidence        TEXT,
        sender            TEXT,
        sender_domain     TEXT,
        recipient_domain  TEXT,
        -- inbound/outbound/internal/unknown, relative to our own
        -- configured email_domains (see site_resolver.email_direction)
        direction         TEXT,
        action_taken      TEXT,
        description       TEXT,
        site_label        TEXT NOT NULL,
        site_tag          TEXT,
        site_matched_by   TEXT,
        link              TEXT,
        PRIMARY KEY (source, event_id)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_email_events_created ON email_events (created_at);",
    "ALTER TABLE email_events ADD COLUMN IF NOT EXISTS direction TEXT;",
    "CREATE INDEX IF NOT EXISTS idx_email_events_direction ON email_events (direction);",
    """
    CREATE TABLE IF NOT EXISTS dmarc_daily (
        report_date         DATE NOT NULL,
        header_from         TEXT NOT NULL,
        source_ip           TEXT NOT NULL,
        source_base_domain  TEXT,
        source_name         TEXT,
        source_country      TEXT,
        messages            BIGINT NOT NULL DEFAULT 0,
        dmarc_pass          BIGINT NOT NULL DEFAULT 0,
        spf_aligned         BIGINT NOT NULL DEFAULT 0,
        dkim_aligned        BIGINT NOT NULL DEFAULT 0,
        quarantined         BIGINT NOT NULL DEFAULT 0,
        rejected            BIGINT NOT NULL DEFAULT 0,
        reporters           TEXT[],
        site_label          TEXT NOT NULL,
        site_tag            TEXT,
        site_matched_by     TEXT,
        PRIMARY KEY (report_date, header_from, source_ip)
    );
    """,
    # --- azure -----------------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS azure_log_metrics (
        snapshot_date  DATE NOT NULL,
        query_name     TEXT NOT NULL,
        site_label     TEXT NOT NULL,
        site_tag       TEXT,
        dimension      TEXT NOT NULL DEFAULT 'all',
        value          DOUBLE PRECISION NOT NULL,
        PRIMARY KEY (snapshot_date, query_name, site_label, dimension)
    );
    """,
    # --- daily snapshots for the new domains (rollup_daily_metrics.py) ----
    """
    CREATE TABLE IF NOT EXISTS daily_source_metrics (
        snapshot_date  DATE NOT NULL,
        site_label     TEXT NOT NULL,
        source         TEXT NOT NULL,
        crit           INTEGER NOT NULL DEFAULT 0,
        high           INTEGER NOT NULL DEFAULT 0,
        medium         INTEGER NOT NULL DEFAULT 0,
        low            INTEGER NOT NULL DEFAULT 0,
        total          INTEGER NOT NULL DEFAULT 0,
        kev            INTEGER NOT NULL DEFAULT 0,
        sla_breaches   INTEGER NOT NULL DEFAULT 0,
        assets         INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (snapshot_date, site_label, source)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS daily_asset_metrics (
        snapshot_date       DATE NOT NULL,
        site_label          TEXT NOT NULL,
        managed_hosts       INTEGER NOT NULL DEFAULT 0,
        stale_sensors       INTEGER NOT NULL DEFAULT 0,
        rfm_hosts           INTEGER NOT NULL DEFAULT 0,
        unmanaged_assets    INTEGER NOT NULL DEFAULT 0,
        external_assets     INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (snapshot_date, site_label)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS daily_alert_metrics (
        snapshot_date    DATE NOT NULL,
        site_label       TEXT NOT NULL,
        new_critical     INTEGER NOT NULL DEFAULT 0,
        new_high         INTEGER NOT NULL DEFAULT 0,
        new_medium       INTEGER NOT NULL DEFAULT 0,
        new_low          INTEGER NOT NULL DEFAULT 0,
        open_total       INTEGER NOT NULL DEFAULT 0,
        open_crit_high   INTEGER NOT NULL DEFAULT 0,
        closed_today     INTEGER NOT NULL DEFAULT 0,
        median_hours_to_close NUMERIC(10,2),
        PRIMARY KEY (snapshot_date, site_label)
    );
    """,
    # new_*/closed_today/median are per EVENT day (created_at/closed_at) and
    # recomputed over a lookback window every run, so past days get filled
    # in. open_* is a point-in-time count only the run day itself can know:
    # NULL on a day no run snapshotted (e.g. backfilled history), never a
    # fake 0.
    "ALTER TABLE daily_alert_metrics ALTER COLUMN open_total DROP NOT NULL;",
    "ALTER TABLE daily_alert_metrics ALTER COLUMN open_crit_high DROP NOT NULL;",
    # Vulns opened/fixed per EVENT day (first_found / last_fixed), recomputed
    # over a lookback window like daily_alert_metrics. Kept as its own
    # snapshot table (540-day retention) because maintenance.sh purges FIXED
    # findings after 180 days -- a quarter-on-quarter comparison can't be
    # recomputed from vuln_findings alone. EXPIRED findings are not counted
    # as opened (Spotlight expires huge volumes of short-lived records).
    """
    CREATE TABLE IF NOT EXISTS daily_vuln_flow_metrics (
        snapshot_date   DATE NOT NULL,
        site_label      TEXT NOT NULL,
        severity        TEXT NOT NULL,
        opened          INTEGER NOT NULL DEFAULT 0,
        fixed           INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (snapshot_date, site_label, severity)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS daily_identity_metrics (
        snapshot_date   DATE NOT NULL,
        site_label      TEXT NOT NULL,
        metric          TEXT NOT NULL,   -- risk:<severity> | factor:<type> | entra_risky:<level> | mfa_registered | mfa_users
        value           INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (snapshot_date, site_label, metric)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS daily_email_metrics (
        snapshot_date  DATE NOT NULL,
        site_label     TEXT NOT NULL,
        event_type     TEXT NOT NULL,
        -- inbound/outbound/internal/unknown; see email_events.direction
        direction      TEXT NOT NULL DEFAULT 'unknown',
        events         INTEGER NOT NULL DEFAULT 0,
        high_plus      INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (snapshot_date, site_label, event_type, direction)
    );
    """,
    # Pre-existing (pre-direction) tables: backfill the column as 'unknown'
    # (matching every row's old implicit "direction wasn't tracked" state)
    # and widen the PK to include it -- safe even with existing rows since
    # the old PK was unique per (date, site, event_type) already, so adding
    # a column that's constant across those rows can't create duplicates.
    "ALTER TABLE daily_email_metrics ADD COLUMN IF NOT EXISTS direction TEXT NOT NULL DEFAULT 'unknown';",
    """
    DO $$ BEGIN
        ALTER TABLE daily_email_metrics DROP CONSTRAINT daily_email_metrics_pkey;
    EXCEPTION WHEN undefined_object THEN NULL;
    END $$;
    """,
    """
    DO $$ BEGIN
        ALTER TABLE daily_email_metrics ADD PRIMARY KEY (snapshot_date, site_label, event_type, direction);
    EXCEPTION WHEN invalid_table_definition THEN NULL;
    END $$;
    """,
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_state ON vuln_findings (state);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_severity ON vuln_findings (severity);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_product_key ON vuln_findings (product_key);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_product_family ON vuln_findings (product_family);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_first_found ON vuln_findings (first_found);",
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_last_fixed ON vuln_findings (last_fixed);",
    # Open endpoint findings only, covering what exec_report / action_pack
    # count per site: lets those answer from the index instead of scanning
    # the whole table (20 GB at ~4.7M rows once Spotlight covered the estate;
    # without it a region report took 15 min). Created CONCURRENTLY by hand
    # on the live DB first; IF NOT EXISTS makes this a no-op there.
    """
    CREATE INDEX IF NOT EXISTS idx_vuln_findings_open_endpoint ON vuln_findings
        (site_label, severity) INCLUDE (product_family, first_found, last_found, is_remote_no_auth, source)
        WHERE state IN ('OPEN','REOPENED') AND source <> 'hadrian';
    """,
    "CREATE INDEX IF NOT EXISTS idx_vuln_findings_source_asset ON vuln_findings (source_asset_id);",
    """
    CREATE INDEX IF NOT EXISTS idx_vuln_findings_open
        ON vuln_findings (site_label, severity)
        WHERE state IN ('OPEN','REOPENED');
    """,
    """
    CREATE TABLE IF NOT EXISTS vuln_finding_cves (
        finding_id BIGINT NOT NULL REFERENCES vuln_findings(id) ON DELETE CASCADE,
        cve        TEXT NOT NULL,
        PRIMARY KEY (finding_id, cve)
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_vuln_finding_cves_cve ON vuln_finding_cves (cve);",
    """
    CREATE TABLE IF NOT EXISTS cisa_kev (
        cve_id                          TEXT PRIMARY KEY,
        vendor_project                  TEXT,
        product                         TEXT,
        vulnerability_name              TEXT,
        date_added                      DATE,
        short_description               TEXT,
        required_action                 TEXT,
        due_date                        DATE,
        known_ransomware_campaign_use   TEXT,
        notes                           TEXT,
        cwes                            TEXT[],
        synced_at                       TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS daily_kev_metrics (
        snapshot_date          DATE NOT NULL,
        site_label             TEXT NOT NULL,
        site_tag               TEXT,
        kev_open_total          INTEGER NOT NULL DEFAULT 0,
        kev_open_crit           INTEGER NOT NULL DEFAULT 0,
        kev_open_high           INTEGER NOT NULL DEFAULT 0,
        kev_open_medium         INTEGER NOT NULL DEFAULT 0,
        kev_open_low            INTEGER NOT NULL DEFAULT 0,
        kev_ransomware_total     INTEGER NOT NULL DEFAULT 0,
        kev_past_due_total       INTEGER NOT NULL DEFAULT 0,
        non_kev_open_total       INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (snapshot_date, site_label)
    );
    """,
    # MTTR trend, per calendar day a finding actually closed (last_fixed's
    # own date -- not a rolling window like daily_product_metrics.fixed_*),
    # broken down by severity so SLA tracking is visible per risk band.
    """
    CREATE TABLE IF NOT EXISTS daily_mttr_metrics (
        snapshot_date            DATE NOT NULL,
        site_label                TEXT NOT NULL,
        site_tag                  TEXT,
        severity                  TEXT NOT NULL,
        fixed_count                 INTEGER NOT NULL DEFAULT 0,
        avg_remediation_days        NUMERIC(10,2),
        median_remediation_days     NUMERIC(10,2),
        sla_compliant_count          INTEGER NOT NULL DEFAULT 0,
        sla_compliance_rate          NUMERIC(5,2),
        PRIMARY KEY (snapshot_date, site_label, severity)
    );
    """,
    # Per-source split of the per-event-day vuln tables, so endpoint
    # (Spotlight) and external (Hadrian) opened/fixed/MTTR can be reported
    # separately -- Grafana panels SUM across sources and are unaffected.
    # Existing rows are all Spotlight (Hadrian had never run when added).
    "ALTER TABLE daily_vuln_flow_metrics ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'falcon_spotlight';",
    """
    DO $$ BEGIN
        ALTER TABLE daily_vuln_flow_metrics DROP CONSTRAINT daily_vuln_flow_metrics_pkey;
    EXCEPTION WHEN undefined_object THEN NULL;
    END $$;
    """,
    """
    DO $$ BEGIN
        ALTER TABLE daily_vuln_flow_metrics ADD PRIMARY KEY (snapshot_date, site_label, severity, source);
    EXCEPTION WHEN invalid_table_definition THEN NULL;
    END $$;
    """,
    "ALTER TABLE daily_mttr_metrics ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'falcon_spotlight';",
    """
    DO $$ BEGIN
        ALTER TABLE daily_mttr_metrics DROP CONSTRAINT daily_mttr_metrics_pkey;
    EXCEPTION WHEN undefined_object THEN NULL;
    END $$;
    """,
    """
    DO $$ BEGIN
        ALTER TABLE daily_mttr_metrics ADD PRIMARY KEY (snapshot_date, site_label, severity, source);
    EXCEPTION WHEN invalid_table_definition THEN NULL;
    END $$;
    """,
    # EPSS (Exploit Prediction Scoring System, FIRST.org): daily-updated
    # probability (0-1) a CVE will be exploited in the wild in the next 30
    # days. Synced whole-catalog by epss_sync.py (public bulk CSV, no auth).
    """
    CREATE TABLE IF NOT EXISTS epss_scores (
        cve_id       TEXT PRIMARY KEY,
        epss         NUMERIC(8,5) NOT NULL,
        percentile   NUMERIC(8,5) NOT NULL,
        score_date   DATE,
        synced_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    "CREATE INDEX IF NOT EXISTS idx_epss_scores_epss ON epss_scores (epss DESC);",
    # Local cache for NVD CVSS lookups (nvd_enrich.py), keyed by CVE, so a
    # given CVE is never re-queried once resolved. found=FALSE rows are
    # only retried after a cooldown (NVD's own analyst backlog means a
    # CVE with no score today may get one in a few weeks).
    """
    CREATE TABLE IF NOT EXISTS nvd_cvss_cache (
        cve_id        TEXT PRIMARY KEY,
        cvss_vector   TEXT,
        cvss_score    NUMERIC(3,1),
        cvss_version  TEXT,
        found         BOOLEAN NOT NULL,
        checked_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS daily_epss_metrics (
        snapshot_date              DATE NOT NULL,
        site_label                 TEXT NOT NULL,
        site_tag                   TEXT,
        avg_epss                   NUMERIC(6,4),
        max_epss                   NUMERIC(6,4),
        high_epss_open_total        INTEGER NOT NULL DEFAULT 0,
        high_epss_non_kev_total     INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (snapshot_date, site_label)
    );
    """,
    # Views are dropped and recreated every run: fact_vuln_findings_current
    # expands vf.*, and Postgres refuses CREATE OR REPLACE when that column
    # list shifts (as it does when the v2 migration adds columns).
    "DROP VIEW IF EXISTS patch_impact_summary, asset_risk_summary, fact_vuln_findings_current, dim_site, dim_product, collector_freshness CASCADE;",
    # Power BI/Grafana fact view: currently-open findings, KEV-enriched.
    # A single LEFT JOIN LATERAL computes all KEV columns from one
    # subquery evaluation per row (same pattern as rollup_kev_metrics()
    # in rollup_daily_metrics.py, proven at this data volume there) --
    # the earlier version used five separate correlated subqueries, which
    # is what was actually timing out Grafana panels at 300k+ open rows
    # against a 6M+ row vuln_finding_cves table. Avoids row fanout the
    # same way the old version did (one KEV row picked per finding via
    # ORDER BY date_added DESC LIMIT 1 inside the LATERAL).
    """
    CREATE OR REPLACE VIEW fact_vuln_findings_current AS
    SELECT
        vf.*,
        EXTRACT(EPOCH FROM now() - vf.first_found) / 86400.0 AS age_days,
        COALESCE(sp.threshold_days, 60) AS sla_threshold_days,
        (EXTRACT(EPOCH FROM now() - vf.first_found) / 86400.0) > COALESCE(sp.threshold_days, 60) AS sla_breach,
        (k.cve_id IS NOT NULL) AS has_kev,
        k.cve_id AS kev_cve_id,
        k.date_added AS kev_date_added,
        k.due_date AS kev_due_date,
        k.known_ransomware_campaign_use AS kev_ransomware_use,
        e.epss AS epss_score,
        e.percentile AS epss_percentile,
        e.cve_id AS epss_cve_id
    FROM vuln_findings vf
    LEFT JOIN sla_policy sp ON sp.severity = vf.severity
    LEFT JOIN LATERAL (
        SELECT kk.cve_id, kk.date_added, kk.due_date, kk.known_ransomware_campaign_use
        FROM vuln_finding_cves fc
        JOIN cisa_kev kk ON kk.cve_id = fc.cve
        WHERE fc.finding_id = vf.id
        ORDER BY kk.date_added DESC
        LIMIT 1
    ) k ON TRUE
    LEFT JOIN LATERAL (
        SELECT es.epss, es.percentile, fc2.cve AS cve_id
        FROM vuln_finding_cves fc2
        JOIN epss_scores es ON es.cve_id = fc2.cve
        WHERE fc2.finding_id = vf.id
        ORDER BY es.epss DESC
        LIMIT 1
    ) e ON TRUE
    WHERE vf.state IN ('OPEN','REOPENED');
    """,
    """
    CREATE OR REPLACE VIEW dim_site AS
    SELECT site_label, site_tag FROM sites;
    """,
    """
    CREATE OR REPLACE VIEW dim_product AS
    SELECT DISTINCT product_key, product_vendor, product_family
    FROM vuln_findings
    WHERE product_key IS NOT NULL;
    """,
    # "Worst devices" hit list: one row per asset, ranked by a weighted
    # risk score. Built on fact_vuln_findings_current so it inherits the
    # same age/SLA/KEV columns for free instead of recomputing them.
    """
    CREATE OR REPLACE VIEW asset_risk_summary AS
    SELECT
        source,
        source_asset_id,
        max(hostname) AS hostname,
        max(site_label) AS site_label,
        max(site_tag) AS site_tag,
        max(asset_type) AS asset_type,
        count(*) FILTER (WHERE severity = 'critical') AS open_critical,
        count(*) FILTER (WHERE severity = 'high') AS open_high,
        count(*) FILTER (WHERE severity = 'medium') AS open_medium,
        count(*) FILTER (WHERE severity = 'low') AS open_low,
        count(*) AS open_total,
        count(*) FILTER (WHERE is_remote_no_auth) AS open_remote_no_auth,
        count(*) FILTER (WHERE has_kev) AS open_kev_count,
        count(*) FILTER (WHERE sla_breach) AS open_sla_breaches,
        max(age_days) AS oldest_open_finding_age_days,
        (count(*) FILTER (WHERE severity = 'critical') * 10)
          + (count(*) FILTER (WHERE severity = 'high') * 5)
          + (count(*) FILTER (WHERE severity = 'medium') * 2)
          + (count(*) FILTER (WHERE severity = 'low') * 1)
          + (count(*) FILTER (WHERE has_kev) * 15)
          + (count(*) FILTER (WHERE is_remote_no_auth) * 5) AS risk_score
    FROM fact_vuln_findings_current
    GROUP BY source, source_asset_id;
    """,
    # "Top patches to deploy": groups open findings by the remediation that
    # closes them -- Spotlight's remediation entity (e.g. "Update Google
    # Chrome to 131.x"), which covers every CVE that one update fixes, or a
    # Hadrian risk title. Findings with no remediation fall back to their
    # product, then to the individual rule. Answers "if I push this one fix,
    # how many findings across how many assets does it close?"
    """
    CREATE OR REPLACE VIEW patch_impact_summary AS
    SELECT
        vf.source,
        COALESCE(vf.fix_id, 'product:' || vf.product_key, vf.source_rule_id) AS fix_key,
        COALESCE(max(vf.fix_title), max(vf.solution), max(vf.product_key), max(vf.title)) AS title,
        max(vf.solution) AS solution,
        mode() WITHIN GROUP (ORDER BY vf.product_family) AS product_family,
        count(*) AS open_findings,
        count(DISTINCT vf.source_asset_id) AS affected_assets,
        count(DISTINCT vf.site_label) AS affected_sites,
        count(*) FILTER (WHERE vf.severity = 'critical') AS crit,
        count(*) FILTER (WHERE vf.severity = 'high') AS high,
        count(*) FILTER (WHERE vf.severity = 'medium') AS medium,
        count(*) FILTER (WHERE vf.severity = 'low') AS low,
        count(*) FILTER (WHERE vf.is_remote_no_auth) AS remote_no_auth_count,
        bool_or(k.cve_id IS NOT NULL) AS has_kev,
        max(e.epss) AS max_epss,
        (
            count(DISTINCT vf.source_asset_id)
            + (count(*) FILTER (WHERE vf.severity = 'critical') * 5)
            + (count(*) FILTER (WHERE vf.severity = 'high') * 2)
            + (count(*) FILTER (WHERE vf.is_remote_no_auth) * 3)
            + (CASE WHEN bool_or(k.cve_id IS NOT NULL)
                    THEN count(DISTINCT vf.source_asset_id) * 5 ELSE 0 END)
            + ROUND(COALESCE(max(e.epss), 0) * count(DISTINCT vf.source_asset_id) * 2)
        )::int AS priority_score
    FROM vuln_findings vf
    LEFT JOIN LATERAL (
        SELECT k.cve_id
        FROM vuln_finding_cves fc
        JOIN cisa_kev k ON k.cve_id = fc.cve
        WHERE fc.finding_id = vf.id
        LIMIT 1
    ) k ON TRUE
    LEFT JOIN LATERAL (
        SELECT es.epss
        FROM vuln_finding_cves fc2
        JOIN epss_scores es ON es.cve_id = fc2.cve
        WHERE fc2.finding_id = vf.id
        ORDER BY es.epss DESC
        LIMIT 1
    ) e ON TRUE
    WHERE vf.state IN ('OPEN','REOPENED')
    GROUP BY vf.source, COALESCE(vf.fix_id, 'product:' || vf.product_key, vf.source_rule_id);
    """,
    # Data freshness: latest run per collector, for the dashboard's
    # "is every feed actually current?" panel.
    """
    CREATE OR REPLACE VIEW collector_freshness AS
    SELECT DISTINCT ON (collector)
        collector,
        started_at AS last_run,
        finished_at,
        status,
        error,
        (SELECT max(started_at) FROM collector_runs c2
          WHERE c2.collector = c.collector AND c2.status IN ('ok','partial')) AS last_success
    FROM collector_runs c
    ORDER BY collector, started_at DESC;
    """,
]


def sync_sla_policy(cur, cfg: Dict[str, Any]) -> None:
    """
    Upserts sla_policy from config.yaml's reporting.sla_days (falling back
    to cvss.DEFAULT_SLA_DAYS for any severity not specified). This is what
    fact_vuln_findings_current's sla_breach/sla_threshold_days and
    rollup_daily_metrics.py's SLA/MTTR queries actually read -- change the
    config value, re-run any script that calls ensure_schema(), and every
    query from that point on uses the new threshold.
    """
    configured = cfg.get("reporting", {}).get("sla_days") or {}
    thresholds = {**cvss.DEFAULT_SLA_DAYS, **configured}
    for severity, days in thresholds.items():
        cur.execute(
            """
            INSERT INTO sla_policy (severity, threshold_days, updated_at)
            VALUES (%s, %s, now())
            ON CONFLICT (severity) DO UPDATE SET
                threshold_days = EXCLUDED.threshold_days,
                updated_at = now();
            """,
            (severity, days),
        )


def sync_sites(cur, cfg: Dict[str, Any]) -> None:
    """sites table <- config.yaml sites (+ Ungrouped). Sites removed from
    config are deleted here; their historical rows keep their label."""
    rows = [(s["key"], s.get("label", s["key"]), s.get("contacts")) for s in cfg.get("sites", []) or []]
    rows.append(("UNGROUPED", cfg.get("ungrouped_label", "Ungrouped"), None))
    keys = [r[0] for r in rows]
    cur.execute("DELETE FROM sites WHERE NOT (site_tag = ANY(%s))", (keys,))
    for key, label, contacts in rows:
        # label is UNIQUE: clear a clashing old row (label moved between keys) first
        cur.execute("DELETE FROM sites WHERE site_label = %s AND site_tag <> %s", (label, key))
        cur.execute(
            """INSERT INTO sites (site_tag, site_label, contacts, synced_at) VALUES (%s,%s,%s,now())
               ON CONFLICT (site_tag) DO UPDATE SET site_label = EXCLUDED.site_label,
                   contacts = EXCLUDED.contacts, synced_at = now()""",
            (key, label, contacts),
        )


def ensure_schema(cfg: Dict[str, Any]) -> None:
    conn = pg_connect(cfg)
    cur = conn.cursor()
    # serialise concurrent ensure_schema calls (cron overlap) -- DDL races otherwise
    cur.execute("SELECT pg_advisory_xact_lock(727274)")
    for stmt in DDL_STATEMENTS:
        cur.execute(stmt)
    sync_sla_policy(cur, cfg)
    sync_sites(cur, cfg)
    conn.commit()
    conn.close()
