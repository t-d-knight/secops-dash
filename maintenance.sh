#!/bin/bash
set -euo pipefail

# maintenance.sh -- weekly pruning + VACUUM + log rotation/cleanup.
# Scheduled in crontab.example (Sundays, after the nightly collection --
# never before it: run_collector.sh skips the night if its lock is held).
#
# psql needs password-free auth as DB_USER: a ~/.pgpass line
#   127.0.0.1:5432:secops_dashboard:secops_user:yourpassword
# or PGPASSWORD in the cron environment.
#
# Retention values should match config.yaml reporting.*; override via env.

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="$APP_DIR/logs"

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_NAME="${DB_NAME:-secops_dashboard}"
DB_USER="${DB_USER:-secops_user}"

RETENTION_DAYS_DB="${RETENTION_DAYS_DB:-540}"            # reporting.retention_days (daily_* snapshots)
RETENTION_DAYS_FINDINGS="${RETENTION_DAYS_FINDINGS:-180}" # reporting.findings_retention_days
RETENTION_DAYS_EVENTS="${RETENTION_DAYS_EVENTS:-365}"     # reporting.events_retention_days
RETENTION_DAYS_RUNS=90
RETENTION_DAYS_LOGS=30
LOG_ROTATE_MB="${LOG_ROTATE_MB:-20}"

TS="$(date -Iseconds)"
echo "[$TS] ===== secops dashboard maintenance start ====="

psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 <<SQL
-- daily snapshots
DELETE FROM daily_product_metrics  WHERE snapshot_date::date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_site_metrics     WHERE snapshot_date::date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_sla_metrics      WHERE snapshot_date::date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_kev_metrics      WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_epss_metrics     WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_mttr_metrics     WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_source_metrics   WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_asset_metrics    WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_alert_metrics    WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_identity_metrics WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_email_metrics    WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_vuln_flow_metrics WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM daily_email_flow_metrics WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};
DELETE FROM azure_log_metrics      WHERE snapshot_date < CURRENT_DATE - ${RETENTION_DAYS_DB};

-- closed-out findings (open ones mirror vendor state and are never aged out)
DELETE FROM vuln_findings
 WHERE (state = 'FIXED'   AND last_fixed < now() - INTERVAL '${RETENTION_DAYS_FINDINGS} days')
    OR (state = 'EXPIRED' AND updated_at < now() - INTERVAL '${RETENTION_DAYS_FINDINGS} days');

-- event-style tables
DELETE FROM security_alerts       WHERE status = 'closed' AND updated_at < now() - INTERVAL '${RETENTION_DAYS_EVENTS} days';
DELETE FROM email_events          WHERE created_at  < now() - INTERVAL '${RETENTION_DAYS_EVENTS} days';
DELETE FROM entra_risk_detections WHERE detected_at < now() - INTERVAL '${RETENTION_DAYS_EVENTS} days';
DELETE FROM dmarc_daily           WHERE report_date < CURRENT_DATE - ${RETENTION_DAYS_EVENTS};

-- retired inventory (gone from the vendor for a long time)
DELETE FROM assets            WHERE retired AND collected_at < now() - INTERVAL '${RETENTION_DAYS_FINDINGS} days';
DELETE FROM external_assets   WHERE retired AND collected_at < now() - INTERVAL '${RETENTION_DAYS_FINDINGS} days';
DELETE FROM identity_entities WHERE retired AND collected_at < now() - INTERVAL '${RETENTION_DAYS_FINDINGS} days';

DELETE FROM collector_runs WHERE started_at < now() - INTERVAL '${RETENTION_DAYS_RUNS} days';
SQL

echo "[$TS] vacuumdb…"
vacuumdb -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -z --schema=public   # our tables only: system catalogs belong to postgres

echo "[$TS] rotating logs over ${LOG_ROTATE_MB}MB, removing rotated logs older than ${RETENTION_DAYS_LOGS} days…"
mkdir -p "$LOG_DIR"
# cron appends to the same files forever, so rotate by size; the manifest
# (logs/publish-manifest.json) is never touched.
find "$LOG_DIR" -maxdepth 1 -type f -name "*.log" -size +"${LOG_ROTATE_MB}"M | while read -r f; do
    mv "$f" "$f.$(date +%Y%m%d)" && gzip -f "$f.$(date +%Y%m%d)"
done
find "$LOG_DIR" -maxdepth 1 -type f -name "*.log.*.gz" -mtime +"$RETENTION_DAYS_LOGS" -delete
find "$LOG_DIR" -maxdepth 1 -type f -name "*.log" -mtime +"$RETENTION_DAYS_LOGS" -delete

echo "[$TS] ===== secops dashboard maintenance complete ====="
