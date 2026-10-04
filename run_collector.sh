#!/bin/bash
set -uo pipefail

# run_collector.sh -- nightly pipeline. Cron example (runs from wherever the repo lives):
#   0 2 * * * /opt/secops-dashboard/run_collector.sh >> /opt/secops-dashboard/logs/collector.log 2>&1
#
# A failing vendor feed does NOT stop the run: collect.py isolates each
# collector, the rollups still run on whatever did arrive, and this script
# exits non-zero at the end so cron mail / monitoring still notices.
# Feed health is also visible on the dashboards (Data freshness panel).

cd "$(dirname "$0")"
source venv/bin/activate
mkdir -p logs

exec 9>logs/.collector.lock
if ! flock -n 9; then
    echo "[$(date -Iseconds)] previous run still going -- skipping"
    exit 0
fi

echo "[$(date -Iseconds)] ===== collector run start ====="
rc=0

# Enrichment catalogs first so today's rollup uses today's KEV/EPSS.
python3 kev_sync.py --config config.yaml   || rc=1
python3 epss_sync.py --config config.yaml  || rc=1

# All enabled collectors (config.yaml `collectors:`), in dependency order.
python3 collect.py --config config.yaml    || rc=1

# NVD CVSS backfill for CVEs the vendor didn't score (rate-limited, capped per run).
python3 nvd_enrich.py --config config.yaml || rc=1

# Daily snapshots for every domain -- runs even if a collector failed.
python3 rollup_daily_metrics.py --config config.yaml || rc=1

# Keep product families tidy after product_groups.yaml rule changes.
python3 reclassify_product_families.py --config config.yaml || rc=1

echo "[$(date -Iseconds)] ===== collector run end (rc=$rc) ====="
exit $rc
