#!/bin/bash
set -euo pipefail

# bootstrap.sh -- first run on a new box (or a full re-verify). Not the
# nightly job; see run_collector.sh for that.
#
#   ./bootstrap.sh                       # everything enabled in config.yaml
#   ./bootstrap.sh falcon_hosts,dmarc    # just these collectors, to bring feeds up one at a time

cd "$(dirname "$0")"
source venv/bin/activate

ONLY="${1:-}"

echo "=== [1/7] Which collectors are enabled ==="
python3 collect.py --config config.yaml --list

echo
echo "=== [2/7] CISA KEV catalog ==="
python3 kev_sync.py --config config.yaml

echo
echo "=== [3/7] EPSS scores ==="
python3 epss_sync.py --config config.yaml

echo
echo "=== [4/7] Collectors (first run pulls full lookback windows -- may take a while) ==="
if [ -n "$ONLY" ]; then
    python3 collect.py --config config.yaml --full --only "$ONLY" || echo "!! some collectors failed -- see above; continuing"
else
    python3 collect.py --config config.yaml --full || echo "!! some collectors failed -- see above; continuing"
fi

echo
echo "=== [5/7] NVD CVSS backfill (rate-limited, capped per run) ==="
python3 nvd_enrich.py --config config.yaml

echo
echo "=== [6/7] Rollups (dry-run preview, then write) ==="
python3 rollup_daily_metrics.py --config config.yaml --dry-run | head -50
python3 rollup_daily_metrics.py --config config.yaml

echo
echo "=== [7/7] Preflight ==="
python3 ./grafana/preflight_check.py --config config.yaml

echo
echo "Bootstrap complete. If preflight is all PASS, import grafana/*.json (README: Grafana)."
