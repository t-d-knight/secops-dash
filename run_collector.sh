#!/bin/bash
set -uo pipefail

# run_collector.sh -- nightly pipeline. Cron example (runs from wherever the repo lives):
#   0 1 * * * /opt/secops-dashboard/run_collector.sh >> /opt/secops-dashboard/logs/collector.log 2>&1
#
# A failing vendor feed does NOT stop the run: collect.py isolates each
# collector, the rollups still run on whatever did arrive, and this script
# exits non-zero at the end so cron mail / monitoring still notices.
# Feed health is also visible on the dashboards (Data freshness panel), and
# notify.py sends a Pushover alert if anything needs a look (config `notify:`).
#
# --catch-up (cron, mid-morning): finish today's pipeline if the night run was
# cut short -- power loss, a Postgres restart, a reboot. Each stage records
# the date it finished in logs/.stage-<name>; catch-up re-runs only the stages
# without today's date, and does nothing if they all have it. It waits for
# the lock, so a night run that's still going finishes first.
#   0 10 * * * /opt/secops-dashboard/run_collector.sh --catch-up >> /opt/secops-dashboard/logs/collector.log 2>&1

cd "$(dirname "$0")"
source venv/bin/activate
mkdir -p logs

mode="${1:-}"
exec 9>logs/.collector.lock
if [[ "$mode" == "--catch-up" ]]; then
    flock -w 43200 9 || exit 0
elif ! flock -n 9; then
    echo "[$(date -Iseconds)] previous run still going -- skipping"
    python3 notify.py --config config.yaml run-skipped
    exit 0
fi

today="$(date +%F)"
STAGES=(kev epss collect nvd rollup reclassify impact)
stage_done() { [[ "$(cat "logs/.stage-$1" 2>/dev/null)" == "$today" ]]; }

# Collectors whose latest run today failed (e.g. a vendor API dropping out mid-pull).
failed_today() {
    python3 - <<'PY'
import datetime as dt, sys
from config import load_config
from db import pg_connect
cur = pg_connect(load_config("config.yaml")).cursor()
cur.execute("""SELECT DISTINCT ON (collector) collector, status FROM collector_runs
               WHERE started_at::date = %s ORDER BY collector, started_at DESC""", (dt.date.today(),))
print(",".join(c for c, s in cur.fetchall() if s not in ("ok", "partial")))
PY
}

if [[ "$mode" == "--catch-up" ]]; then
    todo=()
    for s in "${STAGES[@]}"; do stage_done "$s" || todo+=("$s"); done
    retry=""
    stage_done collect && retry="$(failed_today 2>/dev/null)"
    [[ ${#todo[@]} -eq 0 && -z "$retry" ]] && exit 0     # night run finished cleanly: nothing to log
fi

started="$(date -Iseconds)"
if [[ "$mode" == "--catch-up" ]]; then
    echo "[$started] ===== catch-up run start (unfinished: ${todo[*]:-none}; failed collectors: ${retry:-none}) ====="
else
    echo "[$started] ===== collector run start ====="
fi
python3 notify.py --config config.yaml run-start
rc=0

# stage NAME MARK CMD...: run CMD unless catching up and NAME already finished
# today. MARK=done records NAME as finished whenever CMD exits by itself (a
# vendor feed failing isn't worth re-pulling everything for); MARK=ok only when
# it succeeds (a rollup that died with the database is re-run).
stage() {
    local name="$1" mark="$2" r; shift 2
    if [[ "$mode" == "--catch-up" ]] && stage_done "$name"; then return 0; fi
    "$@"; r=$?
    if [[ $r -eq 0 || ( "$mark" == "done" && $r -lt 128 ) ]]; then echo "$today" > "logs/.stage-$name"; fi
    [[ $r -eq 0 ]] || rc=1
}

# Catch-up: re-pull collectors that failed overnight; if that works, the rollup and
# impact stages run again on the fresh data.
if [[ -n "${retry:-}" ]]; then
    if python3 collect.py --config config.yaml --only "$retry"; then
        rm -f logs/.stage-rollup logs/.stage-reclassify logs/.stage-impact
    else
        rc=1
    fi
fi

# Enrichment catalogs first so today's rollup uses today's KEV/EPSS.
stage kev  done python3 kev_sync.py --config config.yaml
stage epss done python3 epss_sync.py --config config.yaml

# All enabled collectors (config.yaml `collectors:`), in dependency order.
stage collect done python3 collect.py --config config.yaml

# NVD CVSS backfill for CVEs the vendor didn't score (rate-limited, capped per run).
stage nvd done python3 nvd_enrich.py --config config.yaml

# Daily snapshots for every domain -- runs even if a collector failed.
stage rollup ok python3 rollup_daily_metrics.py --config config.yaml

# Keep product families tidy after product_groups.yaml rule changes.
stage reclassify ok python3 reclassify_product_families.py --config config.yaml

# Programme impact: today's impact metrics, Patch Tuesday cohorts, the action log.
stage impact ok python3 impact.py --config config.yaml

# New identity / OverWatch detections since the last digest (one Pushover message,
# nothing if none). Remembers what it sent, so a catch-up run doesn't repeat it.
python3 notify.py --config config.yaml identity-digest

label="collector"; [[ "$mode" == "--catch-up" ]] && label="catch-up"
echo "[$(date -Iseconds)] ===== $label run end (rc=$rc) ====="
python3 notify.py --config config.yaml run-end --rc "$rc" --started "$started"
exit $rc
