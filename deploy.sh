#!/bin/bash
set -euo pipefail

# deploy.sh -- update this install to the latest origin/main and check it
# still works. Run as the service account (not root) from the app dir.
#
#   ./deploy.sh                          # pull, apply, check
#   ./deploy.sh --check                  # just the checks, no pull
#   ./deploy.sh --collect dmarc          # ...and run these collectors as a live test
#   ./deploy.sh --force                  # overwrite local edits to tracked files (backed up first)
#
# First run on a copy that isn't a git checkout (e.g. one unpacked by
# migrate_restore.sh): give the repo URL once and it becomes `origin`:
#   DEPLOY_REPO=https://github.com/<owner>/<repo> ./deploy.sh
#
# Holds logs/.collector.lock throughout, so it never lands mid-run: if the
# nightly collection is going it stops; cron jobs started meanwhile wait.
# config.yaml, secrets.yaml, venv/, logs/, reports/ and backups/ are
# untracked and never touched. Tracked files that differ from the deployed
# commit are copied to backups/deploy-<ts>.tar before being replaced.

# Braced so bash reads the whole script before running it: the pull below
# replaces this file.
{
cd "$(dirname "$0")"
CHECK_ONLY=0; FORCE=0; COLLECT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --check)   CHECK_ONLY=1 ;;
        --force)   FORCE=1 ;;
        --collect) COLLECT="${2:?--collect needs collector names}"; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done
die() { echo "!! $*" >&2; exit 1; }
[ "$(id -u)" -ne 0 ] || die "run as the service account, not root"
[ -x venv/bin/python3 ] && [ -f config.yaml ] || die "run from the app dir (needs venv/ and config.yaml)"
PY=venv/bin/python3
TS="$(date +%Y%m%d-%H%M%S)"

mkdir -p logs backups
exec 9>logs/.collector.lock
flock -n 9 || die "the collector lock is held (nightly run or a report going) -- try again later"

if [ "$CHECK_ONLY" -eq 0 ]; then
    echo "=== [1/4] Fetch origin/main ==="
    if [ ! -d .git ]; then
        [ -n "${DEPLOY_REPO:-}" ] || die "not a git checkout yet -- run once with DEPLOY_REPO=<repo url>"
        git init -q -b main
        git remote add origin "$DEPLOY_REPO"
        PREV=""
    else
        PREV="$(git rev-parse HEAD)"
    fi
    timeout 120 git fetch -q origin main || die "can't fetch from $(git remote get-url origin) -- no route to it?"
    NEW="$(git rev-parse origin/main)"

    # what's on disk now but differs from the commit we're about to deploy
    if [ -z "$PREV" ]; then
        git reset -q origin/main            # index only: the working tree stays as unpacked
        CHANGED="$(git diff --name-only)"
    else
        CHANGED="$(git diff --name-only HEAD)"
        if [ -n "$CHANGED" ] && [ "$FORCE" -eq 0 ]; then
            echo "$CHANGED" | sed 's/^/   /'
            die "tracked files edited locally (above) -- commit them upstream, or --force to back up and overwrite"
        fi
    fi
    if [ -n "$CHANGED" ]; then
        echo "$CHANGED" | while read -r f; do [ -e "$f" ] && echo "$f"; done \
            | tar -cf "backups/deploy-$TS.tar" -T -
        echo "   $(echo "$CHANGED" | wc -l | tr -d ' ') file(s) differing from origin/main saved to backups/deploy-$TS.tar"
    fi

    echo
    echo "=== [2/4] Apply ${PREV:0:7}${PREV:+ -> }${NEW:0:7} ==="
    if [ "$PREV" = "$NEW" ] && [ -z "$CHANGED" ]; then
        echo "   already up to date"
    else
        [ -n "$PREV" ] && git --no-pager log --oneline "$PREV..$NEW" | sed 's/^/   /'
        git reset -q --hard origin/main
        changed() { [ -z "$PREV" ] || ! git diff --quiet "$PREV" "$NEW" -- "$@"; }
        if changed requirements.txt; then
            echo "   requirements.txt changed: pip install"
            venv/bin/pip install -q -r requirements.txt
        fi
        echo "   schema"
        $PY -c "import config, db_schema; db_schema.ensure_schema(config.load_config('config.yaml'))"
        if changed 'grafana/*.json'; then
            echo "   dashboards changed: push to Grafana"
            $PY grafana/push_dashboards.py --config config.yaml --message "deploy.sh ${NEW:0:7}" \
                || echo "!! dashboard push failed -- push by hand: grafana/push_dashboards.py"
        fi
        if changed crontab.example; then
            echo "!! crontab.example changed -- review it against \`crontab -l\` (not installed automatically)"
        fi
    fi
fi

echo
echo "=== [3/4] Checks ==="
FAIL=0
step() { local name="$1"; shift; if "$@" > "logs/.deploy-step.log" 2>&1; then echo "   ok    $name";
         else echo "   FAIL  $name"; sed 's/^/         /' logs/.deploy-step.log | tail -15; FAIL=1; fi; }
step "python compiles"   $PY -m compileall -q -x '/(venv|archive|__pycache__)/' .
step "config + collector imports" $PY collect.py --config config.yaml --list
step "database + dashboard preflight" $PY grafana/preflight_check.py --config config.yaml
$PY - <<'EOF' || FAIL=1
import config, db, notify
cfg = config.load_config("config.yaml")
conn = db.pg_connect(cfg)
try:
    quiet = notify.quiet_feeds(cfg, conn.cursor(), set())
finally:
    conn.close()
print("   ok    feeds have recent data" if not quiet else "   WARN  " + "\n         ".join(l for _, l in quiet))
EOF
if [ -n "$COLLECT" ]; then
    step "collect $COLLECT" $PY collect.py --config config.yaml --only "$COLLECT"
fi
rm -f logs/.deploy-step.log

echo
echo "=== [4/4] Summary ==="
echo "   at $(git rev-parse --short HEAD 2>/dev/null || echo '(not a git checkout)'): $(git log -1 --format=%s 2>/dev/null)"
if [ "$CHECK_ONLY" -eq 0 ]; then
    if [ -n "${PREV:-}" ] && [ "$PREV" != "$NEW" ]; then
        echo "   roll back: git reset --hard ${PREV:0:7} && ./deploy.sh --check"
    elif [ -n "${CHANGED:-}" ]; then
        echo "   roll back: tar -xf backups/deploy-$TS.tar && ./deploy.sh --check"
    fi
fi
[ "$FAIL" -eq 0 ] && echo "   all checks passed" || { echo "!! some checks failed (above)"; exit 1; }
exit 0
}
