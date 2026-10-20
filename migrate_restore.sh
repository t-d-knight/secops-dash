#!/bin/bash
set -euo pipefail

# migrate_restore.sh -- restore a migrate_export.sh bundle on a new box, putting
# every piece back at the path it had on the old one.
#
#   sudo bash <db>-migration-YYYYMMDD-HHMM.restore.sh <db>-migration-YYYYMMDD-HHMM.tar.gpg
#   sudo bash /opt/secops-dashboard/migrate_restore.sh --verify [app_dir]   # re-run the checks only
#
# Before running, install the packages from README "Install" and "Grafana":
# python3, postgresql-server (initialised and running), grafana and chromium.
# Don't clone the repo or create the database or roles; the bundle brings all
# of that. Building the venv needs PyPI. The vendor APIs, the SMB shares and
# Pushover are only needed for the checks at the end.
#
# After one confirmation it:
#   1. checks the .sha256 next to the bundle and decrypts it to a private temp dir
#   2. creates the service account if it's missing; app dir from the git
#      bundle, then config, secrets, reports, logs, etc. over it; rebuilds the venv
#   3. restores ~/.pgpass, and writes the crontab to logs/crontab-from-old-box.txt
#      (NOT installed -- install it once the checks pass)
#   4. Postgres: creates or updates the two app roles (old box's password hashes),
#      pg_restore --create, ANALYZE
#   5. Grafana: data and config dirs (and any cert files) back to their paths
#   6. checks (also --verify): DB login, ensure_schema(), row counts against the
#      old box, Grafana health, preflight_check.py, publish.py --dry-run
#      (must be 0 files), backup_offsite.py --check
#
# Nothing on this box is deleted. An existing app dir, Grafana dir or ~/.pgpass
# is renamed to *.pre-migration-<timestamp>; an existing database is renamed to
# <db>_pre_migration_<timestamp>.
#
# Env: TARGET_APP_DIR (default: the old box's path), STAGE_PARENT (/var/tmp,
# needs ~3x the bundle size), JOBS (pg_restore -j, 4), SKIP_GRAFANA=1.

[[ $EUID -eq 0 ]] || { echo "run as root: sudo bash $0 <bundle.tar.gpg>" >&2; exit 1; }
umask 077

ROWCOUNT_SQL="SELECT table_name, (xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I.%I', table_schema, table_name), false, true, '')))[1]::text FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1"

die() { echo "!! $*" >&2; exit 1; }
log() { echo "[$(date -Iseconds)] $*"; }
ask() { local a; read -r -p "$1 [y/N] " a </dev/tty; [[ $a == [yY]* ]]; }
as_app() { (cd "$APP_DIR" && sudo -u "$APP_USER" -H -- "$@"); }
as_pg() { (cd / && sudo -u postgres -- "$@"); }
app_psql() { as_app psql -h "$SRC_DB_HOST" -U "$SRC_DB_USER" -d "$SRC_DB_NAME" -X "$@"; }
grafana_version() {
    { grafana server -v 2>/dev/null || grafana-server -v 2>/dev/null; } | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
}

# ---------------------------------------------------------------------------
# Checks -- run at the end of a restore, or alone with --verify. Reads the old
# box's manifest and row counts from logs/migration/ (no secrets in either).
# ---------------------------------------------------------------------------
FAILS=0
check() {
    local name="$1"; shift
    echo
    log "check: $name"
    if "$@"; then echo "   ok"; else echo "!! $name: FAILED"; FAILS=$((FAILS + 1)); fi
}
check_login() {
    app_psql -Atc 'SELECT 1' >/dev/null && return 0
    echo "   $SRC_DB_USER can't log in to $SRC_DB_HOST with the ~/.pgpass password."
    echo "   Fedora's default pg_hba.conf uses ident for TCP connections. The old box's rules:"
    grep -vE '^\s*(#|$)' "$APP_DIR/logs/migration/pg_hba.conf" 2>/dev/null | sed 's/^/     /' || true
    echo "   Edit $(as_pg psql -XAtc 'SHOW hba_file') to match, run 'systemctl reload postgresql', then:"
    echo "     sudo bash $APP_DIR/migrate_restore.sh --verify $APP_DIR"
    return 1
}
check_schema() {
    as_app venv/bin/python3 -c 'from config import load_config; import db_schema; db_schema.ensure_schema(load_config("config.yaml"))'
}
check_rowcounts() {
    local now="$APP_DIR/logs/migration/rowcounts-here.tsv"
    app_psql -At -F $'\t' -c "$ROWCOUNT_SQL" > "$now"
    if diff "$APP_DIR/logs/migration/rowcounts.tsv" "$now" > /dev/null; then
        echo "   $(wc -l < "$now") tables, all counts match the old box"
        return 0
    fi
    echo "   differs from the old box (< old, > here):"
    diff "$APP_DIR/logs/migration/rowcounts.tsv" "$now" | grep '^[<>]' | sed 's/^/     /'
    return 1
}
check_grafana() {
    local url
    url="$(as_app venv/bin/python3 -c 'from config import load_config; print((load_config("config.yaml").get("grafana") or {}).get("url") or "http://127.0.0.1:3000")')"
    curl -fsS --max-time 10 "$url/api/health"
}
check_publish() {
    local out
    out="$(as_app venv/bin/python3 publish.py --config config.yaml --dry-run)" || return 1
    echo "$out" | tail -5 | sed 's/^/   /'
    echo "$out" | grep -q '^\[publish\] 0 file(s) to publish' && return 0
    echo "   publish-manifest.json didn't carry over -- the first publish would resend these"
    return 1
}

verify() {
    # shellcheck disable=SC1091
    source "$APP_DIR/logs/migration/manifest.env"
    APP_USER="$(stat -c %U "$APP_DIR")"
    check "database login as $SRC_DB_USER" check_login
    if [[ $FAILS -gt 0 ]]; then die "fix the login, then re-run --verify"; fi
    check "schema up to date (ensure_schema)" check_schema
    check "row counts vs old box" check_rowcounts
    if [[ ${SKIP_GRAFANA:-0} != 1 ]] && systemctl cat "$SRC_GRAFANA_SERVICE" >/dev/null 2>&1; then
        check "grafana health" check_grafana
    fi
    check "preflight (feeds, views)" as_app venv/bin/python3 grafana/preflight_check.py --config config.yaml
    check "publish dry run is empty" check_publish
    check "offsite backup share writable" as_app venv/bin/python3 backup_offsite.py --config config.yaml --check

    echo
    if [[ $FAILS -gt 0 ]]; then
        echo "$FAILS check(s) failed. Network checks (preflight feeds, offsite share) can fail until this box is"
        echo "allowed through to the vendor APIs and the NAS -- fix, then re-run --verify."
    else
        echo "All checks passed."
    fi
    cat <<EOF

Next:
  1. One feed by hand:   cd $APP_DIR && sudo -u $APP_USER venv/bin/python3 collect.py --config config.yaml --only <feed>
  2. Install the schedule (review it first):
                         crontab -u $APP_USER $APP_DIR/logs/crontab-from-old-box.txt
  3. Watch the first 01:00 run (logs/collector.log) and the 09:00 backup (logs/backup.log).
EOF
    [[ $FAILS -eq 0 ]]
}

if [[ ${1:-} == --verify ]]; then
    APP_DIR="$(cd "${2:-$(dirname "$0")}" && pwd)"
    [[ -f "$APP_DIR/logs/migration/manifest.env" ]] || die "$APP_DIR wasn't restored by this script (no logs/migration/manifest.env)"
    verify
    exit
fi

# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------
[[ $# -eq 1 && -f $1 ]] || { echo "usage: sudo bash $0 <bundle.tar.gpg>   |   --verify [app_dir]" >&2; exit 1; }
BUNDLE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
TS="$(date +%Y%m%d-%H%M%S)"
JOBS="${JOBS:-4}"
STAGE_PARENT="${STAGE_PARENT:-/var/tmp}"

for c in gpg git tar psql pg_restore vacuumdb python3 sha256sum curl systemctl sudo; do
    command -v "$c" >/dev/null || die "missing command: $c (README: Install)"
done

SUMS="${BUNDLE%.tar.gpg}.sha256"
if [[ -f $SUMS ]]; then
    log "checking $(basename "$SUMS")"
    (cd "$(dirname "$BUNDLE")" && grep -F "  $(basename "$BUNDLE")" "$SUMS" | sha256sum -c -) \
        || die "checksum mismatch -- the bundle was damaged in transfer; copy it again"
else
    log "no $(basename "$SUMS") next to the bundle -- skipping the checksum (gpg still verifies integrity)"
fi

need_kb=$(( $(stat -c %s "$BUNDLE") * 3 / 1024 ))
avail_kb=$(df -Pk "$STAGE_PARENT" | awk 'NR == 2 {print $4}')
(( avail_kb > need_kb )) || die "need ~$(( need_kb / 1024 )) MB free in $STAGE_PARENT (set STAGE_PARENT)"

read -r -s -p "Bundle passphrase: " PASS </dev/tty; echo
STAGE="$(mktemp -d "$STAGE_PARENT/secops-migration.XXXXXX")"
GF_STOPPED=0
cleanup() {
    rm -rf "$STAGE"
    if [[ $GF_STOPPED -eq 1 ]]; then echo "!! $SRC_GRAFANA_SERVICE was left stopped" >&2; fi
}
trap cleanup EXIT
log "decrypting"
gpg --batch --quiet --pinentry-mode loopback --passphrase-fd 3 -d "$BUNDLE" 3< <(printf '%s' "$PASS") \
    | tar -C "$STAGE" -xpf - || die "decrypt failed -- wrong passphrase or damaged file"
unset PASS
# shellcheck disable=SC1091
source "$STAGE/meta/manifest.env"

APP_USER="$SRC_APP_USER"
APP_DIR="${TARGET_APP_DIR:-$SRC_APP_DIR}"
HAVE_GF=0
if [[ -f "$STAGE/sys/grafana.tar" && ${SKIP_GRAFANA:-0} != 1 ]]; then HAVE_GF=1; fi

# --- preflight: refuse before changing anything ---
PG_NUM="$(as_pg psql -XAtc 'SHOW server_version_num' 2>/dev/null)" \
    || die "Postgres isn't running here (postgresql-setup --initdb && systemctl enable --now postgresql)"
(( PG_NUM / 10000 >= SRC_PG_VERSION_NUM / 10000 )) \
    || die "Postgres here ($PG_NUM) is older than the old box's ($SRC_PG_VERSION) -- pg_restore can't go backwards"
if [[ $HAVE_GF -eq 1 ]]; then
    systemctl cat "$SRC_GRAFANA_SERVICE" >/dev/null 2>&1 || die "Grafana isn't installed (README: Grafana), or set SKIP_GRAFANA=1"
    GF_HERE="$(grafana_version)"
    if [[ -n $SRC_GF_VERSION && -n $GF_HERE && "$(printf '%s\n' "$SRC_GF_VERSION" "$GF_HERE" | sort -V | head -1)" != "$SRC_GF_VERSION" ]]; then
        die "Grafana here ($GF_HERE) is older than the old box's ($SRC_GF_VERSION) -- grafana.db won't downgrade"
    fi
fi
if ! command -v chromium >/dev/null && ! command -v chromium-browser >/dev/null; then
    log "warning: chromium not found -- PDF reports will fail until it's installed"
fi
DB_EXISTS="$(as_pg psql -XAtc "SELECT 1 FROM pg_database WHERE datname = '$SRC_DB_NAME'")"
DB_ASIDE="${SRC_DB_NAME}_pre_migration_${TS//-/_}"

cat <<EOF

Bundle from $SRC_HOST, $SRC_DATE (commit ${SRC_GIT_HEAD:0:7}, Postgres $SRC_PG_VERSION, Grafana ${SRC_GF_VERSION:-none})
  service account  $APP_USER$(id "$APP_USER" >/dev/null 2>&1 || echo "  [will be created, home $SRC_APP_HOME]")
  app dir          $APP_DIR$([[ -e $APP_DIR ]] && echo "  [exists -> moved to $APP_DIR.pre-migration-$TS]")
  database         $SRC_DB_NAME, roles $SRC_DB_USER + $SRC_GRAFANA_DB_USER$([[ -n $DB_EXISTS ]] && echo "  [exists -> renamed $DB_ASIDE]")
  grafana          $([[ $HAVE_GF -eq 1 ]] && echo "$SRC_GRAFANA_DATA, $SRC_GRAFANA_ETC  [existing moved to *.pre-migration-$TS]" || echo "skipped")
  crontab          NOT installed -- written to $APP_DIR/logs/crontab-from-old-box.txt

EOF
ask "Restore?" || die "nothing changed"

# --- service account + app dir ---
if ! id "$APP_USER" >/dev/null 2>&1; then
    useradd -m -d "$SRC_APP_HOME" "$APP_USER"
    log "created user $APP_USER"
fi
APP_HOME="$(getent passwd "$APP_USER" | cut -d: -f6)"

if [[ -e $APP_DIR ]]; then mv "$APP_DIR" "$APP_DIR.pre-migration-$TS"; fi
mkdir -p "$(dirname "$APP_DIR")"
log "code -> $APP_DIR"
git clone -q "$STAGE/code/repo.bundle" "$APP_DIR"
if [[ -n $SRC_GIT_BRANCH ]]; then
    git -C "$APP_DIR" checkout -q -B "$SRC_GIT_BRANCH" "$SRC_GIT_HEAD"
else
    git -C "$APP_DIR" checkout -q --detach "$SRC_GIT_HEAD"
fi
if [[ -n $SRC_GIT_ORIGIN ]]; then git -C "$APP_DIR" remote set-url origin "$SRC_GIT_ORIGIN"; fi
if [[ -n $SRC_GIT_HOOKS_PATH ]]; then git -C "$APP_DIR" config core.hooksPath "$SRC_GIT_HOOKS_PATH"; fi

log "config, secrets, reports, logs and local files"
tar -C "$APP_DIR" -xpf "$STAGE/app/app.tar"
mkdir -p "$APP_DIR/backups" "$APP_DIR/logs/migration"
cp "$STAGE/meta/manifest.env" "$STAGE/meta/rowcounts.tsv" "$STAGE/ref/"* "$APP_DIR/logs/migration/"
sed "s#$SRC_APP_DIR#$APP_DIR#g" "$STAGE/home/crontab.txt" > "$APP_DIR/logs/crontab-from-old-box.txt"
chown -R "$APP_USER": "$APP_DIR"
chmod 700 "$APP_DIR/backups"
chmod 600 "$APP_DIR/secrets.yaml"

if [[ -f "$STAGE/home/pgpass" ]]; then
    if [[ -e "$APP_HOME/.pgpass" ]]; then mv "$APP_HOME/.pgpass" "$APP_HOME/.pgpass.pre-migration-$TS"; fi
    install -o "$APP_USER" -m 600 "$STAGE/home/pgpass" "$APP_HOME/.pgpass"
fi

# --- postgres ---
if [[ $HAVE_GF -eq 1 ]]; then
    systemctl stop "$SRC_GRAFANA_SERVICE"
    GF_STOPPED=1
fi
for r in "$SRC_DB_USER" "$SRC_GRAFANA_DB_USER"; do
    if [[ -z "$(as_pg psql -XAtc "SELECT 1 FROM pg_roles WHERE rolname = '$r'")" ]]; then
        grep -E "^CREATE ROLE $r;" "$STAGE/db/roles.sql" | as_pg psql -X -q -v ON_ERROR_STOP=1
    fi
done
grep -E '^ALTER ROLE ' "$STAGE/db/roles.sql" | as_pg psql -X -q -v ON_ERROR_STOP=1
log "roles $SRC_DB_USER, $SRC_GRAFANA_DB_USER in place (old box's passwords)"

if [[ -n $DB_EXISTS ]]; then
    as_pg psql -X -q -v ON_ERROR_STOP=1 -c "ALTER DATABASE \"$SRC_DB_NAME\" RENAME TO \"$DB_ASIDE\"" \
        || die "couldn't rename the existing $SRC_DB_NAME -- something is connected to it"
    log "existing database renamed to $DB_ASIDE"
fi
chmod 711 "$STAGE" "$STAGE/db"
chown postgres "$STAGE/db/$SRC_DB_NAME.dump"
log "restoring database (pg_restore -j $JOBS -- the big tables take a while)"
as_pg pg_restore --create --exit-on-error -j "$JOBS" -d postgres "$STAGE/db/$SRC_DB_NAME.dump"
log "analyzing"
as_pg vacuumdb -q --analyze-only -d "$SRC_DB_NAME"

# --- grafana ---
if [[ $HAVE_GF -eq 1 ]]; then
    log "grafana -> $SRC_GRAFANA_DATA, $SRC_GRAFANA_ETC"
    for d in "$SRC_GRAFANA_DATA" "$SRC_GRAFANA_ETC"; do
        if [[ -e $d ]]; then mv "$d" "$d.pre-migration-$TS"; fi
    done
    tar -C / --backup=simple --suffix=".pre-migration-$TS" -xpf "$STAGE/sys/grafana.tar"
    if command -v restorecon >/dev/null; then restorecon -R "$SRC_GRAFANA_DATA" "$SRC_GRAFANA_ETC"; fi
    systemctl enable -q --now "$SRC_GRAFANA_SERVICE"
    GF_STOPPED=0
    sleep 5
fi

# Last, so a PyPI problem leaves only this step to redo.
log "building venv"
as_app python3 -m venv venv
as_app venv/bin/pip install -q -r requirements.txt \
    || die "pip install failed -- needs PyPI (or a proxy in /etc/pip.conf). Everything else is restored: run
   cd $APP_DIR && sudo -u $APP_USER venv/bin/pip install -r requirements.txt
   sudo bash $APP_DIR/migrate_restore.sh --verify $APP_DIR"

log "restore done -- old box's pg_hba.conf, postgresql.conf and firewalld settings are in $APP_DIR/logs/migration/ for reference"
if [[ -s "$APP_DIR/logs/migration/firewalld.txt" ]]; then
    echo "   old box's firewalld ports/services:"
    grep -E '^\s*(services|ports):' "$APP_DIR/logs/migration/firewalld.txt" | sed 's/^/     /' || true
fi
verify
