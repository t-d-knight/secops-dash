#!/bin/bash
set -euo pipefail

# migrate_export.sh -- package everything a new box needs to take over from
# this one as a single passphrase-encrypted file. Restore it with
# migrate_restore.sh, which puts every piece back at the path it came from.
#
#   sudo ./migrate_export.sh
#
# Run as root on the old box: it reads the Postgres roles, Grafana's files and
# the service account's crontab. It holds logs/.collector.lock throughout, so
# nothing scheduled runs mid-export -- run it once the night run and the 10:00
# catch-up are done. It offers to remove the service account's crontab first,
# so the export is the old box's final state.
#
# The bundle holds:
#   - the database (pg_dump -Fc, as backup.sh) and the two app roles with their
#     password hashes (pg_dumpall --globals-only, filtered to DB_USER and
#     GRAFANA_DB_USER), so config.yaml / secrets.yaml / ~/.pgpass still match
#   - the code as a git bundle (every branch, unpushed commits included), so the
#     new box doesn't need to reach GitHub
#   - every untracked or ignored file in the app dir, plus uncommitted changes:
#     config.yaml, secrets.yaml, reports/, logs/ (publish-manifest.json and the
#     identity digest state -- without them the first run republishes every
#     report and re-alerts every identity) and local notes. venv/, backups/ and
#     __pycache__/ are left out; the venv is rebuilt.
#   - Grafana's data and config dirs, copied with Grafana stopped (grafana.db
#     holds the datasource, users and API tokens; grafana.ini's secret_key
#     decrypts them), plus any TLS cert files grafana.ini names
#   - the service account's ~/.pgpass and crontab
#   - pg_hba.conf, postgresql.conf and firewalld settings, for reference only
#   - a row count of every table, compared after the restore
#
# Output, next to the nightly dumps in $BACKUP_DIR, and copied to the offsite
# share as well when backup.offsite.enabled (backup_offsite.py never prunes
# these -- it only prunes *.dump):
#   <db>-migration-YYYYMMDD-HHMM.tar.gpg      the bundle (gpg symmetric, AES256)
#   <db>-migration-YYYYMMDD-HHMM.restore.sh   migrate_restore.sh, unencrypted
#   <db>-migration-YYYYMMDD-HHMM.sha256       checksums of both, for the transfer
#
# The bundle contains every credential the system uses. Keep the passphrase
# off the share (password manager), and delete the bundle once the new box is
# live.

[[ $EUID -eq 0 ]] || { echo "run as root: sudo $0" >&2; exit 1; }
umask 077

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_USER="${APP_USER:-$(stat -c %U "$APP_DIR")}"
BACKUP_DIR="${BACKUP_DIR:-$APP_DIR/backups}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_NAME="${DB_NAME:-secops_dashboard}"
DB_USER="${DB_USER:-secops_user}"
GRAFANA_DB_USER="${GRAFANA_DB_USER:-grafana_reader}"
GRAFANA_DATA="${GRAFANA_DATA:-/var/lib/grafana}"
GRAFANA_ETC="${GRAFANA_ETC:-/etc/grafana}"
GRAFANA_SERVICE="${GRAFANA_SERVICE:-grafana-server}"

# Exact row count of every table; migrate_restore.sh runs the same query.
ROWCOUNT_SQL="SELECT table_name, (xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I.%I', table_schema, table_name), false, true, '')))[1]::text FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1"

die() { echo "!! $*" >&2; exit 1; }
log() { echo "[$(date -Iseconds)] $*"; }
ask() { local a; read -r -p "$1 [y/N] " a </dev/tty; [[ $a == [yY]* ]]; }
as_app() { (cd "$APP_DIR" && sudo -u "$APP_USER" -H -- "$@"); }
as_pg() { (cd / && sudo -u postgres -- "$@"); }
git_app() { git -c safe.directory="$APP_DIR" -C "$APP_DIR" "$@"; }
app_psql() { as_app psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -X "$@"; }
grafana_version() {
    { grafana server -v 2>/dev/null || grafana-server -v 2>/dev/null; } | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true
}

for c in pg_dump pg_dumpall psql gpg git tar flock sha256sum; do
    command -v "$c" >/dev/null || die "missing command: $c"
done
[[ -f "$APP_DIR/config.yaml" && -f "$APP_DIR/secrets.yaml" ]] || die "no config.yaml / secrets.yaml in $APP_DIR"
[[ -f "$APP_DIR/migrate_restore.sh" ]] || die "migrate_restore.sh missing from $APP_DIR"
app_psql -Atc 'SELECT 1' >/dev/null || die "can't log in as $DB_USER (needs $APP_USER's ~/.pgpass, as backup.sh)"

exec 9>>"$APP_DIR/logs/.collector.lock"
flock -n 9 || die "logs/.collector.lock is held -- a collection or scheduled job is running; try again once it finishes"

TS="$(date +%Y%m%d-%H%M)"
BASE="${DB_NAME}-migration-$TS"
mkdir -p "$BACKUP_DIR"
chown "$APP_USER": "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
STAGE="$(mktemp -d "$BACKUP_DIR/.$BASE.XXXXXX")"
GF_STOPPED=0
cleanup() {
    rm -rf "$STAGE" "$BACKUP_DIR/$BASE.tar.gpg.partial"
    if [[ $GF_STOPPED -eq 1 ]]; then systemctl start "$GRAFANA_SERVICE" || true; fi
}
trap cleanup EXIT
mkdir -p "$STAGE"/{meta,db,code,app,sys,home,ref}

read -r -s -p "Passphrase for the bundle (min 12 chars): " PASS </dev/tty; echo
read -r -s -p "Again: " PASS2 </dev/tty; echo
[[ "$PASS" == "$PASS2" ]] || die "passphrases differ"
(( ${#PASS} >= 12 )) || die "use at least 12 characters"
unset PASS2

# --- crontab: saved first, then optionally removed so this box goes quiet ---
crontab -l -u "$APP_USER" > "$STAGE/home/crontab.txt" 2>/dev/null || : > "$STAGE/home/crontab.txt"
if [[ -s "$STAGE/home/crontab.txt" ]]; then
    install -o "$APP_USER" -m 600 "$STAGE/home/crontab.txt" "$BACKUP_DIR/crontab-$APP_USER-$TS.txt"
    if ask "Remove $APP_USER's crontab now, so this box stops collecting, publishing and alerting? (saved to backups/crontab-$APP_USER-$TS.txt)"; then
        crontab -r -u "$APP_USER"
        log "crontab removed -- put it back with: crontab -u $APP_USER $BACKUP_DIR/crontab-$APP_USER-$TS.txt"
    else
        log "crontab left in place -- this box keeps running its schedule after the export"
    fi
fi

# --- database ---
log "database dump ($DB_NAME)"
as_app pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -Fc -Z 6 > "$STAGE/db/$DB_NAME.dump"
app_psql -At -F $'\t' -c "$ROWCOUNT_SQL" > "$STAGE/meta/rowcounts.tsv"
log "dump done ($(du -h "$STAGE/db/$DB_NAME.dump" | cut -f1), $(wc -l < "$STAGE/meta/rowcounts.tsv") tables)"

as_pg pg_dumpall --globals-only \
    | grep -E "^(CREATE|ALTER) ROLE (${DB_USER}|${GRAFANA_DB_USER})( |;)" > "$STAGE/db/roles.sql" || true
for r in "$DB_USER" "$GRAFANA_DB_USER"; do
    grep -q "^CREATE ROLE $r;" "$STAGE/db/roles.sql" || die "role $r not found in Postgres (set DB_USER / GRAFANA_DB_USER)"
done

for s in hba_file config_file; do
    f="$(as_pg psql -XAtc "SHOW $s")"
    cp "$f" "$STAGE/ref/"
done
f="$(as_pg psql -XAtc 'SHOW data_directory')/postgresql.auto.conf"
if [[ -f $f ]]; then cp "$f" "$STAGE/ref/"; fi
if command -v firewall-cmd >/dev/null; then firewall-cmd --list-all > "$STAGE/ref/firewalld.txt" 2>&1 || true; fi

# --- code + local files ---
log "code (git bundle) and local files"
git_app bundle create "$STAGE/code/repo.bundle" --all
{
    git_app ls-files -o -z
    git_app diff --name-only -z --diff-filter=ACMRT HEAD
    printf '%s\0' .git/info/exclude
} | grep -zvE '^(venv|backups)/|(^|/)__pycache__/|\.pyc$|^logs/\.collector\.lock$|^logs/\.stage-' \
  | sort -zu > "$STAGE/meta/app-files.lst"
tar -C "$APP_DIR" --null -T "$STAGE/meta/app-files.lst" -cpf "$STAGE/app/app.tar"
log "local files: $(tr -cd '\0' < "$STAGE/meta/app-files.lst" | wc -c), $(du -h "$STAGE/app/app.tar" | cut -f1)"

APP_HOME="$(getent passwd "$APP_USER" | cut -d: -f6)"
if [[ -f "$APP_HOME/.pgpass" ]]; then cp -p "$APP_HOME/.pgpass" "$STAGE/home/pgpass"; fi

# --- grafana ---
GF_VERSION=""
if systemctl cat "$GRAFANA_SERVICE" >/dev/null 2>&1 && [[ -d $GRAFANA_DATA ]]; then
    GF_VERSION="$(grafana_version)"
    gf_paths=("${GRAFANA_DATA#/}" "${GRAFANA_ETC#/}")
    while read -r f; do
        if [[ -n $f && -f $f ]]; then gf_paths+=("${f#/}"); fi
    done < <(grep -hE '^\s*cert_(file|key)\s*=' "$GRAFANA_ETC/grafana.ini" 2>/dev/null | sed -E 's/^[^=]*=\s*//; s/\s+$//; s/^"(.*)"$/\1/')
    log "grafana $GF_VERSION: stopping for a consistent copy of grafana.db"
    systemctl stop "$GRAFANA_SERVICE"
    GF_STOPPED=1
    tar -C / -cpf "$STAGE/sys/grafana.tar" "${gf_paths[@]}"
    systemctl start "$GRAFANA_SERVICE"
    GF_STOPPED=0
    log "grafana copied ($(du -h "$STAGE/sys/grafana.tar" | cut -f1)) and restarted"
else
    log "no $GRAFANA_SERVICE here -- grafana skipped"
fi

# --- manifest: what the restore needs to put everything back where it was ---
SRC_APP_DIR="$APP_DIR"
HOST="$(hostname -f 2>/dev/null || hostname)"
DATE="$(date -Iseconds)"
GIT_HEAD="$(git_app rev-parse HEAD)"
GIT_BRANCH="$(git_app symbolic-ref --short -q HEAD || true)"
GIT_ORIGIN="$(git_app remote get-url origin 2>/dev/null || true)"
GIT_HOOKS_PATH="$(git_app config --local --get core.hooksPath || true)"
PG_VERSION_NUM="$(app_psql -Atc 'SHOW server_version_num')"
PG_VERSION="$(app_psql -Atc 'SHOW server_version')"
PY_VERSION="$("$APP_DIR/venv/bin/python3" -V 2>&1 || true)"
for v in HOST DATE APP_DIR APP_USER APP_HOME DB_HOST DB_NAME DB_USER GRAFANA_DB_USER \
         GRAFANA_DATA GRAFANA_ETC GRAFANA_SERVICE GF_VERSION GIT_HEAD GIT_BRANCH GIT_ORIGIN \
         GIT_HOOKS_PATH PG_VERSION_NUM PG_VERSION PY_VERSION; do
    printf 'SRC_%s=%q\n' "$v" "${!v}"
done > "$STAGE/meta/manifest.env"

# --- encrypt + hand-off files ---
OUT="$BACKUP_DIR/$BASE.tar.gpg"
log "encrypting -> $OUT"
tar -C "$STAGE" -cf - . \
    | gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-fd 3 \
          --symmetric --cipher-algo AES256 --s2k-digest-algo SHA512 --s2k-count 65011712 \
          --compress-algo none -o "$OUT.partial" 3< <(printf '%s' "$PASS")
unset PASS
mv "$OUT.partial" "$OUT"
cp "$APP_DIR/migrate_restore.sh" "$BACKUP_DIR/$BASE.restore.sh"
(cd "$BACKUP_DIR" && sha256sum "$BASE.tar.gpg" "$BASE.restore.sh" > "$BASE.sha256")
chown "$APP_USER": "$OUT" "$BACKUP_DIR/$BASE.restore.sh" "$BACKUP_DIR/$BASE.sha256"
chmod 600 "$OUT" "$BACKUP_DIR/$BASE.restore.sh" "$BACKUP_DIR/$BASE.sha256"
log "bundle done ($(du -h "$OUT" | cut -f1))"

offsite_ok=1
for f in "$BASE.tar.gpg" "$BASE.restore.sh" "$BASE.sha256"; do
    as_app venv/bin/python3 backup_offsite.py --config config.yaml "$BACKUP_DIR/$f" || offsite_ok=0
done

cat <<EOF

Export complete. Copy all three to the new box (same directory):
  $OUT
  $BACKUP_DIR/$BASE.restore.sh
  $BACKUP_DIR/$BASE.sha256
then, on the new box:
  sudo bash $BASE.restore.sh $BASE.tar.gpg
EOF
if [[ $offsite_ok -eq 0 ]]; then die "offsite copy failed -- the files above are still in $BACKUP_DIR; copy them by hand"; fi
