#!/bin/bash
set -euo pipefail

# backup.sh -- nightly pg_dump of the dashboard database (custom format,
# compressed; restore with pg_restore), keeping the last KEEP_DAYS days.
# Scheduled in crontab.example after the nightly collection.
#
# Same password-free auth as maintenance.sh: a ~/.pgpass line
#   127.0.0.1:5432:secops_dashboard:secops_user:yourpassword
#
# These dumps sit on the same disk as the database: they cover "dropped a
# table / bad migration", not "lost the VM". Copy them off the box (VM backup,
# NAS) for that.

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$APP_DIR/backups}"
KEEP_DAYS="${KEEP_DAYS:-7}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_NAME="${DB_NAME:-secops_dashboard}"
DB_USER="${DB_USER:-secops_user}"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
OUT="$BACKUP_DIR/${DB_NAME}-$(date +%Y%m%d-%H%M).dump"

echo "[$(date -Iseconds)] backup start -> $OUT"
pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -Fc -Z 6 -f "$OUT.partial"
mv "$OUT.partial" "$OUT"
echo "[$(date -Iseconds)] backup done ($(du -h "$OUT" | cut -f1))"

find "$BACKUP_DIR" -maxdepth 1 -name "${DB_NAME}-*.dump" -mtime +"$KEEP_DAYS" -print -delete
find "$BACKUP_DIR" -maxdepth 1 -name "*.partial" -mtime +1 -delete
