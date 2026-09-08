#!/usr/bin/env bash
# AntiGravity Postgres backup helper.
#
# Usage:
#   ./scripts/pg_backup.sh                 # writes to $BACKUP_DIR/antigravity_<ts>.dump
#   ./scripts/pg_backup.sh --verify        # ALSO restores into a scratch DB and drops it
#   ./scripts/pg_backup.sh --list          # lists retained backups
#   ./scripts/pg_backup.sh --restore FILE  # restore a specific dump into a fresh DB
#
# Retention: keeps the newest $BACKUP_RETAIN dumps under $BACKUP_DIR (default 30).
#
# Env:
#   POSTGRES_HOST     (required if not in .env)
#   POSTGRES_PORT     default 5432
#   POSTGRES_DB       required
#   POSTGRES_USER     required
#   POSTGRES_PASSWORD required
#   BACKUP_DIR        default /var/backups/antigravity
#   BACKUP_RETAIN     default 30
#
# Suggested cron (daily 03:15):
#   15 3 * * *  /opt/antigravity/scripts/pg_backup.sh >> /var/log/antigravity-backup.log 2>&1

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load .env so operators don't have to export env vars manually.
if [ -f "$REPO_ROOT/.env" ]; then
    # shellcheck disable=SC1091
    set -a
    . "$REPO_ROOT/.env"
    set +a
fi

: "${POSTGRES_HOST:?POSTGRES_HOST is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
: "${POSTGRES_PORT:=5432}"
: "${BACKUP_DIR:=/var/backups/antigravity}"
: "${BACKUP_RETAIN:=30}"

mkdir -p "$BACKUP_DIR"
export PGPASSWORD="$POSTGRES_PASSWORD"

case "${1:-}" in
    --list)
        ls -1t "$BACKUP_DIR"/antigravity_*.dump 2>/dev/null || echo "no backups"
        exit 0
        ;;
    --restore)
        DUMP="${2:?path to dump required}"
        [ -f "$DUMP" ] || { echo "dump not found: $DUMP" >&2; exit 2; }
        FRESH_DB="${POSTGRES_DB}_restore_$(date +%s)"
        echo "→ creating scratch db $FRESH_DB"
        createdb -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" "$FRESH_DB"
        echo "→ restoring $DUMP into $FRESH_DB"
        pg_restore -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" \
            -d "$FRESH_DB" --clean --if-exists --jobs=4 "$DUMP"
        echo "✓ restore complete."
        echo "  Inspect with: PGPASSWORD='***' psql -h $POSTGRES_HOST -U $POSTGRES_USER -d $FRESH_DB"
        echo "  Drop with:    PGPASSWORD='***' dropdb -h $POSTGRES_HOST -U $POSTGRES_USER $FRESH_DB"
        exit 0
        ;;
esac

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$BACKUP_DIR/antigravity_${TS}.dump"

echo "→ dumping $POSTGRES_DB to $OUT"
pg_dump -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" \
    --format=custom --compress=9 --jobs=1 \
    --file="$OUT" "$POSTGRES_DB"
SIZE="$(du -h "$OUT" | awk '{print $1}')"
echo "✓ dump complete ($SIZE)"

if [ "${1:-}" = "--verify" ]; then
    FRESH_DB="${POSTGRES_DB}_verify_$(date +%s)"
    echo "→ verifying restore into scratch db $FRESH_DB"
    createdb -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" "$FRESH_DB"
    pg_restore -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" \
        -d "$FRESH_DB" --clean --if-exists --jobs=4 "$OUT"
    dropdb -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" "$FRESH_DB"
    echo "✓ verified"
fi

# Retention pruning
BACKUPS=("$BACKUP_DIR"/antigravity_*.dump)
COUNT=${#BACKUPS[@]}
if [ "$COUNT" -gt "$BACKUP_RETAIN" ]; then
    echo "→ pruning $((COUNT - BACKUP_RETAIN)) old backup(s)"
    ls -1t "$BACKUP_DIR"/antigravity_*.dump | tail -n +$((BACKUP_RETAIN + 1)) | xargs -r rm --
fi

echo "✓ done"
