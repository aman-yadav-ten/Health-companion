#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_PATH="$ROOT_DIR/health_companion.db"
BACKUP_DIR="$ROOT_DIR/backups/db"
STAMP="$(date +%Y%m%d_%H%M%S)"
TARGET="$BACKUP_DIR/health_companion_${STAMP}.db"

mkdir -p "$BACKUP_DIR"

if [[ ! -f "$DB_PATH" ]]; then
  echo "Database not found at $DB_PATH" >&2
  exit 1
fi

cp "$DB_PATH" "$TARGET"

if [[ -f "${DB_PATH}-wal" ]]; then
  cp "${DB_PATH}-wal" "${TARGET}-wal"
fi

if [[ -f "${DB_PATH}-shm" ]]; then
  cp "${DB_PATH}-shm" "${TARGET}-shm"
fi

echo "Backup created: $TARGET"
