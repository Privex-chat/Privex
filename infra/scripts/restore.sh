#!/usr/bin/env bash
# Privex restore from an encrypted backup (PVX-01). Companion to backup.sh.
#
# SAFE PATH (default): rebuild the SCHEMA with the migrator first, then load only
# the account tables' DATA. We do NOT restore schema/ledger from the backup,
# because the backup holds only 4 tables - loading its (partial) state before the
# migrator runs, or restoring a "fully applied" _sqlx_migrations, would leave the
# UNLOGGED tables (message_queue, kt_log, ...) uncreated. See DISASTER_RECOVERY.md.
#
# Order:
#   1. Fresh/empty Postgres volume is up.
#   2. Migrations applied (schema + _sqlx_migrations) - run BEFORE this script:
#        privex-server migrate         (production)
#        or: bash infra/scripts/deploy.sh up to the migrate step.
#   3. This script: decrypt + `pg_restore --data-only` the account tables.
#
# Usage:
#   BACKUP_GPG_PASSPHRASE_FILE=/etc/privex/backup.pass \
#     bash infra/scripts/restore.sh backups/privex-YYYY...Z.dump.gpg
set -euo pipefail

BACKUP_FILE="${1:?usage: restore.sh <backup.dump.gpg>}"
PRIVEX_HOME="${PRIVEX_HOME:-/home/sonix/Privex}"
COMPOSE=(docker compose -f "${PRIVEX_HOME}/infra/docker-compose.yml")
PGUSER="${POSTGRES_USER:-privex}"
PGDB="${POSTGRES_DB:-privex}"

: "${BACKUP_GPG_PASSPHRASE_FILE:?set BACKUP_GPG_PASSPHRASE_FILE to the backup passphrase file}"
[[ -r "$BACKUP_FILE" ]] || { echo "ERROR: cannot read $BACKUP_FILE" >&2; exit 1; }

# Guard: the schema must already exist (migrator ran). Bail loudly otherwise so we
# don't silently produce an empty restore.
if ! "${COMPOSE[@]}" exec -T postgres \
      psql -U "$PGUSER" -d "$PGDB" -tAc "SELECT to_regclass('public.key_directory')" \
      | grep -q key_directory; then
  echo "ERROR: key_directory table is missing - run migrations first (privex-server migrate)." >&2
  exit 1
fi

# Decrypt and stream straight into pg_restore --data-only (the plaintext dump
# never touches disk). Triggers disabled so FK-referencing rows
# (opaque_records/recovery_shares/history_blobs -> key_directory) load regardless
# of order. Requires superuser (the privex owner). Verified end-to-end by the
# kill-the-volume drill in DISASTER_RECOVERY.md.
gpg --batch --yes --pinentry-mode loopback --decrypt \
    --passphrase-file "$BACKUP_GPG_PASSPHRASE_FILE" "$BACKUP_FILE" \
  | "${COMPOSE[@]}" exec -T postgres \
      pg_restore -U "$PGUSER" -d "$PGDB" --data-only --disable-triggers --no-owner

echo "restore: loaded account tables from $BACKUP_FILE"
echo "VERIFY: an existing account can authenticate and run OPAQUE recovery."
