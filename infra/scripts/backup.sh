#!/usr/bin/env bash
# Privex encrypted off-host backup (PVX-01).
#
# WHAT IS BACKED UP: only the durable, account-CRITICAL LOGGED tables. Losing any
# of these is unrecoverable for users, so they are the entire backup scope:
#   key_directory    - identities (px_id -> public keys). Loss = every account gone.
#   opaque_records   - OPAQUE password-recovery envelopes.
#   recovery_shares  - encrypted Shamir social-recovery shares.
#   history_blobs    - opt-in server-side encrypted history (user data).
#
# WHAT IS DELIBERATELY EXCLUDED (and why):
#   - All UNLOGGED tables (message_queue, blob_index, kt_log, group_state,
#     pow_challenges): transient by design, truncated on crash, re-derived by
#     clients. Backing them up would be pointless and racy.
#   - one_time_prekeys: ephemeral SINGLE-USE inventory. Restoring stale OPKs would
#     risk handing out a prekey already consumed after the snapshot (OPK reuse,
#     weakening the first message's forward secrecy). Clients replenish OPKs
#     automatically, and the server falls back to no-OPK 3-DH, so loss is benign.
#   - relay_nodes: operational directory, re-seedable from ops config, no PII.
#   - _sqlx_migrations: NOT backed up. The restore path rebuilds the schema (and
#     this ledger) with `privex-server migrate`; restoring a "fully applied"
#     ledger next to a partial table set would make the migrator skip creating the
#     UNLOGGED tables (see DISASTER_RECOVERY.md). Schema comes from the migrator.
#
# The dump is encrypted at rest with gpg (AES-256) so it preserves the
# no-plaintext posture even off-host. It contains only ciphertext blobs and
# pseudonymous px_ids - never names, IPs, or plaintext (same argument as
# server/migrations/0012_history_blobs.sql for putting these tables in the WAL).
#
# Usage:
#   BACKUP_GPG_PASSPHRASE_FILE=/etc/privex/backup.pass bash infra/scripts/backup.sh
# Then ship $BACKUP_DIR off-host (see the rclone/rsync line at the end).
set -euo pipefail

PRIVEX_HOME="${PRIVEX_HOME:-/home/sonix/Privex}"
COMPOSE=(docker compose -f "${PRIVEX_HOME}/infra/docker-compose.yml")
BACKUP_DIR="${BACKUP_DIR:-${PRIVEX_HOME}/backups}"
PGUSER="${POSTGRES_USER:-privex}"
PGDB="${POSTGRES_DB:-privex}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"

# Account-critical LOGGED tables ONLY (see header).
TABLES=(key_directory opaque_records recovery_shares history_blobs)

: "${BACKUP_GPG_PASSPHRASE_FILE:?set BACKUP_GPG_PASSPHRASE_FILE to a 0600 file holding the backup passphrase}"
if [[ ! -r "$BACKUP_GPG_PASSPHRASE_FILE" ]]; then
  echo "ERROR: cannot read BACKUP_GPG_PASSPHRASE_FILE=$BACKUP_GPG_PASSPHRASE_FILE" >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
ts="$(date -u +%Y%m%dT%H%M%SZ)"
out="${BACKUP_DIR}/privex-${ts}.dump.gpg"

dump_args=()
for t in "${TABLES[@]}"; do dump_args+=(-t "$t"); done

# pg_dump -Fc (custom, compressed, schema+data) so restore can be selective /
# data-only. Streamed straight into gpg - the plaintext dump never touches disk.
"${COMPOSE[@]}" exec -T postgres \
  pg_dump -U "$PGUSER" -d "$PGDB" -Fc --no-owner "${dump_args[@]}" \
  | gpg --batch --yes --pinentry-mode loopback --symmetric --cipher-algo AES256 \
        --passphrase-file "$BACKUP_GPG_PASSPHRASE_FILE" -o "$out"

echo "backup: wrote $out ($(du -h "$out" | cut -f1))"

# Prune local copies past the retention window (off-host copies retained per policy).
find "$BACKUP_DIR" -maxdepth 1 -name 'privex-*.dump.gpg' -mtime "+${RETENTION_DAYS}" -delete

# OFF-HOST COPY (required - a same-host backup does not survive disk loss).
# Configure ONE of these and uncomment; the file is already encrypted:
#   rclone copy "$out" "${BACKUP_REMOTE:?}"           # e.g. remote:privex-backups
#   rsync -e ssh "$out" "${BACKUP_SSH_DEST:?}"        # e.g. backups@offsite:/privex
echo "REMINDER: ship $out off-host (rclone/rsync) - a local-only backup is not a backup."
