# Privex Disaster Recovery (PVX-01)

Baseline durability for the account-critical data. This covers **what is backed
up, why the scope is what it is, and the tested restore procedure.** The
backup/restore mechanics below were validated end-to-end with a real
kill-the-volume drill (see "Drill", last section).

## What is protected

Only the durable, **account-critical LOGGED** tables — losing any of these is
unrecoverable for users:

| Table | Loss impact |
|---|---|
| `key_directory` | Every identity (px_id → public keys). **Total account loss.** |
| `opaque_records` | OPAQUE password-recovery envelopes. |
| `recovery_shares` | Encrypted Shamir social-recovery shares. |
| `history_blobs` | Opt-in server-side encrypted history (user data). |

The dump contains only ciphertext blobs and pseudonymous `px_` ids — never
names, IPs, or plaintext — and is encrypted at rest with gpg (AES-256), so it
preserves the no-plaintext posture even off-host.

## What is deliberately NOT backed up (and why)

- **All UNLOGGED tables** (`message_queue`, `blob_index`, `kt_log`,
  `group_state`, `pow_challenges`): transient by design, truncated on crash,
  re-derived by clients. Backing them up would be pointless and racy.
- **`one_time_prekeys`**: ephemeral **single-use** inventory. Restoring stale
  OPKs risks handing out a prekey already consumed after the snapshot (OPK
  reuse, weakening the first message's forward secrecy). Clients replenish
  automatically and the server falls back to no-OPK 3-DH, so loss is benign.
- **`relay_nodes`**: operational directory, re-seedable from ops config, no PII.
- **`_sqlx_migrations`**: intentionally rebuilt by the migrator, **not** restored
  from backup. Restoring a "fully applied" ledger next to only these four tables
  would make the migrator believe the schema is complete and **skip creating the
  UNLOGGED tables** — leaving a broken database. Schema always comes from
  `privex-server migrate`; the backup only carries table data.

## Backup

```
BACKUP_GPG_PASSPHRASE_FILE=/etc/privex/backup.pass \
  bash infra/scripts/backup.sh
```

- Writes `backups/privex-<UTC>.dump.gpg` (`pg_dump -Fc` streamed through gpg;
  the plaintext dump never touches disk).
- Prunes local copies older than `BACKUP_RETENTION_DAYS` (default 14).
- **You must ship the file off-host** (rclone/rsync lines in the script). A
  same-host backup does not survive disk loss. Schedule via cron, e.g.:
  ```
  17 3 * * *  BACKUP_GPG_PASSPHRASE_FILE=/etc/privex/backup.pass bash /home/sonix/Privex/infra/scripts/backup.sh >> /var/log/privex-backup.log 2>&1
  ```
  (`/var/log` is tmpfs per §8.4 — send the log off-host too if you want history.)

Keep the passphrase file (`0600`, root-only) **off** the database host — a backup
you can't decrypt after losing the host is not a backup.

## Restore (tested procedure)

The safe order rebuilds the **schema** first, then loads **data**:

1. Bring up a fresh/empty Postgres volume.
2. Apply migrations — this creates the full schema **and** the correct
   `_sqlx_migrations` ledger:
   ```
   privex-server migrate        # production (see PVX-05)
   ```
3. Load the account data from the encrypted backup:
   ```
   BACKUP_GPG_PASSPHRASE_FILE=/etc/privex/backup.pass \
     bash infra/scripts/restore.sh backups/privex-<UTC>.dump.gpg
   ```
   `restore.sh` refuses to run if the schema is missing (guards against a silent
   empty restore) and uses `pg_restore --data-only --disable-triggers` so FK
   order doesn't matter.
4. **Verify**: an existing account authenticates (`POST /auth/challenge` →
   `/auth/verify`) and OPAQUE recovery (`/recovery/opaque/init` → `/complete`)
   succeeds.

### RPO / RTO

- **RPO**: up to one backup interval (nightly ⇒ ≤24h of new registrations /
  recovery-envelope changes). Tighten with a more frequent cron or opt-in PITR
  (see `infra/postgres/postgresql.conf`).
- **RTO**: minutes — fresh volume + migrate + `pg_restore` of small tables.

## Optional: streaming replication + PITR

For a hot standby and point-in-time recovery, flip the commented block in
`infra/postgres/postgresql.conf` (`wal_level=replica`, `archive_mode=on`,
`max_wal_senders`, an encrypted `archive_command`) and stand up a replica. The
WAL then holds only ciphertext + pseudonymous ids for the LOGGED tables, so it
does not violate the Four Laws. Do **not** enable archiving without a standby /
archive sink actually consuming the WAL, or it grows unbounded.

## Drill (how this was validated)

The exact `pg_dump -Fc | gpg` → destroy-volume → `migrate` →
`pg_restore --data-only` flow was run against an isolated throwaway Postgres:
seed a known account across all four tables → back up → `docker rm -f` the
container (simulating disk loss) → fresh empty DB → re-apply migrations →
restore. Result: all four tables restored **byte-identical**, and the UNLOGGED
tables (`message_queue`, `kt_log`) were correctly recreated by the migrator (not
present in the backup) — confirming the `_sqlx_migrations` exclusion above.

Re-run the drill on the deploy host before trusting it in production (the home
lab uses `docker compose exec`, which `backup.sh`/`restore.sh` already target).
