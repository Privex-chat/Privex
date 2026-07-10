# Privex HA & Failover (PVX-11)

Single points of failure today, what the K8s manifests already give you, and what
still needs a stateful-HA operator. Nothing here may enable Redis disk
persistence or add logs/identifiers — the Four Laws and §8.4/§8.5 still hold.

## Current SPOFs

| Component | State | Failure today |
|---|---|---|
| App server | stateless | Single process (PM2) — a crash is an outage until restart. |
| PostgreSQL | **durable** | Single instance/volume — covered for data loss by backups (PVX-01), but no automatic failover. |
| Redis | in-memory, no-persistence | Single instance — a restart drops all ephemeral state. |
| MinIO / object store | durable-ish | Single instance — encrypted chunks, 7-day TTL. |

## App tier — already HA via the manifests (PVX-03)

`deployment.yaml` runs `replicas: 3` with `maxUnavailable: 0`, a `PodDisruptionBudget`
(`minAvailable: 2`), and an HPA (3→10). The **readiness gate does the shedding**:
`/health/ready` returns 503 when Postgres, Redis, or the store is unreachable, so
K8s stops routing to a pod whose dependency is down instead of serving errors
(PVX-02). This is verified by the `readiness_returns_503_when_deps_down`
integration test — no cluster needed to trust that behaviour.

## PostgreSQL failover

The app tier being HA doesn't help if the single Postgres dies. Options, in order
of preference:

1. **Managed Postgres** (provider HA + PITR) — least ops, if the jurisdiction fits
   the threat model.
2. **CloudNativePG or Zalando postgres-operator** on the cluster: a primary + one
   or more hot standbys with automated failover. Turn on the streaming-replication
   block in `infra/postgres/postgresql.conf` (`wal_level=replica`, `archive_mode`,
   `max_wal_senders`). The WAL then carries only ciphertext + pseudonymous px_ids
   for the LOGGED tables (UNLOGGED tables never touch the WAL), so replication does
   not violate the Laws — same argument as migration 0012.
3. **Baseline (single node):** the nightly encrypted backup (PVX-01) bounds data
   loss to one backup interval. Not failover — recovery.

Whatever the topology, backups (PVX-01) stay mandatory: a replica protects against
node loss, not against a bad migration or an operator error propagated to the
standby.

## Redis failover — HA in RAM, never on disk

Redis is intentionally no-persistence (`save ""`, `appendonly no` — §8.5). A
restart drops:

- **session tokens** — accepted tradeoff (clients silently re-authenticate).
- **rate-limit counters / PoW pressure** — self-healing (briefly resets to
  baseline; §8.5.1 item 6).
- **in-flight OPAQUE login state** (`opq:` keys) — the one loss that isn't purely
  cosmetic: a recovery in the ~seconds between `/recovery/opaque/init` and
  `/complete` fails if Redis flips.

**This is transient, not data loss.** `login_id` is single-use; on failure the
client just re-runs `init` → `complete`. No envelope or key material is lost (those
live in Postgres). The correct client behaviour is already "retry recovery from
the start," and the server's record-tag check keeps a stale in-flight login from
minting a session after the record changes.

To make even that blip survivable **without enabling disk persistence**:

- **Redis Sentinel (or a Redis operator) with an in-RAM replica.** The replica
  holds the short-lived `opq:` key in memory; a failover promotes a replica that
  still has it. HA comes from in-memory replication, not from touching disk — the
  no-persistence posture is preserved.
- **Do NOT** turn on AOF/RDB to "remember" in-flight logins or abuse counters.
  That would write user-adjacent state to disk and defeat §8.4/§8.5. Persisting
  rate-limit/PoW counters is explicitly rejected (§8.5.1 item 6).

## Object store

MinIO can run distributed (erasure-coded) for HA, or use a managed S3-compatible
store in an acceptable jurisdiction. Chunks are E2E-encrypted and short-lived, so
availability — not confidentiality — is the only concern here.

## Validation status

- **Code-proven:** the readiness gate sheds a pod when a dependency is down
  (`readiness_returns_503_when_deps_down`); app-tier rollout/PDB/HPA are defined in
  `infra/k8s`.
- **Needs a cluster (deploy session):** stand up the Postgres and Redis HA
  operators, kill the primary of each, and confirm (a) automated failover, (b) the
  readiness gate drains app pods during the switch, and (c) an OPAQUE recovery
  interrupted by a Redis failover succeeds on client retry.
