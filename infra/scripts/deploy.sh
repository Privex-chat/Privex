#!/usr/bin/env bash
# Privex Deployment Script (Phase 1 — Web App)
# Run on the home-lab server after git pull.
# Usage: bash infra/scripts/deploy.sh
set -euo pipefail

PRIVEX_HOME="${PRIVEX_HOME:-/home/sonix/Privex}"
cd "$PRIVEX_HOME"

echo "=== Privex Deployment ==="
echo "Home: $PRIVEX_HOME"
echo ""

if [[ ! -f .env ]]; then
  echo "ERROR: .env not found at $PRIVEX_HOME/.env"
  echo ""
  echo "First-time setup:"
  echo "  1. bash infra/scripts/generate-credentials.sh > .env"
  exit 1
fi
set -a; source .env; set +a

# ── 1. Pull latest code ──
echo "[1/9] Pulling latest code..."
git pull

# ── 2. Docker: start infrastructure ──
echo "[2/9] Starting Docker stack (PostgreSQL, Redis, MinIO)..."
docker compose -f infra/docker-compose.yml --env-file .env up -d

echo "  Waiting for PostgreSQL..."
for i in $(seq 1 30); do
  if pg_isready -h 127.0.0.1 -p 5432 -U privex -d privex -q 2>/dev/null; then
    echo "  PostgreSQL ready"; break
  fi
  sleep 1
done

echo "  Waiting for MinIO..."
for i in $(seq 1 15); do
  if curl -s -o /dev/null http://127.0.0.1:9000/minio/health/live; then
    echo "  MinIO ready"; break
  fi
  sleep 1
done

BUCKET="${R2_BUCKET:-privex-files}"
echo "  Creating MinIO bucket '${BUCKET}'..."
docker compose -f infra/docker-compose.yml exec -T minio \
  mc alias set local http://localhost:9000 "${R2_ACCESS_KEY:-privex}" "${R2_SECRET_KEY:-privexprivex}"
docker compose -f infra/docker-compose.yml exec -T minio \
  mc mb "local/${BUCKET}" --ignore-existing 2>/dev/null || true

# ── 3. Apply database migrations ──
echo "[3/9] Applying database migrations..."
for f in server/migrations/*.sql; do
  echo "  Running $(basename "$f")..."
  docker compose -f infra/docker-compose.yml exec -T postgres \
    psql -U privex -d privex -q -f - < "$f"
done

# ── 4. Install frontend dependencies ──
echo "[4/9] Installing frontend dependencies..."
pnpm install --frozen-lockfile

# ── 5. Build Rust backend (includes helper binaries) ──
echo "[5/9] Building Rust server..."
cd server
cargo build --release --bin privex-server --bin gen_opaque_setup --bin derive_pubkeys
cd "$PRIVEX_HOME"

# ── 6. Derive KT + TIME signing public keys for the frontend build ──
echo "[6/9] Deriving signing public keys..."
eval "$(./server/target/release/derive_pubkeys)"

# ── 7. Build frontend with the correct pinned public keys ──
echo "[7/9] Building frontend..."
VITE_KT_SIGNING_PUB="${VITE_KT_SIGNING_PUB}" \
VITE_TIME_SIGNING_PUB="${VITE_TIME_SIGNING_PUB}" \
pnpm run build

# ── 8. Generate OPAQUE setup if missing ──
if [[ -z "${OPAQUE_SERVER_SETUP:-}" ]]; then
  echo "[8/9] Generating OPAQUE server setup..."
  OPAQUE_B64=$(./server/target/release/gen_opaque_setup 2>/dev/null)
  echo "OPAQUE_SERVER_SETUP=${OPAQUE_B64}" >> .env
  set -a; source .env; set +a
  echo "  OPAQUE setup written to .env"
else
  echo "[8/9] OPAQUE setup present — skipping"
fi

# ── 9. PM2 config + restart ──
echo "[9/9] Restarting PM2..."
cp infra/ecosystem.config.js ecosystem.config.js
pm2 startOrReload ecosystem.config.js --update-env

echo ""
echo "=== Deploy complete ==="
echo "Check logs:   pm2 logs privex-api --lines 20"
echo "Check health: curl -s http://127.0.0.1:8888/health"
