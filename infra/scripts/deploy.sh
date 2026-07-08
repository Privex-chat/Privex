#!/usr/bin/env bash
# =============================================================================
# Privex Deployment Script (Phase 1 — Web App)
# Run on the home-lab server after git pull.
# Usage: bash infra/scripts/deploy.sh
# =============================================================================
set -euo pipefail

PRIVEX_HOME="${PRIVEX_HOME:-/home/sonix/Privex}"
cd "$PRIVEX_HOME"

echo "=== Privex Deployment ==="
echo "Home: $PRIVEX_HOME"
echo ""

# ── 1. Verify .env exists ──
if [[ ! -f .env ]]; then
  echo "ERROR: .env not found at $PRIVEX_HOME/.env"
  echo ""
  echo "First-time setup:"
  echo "  1. cp .env.example .env"
  echo "  2. bash infra/scripts/generate-credentials.sh >> .env"
  echo "  3. Edit .env and generate OPAQUE_SERVER_SETUP:"
  echo "       cargo run --manifest-path server/Cargo.toml --bin gen_opaque_setup"
  echo "       (then paste the base64 output into OPAQUE_SERVER_SETUP in .env)"
  exit 1
fi
# Source it for use in this script
set -a; source .env; set +a

# ── 2. Pull latest code ──
echo "[1/8] Pulling latest code..."
git pull

# ── 3. Docker: start infrastructure services ──
echo "[2/8] Starting Docker stack (PostgreSQL, Redis, MinIO)..."
docker compose -f infra/docker-compose.yml --env-file .env up -d

# Wait for PostgreSQL to be ready
echo "  Waiting for PostgreSQL..."
for i in $(seq 1 30); do
  if pg_isready -h 127.0.0.1 -p 5432 -U privex -d privex -q 2>/dev/null; then
    echo "  PostgreSQL ready"
    break
  fi
  sleep 1
done

# Wait for MinIO and create the bucket
echo "  Waiting for MinIO..."
for i in $(seq 1 15); do
  if curl -s -o /dev/null http://127.0.0.1:9000/minio/health/live; then
    echo "  MinIO ready"
    break
  fi
  sleep 1
done

# Create MinIO bucket if it doesn't exist
BUCKET="${R2_BUCKET:-privex-files}"
echo "  Creating MinIO bucket '${BUCKET}'..."
docker compose -f infra/docker-compose.yml exec -T minio \
  mc alias set local http://localhost:9000 "${R2_ACCESS_KEY:-privex}" "${R2_SECRET_KEY:-privexprivex}"
docker compose -f infra/docker-compose.yml exec -T minio \
  mc mb "local/${BUCKET}" --ignore-existing 2>/dev/null || true

# ── 4. Build frontend ──
echo "[3/8] Installing frontend dependencies..."
pnpm install --frozen-lockfile

echo "[4/8] Building frontend..."
pnpm run build

# ── 5. Build Rust backend ──
echo "[5/8] Building Rust server..."
cd server
cargo build --release
cd "$PRIVEX_HOME"

# ── 6. Generate OPAQUE setup if missing ──
if [[ -z "${OPAQUE_SERVER_SETUP:-}" ]]; then
  echo "[6/8] Generating OPAQUE server setup..."
  OPAQUE_B64=$(cargo run --manifest-path server/Cargo.toml --bin gen_opaque_setup 2>/dev/null)
  echo "OPAQUE_SERVER_SETUP=${OPAQUE_B64}" >> .env
  set -a; source .env; set +a
  echo "  OPAQUE setup written to .env"
else
  echo "[6/8] OPAQUE setup present — skipping"
fi

# ── 7. Copy PM2 ecosystem config & restart ──
echo "[7/8] Configuring PM2..."
cp infra/ecosystem.config.js ecosystem.config.js

echo "[8/8] Restarting PM2..."
pm2 startOrReload ecosystem.config.js --update-env

echo ""
echo "=== Deploy complete ==="
echo "Check status: pm2 status"
echo "Check logs:   pm2 logs privex-api --lines 20"
echo "Check health: curl -s http://127.0.0.1:8888/health"
echo ""

# Show port status
echo "=== Port check ==="
echo "nginx (Privex): curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8088/health"
echo "Rust server:    curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8888/health"
echo "PostgreSQL:     pg_isready -h 127.0.0.1 -p 5432 -U privex"
