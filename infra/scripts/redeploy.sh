#!/usr/bin/env bash
# Safe redeploy for the single-machine host (Docker + PM2 + nginx).
#
# Wraps deploy.sh with the "plan for failure" safety rails:
#   1. a pre-deploy DB snapshot (on top of the scheduled 2x/day backup),
#   2. a rollback copy of the current binary,
#   3. deploy (build -> migrate -> pm2 reload),
#   4. a health gate that auto-reverts the BINARY if the new build isn't healthy.
#
# Migrations are forward-only and additive (CREATE ... IF NOT EXISTS), so a
# binary rollback is safe: the old binary simply ignores any newly-added tables.
# If the app still won't come up, restore the DB from the pre-deploy snapshot
# (see infra/DISASTER_RECOVERY.md).
#
# Usage:  bash infra/scripts/redeploy.sh
set -euo pipefail

PRIVEX_HOME="${PRIVEX_HOME:-/home/sonix/Privex}"
cd "$PRIVEX_HOME"

BIN="server/target/release/privex-server"
PREV="${BIN}.prev"
PM2_APP="${PM2_APP:-privex-api}"
HEALTH_URL="${HEALTH_URL:-http://127.0.0.1:8888/health/ready}"
# Reuse the existing backup infra (same USB + passphrase as backup-all.sh).
USB_MOUNT="${USB_MOUNT:-/mnt/backup-usb}"
PASS_FILE="${PASS_FILE:-/home/sonix/.backup-secrets/passphrase}"
PG_CONTAINER="${PG_CONTAINER:-infra-postgres-1}"
PG_USER="${PG_USER:-privex}"

log() { echo "[$(date '+%F %T')] $*"; }

# 1. Pre-deploy DB snapshot. Belt-and-suspenders on top of the cron backup:
#    captures state at the exact moment before the risky change. Warn (don't
#    abort) if the USB isn't mounted - the scheduled backup still covers us.
snapshot_db() {
  if mountpoint -q "$USB_MOUNT" && [ -r "$PASS_FILE" ]; then
    local dir="$USB_MOUNT/pre-deploy"
    mkdir -p "$dir"
    local out="$dir/privex_pre_$(date +%F_%H%M).sql.gz.gpg"
    if docker exec "$PG_CONTAINER" pg_dumpall -U "$PG_USER" \
        | gzip \
        | gpg --batch --yes --pinentry-mode loopback \
              --passphrase-file "$PASS_FILE" --symmetric --cipher-algo AES256 -o "$out"; then
      log "pre-deploy DB snapshot: $out"
    else
      log "WARN: pre-deploy snapshot FAILED - relying on the scheduled backup."
    fi
  else
    log "WARN: $USB_MOUNT not mounted (or passphrase unreadable) - skipping pre-deploy snapshot."
  fi
}

health_code() { curl -s -o /dev/null -w '%{http_code}' "$HEALTH_URL" 2>/dev/null || echo 000; }

# --- run ---
log "=== Privex safe redeploy ==="
[ -f "$BIN" ] && cp "$BIN" "$PREV" && log "rollback point saved: $PREV"
snapshot_db

log "running deploy.sh (build -> migrate -> pm2 reload) ..."
bash infra/scripts/deploy.sh

# Health gate. /health/ready checks Postgres + Redis + object store; give the
# reloaded process a moment to bind first.
sleep 4
code="$(health_code)"
if [ "$code" = "200" ]; then
  log "health OK ($code). Redeploy complete."
  log "NOTE: if nginx config changed this release, sync it:"
  log "  sudo cp infra/nginx/privex.conf /etc/nginx/sites-available/privex && sudo nginx -t && sudo systemctl reload nginx"
  exit 0
fi

log "HEALTH FAILED ($code) - reverting to the previous binary."
if [ -f "$PREV" ]; then
  cp "$PREV" "$BIN"
  pm2 reload "$PM2_APP" --update-env >/dev/null 2>&1 || pm2 restart "$PM2_APP" >/dev/null 2>&1 || true
  sleep 4
  log "after binary rollback: health $(health_code)"
fi
log "Still investigate: pm2 logs $PM2_APP --lines 50"
log "If the DB is the problem, restore the pre-deploy snapshot from $USB_MOUNT/pre-deploy (DISASTER_RECOVERY.md)."
exit 1
