#!/usr/bin/env bash
# Generate fresh Privex credentials and keys.
# Output: prints export statements — source into your shell or pipe to .env.
set -euo pipefail

echo "# Generated $(date)"
echo "# Privex credentials — SAVE SECURELY, do not commit"

# 32-byte keys (hex)
SESSION_HMAC_KEY=$(openssl rand -hex 32)
KT_SIGNING_KEY=$(openssl rand -hex 32)
TIME_SIGNING_KEY=$(openssl rand -hex 32)

echo "export SESSION_HMAC_KEY=$SESSION_HMAC_KEY"
echo "export KT_SIGNING_KEY=$KT_SIGNING_KEY"
echo "export TIME_SIGNING_KEY=$TIME_SIGNING_KEY"

# PostgreSQL / MinIO passwords
PG_PASS=$(openssl rand -base64 24 | tr -d /=+ | cut -c1-24)
MINIO_PASS=$(openssl rand -base64 24 | tr -d /=+ | cut -c1-24)
echo "export POSTGRES_PASSWORD=$PG_PASS"
echo "export MINIO_PASSWORD=$MINIO_PASS"

# TURN secret
TURN_SECRET=$(openssl rand -hex 32)
echo "export TURN_SECRET=$TURN_SECRET"

echo ""
echo "# Derived URLs"
echo "export DATABASE_URL=postgresql://privex:${PG_PASS}@127.0.0.1:5432/privex"
echo "export R2_ACCESS_KEY=privex"
echo "export R2_SECRET_KEY=$MINIO_PASS"
