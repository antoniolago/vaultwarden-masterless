#!/usr/bin/env bash
###############################################################################
# setup.sh — Bootstrap the vaultwarden-masterless test environment
#
# This script:
#   1. Generates RSA keys for at-rest encryption
#   2. Starts Vaultwarden briefly to generate its RSA key
#   3. Prints next steps
#
# Usage:
#   cd deploy
#   chmod +x setup.sh
#   ./setup.sh
#   podman-compose up     # or: docker compose up
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Detect container runtime
if command -v podman-compose &>/dev/null; then
    COMPOSE="podman-compose"
elif command -v podman &>/dev/null && podman compose version &>/dev/null 2>&1; then
    COMPOSE="podman compose"
elif command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE="docker-compose"
else
    echo "ERROR: Neither podman-compose nor docker compose found."
    exit 1
fi
echo "Using: $COMPOSE"

echo ""
echo "=== Step 0: Ensure .env exists ==="
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "  Created .env from .env.example"
fi

# Generate Pocket-ID encryption key if not set
if grep -q '^POCKET_ID_ENCRYPTION_KEY=$' .env 2>/dev/null || ! grep -q 'POCKET_ID_ENCRYPTION_KEY' .env 2>/dev/null; then
    PID_KEY=$(openssl rand -base64 32)
    if grep -q 'POCKET_ID_ENCRYPTION_KEY' .env 2>/dev/null; then
        sed -i "s|^POCKET_ID_ENCRYPTION_KEY=.*|POCKET_ID_ENCRYPTION_KEY=${PID_KEY}|" .env
    else
        echo "POCKET_ID_ENCRYPTION_KEY=${PID_KEY}" >> .env
    fi
    echo "  Generated Pocket-ID encryption key"
fi

echo ""
echo "=== Step 1: Generate RSA keys ==="
KEYS_DIR="./keys"
mkdir -p "$KEYS_DIR"

if [ -f "$KEYS_DIR/rsa_private.pem" ]; then
    echo "  RSA keys already exist, skipping."
else
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
        -out "$KEYS_DIR/rsa_private.pem" 2>/dev/null
    openssl pkey -in "$KEYS_DIR/rsa_private.pem" -pubout \
        -out "$KEYS_DIR/rsa_public.pem" 2>/dev/null
    chmod 600 "$KEYS_DIR/rsa_private.pem"
    echo "  Generated: $KEYS_DIR/rsa_private.pem"
    echo "  Generated: $KEYS_DIR/rsa_public.pem"
fi

echo ""
echo "=== Step 2: Start Vaultwarden to generate its RSA key ==="
$COMPOSE up -d vaultwarden
echo "  Waiting for Vaultwarden to initialize (10s)..."
sleep 10

echo ""
echo "=== Step 3: Extract Vaultwarden's RSA public key ==="
# Vaultwarden only generates rsa_key.pem (private). We need the public key
# for JWT verification. Extract it from inside the container.
VW_CONTAINER=$($COMPOSE ps -q vaultwarden 2>/dev/null | head -1)
if [ -z "$VW_CONTAINER" ]; then
    VW_CONTAINER="vw-server"
fi

if docker exec "$VW_CONTAINER" test -f /data/rsa_key.pem 2>/dev/null; then
    docker exec "$VW_CONTAINER" openssl pkey -in /data/rsa_key.pem -pubout \
        > "$KEYS_DIR/vw_rsa_key.pub.pem" 2>/dev/null
    echo "  Extracted: $KEYS_DIR/vw_rsa_key.pub.pem"
else
    echo "  WARNING: Vaultwarden's rsa_key.pem not found. You may need to copy it manually."
fi

echo ""
echo "=== Step 4: Stop services ==="
$COMPOSE down

echo ""
echo "=== Setup Complete ==="
echo ""
echo "RSA keys generated in: $KEYS_DIR/"
echo ""
echo "To start the full environment:"
echo "  $COMPOSE up --build"
echo ""
echo "Services will be available at:"
echo "  Vaultwarden (via masterless proxy): http://localhost:8443"
echo "  Pocket-ID (OIDC admin):             http://localhost:3100"
echo ""
echo "Next steps:"
echo "  1. Open Pocket-ID at http://localhost:3100 and create an admin account"
echo "  2. Create an OIDC client in Pocket-ID:"
echo "     - Client ID: vaultwarden"
echo "     - Redirect URI: http://localhost:8443/identity/connect/oidc-signin"
echo "     - Note the client secret and update OIDC_CLIENT_SECRET in .env"
echo "  3. Open Vaultwarden at http://localhost:8443"
echo "  4. Create an account, then try SSO login"
echo ""
