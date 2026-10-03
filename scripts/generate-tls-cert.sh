#!/bin/bash
##############################################################################
# Generate self-signed TLS certificate for Masterless proxy in e2e tests
#
# Usage:
#   ./scripts/generate-tls-cert.sh
#
# This creates:
#   - e2e-tests/data/keys/tls.crt  (certificate)
#   - e2e-tests/data/keys/tls.key  (private key)
##############################################################################

set -e

CERT_DIR="./e2e-tests/data/keys"
CERT_FILE="$CERT_DIR/tls.crt"
KEY_FILE="$CERT_DIR/tls.key"

# Create directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Check if certificate already exists and is valid
if [[ -f "$CERT_FILE" ]] && [[ -f "$KEY_FILE" ]]; then
    echo "TLS certificate already exists at $CERT_FILE"
    # Check expiration (valid for 365 days)
    if openssl x509 -checkend 86400 -noout -in "$CERT_FILE" 2>/dev/null; then
        echo "Certificate is still valid. Skipping regeneration."
        exit 0
    else
        echo "Certificate has expired. Regenerating..."
    fi
fi

echo "Generating self-signed certificate for localhost..."

# Generate a self-signed certificate valid for 2 years
openssl req -x509 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" \
    -days 730 -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:127.0.0.1,IP:127.0.0.1"

echo "✓ TLS certificate generated:"
echo "  - Certificate: $CERT_FILE"
echo "  - Private Key: $KEY_FILE"
