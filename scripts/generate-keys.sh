#!/usr/bin/env bash
# Generate RSA key pair for vaultwarden-masterless at-rest encryption.
# These keys protect the AES wrapping key that encrypts user vault keys.
#
# Usage: ./scripts/generate-keys.sh [output_dir]

set -euo pipefail

OUTPUT_DIR="${1:-./data}"
mkdir -p "$OUTPUT_DIR"

PRIVATE_KEY="$OUTPUT_DIR/rsa_private.pem"
PUBLIC_KEY="$OUTPUT_DIR/rsa_public.pem"

if [ -f "$PRIVATE_KEY" ]; then
    echo "WARNING: $PRIVATE_KEY already exists. Skipping to avoid overwriting."
    echo "         Delete it manually if you want to regenerate."
    exit 1
fi

echo "Generating 4096-bit RSA key pair..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$PRIVATE_KEY"
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

echo "Keys generated:"
echo "  Private: $PRIVATE_KEY"
echo "  Public:  $PUBLIC_KEY"
echo ""
echo "You also need Vaultwarden's RSA public key for JWT verification."
echo "Copy it from your Vaultwarden data directory:"
echo "  cp /path/to/vaultwarden/data/rsa_key.pub.pem $OUTPUT_DIR/vw_rsa_key.pub.pem"
