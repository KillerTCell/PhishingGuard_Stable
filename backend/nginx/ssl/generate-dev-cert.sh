#!/usr/bin/env bash
# ============================================================
# PhishGuard — Self-Signed TLS Certificate Generator
# For DEVELOPMENT USE ONLY. Never use in production.
# Production: replace with Let's Encrypt or a CA-signed cert.
# ============================================================
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"
DAYS=365

echo "Generating self-signed certificate in: $CERT_DIR"

openssl req -x509 \
  -nodes \
  -days "$DAYS" \
  -newkey rsa:4096 \
  -keyout "$KEY_FILE" \
  -out    "$CERT_FILE" \
  -subj "/C=AU/ST=Queensland/L=Brisbane/O=PhishGuard Dev/OU=Engineering/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:api,IP:127.0.0.1"

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo ""
echo "Done:"
echo "  cert.pem → $CERT_FILE"
echo "  key.pem  → $KEY_FILE"
echo ""
echo "Trust the cert in your browser (or use -k with curl) for local HTTPS."
echo "Certificate valid for $DAYS days."
