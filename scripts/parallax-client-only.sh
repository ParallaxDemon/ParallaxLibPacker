#!/usr/bin/env bash
# Parallax "client-only hardened" one-shot profile.
#
# No server dependency: everything is enforced on the device and in the build.
# This wrapper refuses to produce an artifact unless all four controls are on:
#   1. Aegis signed self-integrity (no patched packer frontend)
#   2. Ed25519-signed provenance manifest
#   3. APK signing-certificate SHA-256 pin (repackaged APK fails closed)
#   4. post-protection verify with --require-signature
set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage:
  PARALLAX_PACKER=/path/to/fresh/parallax_linux \
  PARALLAX_SIGNING_KEY=/secure/signing.key \
  PARALLAX_VERIFY_KEY=/secure/verify.pub \
  PARALLAX_APK_CERT_SHA256=<64 hex digits> \
    ./scripts/parallax-client-only.sh input.so output.so

Required environment:
  PARALLAX_PACKER           fresh CI-built packer binary (never a checked-in binary)
  PARALLAX_SIGNING_KEY      32-byte raw Ed25519 private key
  PARALLAX_VERIFY_KEY       32-byte raw Ed25519 public key (same keypair)
  PARALLAX_APK_CERT_SHA256  SHA-256 of the APK signing CERTIFICATE DER
                            (apksigner verify --print-certs; app signing cert)

Optional:
  PARALLAX_AEGIS_STRICT=1   verbose anchor diagnostics for the owner
EOF
}

if [[ $# -ne 2 ]]; then
  usage
  exit 2
fi

PACKER="${PARALLAX_PACKER:-}"
SIGNING_KEY="${PARALLAX_SIGNING_KEY:-}"
VERIFY_KEY="${PARALLAX_VERIFY_KEY:-}"
APK_PIN="${PARALLAX_APK_CERT_SHA256:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

for pair in \
  "PARALLAX_PACKER:$PACKER" \
  "PARALLAX_SIGNING_KEY:$SIGNING_KEY" \
  "PARALLAX_VERIFY_KEY:$VERIFY_KEY" \
  "PARALLAX_APK_CERT_SHA256:$APK_PIN"; do
  if [[ -z "${pair#*:}" ]]; then
    echo "ERROR: ${pair%%:*} is required for the client-only hardened profile." >&2
    exit 1
  fi
done

if [[ ! "$APK_PIN" =~ ^[0-9a-fA-F]{64}$ ]] && [[ ! "$APK_PIN" =~ ^([0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}$ ]]; then
  echo "ERROR: PARALLAX_APK_CERT_SHA256 must be 64 hex digits (colon-separated allowed)." >&2
  exit 1
fi

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required." >&2; exit 1; }

# 1. Never continue from a patched toolchain.
python3 "$HERE/parallax_aegis.py" enforce >/dev/null || {
  echo "ERROR: protection profile unavailable (aegis/0x7B)" >&2
  exit 1
}

# 2. Protect with provenance AND the client-side APK identity pin.
python3 "$HERE/parallax_ultra.py" protect "$1" "$2" \
  --packer "$PACKER" \
  --signing-key "$SIGNING_KEY" \
  --apk-cert-sha256 "$APK_PIN"

# 3. Immediately prove the artifact passed every gate. A quarantined or
#    unsigned output can never reach this point.
python3 "$HERE/parallax_ultra.py" verify "$2" \
  --public-key "$VERIFY_KEY" \
  --require-signature

echo "Client-only hardened profile: COMPLETE"
echo "Enforced: Aegis anchors + signed manifest + APK cert pin + verified artifact"
