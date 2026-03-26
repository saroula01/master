#!/bin/bash
# Secure Build Script for Evilginx (NO PASSWORD)
# Computes VPS fingerprint only - no password prompt on startup

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
GO_BIN="/usr/local/go/bin/go"

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     Evilginx Build (VPS-Locked, No Password)      ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

# --- Step 1: Compute VPS Fingerprint ---
echo -e "${YELLOW}[1/2]${NC} Computing VPS fingerprint..."

MACHINE_ID=""
if [ -f /etc/machine-id ]; then
    MACHINE_ID=$(cat /etc/machine-id | tr -d '\n')
fi

# Get sorted MAC addresses (excluding loopback)
MACS=$(ip link show 2>/dev/null | grep 'link/ether' | awk '{print $2}' | sort | tr '\n' '|' | sed 's/|$//')

PRODUCT_UUID=""
if [ -f /sys/class/dmi/id/product_uuid ]; then
    PRODUCT_UUID=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null | tr -d '\n')
fi

FINGERPRINT_INPUT="${MACHINE_ID}|${MACS}|${PRODUCT_UUID}"
FINGERPRINT=$(echo -n "$FINGERPRINT_INPUT" | sha256sum | awk '{print $1}')

echo -e "${GREEN}  ✓ VPS fingerprint computed${NC}"

# --- Step 2: Build Binary (NO PASSWORD) ---
echo -e "${YELLOW}[2/2]${NC} Building binary with VPS lock only..."

mkdir -p "$BUILD_DIR"

# Only embed fingerprint - leave password hash empty to skip auth
LDFLAGS="-X 'github.com/kgretzky/evilginx2/core.EmbeddedFingerprint=${FINGERPRINT}'"

cd "$SCRIPT_DIR"
$GO_BIN build -o "$BUILD_DIR/evilginx" -mod=vendor -ldflags "$LDFLAGS" main.go

echo -e "${GREEN}  ✓ Binary built successfully${NC}"

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Build complete!${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${WHITE}Binary:${NC}    $BUILD_DIR/evilginx"
echo -e "  ${GREEN}No password required on startup!${NC}"
echo -e "  ${YELLOW}⚠  This binary will ONLY work on this VPS.${NC}"
echo ""
