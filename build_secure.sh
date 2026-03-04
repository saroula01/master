#!/bin/bash
# Secure Build Script for Evilginx
# Generates password, computes VPS fingerprint, and embeds both into the binary

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
AUTH_FILE="/root/.evilginx_auth"
GO_BIN="/usr/local/go/bin/go"

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         Evilginx Secure Build System              ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

# --- Step 1: Compute VPS Fingerprint ---
echo -e "${YELLOW}[1/4]${NC} Computing VPS fingerprint..."

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

# --- Step 2: Generate or Read Password ---
echo -e "${YELLOW}[2/4]${NC} Setting up authentication password..."

if [ -f "$AUTH_FILE" ]; then
    echo -e "${WHITE}  Existing password file found at ${AUTH_FILE}${NC}"
    echo -e -n "${WHITE}  Use existing password? [Y/n]: ${NC}"
    read -r USE_EXISTING
    if [ "$USE_EXISTING" = "n" ] || [ "$USE_EXISTING" = "N" ]; then
        PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)
        echo "$PASSWORD" > "$AUTH_FILE"
        chmod 600 "$AUTH_FILE"
        echo -e "${GREEN}  ✓ New password generated${NC}"
    else
        PASSWORD=$(cat "$AUTH_FILE")
        echo -e "${GREEN}  ✓ Using existing password${NC}"
    fi
else
    PASSWORD=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16)
    echo "$PASSWORD" > "$AUTH_FILE"
    chmod 600 "$AUTH_FILE"
    echo -e "${GREEN}  ✓ New password generated and saved${NC}"
fi

# --- Step 3: Hash the Password ---
echo -e "${YELLOW}[3/4]${NC} Hashing password..."

SALT="evilginx-cl-auth-2026"
PASSWORD_HASH=$(echo -n "${SALT}${PASSWORD}${SALT}" | sha256sum | awk '{print $1}')

echo -e "${GREEN}  ✓ Password hash computed${NC}"

# --- Step 4: Build Binary ---
echo -e "${YELLOW}[4/4]${NC} Building binary with embedded security..."

mkdir -p "$BUILD_DIR"

LDFLAGS="-X 'github.com/kgretzky/evilginx2/core.EmbeddedFingerprint=${FINGERPRINT}' -X 'github.com/kgretzky/evilginx2/core.EmbeddedPasswordHash=${PASSWORD_HASH}'"

cd "$SCRIPT_DIR"
$GO_BIN build -o "$BUILD_DIR/evilginx" -mod=vendor -ldflags "$LDFLAGS" main.go

echo -e "${GREEN}  ✓ Binary built successfully${NC}"

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Build complete!${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${WHITE}Binary:${NC}    $BUILD_DIR/evilginx"
echo -e "  ${WHITE}Password:${NC}  ${GREEN}${PASSWORD}${NC}"
echo -e "  ${WHITE}Stored at:${NC} $AUTH_FILE"
echo ""
echo -e "  ${YELLOW}⚠  Keep the password safe! You need it every time you start evilginx.${NC}"
echo -e "  ${YELLOW}⚠  This binary will ONLY work on this VPS.${NC}"
echo ""
