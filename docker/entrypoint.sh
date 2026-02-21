#!/bin/bash
# ================================================================
# Easy Asterisk Docker Entrypoint
#
# Initializes configuration, starts Asterisk + Web Admin
# Uses the same config functions as the main script
# ================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[entrypoint]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[entrypoint]${NC} $1"; }

CONFIG_DIR="/etc/easy-asterisk"
CONFIG_FILE="${CONFIG_DIR}/config"
WEB_ADMIN_SCRIPT="/usr/local/bin/easy-asterisk-webadmin"

# ── 1. Ensure asterisk user exists ───────────────────────────
if ! id asterisk >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /var/lib/asterisk asterisk 2>/dev/null || true
fi

# ── 2. Generate self-signed certs if missing ──────────────────
if [[ ! -f /etc/asterisk/certs/server.crt ]]; then
    log_info "Generating self-signed TLS certificate..."
    mkdir -p /etc/asterisk/certs
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/asterisk/certs/server.key \
        -out /etc/asterisk/certs/server.crt \
        -subj "/CN=asterisk-local" 2>/dev/null
    chown asterisk:asterisk /etc/asterisk/certs/server.*
    chmod 644 /etc/asterisk/certs/server.crt
    chmod 600 /etc/asterisk/certs/server.key
fi

# ── 3. Create config from environment if first run ────────────
mkdir -p "$CONFIG_DIR"

if [[ ! -f "$CONFIG_FILE" ]]; then
    log_info "Creating initial configuration from environment..."
    cat > "$CONFIG_FILE" << EOF
# Easy Asterisk Configuration (Docker)
KIOSK_USER=""
KIOSK_UID=""
KIOSK_EXTENSION=""
KIOSK_NAME=""
SIP_PASSWORD=""
ASTERISK_HOST="${ASTERISK_HOST:-}"
DOMAIN_NAME="${DOMAIN_NAME:-}"
ENABLE_TLS="${ENABLE_TLS:-n}"
HAS_VLANS="${HAS_VLANS:-n}"
VLAN_SUBNETS="${VLAN_SUBNETS:-}"
CERT_PATH=""
KEY_PATH=""
INSTALLED_SERVER="y"
INSTALLED_CLIENT="n"
CURRENT_PUBLIC_IP=""
PTT_DEVICE=""
PTT_KEYCODE=""
LOCAL_CIDR="${LOCAL_CIDR:-}"
WEB_ADMIN_PORT="${WEB_ADMIN_PORT:-8080}"
WEB_ADMIN_AUTH_DISABLED="${WEB_ADMIN_AUTH_DISABLED:-false}"
VPN_ICE_ENABLED="${VPN_ICE_ENABLED:-n}"
CUSTOM_STUN_SERVER="${CUSTOM_STUN_SERVER:-}"
EOF
    chmod 644 "$CONFIG_FILE"
fi

# Source config for use in this script
source "$CONFIG_FILE" 2>/dev/null || true

# ── 4. Initialize default categories if missing ──────────────
CATEGORIES_FILE="${CONFIG_DIR}/categories.conf"
if [[ ! -f "$CATEGORIES_FILE" ]]; then
    log_info "Creating default device categories..."
    cat > "$CATEGORIES_FILE" << 'EOF'
kiosks|Kiosks|yes|Fixed wall-mount tablets & intercoms
mobile|Mobile|no|Phones & tablets (ring normally)
custom|Custom|no|Custom configuration
EOF
fi

# ── 5. Configure STUN/ICE ────────────────────────────────────
# Allow STUN_SERVER env to override config
if [[ -n "${STUN_SERVER:-}" ]]; then
    log_info "STUN server configured: ${STUN_SERVER}"
    # Update config file
    if ! grep -q "^VPN_ICE_ENABLED=" "$CONFIG_FILE" 2>/dev/null; then
        echo "VPN_ICE_ENABLED=\"y\"" >> "$CONFIG_FILE"
        echo "CUSTOM_STUN_SERVER=\"${STUN_SERVER}\"" >> "$CONFIG_FILE"
    else
        sed -i "s|^VPN_ICE_ENABLED=.*|VPN_ICE_ENABLED=\"y\"|" "$CONFIG_FILE"
        sed -i "s|^CUSTOM_STUN_SERVER=.*|CUSTOM_STUN_SERVER=\"${STUN_SERVER}\"|" "$CONFIG_FILE"
    fi
    VPN_ICE_ENABLED="y"
    CUSTOM_STUN_SERVER="${STUN_SERVER}"
fi

# ── 6. Generate Asterisk configs if missing ───────────────────
local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
raw_cidr=$(ip -o -f inet addr show 2>/dev/null | awk '/scope global/ {print $4}' | head -1)
default_cidr="$raw_cidr"
if [[ "$raw_cidr" =~ \.([0-9]+)/24$ ]]; then default_cidr="${raw_cidr%.*}.0/24"; fi

# Build NAT/local_net settings
nat_settings=""
all_local_nets="local_net=${LOCAL_CIDR:-$default_cidr}"
if [[ "${HAS_VLANS:-n}" == "y" && -n "${VLAN_SUBNETS:-}" ]]; then
    for subnet in $VLAN_SUBNETS; do
        all_local_nets="${all_local_nets}
local_net=${subnet}"
    done
    nat_settings="${all_local_nets}"
fi

if [[ ! -f /etc/asterisk/pjsip.conf ]] || [[ ! -s /etc/asterisk/pjsip.conf ]]; then
    log_info "Generating PJSIP configuration..."
    cat > /etc/asterisk/pjsip.conf << EOF
; Easy Asterisk (Docker)
[global]
type=global
user_agent=EasyAsterisk

[transport-udp]
type=transport
protocol=udp
bind=0.0.0.0:5060
; Server IP: ${local_ip}
${nat_settings}

[transport-tcp]
type=transport
protocol=tcp
bind=0.0.0.0:5060
; Server IP: ${local_ip}
${nat_settings}

[transport-tls]
type=transport
protocol=tls
bind=0.0.0.0:5061
; Server IP: ${local_ip}
cert_file=/etc/asterisk/certs/server.crt
priv_key_file=/etc/asterisk/certs/server.key
ca_list_file=/etc/ssl/certs/ca-certificates.crt
method=tlsv1_2
${nat_settings}

EOF
    chown asterisk:asterisk /etc/asterisk/pjsip.conf
fi

if [[ ! -f /etc/asterisk/extensions.conf ]] || [[ ! -s /etc/asterisk/extensions.conf ]]; then
    log_info "Generating dialplan..."
    cat > /etc/asterisk/extensions.conf << 'EOF'
[general]
static=yes
writeprotect=no
[default]
exten => _X.,1,Hangup()
[intercom]
EOF
    chown asterisk:asterisk /etc/asterisk/extensions.conf
fi

# RTP config with STUN/ICE support
log_info "Configuring RTP..."
ice_stun_config="# icesupport disabled - LAN only mode"
if [[ "${VPN_ICE_ENABLED:-n}" == "y" ]] || [[ -n "${DOMAIN_NAME:-}" ]]; then
    stun_addr="${CUSTOM_STUN_SERVER:-stun.l.google.com:19302}"
    ice_stun_config="icesupport=yes
stunaddr=${stun_addr}"
    log_info "ICE enabled, STUN: ${stun_addr}"
fi

cat > /etc/asterisk/rtp.conf << EOF
[general]
rtpstart=${RTP_START:-10000}
rtpend=${RTP_END:-20000}
strictrtp=yes
${ice_stun_config}
EOF
chown asterisk:asterisk /etc/asterisk/rtp.conf

# Generate other core configs if missing
if [[ ! -f /etc/asterisk/asterisk.conf ]]; then
    cat > /etc/asterisk/asterisk.conf << 'EOF'
[directories]
[options]
runuser = asterisk
rungroup = asterisk
EOF
fi

if [[ ! -f /etc/asterisk/logger.conf ]]; then
    cat > /etc/asterisk/logger.conf << 'EOF'
[general]
[logfiles]
console => notice,warning,error
EOF
fi

if [[ ! -f /etc/asterisk/modules.conf ]]; then
    cat > /etc/asterisk/modules.conf << 'EOF'
[modules]
autoload = yes
EOF
fi

# ── 7. Fix permissions ───────────────────────────────────────
chown -R asterisk:asterisk /etc/asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk /var/run/asterisk 2>/dev/null || true

# ── 8. Start Web Admin in background ─────────────────────────
if [[ -f "$WEB_ADMIN_SCRIPT" ]]; then
    log_info "Starting Web Admin on port ${WEB_ADMIN_PORT:-8080}..."
    WEBADMIN_PORT="${WEB_ADMIN_PORT:-8080}" \
    WEBADMIN_AUTH_DISABLED="${WEB_ADMIN_AUTH_DISABLED:-false}" \
    python3 "$WEB_ADMIN_SCRIPT" &
fi

# ── 9. Trap signals for clean shutdown ────────────────────────
cleanup() {
    log_info "Shutting down..."
    # Stop web admin
    pkill -f "easy-asterisk-webadmin" 2>/dev/null || true
    # Graceful Asterisk shutdown
    asterisk -rx "core stop now" 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# ── 10. Start Asterisk in foreground ──────────────────────────
log_info "Starting Asterisk PBX..."
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Easy Asterisk (Docker)${NC}"
echo -e "${CYAN}  Server IP: ${local_ip}${NC}"
[[ "${VPN_ICE_ENABLED:-n}" == "y" ]] && echo -e "${CYAN}  STUN/ICE: ${CUSTOM_STUN_SERVER:-auto}${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Management:   docker exec -it easy-asterisk easy-asterisk${NC}"
echo -e "${CYAN}  Diagnostics:  docker exec -it easy-asterisk vpn-diagnostics${NC}"
echo -e "${CYAN}  DNS Check:    docker exec -it easy-asterisk dns-whitelist${NC}"
echo -e "${CYAN}  Web Admin:    http://${local_ip}:${WEB_ADMIN_PORT:-8080}/clients${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

exec asterisk -f -U asterisk -G asterisk
