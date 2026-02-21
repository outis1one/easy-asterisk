#!/bin/bash
# ================================================================
# Easy Asterisk Docker Entrypoint
#
# Starts Asterisk + Web Admin, applies environment configuration
# ================================================================

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[entrypoint]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[entrypoint]${NC} $1"; }

# ── 1. Generate self-signed certs if missing ──────────────────
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

# ── 2. Apply environment-based configuration ──────────────────
CONFIG_DIR="/etc/easy-asterisk"
CONFIG_FILE="${CONFIG_DIR}/config"
mkdir -p "$CONFIG_DIR"

# If no config exists, create from environment variables
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

# ── 3. Configure STUN if self-hosted coturn is available ──────
if [[ -n "$STUN_SERVER" ]]; then
    log_info "Using STUN server: ${STUN_SERVER}"
    source "$CONFIG_FILE" 2>/dev/null || true

    # Update rtp.conf with custom STUN
    cat > /etc/asterisk/rtp.conf << EOF
[general]
rtpstart=${RTP_START:-10000}
rtpend=${RTP_END:-20000}
strictrtp=yes
icesupport=yes
stunaddr=${STUN_SERVER}
EOF
    chown asterisk:asterisk /etc/asterisk/rtp.conf
fi

# ── 4. Generate default Asterisk configs if missing ───────────
if [[ ! -f /etc/asterisk/pjsip.conf ]] || [[ ! -s /etc/asterisk/pjsip.conf ]]; then
    log_info "Generating default PJSIP configuration..."
    local_ip=$(hostname -I | awk '{print $1}')
    raw_cidr=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -1)
    default_cidr="$raw_cidr"
    if [[ "$raw_cidr" =~ \.([0-9]+)/24$ ]]; then default_cidr="${raw_cidr%.*}.0/24"; fi

    nat_settings=""
    source "$CONFIG_FILE" 2>/dev/null || true
    if [[ "$HAS_VLANS" == "y" && -n "$VLAN_SUBNETS" ]]; then
        nat_settings="local_net=${default_cidr}"
        for subnet in $VLAN_SUBNETS; do
            nat_settings="${nat_settings}
local_net=${subnet}"
        done
    fi

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
    log_info "Generating default dialplan..."
    cat > /etc/asterisk/extensions.conf << EOF
[general]
static=yes
writeprotect=no
[default]
exten => _X.,1,Hangup()
[intercom]
EOF
    chown asterisk:asterisk /etc/asterisk/extensions.conf
fi

if [[ ! -f /etc/asterisk/rtp.conf ]]; then
    log_info "Generating default RTP configuration..."
    cat > /etc/asterisk/rtp.conf << EOF
[general]
rtpstart=${RTP_START:-10000}
rtpend=${RTP_END:-20000}
strictrtp=yes
# icesupport disabled - LAN only mode
EOF
    chown asterisk:asterisk /etc/asterisk/rtp.conf
fi

# Generate other required configs
for conf in asterisk.conf logger.conf modules.conf; do
    if [[ ! -f "/etc/asterisk/$conf" ]]; then
        log_info "Generating /etc/asterisk/$conf..."
    fi
done

if [[ ! -f /etc/asterisk/asterisk.conf ]]; then
    cat > /etc/asterisk/asterisk.conf << EOF
[directories]
[options]
runuser = asterisk
rungroup = asterisk
EOF
fi

if [[ ! -f /etc/asterisk/logger.conf ]]; then
    cat > /etc/asterisk/logger.conf << EOF
[general]
[logfiles]
console => notice,warning,error
EOF
fi

# ── 5. Fix permissions ───────────────────────────────────────
chown -R asterisk:asterisk /etc/asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk /var/run/asterisk 2>/dev/null || true

# ── 6. Start Web Admin in background (if script exists) ──────
WEB_ADMIN_SCRIPT="/usr/local/bin/easy-asterisk-webadmin"
if [[ -f "$WEB_ADMIN_SCRIPT" ]]; then
    source "$CONFIG_FILE" 2>/dev/null || true
    log_info "Starting Web Admin on port ${WEB_ADMIN_PORT:-8080}..."
    WEBADMIN_PORT="${WEB_ADMIN_PORT:-8080}" \
    WEBADMIN_AUTH_DISABLED="${WEB_ADMIN_AUTH_DISABLED:-false}" \
    python3 "$WEB_ADMIN_SCRIPT" &
fi

# ── 7. Start Asterisk in foreground ──────────────────────────
log_info "Starting Asterisk PBX..."
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${CYAN}  Easy Asterisk (Docker)${NC}"
echo -e "${CYAN}  Management: docker exec -it easy-asterisk easy-asterisk${NC}"
echo -e "${CYAN}  Diagnostics: docker exec -it easy-asterisk vpn-diagnostics${NC}"
echo -e "${CYAN}  DNS Check: docker exec -it easy-asterisk dns-whitelist${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

exec asterisk -f -U asterisk -G asterisk
