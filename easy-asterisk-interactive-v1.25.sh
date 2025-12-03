#!/bin/bash
# ================================================================
# Easy Asterisk - Interactive Installer v1.25
#
# UPDATES in v1.25:
# - QUICK LOCAL SETUP: New recommended installation path (90% use case)
#   * One-click local network setup
#   * PTT with mute-by-default
#   * Auto-answer for kiosks
#   * Audio ducking
#   * No COTURN/internet/certificates needed
#   * Perfect for intercoms, warehouses, offices
#
# - VPN DETECTION: Automatic VPN interface detection
#   * Detects Tailscale, WireGuard, OpenVPN
#   * Offers to bind Asterisk to VPN IP
#   * Shows benefits of VPN vs COTURN
#   * Stores VPN config (USE_VPN, VPN_INTERFACE, VPN_IP)
#
# - SIMPLIFIED COTURN GUIDANCE: Crystal-clear when you need it
#   * Shows "Do you ACTUALLY need COTURN?" with examples
#   * ✗ DON'T need: Local network, VPN, simple NAT
#   * ✓ DO need: Symmetric NAT, VLAN isolation, corporate firewall
#   * Changed default prompt from [Y/n] to [y/N] (opt-in not opt-out)
#
# - TURN DOMAIN: Defaults to SIP domain (same domain is fine!)
#   * TURN_DOMAIN defaults to DOMAIN_NAME
#   * Explains single vs separate domain options
#   * Warns if using separate domains about cert coverage
#
# RETAINED from v1.24:
# - COMPREHENSIVE: Complete OPNsense/pfSense VLAN configuration guide
#   * Full network topology documentation (LAN + VLAN 20/30/40)
#   * Step-by-step firewall rules for VLAN isolation
#   * Port forwarding tables with complete relay range
#   * Visual flow diagrams showing cross-VLAN communication
#   * Testing procedures for TURN/COTURN validation
#
# - FQDN/DOMAIN: Separate SIP and TURN domain support
#   * Can use turn.example.com separate from sip.example.com
#   * Caddy cert sync searches for certs covering both domains
#   * Supports wildcard certs (*.example.com) or multi-SAN certs
#   * Automatically displays snippets for both domains in Caddyfile
#
# - STATIC vs DYNAMIC IP: Intelligent IP type detection
#   * Detects if user has static or dynamic public IP
#   * Guides users on Dynamic DNS setup if needed
#   * Lists popular DNS providers (Cloudflare, Namecheap, etc.)
#   * Suggests VPN alternative (Tailscale) to avoid IP issues entirely
#   * Prevents COTURN installation without proper DNS setup
#
# - COTURN: Enhanced configuration with listening-ip and relay-ip
#   * Automatic local IP detection and binding
#   * TLS support on port 5349
#   * Optimized for OPNsense/VLAN environments
#   * Checks IP type before installation
#
# - ASTERISK: Automatic ICE/STUN/TURN integration
#   * pjsip.conf now includes ice_support on all transports
#   * rtp.conf auto-configures with COTURN when enabled
#   * Google STUN fallback made OPTIONAL (asks user)
#   * Can run with no STUN/TURN for VPN-only setups
#
# - BARESIP: Automatic TURN configuration
#   * Auto-injects TURN credentials when COTURN enabled
#   * No manual configuration required
#
# - AUTOMATION: Everything configures automatically - zero manual edits needed!
#
# RETAINED from v1.23:
# - PTT Mute-default, Audio Ducking, Device Management
# ================================================================

set +e

# Version and Update Info
SCRIPT_VERSION="1.25"
GITHUB_REPO="outis1one/asterisk-easy"
SCRIPT_NAME="easy-asterisk-interactive-v1.25.sh"
BACKUP_DIR="/etc/easy-asterisk/backups"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Defaults
DEFAULT_SIP_PORT="5060"
DEFAULT_SIPS_PORT="5061"
DEFAULT_TURN_PORT="3478"
CONFIG_DIR="/etc/easy-asterisk"
CONFIG_FILE="${CONFIG_DIR}/config"
PTT_CONFIG_FILE="${CONFIG_DIR}/ptt-device"
CATEGORIES_FILE="${CONFIG_DIR}/categories.conf"
ROOMS_FILE="${CONFIG_DIR}/rooms.conf"
COTURN_CONFIG="/etc/turnserver.conf"

# ================================================================
# 1. CORE HELPER FUNCTIONS
# ================================================================

print_header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}\n"
}

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

generate_password() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16
}

load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE" 2>/dev/null || true
    fi
    INSTALLED_SERVER="${INSTALLED_SERVER:-n}"
    INSTALLED_CLIENT="${INSTALLED_CLIENT:-n}"
    INSTALLED_COTURN="${INSTALLED_COTURN:-n}"
    KIOSK_USER="${KIOSK_USER:-}"
    KIOSK_UID="${KIOSK_UID:-}"
    USE_COTURN="${USE_COTURN:-n}"
    USE_VPN="${USE_VPN:-n}"
    VPN_INTERFACE="${VPN_INTERFACE:-}"
    VPN_IP="${VPN_IP:-}"
    VPN_TYPE="${VPN_TYPE:-}"
    TURN_SECRET="${TURN_SECRET:-}"
    TURN_USER="${TURN_USER:-kioskuser}"
    TURN_PASS="${TURN_PASS:-}"
    TURN_DOMAIN="${TURN_DOMAIN:-}"
    USE_GOOGLE_STUN="${USE_GOOGLE_STUN:-n}"
    IP_TYPE="${IP_TYPE:-}"
    HAS_DYNAMIC_DNS="${HAS_DYNAMIC_DNS:-}"
    return 0
}

backup_config() {
    local file=$1
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.backup-$(date +%s)"
        ls -tp "${file}.backup-"* 2>/dev/null | tail -n +6 | xargs -I {} rm -- {} 2>/dev/null
    fi
}

save_config() {
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" << EOF
# Easy Asterisk Configuration - $(date)
KIOSK_USER="$KIOSK_USER"
KIOSK_UID="$KIOSK_UID"
KIOSK_EXTENSION="$KIOSK_EXTENSION"
KIOSK_NAME="$KIOSK_NAME"
SIP_PASSWORD="$SIP_PASSWORD"
ASTERISK_HOST="$ASTERISK_HOST"
DOMAIN_NAME="$DOMAIN_NAME"
TURN_DOMAIN="$TURN_DOMAIN"
ENABLE_TLS="$ENABLE_TLS"
CERT_PATH="$CERT_PATH"
KEY_PATH="$KEY_PATH"
INSTALLED_SERVER="$INSTALLED_SERVER"
INSTALLED_CLIENT="$INSTALLED_CLIENT"
INSTALLED_COTURN="$INSTALLED_COTURN"
USE_COTURN="$USE_COTURN"
USE_VPN="$USE_VPN"
VPN_INTERFACE="$VPN_INTERFACE"
VPN_IP="$VPN_IP"
VPN_TYPE="$VPN_TYPE"
USE_GOOGLE_STUN="$USE_GOOGLE_STUN"
IP_TYPE="$IP_TYPE"
HAS_DYNAMIC_DNS="$HAS_DYNAMIC_DNS"
TURN_SECRET="$TURN_SECRET"
TURN_USER="$TURN_USER"
TURN_PASS="$TURN_PASS"
CURRENT_PUBLIC_IP="$CURRENT_PUBLIC_IP"
PTT_DEVICE="$PTT_DEVICE"
PTT_KEYCODE="$PTT_KEYCODE"
LOCAL_CIDR="$LOCAL_CIDR"
CLIENT_ANSWERMODE="$CLIENT_ANSWERMODE"
EOF
    chmod 600 "$CONFIG_FILE"
    
    # Save PTT config separately
    if [[ -n "$PTT_DEVICE" ]]; then
        cat > "$PTT_CONFIG_FILE" << EOF
PTT_DEVICE="$PTT_DEVICE"
PTT_KEYCODE="$PTT_KEYCODE"
EOF
        chmod 600 "$PTT_CONFIG_FILE"
    fi
}

open_firewall_ports() {
    print_info "Configuring firewall ports..."
    if command -v ufw &>/dev/null; then
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw allow 5060/udp comment "SIP UDP" 2>/dev/null || true
            ufw allow 5061/tcp comment "SIP TLS" 2>/dev/null || true
            ufw allow 10000:20000/udp comment "RTP Media" 2>/dev/null || true
            if [[ "$USE_COTURN" == "y" ]]; then
                ufw allow ${DEFAULT_TURN_PORT}/udp comment "TURN UDP" 2>/dev/null || true
                ufw allow ${DEFAULT_TURN_PORT}/tcp comment "TURN TCP" 2>/dev/null || true
                # Allow relay range for TURN
                ufw allow 49152:65535/udp comment "TURN Relay" 2>/dev/null || true
            fi
            ufw reload 2>/dev/null || true
            print_success "UFW firewall ports opened"
        fi
    fi
}

# ================================================================
# 2. VPN & NETWORK DETECTION
# ================================================================

detect_vpn_interface() {
    print_header "VPN Detection"

    # Check for common VPN interfaces
    local vpn_interfaces=()
    local vpn_ips=()
    local vpn_types=()

    # Tailscale
    if ip link show tailscale0 &>/dev/null; then
        local ts_ip=$(ip -4 addr show tailscale0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [[ -n "$ts_ip" ]]; then
            vpn_interfaces+=("tailscale0")
            vpn_ips+=("$ts_ip")
            vpn_types+=("Tailscale")
        fi
    fi

    # NetBird
    if ip link show wt0 &>/dev/null; then
        local nb_ip=$(ip -4 addr show wt0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [[ -n "$nb_ip" ]]; then
            vpn_interfaces+=("wt0")
            vpn_ips+=("$nb_ip")
            vpn_types+=("NetBird")
        fi
    fi

    # WireGuard
    for wg_if in $(ip link show | grep -oP 'wg\d+|wireguard\d+' | sort -u); do
        local wg_ip=$(ip -4 addr show "$wg_if" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [[ -n "$wg_ip" ]]; then
            vpn_interfaces+=("$wg_if")
            vpn_ips+=("$wg_ip")
            vpn_types+=("WireGuard")
        fi
    done

    # OpenVPN (tun/tap)
    for tun_if in $(ip link show | grep -oP 'tun\d+|tap\d+' | sort -u); do
        local tun_ip=$(ip -4 addr show "$tun_if" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        if [[ -n "$tun_ip" ]]; then
            vpn_interfaces+=("$tun_if")
            vpn_ips+=("$tun_ip")
            vpn_types+=("OpenVPN")
        fi
    done

    if [[ ${#vpn_interfaces[@]} -eq 0 ]]; then
        echo "No VPN interfaces detected."
        echo ""
        echo "Supported VPNs: Tailscale, NetBird, WireGuard, OpenVPN"
        echo ""
        echo "Want to use VPN? Install one of the above, then re-run this script."
        return 1
    fi

    echo "Detected VPN interface(s):"
    for i in "${!vpn_interfaces[@]}"; do
        echo "  $((i+1))) ${vpn_types[$i]}: ${vpn_interfaces[$i]} → ${vpn_ips[$i]}"
    done
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  IMPORTANT: VPN Setup Requirements                        ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "For VPN to work, you must install it on:"
    echo "  ${BOLD}1. This Asterisk server${NC} ${GREEN}✓${NC} (detected above)"
    echo "  ${BOLD}2. ALL kiosk/client devices${NC}"
    echo ""
    echo "Benefits of using VPN:"
    echo "  ${GREEN}✓${NC} No COTURN needed (simpler setup)"
    echo "  ${GREEN}✓${NC} No port forwarding needed (more secure)"
    echo "  ${GREEN}✓${NC} No public IP/DNS issues (works with dynamic IP)"
    echo "  ${GREEN}✓${NC} Works across VLANs automatically"
    echo "  ${GREEN}✓${NC} Internet users can still call in via FQDN"
    echo ""
    echo "How it works:"
    echo "  • Clients register to Asterisk using VPN IP"
    echo "  • Asterisk acts as a bridge between VPN and public internet"
    echo "  • External callers use FQDN (port forward 5060/5061 + 10000-20000)"
    echo ""
    read -p "Use VPN interface for Asterisk? [Y/n]: " use_vpn

    if [[ ! "$use_vpn" =~ ^[Nn]$ ]]; then
        if [[ ${#vpn_interfaces[@]} -eq 1 ]]; then
            VPN_INTERFACE="${vpn_interfaces[0]}"
            VPN_IP="${vpn_ips[0]}"
            VPN_TYPE="${vpn_types[0]}"
        else
            read -p "Select interface [1-${#vpn_interfaces[@]}]: " vpn_choice
            vpn_choice=$((vpn_choice - 1))
            VPN_INTERFACE="${vpn_interfaces[$vpn_choice]}"
            VPN_IP="${vpn_ips[$vpn_choice]}"
            VPN_TYPE="${vpn_types[$vpn_choice]}"
        fi

        ASTERISK_HOST="$VPN_IP"
        USE_VPN="y"
        print_success "VPN Mode: ${VPN_TYPE} ($VPN_INTERFACE → $VPN_IP)"
        echo ""
        print_warn "Remember: Install ${VPN_TYPE} on all kiosk devices!"
        save_config
        return 0
    fi

    return 1
}

get_public_ip() {
    local ip=$(curl -s -4 --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s -4 --connect-timeout 5 icanhazip.com 2>/dev/null || echo "")
    echo "$ip"
}

check_ip_type_and_dns() {
    print_header "IP Address Configuration"

    local current_ip=$(get_public_ip)
    [[ -n "$current_ip" ]] && echo "Your current public IP: ${BOLD}$current_ip${NC}"
    echo ""

    echo "Do you have a STATIC or DYNAMIC public IP address?"
    echo "  ${BOLD}Static${NC}:  IP never changes (common with business internet)"
    echo "  ${BOLD}Dynamic${NC}: IP changes periodically (common with residential internet)"
    echo ""
    echo "Not sure? Check with your ISP or wait 24-48 hours and run 'curl ifconfig.me'"
    echo "to see if your IP changed."
    echo ""
    read -p "Is your IP [S]tatic or [D]ynamic? [s/D]: " ip_choice

    if [[ "$ip_choice" =~ ^[Ss]$ ]]; then
        IP_TYPE="static"
        print_success "Static IP configured - COTURN will work reliably!"
        return 0
    else
        IP_TYPE="dynamic"
        print_warn "Dynamic IP detected"
        echo ""
        echo "With a dynamic IP, your TURN server will break when your IP changes."
        echo ""
        echo "Do you have a method to automatically update your domain's DNS record"
        echo "when your IP changes? (Examples: ddclient, router built-in DDNS,"
        echo "Cloudflare API script, etc.)"
        echo ""
        read -p "Do you have automatic DNS updates configured? [y/N]: " dns_choice

        if [[ "$dns_choice" =~ ^[Yy]$ ]]; then
            HAS_DYNAMIC_DNS="y"
            print_success "Great! Your COTURN should work with DDNS."
        else
            HAS_DYNAMIC_DNS="n"
            echo ""
            print_warn "${BOLD}STOPPING POINT:${NC} You need to configure Dynamic DNS first!"
            echo ""
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║  OPTION 1: Configure Dynamic DNS with your provider       ║"
            echo "╚════════════════════════════════════════════════════════════╝"
            echo ""
            echo "Popular DNS providers and their DDNS solutions:"
            echo "  • Cloudflare: Use 'cloudflare-ddns' or API scripts"
            echo "  • Google Domains: Built-in Dynamic DNS"
            echo "  • Namecheap: Built-in Dynamic DNS"
            echo "  • No-IP / DynDNS: Dedicated DDNS services"
            echo "  • Your Router: Many routers have built-in DDNS clients"
            echo ""
            echo "Search for: 'YOUR_PROVIDER dynamic dns setup'"
            echo ""
            echo "╔════════════════════════════════════════════════════════════╗"
            echo "║  OPTION 2: Use a VPN Instead (Recommended!)               ║"
            echo "╚════════════════════════════════════════════════════════════╝"
            echo ""
            echo "A VPN (like Tailscale or WireGuard) avoids ALL these issues:"
            echo "  ✓ No port forwarding needed"
            echo "  ✓ No COTURN needed"
            echo "  ✓ No dynamic IP problems"
            echo "  ✓ Works across VLANs automatically"
            echo "  ✓ More secure than exposing services to internet"
            echo ""
            echo "To use VPN mode with this script:"
            echo "  1. Install Tailscale (curl -fsSL https://tailscale.com/install.sh | sh)"
            echo "  2. Run: tailscale up"
            echo "  3. Use your Tailscale IP (100.x.x.x) as ASTERISK_HOST"
            echo "  4. Skip COTURN installation entirely"
            echo ""
            read -p "Press Enter to continue or Ctrl+C to exit and set up DDNS/VPN..."
        fi
    fi

    save_config
    return 0
}

install_coturn() {
    print_header "Installing COTURN"

    # Check IP type and DNS configuration first
    if [[ "$IP_TYPE" != "static" && "$HAS_DYNAMIC_DNS" != "y" ]]; then
        check_ip_type_and_dns
    fi

    apt update
    apt install -y coturn

    if [[ -z "$TURN_PASS" ]]; then
        TURN_PASS=$(generate_password)
    fi

    local public_ip=$(get_public_ip)
    CURRENT_PUBLIC_IP="$public_ip"

    if [[ -z "$public_ip" ]]; then
        print_error "Could not detect public IP"
        return 1
    fi

    # Get local IP
    local local_ip=$(hostname -I | cut -d' ' -f1)
    [[ -z "$local_ip" ]] && local_ip="0.0.0.0"

    print_info "Public IP: $public_ip"
    print_info "Local IP: $local_ip"

    # Enable coturn
    sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn 2>/dev/null || true

    # Configure coturn
    backup_config "$COTURN_CONFIG"
    cat > "$COTURN_CONFIG" << EOF
# Easy Asterisk COTURN Configuration (OPNsense/VLAN Ready)
# Generated: $(date)

# Listening Configuration (Internal IP)
listening-ip=${local_ip}
relay-ip=${local_ip}
listening-port=${DEFAULT_TURN_PORT}
tls-listening-port=5349

# External IP (for NAT traversal)
external-ip=${public_ip}

# Realm and Authentication
realm=${TURN_DOMAIN:-${DOMAIN_NAME:-turn.local}}
fingerprint
lt-cred-mech

# Relay Port Range (CRITICAL for VLAN/NAT)
min-port=49152
max-port=65535

# User Credentials
user=${TURN_USER}:${TURN_PASS}

# Security Settings
total-quota=100
user-quota=12
stale-nonce=600
no-multicast-peers
no-loopback-peers

# TLS Configuration (if certs available)
cert=/etc/asterisk/certs/server.crt
pkey=/etc/asterisk/certs/server.key
no-tlsv1
no-tlsv1_1
cipher-list="ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384"
dh2066

# Logging
no-stdout-log
log-file=/var/log/turnserver.log
simple-log

# Optimization
no-cli
EOF

    chmod 600 "$COTURN_CONFIG"

    systemctl enable coturn
    systemctl restart coturn

    if systemctl is-active coturn >/dev/null; then
        print_success "COTURN installed and running"
        print_info "Listening on: $local_ip:${DEFAULT_TURN_PORT}"
        print_info "External IP: $public_ip"
        print_info "Relay Range: 49152-65535"
        INSTALLED_COTURN="y"
        USE_COTURN="y"
        save_config
        return 0
    else
        print_error "COTURN failed to start"
        journalctl -u coturn -n 20 --no-pager
        return 1
    fi
}

configure_coturn_credentials() {
    print_header "Configure TURN Credentials"
    echo "Current User: ${TURN_USER}"
    echo "Current Pass: ${TURN_PASS}"
    echo ""
    read -p "Enter Username [${TURN_USER}]: " t_user
    t_user="${t_user:-$TURN_USER}"
    read -p "Enter Password [generate]: " t_pass
    t_pass="${t_pass:-$(generate_password)}"
    
    TURN_USER="$t_user"
    TURN_PASS="$t_pass"
    
    if [[ -f "$COTURN_CONFIG" ]]; then
        # Remove old user lines and add new one
        sed -i '/^user=/d' "$COTURN_CONFIG"
        echo "user=${TURN_USER}:${TURN_PASS}" >> "$COTURN_CONFIG"
        systemctl restart coturn
        print_success "Credentials updated and service restarted"
    else
        print_error "COTURN not installed. Run install first."
    fi
    save_config
}

update_coturn_ip() {
    local new_ip=$(get_public_ip)
    
    if [[ -z "$new_ip" ]]; then
        print_warn "Could not detect public IP"
        return 1
    fi
    
    if [[ "$new_ip" == "$CURRENT_PUBLIC_IP" ]]; then
        print_info "IP unchanged: $new_ip"
        return 0
    fi
    
    print_info "IP changed: $CURRENT_PUBLIC_IP -> $new_ip"
    
    # Update coturn config
    if [[ -f "$COTURN_CONFIG" ]]; then
        sed -i "s/^external-ip=.*/external-ip=${new_ip}/" "$COTURN_CONFIG"
        systemctl restart coturn
        print_success "COTURN updated"
    fi
    
    # Update pjsip config
    if [[ -f /etc/asterisk/pjsip.conf ]]; then
        sed -i "s/^external_media_address=.*/external_media_address=${new_ip}/" /etc/asterisk/pjsip.conf
        sed -i "s/^external_signaling_address=.*/external_signaling_address=${new_ip}/" /etc/asterisk/pjsip.conf
        asterisk -rx "pjsip reload" 2>/dev/null
        print_success "Asterisk updated"
    fi
    
    CURRENT_PUBLIC_IP="$new_ip"
    save_config
    return 0
}

create_ip_update_script() {
    cat > /usr/local/bin/easy-asterisk-update-ip << 'IPSCRIPT'
#!/bin/bash
CONFIG_FILE="/etc/easy-asterisk/config"
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

get_public_ip() {
    curl -s -4 --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s -4 --connect-timeout 5 icanhazip.com 2>/dev/null
}

NEW_IP=$(get_public_ip)
[[ -z "$NEW_IP" ]] && exit 0
[[ "$NEW_IP" == "$CURRENT_PUBLIC_IP" ]] && exit 0

# Update COTURN
if [[ -f /etc/turnserver.conf ]]; then
    sed -i "s/^external-ip=.*/external-ip=${NEW_IP}/" /etc/turnserver.conf
    systemctl restart coturn
fi

# Update Asterisk
if [[ -f /etc/asterisk/pjsip.conf ]]; then
    sed -i "s/^external_media_address=.*/external_media_address=${NEW_IP}/" /etc/asterisk/pjsip.conf
    sed -i "s/^external_signaling_address=.*/external_signaling_address=${NEW_IP}/" /etc/asterisk/pjsip.conf
    asterisk -rx "pjsip reload" 2>/dev/null
fi

# Update config file
sed -i "s/^CURRENT_PUBLIC_IP=.*/CURRENT_PUBLIC_IP=\"${NEW_IP}\"/" "$CONFIG_FILE"

logger "Easy Asterisk: Updated IP to ${NEW_IP}"
IPSCRIPT
    chmod +x /usr/local/bin/easy-asterisk-update-ip
    
    # Create systemd timer
    cat > /etc/systemd/system/easy-asterisk-ip-update.service << 'EOF'
[Unit]
Description=Easy Asterisk IP Update
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/easy-asterisk-update-ip
EOF

    cat > /etc/systemd/system/easy-asterisk-ip-update.timer << 'EOF'
[Unit]
Description=Easy Asterisk IP Update Timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable easy-asterisk-ip-update.timer
    systemctl start easy-asterisk-ip-update.timer
    
    print_success "IP update timer installed (checks every 10 minutes)"
}

configure_coturn_menu() {
    print_header "Configure COTURN (TURN Server)"
    
    if [[ "$INSTALLED_COTURN" == "y" ]]; then
        echo -e "Status: ${GREEN}Installed${NC}"
        echo "User:   ${TURN_USER}"
        echo "Pass:   ${TURN_PASS}"
        echo ""
        echo "  1) Update Credentials (User/Pass)"
        echo "  2) Reinstall/Reconfigure"
        echo "  3) Update IP manually"
        echo "  4) Show configuration"
        echo "  5) Uninstall"
        echo "  0) Back"
        read -p "Select: " choice
        case $choice in
            1) configure_coturn_credentials ;;
            2) install_coturn ;;
            3) update_coturn_ip ;;
            4) show_coturn_config ;;
            5) uninstall_coturn ;;
        esac
    else
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║             Do you ACTUALLY need COTURN?                  ║"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""
        echo "${RED}✗ You DON'T need COTURN if:${NC}"
        echo "  • Local network only"
        echo "  • Using VPN (Tailscale/WireGuard)"
        echo "  • Server has public IP + simple port forwarding"
        echo ""
        echo "${GREEN}✓ You DO need COTURN if:${NC}"
        echo "  • Symmetric NAT / strict firewall"
        echo "  • VLAN isolation (like OPNsense example)"
        echo "  • Corporate network with limited ports"
        echo ""
        echo "COTURN requires:"
        echo "  • Domain name (FQDN)"
        echo "  • Static IP OR Dynamic DNS"
        echo "  • Port forwarding (3478, 49152-65535)"
        echo ""
        read -p "Install COTURN anyway? [y/N]: " install
        if [[ "$install" =~ ^[Yy]$ ]]; then
            install_coturn
            if [[ "$INSTALLED_COTURN" == "y" ]]; then
                create_ip_update_script
            fi
        fi
    fi
}

show_coturn_config() {
    print_header "COTURN Configuration"
    echo "Status: $(systemctl is-active coturn)"
    echo "Public IP: $CURRENT_PUBLIC_IP"
    echo "Port: ${DEFAULT_TURN_PORT}"
    echo "Credentials: ${TURN_USER} : ${TURN_PASS}"
    echo ""
    echo "Client Config String:"
    echo "turn:${TURN_USER}:${TURN_PASS}@${TURN_DOMAIN:-${DOMAIN_NAME:-$CURRENT_PUBLIC_IP}}:${DEFAULT_TURN_PORT}"
    echo ""
    echo "Logs:"
    tail -n 20 /var/log/turnserver.log 2>/dev/null || echo "  No logs found"
}

uninstall_coturn() {
    systemctl stop coturn 2>/dev/null || true
    systemctl disable coturn 2>/dev/null || true
    apt purge -y coturn 2>/dev/null || true
    rm -f /etc/turnserver.conf
    rm -f /usr/local/bin/easy-asterisk-update-ip
    systemctl stop easy-asterisk-ip-update.timer 2>/dev/null || true
    systemctl disable easy-asterisk-ip-update.timer 2>/dev/null || true
    rm -f /etc/systemd/system/easy-asterisk-ip-update.*
    systemctl daemon-reload
    INSTALLED_COTURN="n"
    USE_COTURN="n"
    save_config
    print_success "COTURN uninstalled"
}

# ================================================================
# 3. DEVICE MANAGEMENT
# ================================================================

initialize_default_categories() {
    mkdir -p "$CONFIG_DIR"
    if [[ ! -f "$CATEGORIES_FILE" ]]; then
        cat > "$CATEGORIES_FILE" << 'EOF'
# Format: id|name|auto_answer(yes/no)|description
kiosk|Kiosks|yes|Fixed auto-answer intercoms
mobile|Mobile Devices|no|Phones and mobile devices
EOF
        chmod 600 "$CATEGORIES_FILE"
    fi
    if [[ ! -f "$ROOMS_FILE" ]]; then
        cat > "$ROOMS_FILE" << 'EOF'
# Format: ext|name|members|timeout|type(ring/page)
199|All Kiosks|101,102,103,104,105|60|page
299|All Mobile|201,202,203,204,205|60|ring
EOF
        chmod 600 "$ROOMS_FILE"
    fi
}

list_categories() {
    initialize_default_categories
    local index=1
    while IFS='|' read -r cat_id cat_name auto_answer description; do
        [[ "$cat_id" =~ ^# ]] && continue
        [[ -z "$cat_id" ]] && continue
        local auto_text="${RED}Ring${NC}"
        [[ "$auto_answer" == "yes" ]] && auto_text="${GREEN}Auto-answer${NC}"
        echo -e "  ${CYAN}$index)${NC} ${BOLD}$cat_name${NC} ($cat_id) - $auto_text"
        ((index++))
    done < "$CATEGORIES_FILE"
}

get_category_by_index() {
    local target_index=$1
    local index=1
    while IFS='|' read -r cat_id cat_name auto_answer description; do
        [[ "$cat_id" =~ ^# ]] && continue
        [[ -z "$cat_id" ]] && continue
        if [[ $index -eq $target_index ]]; then
            echo "$cat_id|$cat_name|$auto_answer"
            return 0
        fi
        ((index++))
    done < "$CATEGORIES_FILE"
}

manage_categories() {
    print_header "Manage Categories"
    list_categories
    echo ""
    echo "  1) Add Category"
    echo "  2) Delete Category"
    echo "  0) Back"
    read -p "Select: " choice
    case $choice in
        1)
            read -p "ID (lowercase): " cid
            read -p "Display Name: " cname
            read -p "Auto Answer? [y/N]: " ca
            local ans="no"
            [[ "$ca" =~ ^[Yy]$ ]] && ans="yes"
            echo "${cid}|${cname}|${ans}|Custom category" >> "$CATEGORIES_FILE"
            print_success "Category added"
            rebuild_dialplan
            ;;
        2)
            read -p "Number to delete: " num
            local data=$(get_category_by_index "$num")
            local cid=$(echo "$data" | cut -d'|' -f1)
            [[ -n "$cid" ]] && sed -i "/^${cid}|/d" "$CATEGORIES_FILE"
            print_success "Deleted"
            rebuild_dialplan
            ;;
    esac
}

manage_rooms() {
    print_header "Manage Rooms"
    initialize_default_categories
    echo "Current Rooms:"
    local index=1
    while IFS='|' read -r rext rname rmem rtime rtype; do
        [[ "$rext" =~ ^# ]] && continue
        [[ -z "$rext" ]] && continue
        local type_text="Ring Group"
        [[ "$rtype" == "page" ]] && type_text="${GREEN}PAGE/INTERCOM${NC}"
        echo -e "  ${CYAN}$index)${NC} ${BOLD}$rname${NC} ($rext) - $type_text"
        echo -e "      Members: $rmem"
        ((index++))
    done < "$ROOMS_FILE"
    echo ""
    echo "  1) Add Room"
    echo "  2) Edit Room Members"
    echo "  3) Delete Room"
    echo "  0) Back"
    read -p "Select: " choice
    case $choice in
        1)
            read -p "Room Extension: " new_ext
            read -p "Room Name: " new_name
            echo "  1) Ring Group (Phones ring)"
            echo "  2) Page/Intercom (Auto-answer)"
            read -p "Select [1]: " type_sel
            local rtype="ring"
            [[ "$type_sel" == "2" ]] && rtype="page"
            read -p "Members (e.g. 101,102): " members
            echo "${new_ext}|${new_name}|${members}|60|${rtype}" >> "$ROOMS_FILE"
            rebuild_dialplan
            print_success "Room Created"
            ;;
        2)
            read -p "Select Room #: " rnum
            local target_line=""
            local count=0
            while IFS= read -r line; do
                if [[ ! "$line" =~ ^# ]] && [[ -n "$line" ]]; then
                    ((count++))
                    if [[ $count -eq $rnum ]]; then target_line="$line"; break; fi
                fi
            done < "$ROOMS_FILE"
            if [[ -n "$target_line" ]]; then
                IFS='|' read -r rext rname rmem rtime rtype <<< "$target_line"
                echo "Current members: $rmem"
                read -p "New members: " new_mem
                sed -i "/^${rext}|/d" "$ROOMS_FILE"
                echo "${rext}|${rname}|${new_mem}|${rtime}|${rtype}" >> "$ROOMS_FILE"
                rebuild_dialplan
                print_success "Room Updated"
            fi
            ;;
        3)
            read -p "Select Room #: " rnum
            local count=0
            local target_ext=""
            while IFS='|' read -r rext rrest; do
                if [[ ! "$rext" =~ ^# ]] && [[ -n "$rext" ]]; then
                    ((count++))
                    if [[ $count -eq $rnum ]]; then target_ext="$rext"; break; fi
                fi
            done < "$ROOMS_FILE"
            if [[ -n "$target_ext" ]]; then
                sed -i "/^${target_ext}|/d" "$ROOMS_FILE"
                rebuild_dialplan
                print_success "Room Deleted"
            fi
            ;;
    esac
}

add_device_menu() {
    print_header "Add Device"
    list_categories
    read -p "Category number: " cat_num
    local cat_data=$(get_category_by_index "$cat_num")
    if [[ -z "$cat_data" ]]; then print_error "Invalid"; return; fi
    local cat_id=$(echo "$cat_data" | cut -d'|' -f1)
    local cat_name=$(echo "$cat_data" | cut -d'|' -f2)
    local auto_answer=$(echo "$cat_data" | cut -d'|' -f3)
    
    local start_range=101 end_range=199
    case "$cat_id" in
        kiosk)   start_range=101; end_range=199 ;;
        mobile)  start_range=201; end_range=299 ;;
        *)       start_range=301; end_range=399 ;;
    esac

    local suggested_ext=""
    for ext in $(seq $start_range $end_range); do
        if ! grep -q "^\[${ext}\]" /etc/asterisk/pjsip.conf 2>/dev/null; then
            suggested_ext=$ext; break
        fi
    done
    
    read -p "Extension [$suggested_ext]: " ext
    ext="${ext:-$suggested_ext}"
    
    if grep -q "^\[${ext}\]" /etc/asterisk/pjsip.conf 2>/dev/null; then
        print_error "Extension exists!"; return
    fi
    
    read -p "Name: " name
    name="${name:-Device $ext}"
    local pass=$(generate_password)
    
    local override_tag=""
    if [[ "$auto_answer" == "no" ]]; then
        read -p "Force AUTO-ANSWER? [y/N]: " force_aa
        [[ "$force_aa" =~ ^[Yy]$ ]] && override_tag="[AA:yes]" && auto_answer="yes"
    elif [[ "$auto_answer" == "yes" ]]; then
        read -p "Force RING? [y/N]: " force_ring
        [[ "$force_ring" =~ ^[Yy]$ ]] && override_tag="[AA:no]" && auto_answer="no"
    fi
    
    # SDES-SRTP for compatibility
    local encryption_block=""
    if [[ "$ENABLE_TLS" == "y" ]]; then
        encryption_block="media_encryption=sdes
transport=transport-tls"
    fi
    
    backup_config "/etc/asterisk/pjsip.conf"

    cat >> /etc/asterisk/pjsip.conf << EOF

; === Device: $name ($cat_id) $override_tag ===
[${ext}]
type=endpoint
context=intercom
disallow=all
allow=opus
allow=ulaw
allow=alaw
allow=g722
${encryption_block}
direct_media=no
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
ice_support=yes
auth=${ext}
aors=${ext}
callerid="${name}" <${ext}>

[${ext}]
type=auth
auth_type=userpass
username=${ext}
password=${pass}

[${ext}]
type=aor
max_contacts=5
remove_existing=yes
qualify_frequency=60
EOF
    
    chown -R asterisk:asterisk /etc/asterisk
    asterisk -rx "pjsip reload" >/dev/null 2>&1
    rebuild_dialplan
    
    echo "════════════════════════════════════════════════════════"
    echo "  DEVICE ADDED"
    echo "════════════════════════════════════════════════════════"
    echo "  Server:    ${DOMAIN_NAME:-$(hostname -I | awk '{print $1}')}"
    echo "  Extension: $ext"
    echo "  Password:  $pass"
    echo "  Transport: TLS (port 5061)"
    echo "  SRTP:      Required"
    if [[ "$USE_COTURN" == "y" ]]; then
        echo "  TURN:      ${TURN_DOMAIN:-${DOMAIN_NAME:-$CURRENT_PUBLIC_IP}}:${DEFAULT_TURN_PORT}"
    fi
    echo "════════════════════════════════════════════════════════"
}

remove_device() {
    print_header "Remove Device"
    declare -A REMOVE_MAP
    local count=1
    echo "Select device to remove:"
    echo ""
    while IFS= read -r line; do
        if [[ "$line" == *"; === Device:"* ]]; then
            local temp="${line#*; === Device: }"
            temp="${temp% ===}"
            temp="${temp% \[AA:*\]}" 
            local name="${temp% (*)}"
        fi
        if [[ "$line" =~ ^\[([0-9]+)\] ]]; then
            local ext="${BASH_REMATCH[1]}"
            if [[ -n "$name" ]]; then
                echo "  ${count}) Ext ${ext} - ${name}"
                REMOVE_MAP[$count]=$ext
                ((count++))
                name=""
            fi
        fi
    done < /etc/asterisk/pjsip.conf
    echo ""
    echo "  98) DELETE ALL DEVICES"
    echo "  0) Cancel"
    echo ""
    read -p "Select: " choice
    
    if [[ "$choice" == "98" ]]; then
        echo ""
        print_warn "This will DELETE ALL DEVICES!"
        read -p "Type 'DELETE ALL' to confirm: " confirm
        if [[ "$confirm" == "DELETE ALL" ]]; then
            backup_config "/etc/asterisk/pjsip.conf"
            # Remove all device sections
            sed -i '/^; === Device:/,/^$/d' /etc/asterisk/pjsip.conf
            sed -i '/^\[[0-9]\{3\}\]/,/^$/d' /etc/asterisk/pjsip.conf
            asterisk -rx "pjsip reload" 2>/dev/null
            rebuild_dialplan
            print_success "All devices deleted"
        else
            print_error "Cancelled"
        fi
        return
    fi
    
    [[ "$choice" == "0" || -z "${REMOVE_MAP[$choice]}" ]] && return
    
    local ext="${REMOVE_MAP[$choice]}"
    read -p "Confirm removal of $ext? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        backup_config "/etc/asterisk/pjsip.conf"
        sed -i "/^; === Device:.*${ext}.*/,/^$/d" /etc/asterisk/pjsip.conf
        sed -i "/^\[${ext}\]/,/^$/d" /etc/asterisk/pjsip.conf
        asterisk -rx "pjsip reload" 2>/dev/null
        rebuild_dialplan
        print_success "Removed"
    fi
}

show_registered_devices() {
    print_header "Device Status"
    printf "${CYAN}%-6s %-20s %-15s %-15s %-15s${NC}\n" "Ext" "Name" "Category" "Status" "Password"
    echo "------------------------------------------------------------------------------"
    local dev_name="" dev_cat=""
    while IFS= read -r line; do
        if [[ "$line" == *"; === Device:"* ]]; then
            local temp="${line#*; === Device: }"
            temp="${temp% ===}"
            [[ "$temp" == *"[AA:"* ]] && temp="${temp% \[AA:*\]}"
            dev_cat="${temp##* (}"; dev_cat="${dev_cat%)}"
            dev_name="${temp% (*)}" 
        fi
        if [[ "$line" =~ ^\[([0-9]+)\] ]]; then
            local ext="${BASH_REMATCH[1]}"
            if [[ -n "$dev_name" ]]; then
                local status="${RED}Offline${NC}"
                local avail=$(asterisk -rx "pjsip show endpoint ${ext}" 2>/dev/null | grep -E "Contact:.*(Avail|NonQual)" || true)
                [[ -n "$avail" ]] && status="${GREEN}Online${NC}"
                local password=$(grep -A 10 "^\[$ext\]" /etc/asterisk/pjsip.conf | grep "password=" | head -1 | cut -d= -f2)
                printf "%-6s %-20s %-15s %b %-15s\n" "$ext" "${dev_name:0:18}" "$dev_cat" "$status" "$password"
                dev_name=""
            fi
        fi
    done < /etc/asterisk/pjsip.conf
    echo ""
    echo "Connection Details:"
    echo "  Domain: ${DOMAIN_NAME:-$(hostname -I | awk '{print $1}')}"
    echo "  Port:   ${DEFAULT_SIP_PORT}/udp (LAN) or ${DEFAULT_SIPS_PORT}/tcp (TLS)"
}

# ================================================================
# 4. PTT WIZARD (Fixed: Mute by default)
# ================================================================

configure_ptt_menu() {
    print_header "Configure PTT Button"
    detect_ptt_button
}

detect_ptt_button() {
    # Ensure evtest is installed
    if ! command -v evtest &>/dev/null; then
        apt install -y evtest >/dev/null 2>&1
    fi
    
    # Add user to input group
    [[ -n "$KIOSK_USER" ]] && usermod -aG input "$KIOSK_USER" 2>/dev/null || true
    
    print_info "Scanning input devices..."
    echo ""
    
    declare -a SUGGESTED_DEVICES SUGGESTED_NAMES OTHER_DEVICES OTHER_NAMES
    
    for dev in /dev/input/event*; do
        [[ -e "$dev" ]] || continue
        local name=$(cat "/sys/class/input/$(basename $dev)/device/name" 2>/dev/null || echo "Unknown")
        local lname=$(echo "$name" | tr '[:upper:]' '[:lower:]')
        
        # Filter out system devices that aren't PTT candidates
        if [[ "$lname" =~ (power.button|sleep.button|lid.switch|virtual|video.bus|hdmi|dp,pcm|hotkey|touchpad|touchscreen) ]]; then
            OTHER_DEVICES+=("$dev")
            OTHER_NAMES+=("$name")
        # Prioritize keyboards, USB HID devices, pedals
        elif [[ "$lname" =~ (keyboard|sayo.*nano$|pedal|foot|^hid) ]]; then
            SUGGESTED_DEVICES+=("$dev")
            SUGGESTED_NAMES+=("$name")
        else
            OTHER_DEVICES+=("$dev")
            OTHER_NAMES+=("$name")
        fi
    done
    
    # Display suggested devices first
    if [[ ${#SUGGESTED_DEVICES[@]} -gt 0 ]]; then
        echo -e "${GREEN}Keyboards and USB buttons:${NC}"
        for i in "${!SUGGESTED_DEVICES[@]}"; do
            printf "  ${CYAN}%2d)${NC} %s - %s\n" "$((i+1))" "$(basename ${SUGGESTED_DEVICES[$i]})" "${SUGGESTED_NAMES[$i]}"
        done
        echo ""
    fi
    
    # Display other devices
    if [[ ${#OTHER_DEVICES[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Other devices:${NC}"
        local offset=${#SUGGESTED_DEVICES[@]}
        for i in "${!OTHER_DEVICES[@]}"; do
            printf "  ${CYAN}%2d)${NC} %s - %s\n" "$((offset+i+1))" "$(basename ${OTHER_DEVICES[$i]})" "${OTHER_NAMES[$i]}"
        done
        echo ""
    fi
    
    local ALL_DEVICES=("${SUGGESTED_DEVICES[@]}" "${OTHER_DEVICES[@]}")
    local total=${#ALL_DEVICES[@]}
    
    if [[ $total -eq 0 ]]; then
        print_error "No input devices found"
        return 1
    fi
    
    echo "  0) Back"
    echo ""
    read -p "Select device [1]: " selection
    selection="${selection:-1}"
    
    [[ "$selection" == "0" ]] && return 0
    [[ "$selection" -lt 1 || "$selection" -gt "$total" ]] && { print_error "Invalid selection"; return 1; }
    
    PTT_DEVICE="${ALL_DEVICES[$((selection-1))]}"
    local dev_name=$(cat "/sys/class/input/$(basename $PTT_DEVICE)/device/name" 2>/dev/null || echo "Unknown")
    echo ""
    print_success "Selected: $dev_name"
    echo "          ($PTT_DEVICE)"
    echo ""
    
    # Key detection loop
    while true; do
        echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}  DO NOT PRESS YET - wait for countdown${NC}"
        echo -e "${YELLOW}══════════════════════════════════════════════════${NC}"
        
        for i in 5 4 3 2 1; do
            echo -ne "\r  Waiting... $i "
            sleep 1
        done
        echo ""
        echo ""
        echo -e "${GREEN}>>> NOW PRESS YOUR PTT BUTTON <<<${NC}"
        echo ""
        
        local detected_code=$(timeout 10 evtest "$PTT_DEVICE" 2>/dev/null | grep -m1 "value 1$" | grep -oP 'code \K[0-9]+' || echo "")
        
        if [[ -n "$detected_code" && "$detected_code" -gt 0 ]]; then
            # Map common key codes to friendly names
            local key_name="Key $detected_code"
            case "$detected_code" in
                1) key_name="Escape" ;;
                28) key_name="Enter" ;;
                57) key_name="Spacebar" ;;
                69) key_name="Num Lock" ;;
                113) key_name="Mute" ;;
                114) key_name="Volume Down" ;;
                115) key_name="Volume Up" ;;
                116) key_name="Power" ;;
                142) key_name="Sleep" ;;
                272) key_name="Left Click" ;;
                273) key_name="Right Click" ;;
            esac
            
            print_success "Detected: $key_name (code $detected_code)"
            echo ""
            read -p "Use this key? [Y/n]: " use_key
            
            if [[ ! "$use_key" =~ ^[Nn]$ ]]; then
                PTT_KEYCODE="$detected_code"
                PTT_KEYNAME="$key_name"
                break
            fi
        else
            print_warn "No button press detected"
        fi
        
        echo ""
        echo "  1) Try again"
        echo "  2) Enter key code manually"
        echo "  3) Cancel"
        read -p "Select [1]: " retry
        
        case "${retry:-1}" in
            2)
                read -p "Enter key code: " PTT_KEYCODE
                PTT_KEYNAME="Manual"
                break
                ;;
            3)
                return 1
                ;;
        esac
    done
    
    # Save configuration
    mkdir -p "$(dirname "$PTT_CONFIG_FILE")"
    cat > "$PTT_CONFIG_FILE" << EOF
PTT_DEVICE="$PTT_DEVICE"
PTT_KEYCODE="$PTT_KEYCODE"
PTT_KEYNAME="$PTT_KEYNAME"
EOF
    chmod 600 "$PTT_CONFIG_FILE"
    
    # Also save to main config
    save_config
    
    print_success "PTT configured: $PTT_KEYNAME on $(basename $PTT_DEVICE)"
    
    # Restart PTT service if client is installed
    if [[ "$INSTALLED_CLIENT" == "y" && -n "$KIOSK_USER" ]]; then
        local user_dbus="XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}"
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user restart kiosk-ptt 2>/dev/null || true
    fi
    
    return 0
}

create_ptt_handler() {
    cat > /usr/local/bin/kiosk-ptt << 'PTTSCRIPT'
#!/bin/bash
CONFIG="/etc/easy-asterisk/config"
PTT_CONFIG="/etc/easy-asterisk/ptt-device"
[[ -f "$CONFIG" ]] && source "$CONFIG"
[[ -f "$PTT_CONFIG" ]] && source "$PTT_CONFIG"
[[ -z "$PTT_DEVICE" ]] && exit 0

# Default: Mute audio source on start
pactl set-source-mute @DEFAULT_SOURCE@ 1

# Unmute on press, mute on release
evtest --grab "$PTT_DEVICE" 2>/dev/null | while read -r line; do
    if [[ "$line" =~ "value 1" ]]; then
        pactl set-source-mute @DEFAULT_SOURCE@ 0
    fi
    if [[ "$line" =~ "value 0" ]]; then
        pactl set-source-mute @DEFAULT_SOURCE@ 1
    fi
done
PTTSCRIPT
    chmod +x /usr/local/bin/kiosk-ptt
}

# ================================================================
# 5. AUDIO DUCKING
# ================================================================

configure_audio_ducking() {
    [[ -z "$KIOSK_USER" ]] && return
    local wp_dir="/home/${KIOSK_USER}/.config/wireplumber/wireplumber.conf.d"
    mkdir -p "$wp_dir"
    cat > "${wp_dir}/50-intercom-ducking.conf" << 'EOF'
wireplumber.settings = { linking.allow-moving-streams = true }
EOF
    chown -R ${KIOSK_USER}:${KIOSK_USER} "/home/${KIOSK_USER}/.config"
}

# ================================================================
# 6. DIAGNOSTICS & FIREWALL
# ================================================================

show_port_requirements() {
    print_header "Port / Firewall Requirements"
    echo "This server needs traffic to pass from your Clients (Kiosks/Phones)."
    echo ""
    echo "Does your Asterisk server have a PUBLIC IP (VPS/Cloud)?"
    echo "  -> YES: You must use 'Forwarding' (DNAT) rules on your router."
    echo "  -> NO:  You must use 'Allow/Pass' rules on your VLAN interfaces."
    echo ""
    echo "Required Ports:"
    echo "┌──────────────────┬──────────┬───────────────────────────────┐"
    echo "│ Port             │ Protocol │ Purpose                       │"
    echo "├──────────────────┼──────────┼───────────────────────────────┤"
    echo "│ 5060             │ UDP      │ SIP Signaling (Registration)  │"
    echo "│ 5061             │ TCP      │ SIP-TLS Signaling (Secure)    │"
    echo "│ 10000-20000      │ UDP      │ RTP Media (Audio/Video)       │"
    if [[ "$USE_COTURN" == "y" ]]; then
        echo "│ ${DEFAULT_TURN_PORT}             │ UDP/TCP  │ TURN Signaling (Handshake)    │"
        echo "│ 49152-65535      │ UDP      │ TURN Relay (Actual Media Path)│"
    fi
    echo "└──────────────────┴──────────┴───────────────────────────────┘"
    echo ""
    echo "NOTE: VPN Users"
    echo "If ALL clients and server are on a VPN (Tailscale/NetBird/Wireguard), you DO NOT"
    echo "need port forwarding or COTURN. Just bind Asterisk to the VPN IP."
    echo ""
    echo "For detailed internet calling scenarios, see: Server Settings → Internet Calling Guide"
}

show_internet_calling_guide() {
    print_header "Internet Calling Scenarios"

    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  SCENARIO 1: Simple Internet Calling (No VPN)             ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Setup:"
    echo "  • Asterisk server has public IP (or port forwarding)"
    echo "  • FQDN points to public IP (e.g., sip.example.com)"
    echo "  • Port forward: 5060/5061 (SIP) + 10000-20000 (RTP)"
    echo "  • Clients on LAN or internet"
    echo ""
    echo "Works for:"
    echo "  ${GREEN}✓${NC} Internet users calling in"
    echo "  ${GREEN}✓${NC} LAN users calling each other"
    echo "  ${GREEN}✓${NC} Simple NAT scenarios"
    echo ""
    echo "Limitations:"
    echo "  ${RED}✗${NC} May not work with symmetric NAT"
    echo "  ${RED}✗${NC} May not work with strict corporate firewalls"
    echo "  ${RED}✗${NC} Requires COTURN for VLAN isolation"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  SCENARIO 2: VPN + Internet Calling (BEST!)               ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Setup:"
    echo "  • VPN installed on: Asterisk server + ALL kiosks"
    echo "  • Asterisk listens on: VPN IP (e.g., 100.64.1.1)"
    echo "  • FQDN points to public IP (sip.example.com)"
    echo "  • Port forward: 5060/5061 + 10000-20000 (for internet callers)"
    echo ""
    echo "How it works:"
    echo "  ${BOLD}Kiosks → Server:${NC}"
    echo "    Kiosk registers to Asterisk via VPN IP (100.64.1.1)"
    echo "    No port forwarding needed for kiosks"
    echo "    Works even if kiosks are on different VLANs!"
    echo ""
    echo "  ${BOLD}Internet → Server → Kiosk:${NC}"
    echo "    1. Internet user calls sip.example.com:5060"
    echo "    2. Port forward routes to Asterisk (public interface)"
    echo "    3. Asterisk routes call to kiosk via VPN network"
    echo "    4. Kiosk receives call (even if on VLAN 20!)"
    echo ""
    echo "Benefits:"
    echo "  ${GREEN}✓${NC} No COTURN needed"
    echo "  ${GREEN}✓${NC} Works across VLANs automatically"
    echo "  ${GREEN}✓${NC} Kiosks don't need port forwarding"
    echo "  ${GREEN}✓${NC} Internet users can still call in"
    echo "  ${GREEN}✓${NC} More secure (VPN encrypted)"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  SCENARIO 3: COTURN + VLAN Isolation                      ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Setup:"
    echo "  • OPNsense/pfSense router with VLAN isolation"
    echo "  • COTURN on LAN (e.g., 192.168.1.50)"
    echo "  • Kiosks on isolated VLANs (192.168.2.x, 192.168.3.x, etc.)"
    echo "  • Firewall allows: VLAN → COTURN ports"
    echo "  • Firewall blocks: VLAN → VLAN direct communication"
    echo ""
    echo "How it works:"
    echo "  Kiosk A (VLAN 20) ↔ COTURN ↔ Kiosk B (VLAN 30)"
    echo "  VLANs communicate through COTURN relay"
    echo ""
    echo "When to use:"
    echo "  ${YELLOW}⚠${NC} Only if you can't use VPN"
    echo "  ${YELLOW}⚠${NC} Only if you need strict VLAN isolation"
    echo "  ${YELLOW}⚠${NC} Requires: FQDN, static IP or DDNS, complex firewall rules"
    echo ""
    echo "${CYAN}Recommendation: Use VPN instead - it's simpler and more reliable!${NC}"
    echo ""
    read -p "Press Enter to return..."
}

show_firewall_guide() {
    print_header "OPNsense/pfSense Configuration Guide"

    local server_ip="${ASTERISK_HOST:-192.168.1.50}"
    local server_fqdn="${DOMAIN_NAME:-your.fqdn.com}"

    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           YOUR NETWORK LAYOUT (Example)                       ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "    Internet"
    echo "        ↓"
    echo "    OPNsense Router ($server_fqdn)"
    echo "        ↓"
    echo "    ├─ LAN    (192.168.1.0/24) ← Asterisk + COTURN ($server_ip)"
    echo "    ├─ VLAN 20 (192.168.2.0/24) ← Devices that need intercom"
    echo "    ├─ VLAN 30 (192.168.3.0/24) ← Devices that need intercom"
    echo "    └─ VLAN 40 (192.168.4.0/24) ← Devices that need intercom"
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "${BOLD}STEP 1: PORT FORWARDING (WAN → COTURN/Asterisk)${NC}"
    echo "Location: Firewall → NAT → Port Forward"
    echo ""
    echo "┌───────────┬──────────┬─────────┬──────────────┬──────────────┬────────────────────────┐"
    echo "│ Interface │ Protocol │ Src     │ Dst Port     │ Redirect IP  │ Redirect Port │ Description           │"
    echo "├───────────┼──────────┼─────────┼──────────────┼──────────────┼───────────────┼────────────────────────┤"
    echo "│ WAN       │ UDP      │ *       │ 3478         │ $server_ip   │ 3478          │ COTURN STUN/TURN      │"
    echo "│ WAN       │ UDP/TCP  │ *       │ 5349         │ $server_ip   │ 5349          │ COTURN TLS            │"
    echo "│ WAN       │ UDP      │ *       │ 49152-65535  │ $server_ip   │ 49152-65535   │ COTURN relay          │"
    echo "│ WAN       │ UDP      │ *       │ 5060         │ $server_ip   │ 5060          │ Asterisk SIP          │"
    echo "│ WAN       │ TCP      │ *       │ 5061         │ $server_ip   │ 5061          │ Asterisk SIP-TLS      │"
    echo "└───────────┴──────────┴─────────┴──────────────┴──────────────┴───────────────┴────────────────────────┘"
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "${BOLD}STEP 2: FIREWALL RULES FOR VLAN ISOLATION${NC}"
    echo ""
    echo "${CYAN}━━━ LAN Rules (192.168.1.0/24 - Where Asterisk/COTURN Live) ━━━${NC}"
    echo "Location: Firewall → Rules → LAN"
    echo ""
    echo "┌───┬────────┬──────────┬─────────────────┬─────────────────┬──────────────┬──────────────────────────┐"
    echo "│ # │ Action │ Protocol │ Source          │ Destination     │ Dst Port     │ Description              │"
    echo "├───┼────────┼──────────┼─────────────────┼─────────────────┼──────────────┼──────────────────────────┤"
    echo "│ 1 │ Pass   │ IPv4 *   │ $server_ip      │ any             │ *            │ Asterisk/COTURN outbound │"
    echo "│ 2 │ Pass   │ UDP      │ LAN net         │ $server_ip      │ 3478         │ Local STUN/TURN          │"
    echo "│ 3 │ Pass   │ UDP      │ LAN net         │ $server_ip      │ 5060         │ Local SIP                │"
    echo "│ 4 │ Pass   │ TCP      │ LAN net         │ $server_ip      │ 5061         │ Local SIP-TLS            │"
    echo "│ 5 │ Pass   │ IPv4 *   │ LAN net         │ any             │ *            │ Allow other LAN traffic  │"
    echo "│ 6 │ Block  │ IPv4 *   │ LAN net         │ 192.168.2.0/24  │ *            │ Block to VLAN 20         │"
    echo "│ 7 │ Block  │ IPv4 *   │ LAN net         │ 192.168.3.0/24  │ *            │ Block to VLAN 30         │"
    echo "│ 8 │ Block  │ IPv4 *   │ LAN net         │ 192.168.4.0/24  │ *            │ Block to VLAN 40         │"
    echo "└───┴────────┴──────────┴─────────────────┴─────────────────┴──────────────┴──────────────────────────┘"
    echo ""
    echo "${YELLOW}Note: Rules 6-8 block LAN from initiating connections to VLANs (optional)${NC}"
    echo ""
    echo "${CYAN}━━━ VLAN 20 Rules (192.168.2.0/24) ━━━${NC}"
    echo "Location: Firewall → Rules → VLAN_20"
    echo ""
    echo "┌───┬────────┬──────────┬──────────────┬──────────────┬──────────────┬─────────────────────────────┐"
    echo "│ # │ Action │ Protocol │ Source       │ Destination  │ Dst Port     │ Description                 │"
    echo "├───┼────────┼──────────┼──────────────┼──────────────┼──────────────┼─────────────────────────────┤"
    echo "│ 1 │ Pass   │ UDP      │ VLAN_20 net  │ $server_ip   │ 5060         │ SIP to Asterisk             │"
    echo "│ 2 │ Pass   │ TCP      │ VLAN_20 net  │ $server_ip   │ 5061         │ SIP-TLS to Asterisk         │"
    echo "│ 3 │ Pass   │ UDP      │ VLAN_20 net  │ $server_ip   │ 3478         │ STUN/TURN                   │"
    echo "│ 4 │ Pass   │ UDP      │ VLAN_20 net  │ $server_ip   │ 5349         │ TURN-TLS                    │"
    echo "│ 5 │ Pass   │ UDP      │ VLAN_20 net  │ $server_ip   │ 49152-65535  │ TURN relay ports            │"
    echo "│ 6 │ Pass   │ IPv4 *   │ VLAN_20 net  │ !RFC1918     │ *            │ Internet access only        │"
    echo "│ 7 │ Block  │ IPv4 *   │ VLAN_20 net  │ 192.168.1.0/24│ *           │ Block to LAN (except above) │"
    echo "│ 8 │ Block  │ IPv4 *   │ VLAN_20 net  │ 192.168.3.0/24│ *           │ Block to VLAN 30            │"
    echo "│ 9 │ Block  │ IPv4 *   │ VLAN_20 net  │ 192.168.4.0/24│ *           │ Block to VLAN 40            │"
    echo "└───┴────────┴──────────┴──────────────┴──────────────┴──────────────┴─────────────────────────────┘"
    echo ""
    echo "${BOLD}IMPORTANT:${NC} Rules are processed top-down. Rules 1-5 match first (allow to"
    echo "COTURN/Asterisk), then rules 7-9 block everything else."
    echo ""
    echo "${CYAN}━━━ VLAN 30 Rules (192.168.3.0/24) ━━━${NC}"
    echo "Same as VLAN 20, but:"
    echo "  - Rule 7: Block to 192.168.1.0/24 (LAN)"
    echo "  - Rule 8: Block to 192.168.2.0/24 (VLAN 20)"
    echo "  - Rule 9: Block to 192.168.4.0/24 (VLAN 40)"
    echo ""
    echo "${CYAN}━━━ VLAN 40 Rules (192.168.4.0/24) ━━━${NC}"
    echo "Same as VLAN 20, but:"
    echo "  - Rule 7: Block to 192.168.1.0/24 (LAN)"
    echo "  - Rule 8: Block to 192.168.2.0/24 (VLAN 20)"
    echo "  - Rule 9: Block to 192.168.3.0/24 (VLAN 30)"
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "${BOLD}VISUAL FLOW (How VLANs Communicate)${NC}"
    echo ""
    echo "Device 192.168.2.10 (VLAN 20)"
    echo "    ↓ Firewall allows: .2.10 → .1.50:3478"
    echo "COTURN 192.168.1.50"
    echo "    ↓ Firewall allows: .1.50 → .3.20"
    echo "Device 192.168.3.20 (VLAN 30)"
    echo ""
    echo "${GREEN}✓ VLANs communicate through COTURN:${NC}"
    echo "  192.168.2.10 → 192.168.1.50 → 192.168.3.20 ${GREEN}ALLOWED${NC}"
    echo ""
    echo "${RED}✗ VLANs cannot talk directly:${NC}"
    echo "  192.168.2.10 → 192.168.3.20 ${RED}BLOCKED${NC}"
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    echo "${BOLD}TESTING YOUR CONFIGURATION${NC}"
    echo ""
    echo "Test 1: VLAN 20 can reach COTURN"
    echo "  From device on 192.168.2.x:"
    echo "  ${CYAN}nc -vuz $server_ip 3478${NC}"
    echo "  Should succeed"
    echo ""
    echo "Test 2: VLAN 20 CANNOT reach VLAN 30"
    echo "  From device on 192.168.2.x:"
    echo "  ${CYAN}ping 192.168.3.1${NC}"
    echo "  Should FAIL (timeout)"
    echo ""
    echo "Test 3: Verify traffic flows through COTURN"
    echo "  On Asterisk server:"
    echo "  ${CYAN}tcpdump -i any host $server_ip and port 3478 -n${NC}"
    echo "  You should see packets from 192.168.2.x, 192.168.3.x, 192.168.4.x"
    echo ""
    echo "Test 4: Cross-VLAN call"
    echo "  Device on 192.168.2.x calls device on 192.168.3.x"
    echo "  Check COTURN logs:"
    echo "  ${CYAN}journalctl -u coturn -f${NC}"
    echo ""
    read -p "Press Enter to return..."
}

show_preflight_check() {
    print_header "Pre-Flight Requirements Check"
    echo "Modern browsers (Chrome, Safari, Kiosk Mode) have strict security settings."
    echo ""
    echo "1. HTTPS / SSL Certificate (Required for Camera/Mic)"
    echo "   - Browsers block Mic/Cam on 'Insecure Origins' (HTTP)."
    echo "   - Exception: http://localhost is allowed."
    echo "   - Solution: You NEED a domain (FQDN) and SSL Cert (LetsEncrypt)."
    echo "   - Workaround: Use the 'Caddy Cert Sync' option in this script."
    echo ""
    echo "2. Static vs Dynamic IP"
    echo "   - If your Public IP changes, COTURN will break."
    echo "   - Solution: Use the 'Update IP manually' or auto-script in the menu."
    echo ""
    echo "3. VPN Alternative"
    echo "   - A VPN (Tailscale) negates the need for COTURN and Port Forwarding."
    echo "   - It treats all devices as if they are on the same flat network."
    echo ""
    read -p "Press Enter to return..."
}

test_sip_connectivity() {
    print_header "SIP Connectivity Test"
    if systemctl is-active asterisk >/dev/null; then
        print_success "Asterisk Running"
    else
        print_error "Asterisk Down"
    fi
    echo ""
    echo "Listening ports:"
    ss -ulnp | grep 5060 || echo "  UDP 5060: Not listening"
    ss -tlnp | grep 5061 || echo "  TCP 5061: Not listening"
    if [[ -n "$DOMAIN_NAME" ]]; then
        echo ""
        echo "TLS Certificate check:"
        timeout 5 openssl s_client -connect localhost:5061 -servername "$DOMAIN_NAME" 2>/dev/null | grep "Verify return code" || echo "  TLS test failed"
    fi
}

verify_cidr_config() {
    print_header "CIDR Configuration"
    local my_ip=$(hostname -I | cut -d' ' -f1)
    echo "Server IP: $my_ip"
    echo ""
    echo "Current NAT settings in pjsip.conf:"
    grep -E "external_|local_net" /etc/asterisk/pjsip.conf 2>/dev/null || echo "  No NAT settings found"
}

watch_live_logs() {
    print_header "Live Debugging"
    echo "Enabling PJSIP Logger..."
    asterisk -rx "module load res_pjsip_logger.so" 2>/dev/null || true
    asterisk -rx "pjsip set logger on" 2>/dev/null
    echo ""
    echo "Options:"
    echo "  1) Asterisk Console (verbose)"
    echo "  2) Packet Capture (tcpdump)"
    read -p "Select [1]: " pcap
    if [[ "$pcap" == "2" ]]; then
        echo "Starting tcpdump. Press CTRL+C to stop."
        tcpdump -i any port 5060 or port 5061 -nn -v
    else
        echo "Starting Console. Press CTRL+C to exit."
        asterisk -rvvv
    fi
    asterisk -rx "pjsip set logger off" 2>/dev/null
}

router_doctor() {
    print_header "Router Traffic Doctor"
    if ! systemctl is-active asterisk >/dev/null; then
        print_error "Asterisk is NOT RUNNING"
        restart_asterisk_safe
        return
    fi
    
    print_success "Asterisk is UP"
    echo ""
    echo "Server Listening IPs:"
    ip -o -4 addr show | awk '{print "  " $2 ": " $4}'
    echo ""
    echo "Instructions:"
    echo "  1. Take out your phone/laptop"
    echo "  2. Attempt to REGISTER or CALL"
    echo "  3. I will listen for 15 seconds"
    echo ""
    read -p "Press Enter to start listening..."
    
    if timeout 15 tcpdump -i any -c 1 "port 5060 or port 5061" 2>/dev/null; then
        echo ""
        print_success "PACKET RECEIVED! Router forwarding is working."
    else
        echo ""
        print_error "NO PACKETS RECEIVED."
        echo "Your router or firewall is blocking the connection."
    fi
}

configure_local_client() {
    print_header "Configure Local Client"
    load_config
    if [[ -z "$KIOSK_USER" ]]; then
        local default_user="${SUDO_USER:-$USER}"
        read -p "User [$default_user]: " KIOSK_USER
        KIOSK_USER="${KIOSK_USER:-$default_user}"
        KIOSK_UID=$(id -u "$KIOSK_USER" 2>/dev/null)
    fi
    
    if [[ ! -d "/home/${KIOSK_USER}/.baresip" ]]; then
        print_error "Baresip config not found for $KIOSK_USER"
        return
    fi
    
    read -p "Extension: " ext
    read -p "Password: " pass
    read -p "Server Domain/IP: " server
    
    local transport_str="udp"
    local media_enc=""
    
    if [[ "$server" =~ [a-zA-Z] ]]; then 
        print_info "Domain detected. Using TLS."
        transport_str="tls"
        media_enc=";mediaenc=srtp"
    fi
    
    echo ""
    echo "Answer Mode:"
    echo "  1) Manual (ring on incoming)"
    echo "  2) Auto (auto-answer)"
    read -p "Select [1]: " amode
    local answermode="manual"
    [[ "$amode" == "2" ]] && answermode="auto"
    
    echo ""
    echo "Enable TURN? (Required if behind NAT/VLAN without VPN)"
    read -p "Use TURN server? [y/N]: " use_turn
    local turn_config=""
    if [[ "$use_turn" =~ ^[Yy]$ ]]; then
        read -p "TURN User [${TURN_USER}]: " t_user
        t_user="${t_user:-$TURN_USER}"
        read -p "TURN Pass [${TURN_PASS}]: " t_pass
        t_pass="${t_pass:-$TURN_PASS}"
        local turn_host="${server}"
        if [[ ! "$turn_host" =~ [a-zA-Z] ]]; then
             # If server is IP, ask if TURN host is different
             read -p "TURN Host [${server}]: " th
             turn_host="${th:-$server}"
        fi
        turn_config="turn_server turn:${t_user}:${t_pass}@${turn_host}:3478"
    fi
    
    # Update config file for TURN
    local conf_file="/home/${KIOSK_USER}/.baresip/config"
    if [[ -f "$conf_file" ]]; then
        sed -i '/^turn_server/d' "$conf_file"
        if [[ -n "$turn_config" ]]; then
            echo "$turn_config" >> "$conf_file"
            print_success "TURN configuration added"
        fi
    fi
    
    cat > "/home/${KIOSK_USER}/.baresip/accounts" << EOF
<sip:${ext}@${server};transport=${transport_str}>;auth_pass=${pass};answermode=${answermode}${media_enc}
EOF
    chown ${KIOSK_USER}:${KIOSK_USER} "/home/${KIOSK_USER}/.baresip/accounts"
    
    local user_dbus="XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}"
    sudo -u "${KIOSK_USER}" $user_dbus systemctl --user restart baresip 2>/dev/null
    
    print_success "Client Updated & Restarted"
}

run_client_diagnostics() {
    print_header "Client Diagnostics"
    load_config
    local t_user="${KIOSK_USER:-$SUDO_USER}"
    t_user="${t_user:-$USER}"
    local t_uid=$(id -u "$t_user" 2>/dev/null)
    
    echo -e "User: ${BOLD}$t_user${NC}"
    echo "---------------------------------------------------"
    if sudo -u "$t_user" XDG_RUNTIME_DIR=/run/user/$t_uid systemctl --user is-active baresip >/dev/null 2>&1; then
        print_success "Baresip RUNNING"
    else
        print_error "Baresip STOPPED/FAILED"
    fi
    echo "---------------------------------------------------"
    
    echo "Network Interface:"
    grep "^net_interface" "/home/$t_user/.baresip/config" 2>/dev/null || echo "  Not set"
    
    echo "---------------------------------------------------"
    echo "Account Config:"
    cat "/home/$t_user/.baresip/accounts" 2>/dev/null | sed 's/auth_pass=[^;]*/auth_pass=***/' || echo "  Not found"
    
    echo "---------------------------------------------------"
    if [[ -n "$ASTERISK_HOST" ]]; then
        echo -n "Server ($ASTERISK_HOST): "
        if ping -c 1 -W 2 "$ASTERISK_HOST" >/dev/null 2>&1; then
            print_success "Reachable"
        else
            print_error "Unreachable"
        fi
    fi
    echo "---------------------------------------------------"
    echo "Last 15 lines of log:"
    sudo -u "$t_user" journalctl --user -u baresip -n 15 --no-pager 2>/dev/null || echo "  No logs"
    echo "---------------------------------------------------"
}

run_audio_test() {
    print_header "Audio Test"
    echo "Playing test tone..."
    speaker-test -t sine -f 440 -c 2 -l 1 >/dev/null 2>&1
    echo ""
    read -p "Did you hear audio? [y/N]: " res
    if [[ "$res" =~ ^[Yy]$ ]]; then
        print_success "Audio OK"
    else
        print_error "Check volume/connections"
    fi
}

verify_audio_setup() {
    print_header "Audio Verification"
    echo "=== Codecs ==="
    asterisk -rx "core show codecs" 2>/dev/null | grep -E "(opus|ulaw|alaw|g722)" || echo "  N/A"
    echo ""
    echo "=== PJSIP Modules ==="
    asterisk -rx "module show like pjsip" 2>/dev/null | head -10 || echo "  N/A"
    echo ""
    echo "=== Certificate ==="
    if [[ -f /etc/asterisk/certs/server.crt ]]; then
        openssl x509 -in /etc/asterisk/certs/server.crt -noout -subject -dates 2>/dev/null
    else
        echo "  None"
    fi
}

# ================================================================
# 7. ASTERISK CONFIG
# ================================================================

fix_asterisk_systemd() {
    print_info "Configuring systemd..."
    mkdir -p /etc/systemd/system/asterisk.service.d/
    cat > /etc/systemd/system/asterisk.service.d/override.conf << 'SVCEOF'
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=
ExecStart=/usr/sbin/asterisk -f -U asterisk -G asterisk
RuntimeDirectory=asterisk
RuntimeDirectoryMode=0750
MemoryMax=infinity
TasksMax=infinity
KillMode=mixed
KillSignal=SIGTERM
TimeoutStartSec=60
TimeoutStopSec=30
SendSIGKILL=no
Restart=always
RestartSec=10
Type=simple
SVCEOF
    systemctl daemon-reload
}

recover_xml_docs() {
    mkdir -p /var/lib/asterisk/documentation/thirdparty
    chown -R asterisk:asterisk /var/lib/asterisk/documentation 2>/dev/null
}

repair_core_configs() {
    print_info "Repairing configs..."
    
    # Copy modules (not symlink - AppArmor blocks symlinks)
    if [[ -d "/usr/lib/x86_64-linux-gnu/asterisk/modules" ]]; then
        mkdir -p /usr/lib/asterisk/modules
        cp -rn /usr/lib/x86_64-linux-gnu/asterisk/modules/* /usr/lib/asterisk/modules/ 2>/dev/null || true
    fi

    mkdir -p /etc/asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk /var/run/asterisk
    recover_xml_docs
    
    if [[ ! -f /etc/asterisk/asterisk.conf ]]; then
        cat > /etc/asterisk/asterisk.conf << EOF
[directories]
astetcdir => /etc/asterisk
astmoddir => /usr/lib/asterisk/modules
astvarlibdir => /var/lib/asterisk
astdbdir => /var/lib/asterisk
astkeydir => /var/lib/asterisk
astdatadir => /var/lib/asterisk
astagidir => /var/lib/asterisk/agi-bin
astspooldir => /var/spool/asterisk
astrundir => /var/run/asterisk
astlogdir => /var/log/asterisk
EOF
    fi

    cat > /etc/asterisk/modules.conf << EOF
[modules]
autoload=yes
noload => chan_sip.so
noload => chan_iax2.so
load => res_pjsip.so
load => res_pjsip_session.so
load => res_pjsip_logger.so
load => chan_pjsip.so
load => codec_ulaw.so
load => codec_alaw.so
load => codec_g722.so
load => codec_opus.so
load => res_rtp_asterisk.so
load => app_dial.so
load => app_page.so
load => pbx_config.so
EOF
    
    for conf in stasis ari http manager geolocation; do
        cat > "/etc/asterisk/${conf}.conf" << EOF
[general]
enabled = no
EOF
    done
    
    if [[ ! -f /etc/asterisk/sorcery.conf ]]; then
        cat > /etc/asterisk/sorcery.conf << EOF
[res_pjsip]
endpoint=config,pjsip.conf,criteria=type=endpoint
auth=config,pjsip.conf,criteria=type=auth
aor=config,pjsip.conf,criteria=type=aor
transport=config,pjsip.conf,criteria=type=transport
EOF
    fi
    
    # Configure RTP with TURN/STUN
    local turn_host="${DOMAIN_NAME:-${ASTERISK_HOST:-$(hostname -I | cut -d' ' -f1)}}"
    local turn_config=""

    if [[ "$USE_COTURN" == "y" && -n "$TURN_USER" && -n "$TURN_PASS" ]]; then
        turn_config="stunaddr=${turn_host}:${DEFAULT_TURN_PORT}
turnaddr=${turn_host}:${DEFAULT_TURN_PORT}
turnusername=${TURN_USER}
turnpassword=${TURN_PASS}"
        print_info "RTP.conf: Configured with COTURN server"
    elif [[ "$USE_GOOGLE_STUN" == "y" ]]; then
        turn_config="stunaddr=stun.l.google.com:19302"
        print_info "RTP.conf: Using Google STUN fallback"
    else
        turn_config="# STUN/TURN not configured - using direct connections"
        print_info "RTP.conf: No STUN/TURN (direct connections only)"
    fi

    cat > /etc/asterisk/rtp.conf << EOF
; Easy Asterisk RTP Configuration
; Generated: $(date)
[general]
rtpstart=10000
rtpend=20000
strictrtp=yes
icesupport=yes
${turn_config}
EOF
    
    cat > /etc/asterisk/logger.conf << EOF
[general]
[logfiles]
console => notice,warning,error
EOF

    rm -f /var/lib/asterisk/.asterisk_history
    chown -R asterisk:asterisk /etc/asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk 2>/dev/null || true
    chown -R asterisk:asterisk /usr/lib/asterisk/modules 2>/dev/null || true
}

generate_pjsip_conf() {
    print_info "Generating PJSIP..."
    load_config
    local conf_file="/etc/asterisk/pjsip.conf"
    backup_config "$conf_file"
    
    # Prioritize CURRENT_PUBLIC_IP from coturn/updater if available, else detect
    local public_ip="${CURRENT_PUBLIC_IP}"
    if [[ -z "$public_ip" ]]; then
        public_ip=$(curl -s -4 --connect-timeout 5 ifconfig.me 2>/dev/null || echo "")
    fi
    
    local raw_cidr=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -1)
    local default_cidr="$raw_cidr"
    if [[ "$raw_cidr" =~ \.([0-9]+)/24$ ]]; then default_cidr="${raw_cidr%.*}.0/24"; fi
    
    # Use stored CIDR if available
    local local_net="${LOCAL_CIDR:-$default_cidr}"
    
    local nat_settings=""
    if [[ -n "$public_ip" && -n "$DOMAIN_NAME" ]]; then
        nat_settings="external_media_address=$public_ip
external_signaling_address=$public_ip
local_net=$local_net"
        print_info "NAT: Public IP=$public_ip, Local=$local_net"
    fi

    cat > "$conf_file" << EOF
; Easy Asterisk v1.23 (OPNsense/VLAN Ready)
; Generated: $(date)
[global]
type=global
user_agent=EasyAsterisk

[transport-udp]
type=transport
protocol=udp
bind=0.0.0.0:${DEFAULT_SIP_PORT}
ice_support=yes
${nat_settings}

[transport-tcp]
type=transport
protocol=tcp
bind=0.0.0.0:${DEFAULT_SIP_PORT}
ice_support=yes
${nat_settings}

[transport-tls]
type=transport
protocol=tls
bind=0.0.0.0:${DEFAULT_SIPS_PORT}
ice_support=yes
cert_file=/etc/asterisk/certs/server.crt
priv_key_file=/etc/asterisk/certs/server.key
ca_list_file=/etc/ssl/certs/ca-certificates.crt
method=tlsv1_2
${nat_settings}

EOF

    local backup_file=$(ls -t "${conf_file}.backup-"* 2>/dev/null | head -1)
    if [[ -f "$backup_file" ]]; then
        awk '/^; === Device:/{flag=1} flag' "$backup_file" >> "$conf_file"
        print_success "Restored devices from backup"
    fi
    chown asterisk:asterisk "$conf_file"
}

rebuild_dialplan() {
    local quiet=$1
    [[ "$quiet" != "quiet" ]] && print_info "Rebuilding dialplan..."
    local conf_file="/etc/asterisk/extensions.conf"
    backup_config "$conf_file"
    
    cat > "$conf_file" << EOF
[general]
static=yes
writeprotect=no
[default]
exten => _X.,1,Hangup()
[intercom]
EOF

    local dev_name="" dev_cat="" dev_auto="" dev_aa_override=""
    while IFS= read -r line; do
        if [[ "$line" == *"; === Device:"* ]]; then
            dev_aa_override=""
            local temp="${line#*; === Device: }"
            temp="${temp% ===}"
            if [[ "$temp" == *"[AA:yes]"* ]]; then
                dev_aa_override="yes"; temp="${temp% [AA:yes]}"
            elif [[ "$temp" == *"[AA:no]"* ]]; then
                dev_aa_override="no"; temp="${temp% [AA:no]}"
            fi
            dev_cat="${temp##* (}"; dev_cat="${dev_cat%)}"
            dev_name="${temp% (*)}"
            dev_auto="no"
            local cat_data=$(grep "^${dev_cat}|" "$CATEGORIES_FILE" 2>/dev/null || true)
            if [[ -n "$cat_data" ]]; then
                local is_auto=$(echo "$cat_data" | cut -d'|' -f3)
                [[ "$is_auto" == "yes" ]] && dev_auto="yes"
            fi
            [[ "$dev_aa_override" == "yes" ]] && dev_auto="yes"
            [[ "$dev_aa_override" == "no" ]] && dev_auto="no"
        fi
        if [[ "$line" =~ ^\[([0-9]+)\] ]]; then
            local ext="${BASH_REMATCH[1]}"
            if [[ -n "$dev_name" ]]; then
                if [[ "$dev_auto" == "yes" ]]; then
                    cat >> "$conf_file" << EOF
exten => ${ext},1,NoOp(Auto-Answer ${ext})
 same => n,Set(PJSIP_HEADER(add,Call-Info)=\;answer-after=0)
 same => n,Set(PJSIP_HEADER(add,Alert-Info)=auto-answer)
 same => n,Dial(PJSIP/${ext},60)
 same => n,Hangup()

EOF
                else
                    cat >> "$conf_file" << EOF
exten => ${ext},1,NoOp(Call ${ext})
 same => n,Dial(PJSIP/${ext},60)
 same => n,Hangup()

EOF
                fi
                dev_name=""
            fi
        fi
    done < /etc/asterisk/pjsip.conf

    # Add rooms
    if [[ -f "$ROOMS_FILE" ]]; then
        while IFS='|' read -r rext rname rmem rtime rtype; do
            [[ "$rext" =~ ^# ]] && continue
            [[ -z "$rext" ]] && continue
            local dial_list=""
            IFS=',' read -ra EXTS <<< "$rmem"
            for ext in "${EXTS[@]}"; do
                ext=$(echo "$ext" | tr -d ' ')
                [[ -n "$dial_list" ]] && dial_list="${dial_list}&"
                dial_list="${dial_list}PJSIP/${ext}"
            done
            if [[ "$rtype" == "page" ]]; then
                cat >> "$conf_file" << EOF
; Room: ${rname} (Page)
exten => ${rext},1,NoOp(Page ${rname})
 same => n,Set(PJSIP_HEADER(add,Call-Info)=\;answer-after=0)
 same => n,Page(${dial_list},i,${rtime})
 same => n,Hangup()

EOF
            else
                cat >> "$conf_file" << EOF
; Room: ${rname} (Ring)
exten => ${rext},1,NoOp(Call ${rname})
 same => n,Dial(${dial_list},${rtime})
 same => n,Hangup()

EOF
            fi
        done < "$ROOMS_FILE"
    fi
    
    chown -R asterisk:asterisk /etc/asterisk
    asterisk -rx "dialplan reload" &>/dev/null || true
}

configure_asterisk() {
    if ! id asterisk >/dev/null 2>&1; then
        useradd -r -s /bin/false -d /var/lib/asterisk asterisk 2>/dev/null || true
    fi

    print_info "Configuring Asterisk..."
    fix_asterisk_systemd
    initialize_default_categories
    repair_core_configs
    
    mkdir -p /etc/asterisk/certs
    if [[ ! -f /etc/asterisk/certs/server.crt ]]; then
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout /etc/asterisk/certs/server.key \
            -out /etc/asterisk/certs/server.crt \
            -subj "/CN=asterisk-local" 2>/dev/null
    fi
    
    chown asterisk:asterisk /etc/asterisk/certs/server.* 2>/dev/null || true
    chmod 644 /etc/asterisk/certs/server.crt 2>/dev/null || true
    chmod 600 /etc/asterisk/certs/server.key 2>/dev/null || true
    
    generate_pjsip_conf
    rebuild_dialplan "quiet"
    
    restart_asterisk_safe
    systemctl enable asterisk
}

restart_asterisk_safe() {
    print_info "Restarting Asterisk..."
    systemctl stop asterisk 2>/dev/null || true
    sleep 2
    # Use -x for exact match to avoid killing this script
    pkill -9 -x asterisk 2>/dev/null || true
    rm -f /var/run/asterisk/asterisk.pid 2>/dev/null || true
    rm -f /var/lib/asterisk/.asterisk_history 2>/dev/null || true
    systemctl start asterisk
    sleep 3
    
    if systemctl is-active asterisk >/dev/null; then
        print_success "Asterisk running"
    else
        print_error "Asterisk failed to start"
        journalctl -u asterisk -n 15 --no-pager
    fi
}

# ================================================================
# 8. CLIENT CONFIG
# ================================================================

configure_baresip() {
    local baresip_dir="/home/${KIOSK_USER}/.baresip"
    mkdir -p "$baresip_dir"

    # Detect network interface
    local found_iface=""
    for target in 8.8.8.8 1.1.1.1 9.9.9.9; do
        local iface=$(ip route get "$target" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
        if [[ -n "$iface" ]]; then
            found_iface="$iface"
            print_success "Network interface: $found_iface"
            break
        fi
    done

    cat > "${baresip_dir}/config" << EOF
poll_method epoll
audio_player pulse
audio_source pulse
audio_alert pulse
sip_autoanswer yes
sip_cafile /etc/ssl/certs/ca-certificates.crt
rtp_timeout 0
net_af ipv4
module_path /usr/lib/baresip/modules
module srtp.so
module stdio.so
module pulse.so
module g711.so
module opus.so
module account.so
module stun.so
module ice.so
module turn.so
EOF

    [[ -n "$found_iface" ]] && echo "net_interface $found_iface" >> "${baresip_dir}/config"

    # Configure TURN if COTURN is enabled
    if [[ "$USE_COTURN" == "y" && -n "$TURN_USER" && -n "$TURN_PASS" ]]; then
        local turn_host="${DOMAIN_NAME:-${ASTERISK_HOST}}"
        echo "turn_server turn:${TURN_USER}:${TURN_PASS}@${turn_host}:${DEFAULT_TURN_PORT}" >> "${baresip_dir}/config"
        print_success "Baresip: TURN server configured (${turn_host}:${DEFAULT_TURN_PORT})"
    fi

    local transport="udp"
    local mediaenc=""
    if [[ "$ENABLE_TLS" == "y" ]]; then
        transport="tls"
        mediaenc=";mediaenc=srtp"
    fi

    local amode="${CLIENT_ANSWERMODE:-auto}"

    cat > "${baresip_dir}/accounts" << EOF
<sip:${KIOSK_EXTENSION}@${ASTERISK_HOST};transport=${transport}>;auth_pass=${SIP_PASSWORD};answermode=${amode}${mediaenc}
EOF
    chown -R ${KIOSK_USER}:${KIOSK_USER} "$baresip_dir"
    chmod 700 "$baresip_dir"

    configure_audio_ducking
    create_ptt_handler
    create_baresip_launcher
}

create_baresip_launcher() {
    local launcher_user="${KIOSK_USER}"
    cat > /usr/local/bin/easy-asterisk-launcher << LAUNCHER
#!/bin/bash
CONFIG_FILE="/home/${launcher_user}/.baresip/config"
TARGETS=("8.8.8.8" "1.1.1.1" "9.9.9.9")
FOUND_IFACE=""

for i in {1..6}; do
    for target in "\${TARGETS[@]}"; do
        IFACE=\$(ip route get "\$target" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i=="dev") print \$(i+1)}' | head -1)
        if [[ -n "\$IFACE" ]]; then
            FOUND_IFACE="\$IFACE"
            break 2
        fi
    done
    sleep 5
done

if [[ -f "\$CONFIG_FILE" && -n "\$FOUND_IFACE" ]]; then
    sed -i '/^#*net_interface/d' "\$CONFIG_FILE"
    echo "net_interface \${FOUND_IFACE}" >> "\$CONFIG_FILE"
fi

exec /usr/bin/baresip -f "/home/${launcher_user}/.baresip"
LAUNCHER
    chmod +x /usr/local/bin/easy-asterisk-launcher
}

enable_client_services() {
    local systemd_dir="/home/${KIOSK_USER}/.config/systemd/user"
    mkdir -p "$systemd_dir"
    
    # Baresip service
    cat > "${systemd_dir}/baresip.service" << EOF
[Unit]
Description=Baresip SIP Client
After=pipewire.service network-online.target
Wants=network-online.target pipewire.service

[Service]
Type=simple
ExecStart=/usr/local/bin/easy-asterisk-launcher
Restart=always
RestartSec=5
Environment=XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}

[Install]
WantedBy=default.target
EOF

    # PTT service
    cat > "${systemd_dir}/kiosk-ptt.service" << EOF
[Unit]
Description=PTT Button Handler
After=pipewire.service

[Service]
Type=simple
ExecStartPre=/bin/sleep 3
ExecStart=/usr/local/bin/kiosk-ptt
Restart=always
RestartSec=5
Environment=XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}

[Install]
WantedBy=default.target
EOF
    
    chown -R ${KIOSK_USER}:${KIOSK_USER} "/home/${KIOSK_USER}/.config"
    
    if [[ -n "$KIOSK_USER" ]]; then
        loginctl enable-linger $KIOSK_USER 2>/dev/null || true
        local user_dbus="XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}"
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user daemon-reload
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user enable baresip kiosk-ptt
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user restart baresip kiosk-ptt
    fi
}

# ================================================================
# 9. CERTIFICATE HANDLING
# ================================================================

check_cert_coverage() {
    local cert_file=$1 target_domain=$2 base_domain=$3
    [[ ! -f "$cert_file" ]] && return 1
    local sans=$(openssl x509 -in "$cert_file" -text -noout 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -1)
    echo "$sans" | grep -q "DNS:${target_domain}" && return 0
    echo "$sans" | grep -q "DNS:\*.${base_domain}" && return 0
    return 1
}

setup_caddy_cert_sync() {
    local mode=$1
    [[ "$mode" == "force" ]] && print_header "Caddy Cert Sync"

    load_config
    local domain=${DOMAIN_NAME:-sip.example.com}
    local turn_domain=${TURN_DOMAIN:-$domain}

    if [[ "$mode" == "force" ]]; then
        read -p "SIP Domain [$domain]: " input_domain
        domain="${input_domain:-$domain}"
        read -p "TURN Domain [$turn_domain]: " input_turn
        turn_domain="${input_turn:-$turn_domain}"
    fi

    local actual_user="${SUDO_USER:-$USER}"
    local actual_home=$(eval echo ~"$actual_user")
    local base_domain=$(echo "$domain" | awk -F. '{print $(NF-1)"."$NF}')

    local search_paths=(
        "${actual_home}/docker/caddy/ssl"
        "${actual_home}/docker/caddy/caddy_data"
        "${actual_home}/docker/caddy/caddy_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory"
        "/var/lib/caddy"
        "/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory"
        "/data/caddy"
        "/root/.local/share/caddy/certificates"
    )
    local caddy_cert="" caddy_key=""

    [[ "$mode" == "force" ]] && echo "Searching for certificates covering: $domain and $turn_domain..."

    # Search for a cert that covers both domains (or just SIP if they're the same)
    for base_path in "${search_paths[@]}"; do
        if ! sudo test -d "$base_path" 2>/dev/null; then continue; fi
        [[ "$mode" == "force" ]] && echo "  Checking: $base_path"

        local candidates=$(sudo find "$base_path" -maxdepth 5 -type f \( -name "fullchain.pem" -o -name "*.crt" \) 2>/dev/null)

        for cert in $candidates; do
            sudo cp "$cert" /tmp/cert_check.pem 2>/dev/null || continue

            # Check if cert covers SIP domain
            local sip_ok=false
            local turn_ok=false

            if check_cert_coverage "/tmp/cert_check.pem" "$domain" "$base_domain"; then
                sip_ok=true
            fi

            # If TURN domain is different, check if cert covers it too
            if [[ "$turn_domain" != "$domain" ]]; then
                if check_cert_coverage "/tmp/cert_check.pem" "$turn_domain" "$base_domain"; then
                    turn_ok=true
                fi
            else
                turn_ok=true  # Same domain, so already covered
            fi

            # If cert covers both (or just SIP if same), we found it!
            if [[ "$sip_ok" == "true" && "$turn_ok" == "true" ]]; then
                [[ "$mode" == "force" ]] && print_success "Found cert covering both domains: $cert"
                caddy_cert="$cert"
                local dir=$(dirname "$cert")
                local name=$(basename "$cert")
                if [[ "$name" == "fullchain.pem" ]]; then
                    caddy_key="${dir}/privkey.pem"
                else
                    caddy_key=$(echo "$cert" | sed 's/\.crt/\.key/')
                fi
                if sudo test -f "$caddy_key"; then
                    rm -f /tmp/cert_check.pem
                    break 2
                fi
            fi
            rm -f /tmp/cert_check.pem
        done
    done

    if [[ -n "$caddy_cert" && -n "$caddy_key" ]]; then
        mkdir -p /etc/asterisk/certs
        sudo cat "$caddy_cert" > /etc/asterisk/certs/server.crt
        sudo cat "$caddy_key" > /etc/asterisk/certs/server.key

        chown asterisk:asterisk /etc/asterisk/certs/server.*
        chmod 644 /etc/asterisk/certs/server.crt
        chmod 600 /etc/asterisk/certs/server.key

        DOMAIN_NAME="$domain"
        TURN_DOMAIN="$turn_domain"
        ENABLE_TLS="y"
        ASTERISK_HOST="$domain"
        save_config

        generate_pjsip_conf
        restart_asterisk_safe

        if [[ "$turn_domain" != "$domain" ]]; then
            [[ "$mode" == "force" ]] && print_success "Certificates installed for $domain and $turn_domain"
        else
            [[ "$mode" == "force" ]] && print_success "Certificates installed for $domain"
        fi
        return 0
    else
        if [[ "$turn_domain" != "$domain" ]]; then
            [[ "$mode" == "force" ]] && print_warn "No certificate found covering both $domain and $turn_domain"
            [[ "$mode" == "force" ]] && echo "Hint: Use a wildcard cert (*.$(echo $domain | awk -F. '{print $(NF-1)"."$NF}')) or a cert with both domains in SAN"
        else
            [[ "$mode" == "force" ]] && print_warn "No matching certificates found for $domain"
        fi
        return 1
    fi
}

setup_internet_access() {
    print_header "Setup Internet Access"
    
    echo "Select Certificate Source:"
    echo "  1) Auto-Sync from Caddy (Docker/Native)"
    echo "  2) Standalone Certbot (Requires Port 80 open)"
    echo "  3) Self-Signed (Internal testing only)"
    echo "  4) Manual Path"
    echo "  0) Cancel"
    read -p "Select: " cert_opt
    
    [[ "$cert_opt" == "0" ]] && return

    # Show port requirements
    show_preflight_check
    show_port_requirements
    echo ""
    read -p "Continue? [Y/n]: " cont
    [[ "$cont" =~ ^[Nn]$ ]] && return

    load_config
    read -p "FQDN [${DOMAIN_NAME:-sip.example.com}]: " fqdn
    DOMAIN_NAME="${fqdn:-${DOMAIN_NAME:-sip.example.com}}"
    ASTERISK_HOST="$DOMAIN_NAME"
    
    echo ""
    echo "TURN domain (for COTURN server):"
    echo "  → Press Enter to use same domain: ${DOMAIN_NAME}"
    echo "  → Or enter separate domain (e.g., turn.example.com)"
    read -p "TURN domain [$DOMAIN_NAME]: " t_dom
    TURN_DOMAIN="${t_dom:-$DOMAIN_NAME}"

    if [[ "$TURN_DOMAIN" == "$DOMAIN_NAME" ]]; then
        print_info "Using single domain for both SIP and TURN: $DOMAIN_NAME"
    else
        print_info "Separate domains: SIP=$DOMAIN_NAME, TURN=$TURN_DOMAIN"
        print_warn "Make sure your certificate covers BOTH domains!"
    fi
    
    # CIDR Prompt
    echo ""
    print_header "Local Network CIDR"
    local raw_cidr=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -1)
    local default_cidr="$raw_cidr"
    if [[ "$raw_cidr" =~ \.([0-9]+)/24$ ]]; then default_cidr="${raw_cidr%.*}.0/24"; fi
    echo "This helps Asterisk distinguish local vs external traffic."
    read -p "Local network CIDR [$default_cidr]: " local_net
    LOCAL_CIDR="${local_net:-$default_cidr}"
    
    save_config
    
    case "$cert_opt" in
        1) # Caddy
            # Show Caddy Helper text
            echo "---------------------------------------------------------"
            echo "CADDY HELPER: Ensure these are in your Caddyfile to get certs:"
            echo ""
            echo "${DOMAIN_NAME} {"
            echo "    respond \"Asterisk Cert Placeholder\" 200"
            echo "}"
            if [[ "$TURN_DOMAIN" != "$DOMAIN_NAME" ]]; then
                echo ""
                echo "${TURN_DOMAIN} {"
                echo "    respond \"TURN Cert Placeholder\" 200"
                echo "}"
            fi
            echo ""
            echo "Restart Caddy, wait 30s, then press Enter."
            echo "---------------------------------------------------------"
            read -p "Press Enter to sync..."
            if setup_caddy_cert_sync "auto"; then
                print_success "Setup complete using Caddy certificates!"
            else
                print_error "Caddy sync failed. Ensure Caddy is running."
                return
            fi
            ;;
        2) # Certbot
            print_info "Installing Certbot..."
            apt install -y certbot
            certbot certonly --standalone -d "$DOMAIN_NAME" --non-interactive --agree-tos --register-unsafely-without-email
            if [[ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]]; then
                mkdir -p /etc/asterisk/certs
                cat "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" > /etc/asterisk/certs/server.crt
                cat "/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem" > /etc/asterisk/certs/server.key
                chown asterisk:asterisk /etc/asterisk/certs/server.*
                print_success "Certbot Success"
            else
                print_error "Certbot failed"
                return
            fi
            ;;
        3) # Self-Signed
            mkdir -p /etc/asterisk/certs
            openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
                -keyout /etc/asterisk/certs/server.key \
                -out /etc/asterisk/certs/server.crt \
                -subj "/CN=$DOMAIN_NAME" 2>/dev/null
            chown asterisk:asterisk /etc/asterisk/certs/server.*
            chmod 644 /etc/asterisk/certs/server.crt
            chmod 600 /etc/asterisk/certs/server.key
            print_success "Self-signed certificate generated"
            print_warn "Clients will need to trust this certificate"
            ;;
        4) # Manual
            read -p "Certificate Path: " cp
            read -p "Private Key Path: " kp
            if [[ -f "$cp" && -f "$kp" ]]; then
                mkdir -p /etc/asterisk/certs
                cat "$cp" > /etc/asterisk/certs/server.crt
                cat "$kp" > /etc/asterisk/certs/server.key
                chown asterisk:asterisk /etc/asterisk/certs/server.*
                print_success "Certificates installed"
            else
                print_error "Files not found!"
                return
            fi
            ;;
    esac

    # Ask about Google STUN fallback
    if [[ "$USE_COTURN" != "y" ]]; then
        echo ""
        echo "─────────────────────────────────────────────────────────────"
        echo "STUN/TURN Configuration"
        echo ""
        echo "Without a TURN server (COTURN), clients may have trouble with"
        echo "NAT traversal and cross-VLAN calls."
        echo ""
        echo "Would you like to enable Google's public STUN server as a fallback?"
        echo "  ${GREEN}Pro:${NC} Free, helps with basic NAT traversal"
        echo "  ${RED}Con:${NC} Won't work for strict firewalls or VLAN isolation"
        echo ""
        read -p "Enable Google STUN fallback? [y/N]: " use_google
        if [[ "$use_google" =~ ^[Yy]$ ]]; then
            USE_GOOGLE_STUN="y"
            print_info "Google STUN enabled"
        else
            USE_GOOGLE_STUN="n"
            print_info "Direct connections only (consider installing COTURN for NAT/VLAN support)"
        fi
    fi

    ENABLE_TLS="y"
    save_config
    generate_pjsip_conf
    restart_asterisk_safe
    print_success "Internet access configuration complete"
}

# ================================================================
# 9A. UPDATE SYSTEM
# ================================================================

check_for_updates() {
    print_header "Check for Updates"

    echo "Current Version: ${BOLD}v${SCRIPT_VERSION}${NC}"
    echo ""
    echo "Checking GitHub for latest release..."
    echo ""

    # Fetch latest release from GitHub
    local latest_info=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null)

    if [[ -z "$latest_info" ]] || echo "$latest_info" | grep -q "API rate limit"; then
        print_warn "Unable to check for updates (GitHub API unavailable or rate limited)"
        echo ""
        echo "You can manually check: https://github.com/${GITHUB_REPO}/releases"
        return 1
    fi

    # Parse version and download URL
    local latest_version=$(echo "$latest_info" | grep -oP '"tag_name":\s*"v?\K[0-9]+\.[0-9]+')
    local release_url=$(echo "$latest_info" | grep -oP '"html_url":\s*"\K[^"]+' | head -1)
    local download_url=$(echo "$latest_info" | grep -oP '"browser_download_url":\s*"\K[^"]+' | grep "\.sh$" | head -1)

    if [[ -z "$latest_version" ]]; then
        print_warn "Could not determine latest version"
        return 1
    fi

    echo "Latest Version:  ${BOLD}v${latest_version}${NC}"
    echo ""

    # Compare versions
    if [[ "$SCRIPT_VERSION" == "$latest_version" ]]; then
        print_success "You are running the latest version!"
        return 0
    fi

    # Version comparison (simple numeric)
    local current_num=$(echo "$SCRIPT_VERSION" | tr -d '.')
    local latest_num=$(echo "$latest_version" | tr -d '.')

    if [[ "$current_num" -gt "$latest_num" ]]; then
        print_info "You are running a NEWER version (development/testing)"
        return 0
    fi

    # Update available
    print_warn "Update available: v${SCRIPT_VERSION} → v${latest_version}"
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  ${YELLOW}⚠  IMPORTANT: Read About Breaking Changes${NC}              ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Before updating, please review the changelog:"
    echo "  ${CYAN}${release_url}${NC}"
    echo ""
    echo "Breaking changes, new features, and migration notes are documented there."
    echo ""
    read -p "Continue with update? [y/N]: " do_update

    if [[ "$do_update" =~ ^[Yy]$ ]]; then
        perform_update "$latest_version" "$download_url" "$release_url"
    else
        print_info "Update cancelled"
    fi
}

perform_update() {
    local new_version=$1
    local download_url=$2
    local release_url=$3

    print_header "Updating to v${new_version}"

    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    local backup_timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="${BACKUP_DIR}/easy-asterisk-v${SCRIPT_VERSION}_${backup_timestamp}.sh"

    # Backup current script
    echo "Creating backup..."
    local script_path=$(readlink -f "$0")
    cp "$script_path" "$backup_file"

    if [[ ! -f "$backup_file" ]]; then
        print_error "Failed to create backup!"
        return 1
    fi

    print_success "Backup created: $backup_file"
    echo ""

    # Backup configuration
    if [[ -d "$CONFIG_DIR" ]]; then
        local config_backup="${BACKUP_DIR}/config_${backup_timestamp}.tar.gz"
        tar -czf "$config_backup" -C "$CONFIG_DIR" . 2>/dev/null
        print_success "Config backup: $config_backup"
    fi

    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  Rollback Instructions (if needed)                         ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "If the new version has issues, restore the backup:"
    echo "  ${CYAN}cp $backup_file $script_path${NC}"
    echo ""
    echo "To restore config:"
    echo "  ${CYAN}tar -xzf ${BACKUP_DIR}/config_${backup_timestamp}.tar.gz -C $CONFIG_DIR${NC}"
    echo ""
    read -p "Press Enter to continue with update..."

    # Download new version
    echo ""
    echo "Downloading v${new_version}..."

    if [[ -n "$download_url" ]]; then
        # Download from release asset
        local temp_file="/tmp/easy-asterisk-update-${new_version}.sh"
        if curl -fsSL "$download_url" -o "$temp_file"; then
            chmod +x "$temp_file"
            cp "$temp_file" "$script_path"
            rm -f "$temp_file"
            print_success "Update downloaded and installed!"
        else
            print_error "Download failed!"
            echo "Manual update: Download from ${release_url}"
            return 1
        fi
    else
        # Fallback: clone repo and copy script
        print_warn "Direct download not available, using git clone method..."
        local temp_dir="/tmp/easy-asterisk-update-$$"
        if git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$temp_dir" 2>/dev/null; then
            local new_script=$(find "$temp_dir" -name "easy-asterisk-interactive-v${new_version}.sh" -o -name "easy-asterisk-interactive-v*.sh" | sort -V | tail -1)
            if [[ -f "$new_script" ]]; then
                chmod +x "$new_script"
                cp "$new_script" "$script_path"
                rm -rf "$temp_dir"
                print_success "Update installed via git!"
            else
                print_error "Could not find script in repository"
                rm -rf "$temp_dir"
                return 1
            fi
        else
            print_error "Git clone failed!"
            echo "Manual update: Download from ${release_url}"
            return 1
        fi
    fi

    echo ""
    print_success "Update complete: v${SCRIPT_VERSION} → v${new_version}"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "${BOLD}What's Next:${NC}"
    echo "  1. Review changelog: ${release_url}"
    echo "  2. Restart services if needed (offered below)"
    echo "  3. Test your configuration"
    echo ""

    # Offer to restart services
    if systemctl is-active asterisk >/dev/null 2>&1 || systemctl is-active baresip >/dev/null 2>&1; then
        read -p "Restart Asterisk and Baresip services now? [Y/n]: " restart_services
        if [[ ! "$restart_services" =~ ^[Nn]$ ]]; then
            restart_all_services
        fi
    fi

    echo ""
    print_warn "Script has been updated. Please re-run it to use the new version:"
    echo "  ${CYAN}sudo $script_path${NC}"
    echo ""
    read -p "Press Enter to exit..."
    exit 0
}

restart_all_services() {
    print_header "Restarting Services"

    # Restart Asterisk
    if systemctl is-active asterisk >/dev/null 2>&1; then
        echo "Restarting Asterisk..."
        systemctl restart asterisk
        if systemctl is-active asterisk >/dev/null 2>&1; then
            print_success "Asterisk restarted"
        else
            print_error "Asterisk failed to restart"
            echo "Check logs: journalctl -u asterisk -n 50"
        fi
    fi

    # Restart Baresip (user service)
    if [[ -n "$KIOSK_USER" && -n "$KIOSK_UID" ]]; then
        local user_dbus="XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}"
        if sudo -u "$KIOSK_USER" $user_dbus systemctl --user is-active baresip >/dev/null 2>&1; then
            echo "Restarting Baresip..."
            sudo -u "$KIOSK_USER" $user_dbus systemctl --user restart baresip kiosk-ptt 2>/dev/null
            sleep 2
            if sudo -u "$KIOSK_USER" $user_dbus systemctl --user is-active baresip >/dev/null 2>&1; then
                print_success "Baresip restarted"
            else
                print_error "Baresip failed to restart"
                echo "Check logs: sudo -u $KIOSK_USER journalctl --user -u baresip -n 50"
            fi
        fi
    fi

    # Restart COTURN
    if systemctl is-active coturn >/dev/null 2>&1; then
        echo "Restarting COTURN..."
        systemctl restart coturn
        if systemctl is-active coturn >/dev/null 2>&1; then
            print_success "COTURN restarted"
        else
            print_error "COTURN failed to restart"
        fi
    fi
}

# ================================================================
# 10. INSTALLATION
# ================================================================

install_quick_local() {
    print_header "Quick Local Network Setup"

    echo "This is the recommended setup for 90% of users:"
    echo "  ${GREEN}✓${NC} Local network only (no internet)"
    echo "  ${GREEN}✓${NC} PTT (push-to-talk) with mute-by-default"
    echo "  ${GREEN}✓${NC} Auto-answer for kiosks"
    echo "  ${GREEN}✓${NC} Audio ducking"
    echo "  ${GREEN}✓${NC} No COTURN/certificates needed"
    echo ""
    echo "Perfect for:"
    echo "  • Intercom systems"
    echo "  • Warehouse communication"
    echo "  • Office quick-call systems"
    echo "  • Security/monitoring stations"
    echo ""
    read -p "Continue with quick setup? [Y/n]: " confirm
    [[ "$confirm" =~ ^[Nn]$ ]] && return

    # Check for VPN first
    detect_vpn_interface || true

    # Get client user
    local default_user="${SUDO_USER:-$USER}"
    read -p "Client User [$default_user]: " target_user
    KIOSK_USER="${target_user:-$default_user}"
    KIOSK_UID=$(id -u "$KIOSK_USER")

    # Simple config
    if [[ "$USE_VPN" == "y" ]]; then
        ASTERISK_HOST="$VPN_IP"
    else
        ASTERISK_HOST=$(hostname -I | cut -d' ' -f1)
    fi

    SIP_PASSWORD=$(generate_password)
    ENABLE_TLS="n"
    CLIENT_ANSWERMODE="auto"
    USE_COTURN="n"
    USE_GOOGLE_STUN="n"

    # Install
    install_dependencies
    INSTALLED_SERVER="y"
    INSTALLED_CLIENT="y"
    configure_asterisk
    configure_baresip
    enable_client_services
    open_firewall_ports

    # Configure PTT
    echo ""
    read -p "Configure PTT button now? [Y/n]: " do_ptt
    if [[ ! "$do_ptt" =~ ^[Nn]$ ]]; then
        detect_ptt_button
    fi

    save_config

    print_success "Quick setup complete!"
    echo ""
    echo "═══════════════════════════════════════════════════════════"
    echo "Your Asterisk server is running on: ${BOLD}$ASTERISK_HOST${NC}"
    echo "  Extension: 101"
    echo "  Password:  $SIP_PASSWORD"
    echo ""
    echo "Add more devices: Main Menu → Device Management → Add device"
    echo "═══════════════════════════════════════════════════════════"
}

install_full() {
    print_header "Full Installation"
    local default_user="${SUDO_USER:-$USER}"
    read -p "Client User [$default_user]: " target_user
    KIOSK_USER="${target_user:-$default_user}"
    KIOSK_UID=$(id -u "$KIOSK_USER")

    # Check for VPN
    detect_vpn_interface || true

    if ! collect_common_config; then return; fi
    collect_client_config
    install_dependencies
    INSTALLED_SERVER="y"
    INSTALLED_CLIENT="y"
    configure_asterisk
    configure_baresip
    enable_client_services
    open_firewall_ports
    save_config

    # Configure PTT for client
    echo ""
    read -p "Configure PTT button now? [Y/n]: " do_ptt
    if [[ ! "$do_ptt" =~ ^[Nn]$ ]]; then
        detect_ptt_button
    fi

    echo ""
    read -p "Run Internet/Certificate Setup wizard now? [Y/n]: " run_setup
    [[ ! "$run_setup" =~ ^[Nn]$ ]] && setup_internet_access

    print_success "Installation complete"
}

install_server_only() {
    print_header "Server Installation"
    ASTERISK_HOST="127.0.0.1"
    ENABLE_TLS="y"
    install_asterisk_packages
    configure_asterisk
    open_firewall_ports
    INSTALLED_SERVER="y"
    save_config
    
    echo ""
    read -p "Run Internet/Certificate Setup wizard now? [Y/n]: " run_setup
    [[ ! "$run_setup" =~ ^[Nn]$ ]] && setup_internet_access
    
    print_success "Server installed"
}

install_client_only() {
    print_header "Client Installation"
    local default_user="${SUDO_USER:-$USER}"
    read -p "User [$default_user]: " target_user
    KIOSK_USER="${target_user:-$default_user}"
    KIOSK_UID=$(id -u "$KIOSK_USER")
    
    if ! id -nG "$KIOSK_USER" | grep -qw "audio"; then
        usermod -aG audio "$KIOSK_USER"
    fi

    read -p "Server (IP or domain): " ASTERISK_HOST
    read -p "SIP Password: " SIP_PASSWORD
    
    if [[ "$ASTERISK_HOST" =~ [a-zA-Z] ]]; then 
        ENABLE_TLS="y"
    else
        ENABLE_TLS="n"
    fi

    echo ""
    echo "Answer Mode:"
    echo "  1) Auto (auto-answer incoming calls)"
    echo "  2) Manual (ring on incoming)"
    read -p "Select [1]: " aa_sel
    CLIENT_ANSWERMODE="auto"
    [[ "$aa_sel" == "2" ]] && CLIENT_ANSWERMODE="manual"

    collect_client_config
    install_baresip_packages
    INSTALLED_CLIENT="y"
    configure_baresip
    enable_client_services

    # Configure PTT
    echo ""
    read -p "Configure PTT button now? [Y/n]: " do_ptt
    if [[ ! "$do_ptt" =~ ^[Nn]$ ]]; then
        detect_ptt_button
    fi

    save_config
    print_success "Client installed"
}

collect_common_config() {
    SIP_PASSWORD="${SIP_PASSWORD:-$(generate_password)}"
    ASTERISK_HOST="127.0.0.1"
    return 0
}

collect_client_config() {
    read -p "Extension [101]: " KIOSK_EXTENSION
    KIOSK_EXTENSION="${KIOSK_EXTENSION:-101}"
    KIOSK_NAME="kiosk-${KIOSK_EXTENSION}"
}

install_dependencies() {
    install_asterisk_packages
    install_baresip_packages
}

install_asterisk_packages() {
    echo "exit 101" > /usr/sbin/policy-rc.d
    chmod +x /usr/sbin/policy-rc.d
    apt update
    # asterisk-opus removed (included in asterisk-modules on Ubuntu 24.04+)
    apt install -y asterisk asterisk-core-sounds-en-gsm asterisk-modules openssl curl tcpdump sngrep || true
    mkdir -p /var/lib/asterisk /var/log/asterisk /var/spool/asterisk /var/run/asterisk
    ldconfig
    update-ca-certificates 2>/dev/null || true
    rm -f /usr/sbin/policy-rc.d
    fix_asterisk_systemd
}

install_baresip_packages() {
    apt update
    apt install -y baresip baresip-core pipewire pipewire-alsa pipewire-pulse wireplumber alsa-utils evtest || true
}

uninstall_menu() {
    print_header "Uninstall"
    echo "  1) Remove Everything"
    echo "  2) Asterisk Only"
    echo "  3) Baresip Only"
    echo "  0) Cancel"
    read -p "Select: " ch
    case $ch in
        1)
            systemctl stop asterisk 2>/dev/null || true
            apt purge -y asterisk* baresip baresip-core 2>/dev/null || true
            rm -rf /etc/asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk /usr/lib/asterisk
            rm -rf /etc/systemd/system/asterisk.service.d /etc/easy-asterisk
            [[ -n "$KIOSK_USER" ]] && rm -rf "/home/${KIOSK_USER}/.baresip"
            systemctl daemon-reload
            INSTALLED_SERVER="n"
            INSTALLED_CLIENT="n"
            rm -f "$CONFIG_FILE"
            print_success "Removed all"
            ;;
        2)
            systemctl stop asterisk 2>/dev/null || true
            apt purge -y asterisk* 2>/dev/null || true
            rm -rf /etc/asterisk /var/lib/asterisk
            INSTALLED_SERVER="n"
            save_config
            print_success "Removed Asterisk"
            ;;
        3)
            apt purge -y baresip baresip-core 2>/dev/null || true
            [[ -n "$KIOSK_USER" ]] && rm -rf "/home/${KIOSK_USER}/.baresip"
            INSTALLED_CLIENT="n"
            save_config
            print_success "Removed Baresip"
            ;;
    esac
}

# ================================================================
# 11. MENU SYSTEM (Reordered: Server #2, Devices #3)
# ================================================================

show_main_menu() {
    clear
    print_header "Easy Asterisk v1.25"
    
    load_config
    echo "  Status:"
    if [[ -f "$CONFIG_FILE" ]]; then
        [[ "$INSTALLED_SERVER" == "y" ]] && echo -e "    Server: ${GREEN}Installed${NC}" || echo -e "    Server: ${YELLOW}Not installed${NC}"
        [[ "$INSTALLED_CLIENT" == "y" ]] && echo -e "    Client: ${GREEN}Installed${NC}" || echo -e "    Client: ${YELLOW}Not installed${NC}"
        [[ "$INSTALLED_COTURN" == "y" ]] && echo -e "    COTURN: ${GREEN}Installed${NC}" || echo -e "    COTURN: ${YELLOW}Not installed${NC}"
        [[ -n "$DOMAIN_NAME" ]] && echo -e "    Domain: ${DOMAIN_NAME}"
    else
        echo -e "    ${YELLOW}Not configured${NC}"
    fi
    echo ""
    
    declare -A menu_map
    local count=1
    
    echo "  ${count}) Install/Configure"; menu_map[$count]="submenu_install"; ((count++))
    if [[ "$INSTALLED_SERVER" == "y" ]]; then
        echo "  ${count}) Server Settings"; menu_map[$count]="submenu_server"; ((count++))
        echo "  ${count}) Device Management"; menu_map[$count]="submenu_devices"; ((count++))
    fi
    echo "  ${count}) Client Settings"; menu_map[$count]="submenu_client"; ((count++))
    echo "  ${count}) Tools"; menu_map[$count]="submenu_tools"; ((count++))
    echo "  0) Exit"
    echo ""
    
    read -p "  Select: " choice
    [[ "$choice" == "0" ]] && exit 0
    local action=${menu_map[$choice]}
    [[ -n "$action" ]] && $action
    show_main_menu
}

submenu_install() {
    clear
    print_header "Install"
    echo "  ${BOLD}1) Quick Local Setup (Recommended)${NC}"
    echo "     └─ Local network, PTT, auto-answer - No internet needed"
    echo ""
    echo "  ${CYAN}Advanced Options:${NC}"
    echo "  2) Full (server + client with internet setup)"
    echo "  3) Server only"
    echo "  4) Client only"
    echo "  5) Uninstall"
    echo "  0) Back"
    read -p "  Select: " choice
    case $choice in
        1) install_quick_local; read -p "Press Enter..." ;;
        2) install_full; read -p "Press Enter..." ;;
        3) install_server_only; read -p "Press Enter..." ;;
        4) install_client_only; read -p "Press Enter..." ;;
        5) uninstall_menu; read -p "Press Enter..." ;;
    esac
}

submenu_server() {
    clear
    print_header "Server Settings"
    echo "  1) Setup Internet Access (TLS/Certs/NAT)"
    echo "  2) Force re-sync Caddy certs"
    echo "  3) Show port/firewall requirements"
    echo "  4) Internet Calling Guide (VPN/FQDN/COTURN scenarios)"
    echo "  5) Interactive Firewall Guide (OPNsense/pfSense)"
    echo "  6) Test SIP connectivity"
    echo "  7) Verify CIDR/NAT config"
    echo "  8) Watch Live Logs"
    echo "  9) Router Doctor"
    echo " 10) Configure TURN Server (COTURN)"
    echo "  0) Back"
    read -p "  Select: " choice
    case $choice in
        1) setup_internet_access ;;
        2) setup_caddy_cert_sync "force" ;;
        3) show_port_requirements ;;
        4) show_internet_calling_guide ;;
        5) show_firewall_guide ;;
        6) test_sip_connectivity ;;
        7) verify_cidr_config ;;
        8) watch_live_logs ;;
        9) router_doctor ;;
        10) configure_coturn_menu ;;
        0) return ;;
    esac
    [[ "$choice" != "0" ]] && read -p "Press Enter..."
    [[ "$choice" != "0" ]] && submenu_server
}

submenu_devices() {
    clear
    print_header "Device Management"
    echo "  1) Add device"
    echo "  2) Remove device"
    echo "  3) List devices"
    echo "  4) Manage categories"
    echo "  5) Manage rooms"
    echo "  0) Back"
    read -p "  Select: " choice
    case $choice in
        1) add_device_menu ;;
        2) remove_device ;;
        3) show_registered_devices ;;
        4) manage_categories ;;
        5) manage_rooms ;;
        0) return ;;
    esac
    [[ "$choice" != "0" ]] && read -p "Press Enter..."
    [[ "$choice" != "0" ]] && submenu_devices
}

submenu_client() {
    clear
    print_header "Client Settings"
    echo "  1) Configure Local Client"
    echo "  2) Configure PTT Button"
    echo "  3) Run Diagnostics"
    echo "  0) Back"
    read -p "  Select: " choice
    case $choice in
        1) configure_local_client ;;
        2) configure_ptt_menu ;;
        3) run_client_diagnostics ;;
        0) return ;;
    esac
    [[ "$choice" != "0" ]] && read -p "Press Enter..."
    [[ "$choice" != "0" ]] && submenu_client
}

submenu_tools() {
    clear
    print_header "Tools"
    echo "  1) Audio Test"
    echo "  2) Verify Audio/Codec Setup"
    echo "  3) Check for Updates"
    echo "  0) Back"
    read -p "  Select: " choice
    case $choice in
        1) run_audio_test ;;
        2) verify_audio_setup ;;
        3) check_for_updates ;;
        0) return ;;
    esac
    [[ "$choice" != "0" ]] && read -p "Press Enter..."
    [[ "$choice" != "0" ]] && submenu_tools
}

main() {
    check_root
    load_config
    show_main_menu
}

main "$@"
