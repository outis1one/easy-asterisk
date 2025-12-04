#!/bin/bash
# ================================================================
# Easy Asterisk - Interactive Installer v1.37.1
#
# BUG FIXES in v1.37.1:
# - FIXED: Function name bug (rebuild_pjsip_config → generate_pjsip_conf)
# - FIXED: Uninstall menu now adapts based on what's installed
# - IMPROVED: Better Asterisk failure diagnostics (shows cert status)
# - IMPROVED: Port forwarding instructions now say "router" not "OPNsense"
#
# MAJOR UPDATES in v1.37:
# - ADDED: VLAN/NAT Traversal toggle (Server Tools menu option 8)
# - ADDED: Optional VLAN subnet configuration
# - IMPROVED: Support for devices on VLANs without inter-VLAN routing
# - COMPATIBLE: Works with flat networks, VLANs, VPNs, and FQDN modes
#
# NEW FEATURE - VLAN/NAT Traversal:
#   Enables communication with devices on VLANs without requiring
#   inter-VLAN routing. Uses symmetric RTP and dynamic NAT handling
#   to respond to packets at their source address.
#
# RETAINED from v1.30:
# - Two client types: LAN/VPN (IP) or FQDN (domain)
# - Per-device connection type selection
# - FQDN access setup wizard
# - Kiosk client fixes (DBUS, PipeWire deps)
# - PTT button configuration
# ================================================================

set +e

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
SCRIPT_VERSION="1.37.1"

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

select_server_ip() {
    # Returns selected IP in SELECTED_IP variable
    # Filters out docker, virtual bridges, loopback
    
    local -a ips=()
    local -a ifaces=()
    local -a labels=()
    local count=0
    
    while IFS= read -r line; do
        local iface=$(echo "$line" | awk '{print $2}' | tr -d ':')
        local ip=$(echo "$line" | awk '{print $4}' | cut -d'/' -f1)
        
        # Skip unwanted interfaces
        [[ "$iface" =~ ^(lo|docker|br-|veth|virbr|lxc|lxd) ]] && continue
        [[ "$iface" == "lo" ]] && continue
        [[ -z "$ip" ]] && continue
        
        # Determine label
        local label="LAN"
        if [[ "$iface" =~ ^tailscale ]]; then
            label="VPN-Tailscale"
        elif [[ "$iface" =~ ^(wg[0-9]) ]]; then
            label="VPN-WireGuard"
        elif [[ "$iface" =~ ^(wt[0-9]|utun) ]]; then
            label="VPN-Netbird"
        elif [[ "$iface" =~ ^tun ]]; then
            label="VPN-OpenVPN"
        elif [[ "$iface" =~ ^zt ]]; then
            label="VPN-ZeroTier"
        elif [[ "$iface" =~ ^nordlynx ]]; then
            label="VPN-NordVPN"
        elif [[ "$iface" =~ ^proton ]]; then
            label="VPN-Proton"
        elif [[ "$iface" =~ ^mullvad ]]; then
            label="VPN-Mullvad"
        fi
        
        ((count++))
        ips+=("$ip")
        ifaces+=("$iface")
        labels+=("$label")
        
    done < <(ip -o -4 addr show 2>/dev/null)
    
    if [[ $count -eq 0 ]]; then
        SELECTED_IP=$(hostname -I | awk '{print $1}')
        return
    fi
    
    echo ""
    echo "  Available server IPs:"
    for i in "${!ips[@]}"; do
        printf "    %d) %-15s (%s - %s)\n" "$((i+1))" "${ips[$i]}" "${ifaces[$i]}" "${labels[$i]}"
    done
    echo "    $((count+1))) Enter manually"
    echo ""
    
    read -p "  Select [1]: " ip_choice
    ip_choice="${ip_choice:-1}"
    
    if [[ "$ip_choice" == "$((count+1))" ]]; then
        read -p "  Enter IP: " SELECTED_IP
    elif [[ "$ip_choice" -ge 1 && "$ip_choice" -le "$count" ]]; then
        SELECTED_IP="${ips[$((ip_choice-1))]}"
    else
        SELECTED_IP="${ips[0]}"
    fi
}

select_user() {
    local -a users=()
    local -a user_ids=()
    local count=0

    echo "Scanning for users..."
    echo ""

    while IFS=: read -r username _ uid _ _ homedir shell; do
        if [[ $uid -ge 1000 && -d "$homedir" && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
            ((count++))
            users+=("$username")
            user_ids+=("$uid")
            echo "  ${count}) ${username} (UID: ${uid}, Home: ${homedir})"
        fi
    done < /etc/passwd

    ((count++))
    echo "  ${count}) Enter username manually"
    echo ""

    local default_choice=""
    local default_user="${SUDO_USER:-}"
    if [[ -z "$default_user" ]]; then
        default_user="${users[0]:-}"
        default_choice="1"
    else
        for i in "${!users[@]}"; do
            if [[ "${users[$i]}" == "$default_user" ]]; then
                default_choice=$((i + 1))
                break
            fi
        done
    fi

    if [[ -n "$default_choice" ]]; then
        read -p "Select user [${default_choice}]: " choice
        choice="${choice:-$default_choice}"
    else
        read -p "Select user: " choice
    fi

    if [[ "$choice" =~ ^[0-9]+$ && "$choice" -le "${#users[@]}" && "$choice" -gt 0 ]]; then
        local idx=$((choice - 1))
        KIOSK_USER="${users[$idx]}"
        KIOSK_UID="${user_ids[$idx]}"
        echo ""
        print_success "Selected user: $KIOSK_USER (UID: $KIOSK_UID)"
        return 0
    elif [[ "$choice" == "$count" ]]; then
        echo ""
        read -p "Enter username: " KIOSK_USER
        if id "$KIOSK_USER" >/dev/null 2>&1; then
            KIOSK_UID=$(id -u "$KIOSK_USER")
            print_success "Selected user: $KIOSK_USER (UID: $KIOSK_UID)"
            return 0
        else
            print_error "User '$KIOSK_USER' not found"
            return 1
        fi
    else
        print_error "Invalid selection"
        return 1
    fi
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
    TURN_SECRET="${TURN_SECRET:-}"
    TURN_USER="${TURN_USER:-kioskuser}"
    TURN_PASS="${TURN_PASS:-}"
    TURN_DOMAIN="${TURN_DOMAIN:-}"
    FQDN_ENABLED="${FQDN_ENABLED:-n}"
    VLAN_NAT_TRAVERSAL="${VLAN_NAT_TRAVERSAL:-n}"
    VLAN_SUBNETS="${VLAN_SUBNETS:-}"
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
    chmod 755 "$CONFIG_DIR"

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
FQDN_ENABLED="$FQDN_ENABLED"
CERT_PATH="$CERT_PATH"
KEY_PATH="$KEY_PATH"
INSTALLED_SERVER="$INSTALLED_SERVER"
INSTALLED_CLIENT="$INSTALLED_CLIENT"
INSTALLED_COTURN="$INSTALLED_COTURN"
USE_COTURN="$USE_COTURN"
TURN_SECRET="$TURN_SECRET"
TURN_USER="$TURN_USER"
TURN_PASS="$TURN_PASS"
VLAN_NAT_TRAVERSAL="$VLAN_NAT_TRAVERSAL"
VLAN_SUBNETS="$VLAN_SUBNETS"
CURRENT_PUBLIC_IP="$CURRENT_PUBLIC_IP"
PTT_DEVICE="$PTT_DEVICE"
PTT_KEYCODE="$PTT_KEYCODE"
LOCAL_CIDR="$LOCAL_CIDR"
SERVER_LAN_IP="$SERVER_LAN_IP"
EOF
    chmod 644 "$CONFIG_FILE"

    if [[ -n "$PTT_DEVICE" ]]; then
        cat > "$PTT_CONFIG_FILE" << EOF
PTT_DEVICE="$PTT_DEVICE"
PTT_KEYCODE="$PTT_KEYCODE"
EOF
        chmod 644 "$PTT_CONFIG_FILE"
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
                ufw allow 49152:65535/udp comment "TURN Relay" 2>/dev/null || true
            fi
            ufw reload 2>/dev/null || true
            print_success "UFW firewall ports opened"
        fi
    fi
}

# ================================================================
# 2. FQDN ACCESS SETUP
# ================================================================

setup_fqdn_access() {
    print_header "Setup FQDN Access"
    
    echo "This configures your server for clients connecting via domain name."
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  WHO NEEDS FQDN ACCESS?"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  • Internet clients (remote locations, mobile phones)"
    echo "  • Cross-VLAN clients (different VLAN using hairpin NAT)"
    echo ""
    echo "  These clients connect through your router's WAN interface,"
    echo "  so they need the same setup: FQDN + port forwarding."
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    load_config
    
    read -p "Domain name (e.g., sip.example.com): " domain
    if [[ -z "$domain" ]]; then
        print_error "Domain name required"
        return 1
    fi
    DOMAIN_NAME="$domain"
    
    # Detect IPs
    local detected_lan_ip=$(hostname -I | awk '{print $1}')
    local detected_public_ip=$(get_public_ip)
    
    echo ""
    echo "Detected IPs:"
    echo "  LAN IP:    ${detected_lan_ip:-not detected}"
    echo "  Public IP: ${detected_public_ip:-not detected}"
    echo ""
    
    SERVER_LAN_IP="${SERVER_LAN_IP:-$detected_lan_ip}"
    CURRENT_PUBLIC_IP="$detected_public_ip"
    
    # CIDR for NAT
    local raw_cidr=$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -1)
    local default_cidr="$raw_cidr"
    if [[ "$raw_cidr" =~ \.([0-9]+)/24$ ]]; then 
        default_cidr="${raw_cidr%.*}.0/24"
    fi
    read -p "Local network CIDR [$default_cidr]: " local_net
    LOCAL_CIDR="${local_net:-$default_cidr}"
    
    FQDN_ENABLED="y"
    save_config
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  CERTIFICATE SETUP"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    setup_certificates
    
    # Regenerate configs
    if [[ "$INSTALLED_SERVER" == "y" ]]; then
        generate_pjsip_conf
        restart_asterisk_safe
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ROUTER PORT FORWARDING REQUIRED"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  On your router, configure these port forwards:"
    echo ""
    echo "  ┌──────────────────┬──────────┬─────────────────────────────┐"
    echo "  │ WAN Port         │ Protocol │ Forward To                  │"
    echo "  ├──────────────────┼──────────┼─────────────────────────────┤"
    echo "  │ 5061             │ TCP      │ ${SERVER_LAN_IP}:5061       │"
    echo "  │ 10000-20000      │ UDP      │ ${SERVER_LAN_IP}:10000-20000│"
    echo "  └──────────────────┴──────────┴─────────────────────────────┘"
    echo ""
    echo "  (Usually found in: Firewall → NAT → Port Forward)"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    print_success "FQDN access configured"
}

setup_certificates() {
    echo "Select Certificate Source:"
    echo "  1) Auto-Sync from Caddy"
    echo "  2) Certbot (requires port 80 open)"
    echo "  3) Self-Signed (testing only)"
    echo "  4) Manual path"
    echo "  0) Skip"
    read -p "Select [1]: " cert_opt
    cert_opt="${cert_opt:-1}"
    
    [[ "$cert_opt" == "0" ]] && return

    case "$cert_opt" in
        1) setup_caddy_cert_sync "auto" ;;
        2)
            print_info "Installing Certbot..."
            apt install -y certbot
            certbot certonly --standalone -d "$DOMAIN_NAME" --non-interactive --agree-tos --register-unsafely-without-email
            if [[ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]]; then
                mkdir -p /etc/asterisk/certs
                cat "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" > /etc/asterisk/certs/server.crt
                cat "/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem" > /etc/asterisk/certs/server.key
                chown asterisk:asterisk /etc/asterisk/certs/server.* 2>/dev/null
                chmod 644 /etc/asterisk/certs/server.crt
                chmod 600 /etc/asterisk/certs/server.key
                print_success "Certbot success"
            else
                print_error "Certbot failed"
            fi
            ;;
        3)
            mkdir -p /etc/asterisk/certs
            openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
                -keyout /etc/asterisk/certs/server.key \
                -out /etc/asterisk/certs/server.crt \
                -subj "/CN=$DOMAIN_NAME" 2>/dev/null
            chown asterisk:asterisk /etc/asterisk/certs/server.* 2>/dev/null
            chmod 644 /etc/asterisk/certs/server.crt
            chmod 600 /etc/asterisk/certs/server.key
            print_success "Self-signed certificate generated"
            print_warn "Clients must trust this certificate"
            ;;
        4)
            read -p "Certificate path: " cp
            read -p "Private key path: " kp
            if [[ -f "$cp" && -f "$kp" ]]; then
                mkdir -p /etc/asterisk/certs
                cat "$cp" > /etc/asterisk/certs/server.crt
                cat "$kp" > /etc/asterisk/certs/server.key
                chown asterisk:asterisk /etc/asterisk/certs/server.* 2>/dev/null
                chmod 644 /etc/asterisk/certs/server.crt
                chmod 600 /etc/asterisk/certs/server.key
                print_success "Certificates installed"
            else
                print_error "Files not found"
            fi
            ;;
    esac
}

get_public_ip() {
    curl -s -4 --connect-timeout 5 ifconfig.me 2>/dev/null || \
    curl -s -4 --connect-timeout 5 icanhazip.com 2>/dev/null || echo ""
}

# ================================================================
# 3. COTURN SETUP
# ================================================================

install_coturn() {
    print_header "Installing COTURN"
    apt update
    apt install -y coturn
    
    [[ -z "$TURN_PASS" ]] && TURN_PASS=$(generate_password)
    
    local public_ip=$(get_public_ip)
    CURRENT_PUBLIC_IP="$public_ip"
    
    if [[ -z "$public_ip" ]]; then
        print_error "Could not detect public IP"
        return 1
    fi
    
    print_info "Public IP: $public_ip"
    
    sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn 2>/dev/null || true
    
    backup_config "$COTURN_CONFIG"
    cat > "$COTURN_CONFIG" << EOF
listening-port=${DEFAULT_TURN_PORT}
fingerprint
lt-cred-mech
realm=${TURN_DOMAIN:-${DOMAIN_NAME:-turn.local}}
total-quota=100
stale-nonce=600
cert=/etc/asterisk/certs/server.crt
pkey=/etc/asterisk/certs/server.key
no-tlsv1
no-tlsv1_1
cipher-list="ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512"
dh2066
no-stdout-log
log-file=/var/log/turnserver.log
simple-log
external-ip=${public_ip}
min-port=49152
max-port=65535
user-quota=12
no-multicast-peers
no-cli
user=${TURN_USER}:${TURN_PASS}
EOF

    chmod 600 "$COTURN_CONFIG"
    
    systemctl enable coturn
    systemctl restart coturn
    
    if systemctl is-active coturn >/dev/null; then
        print_success "COTURN installed and running"
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

toggle_vlan_nat_traversal() {
    print_header "VLAN/NAT Traversal Configuration"
    load_config

    echo "═══════════════════════════════════════════════════════════════"
    echo "  VLAN/NAT TRAVERSAL SETTINGS"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  This feature helps devices on VLANs communicate with the"
    echo "  Asterisk server without requiring inter-VLAN routing."
    echo ""
    echo "  It works by treating VLAN traffic similar to NAT traversal,"
    echo "  sending responses back to the source address of incoming packets."
    echo ""
    echo "  Current status: $(if [[ "$VLAN_NAT_TRAVERSAL" == "y" ]]; then echo -e "${GREEN}ENABLED${NC}"; else echo -e "${YELLOW}DISABLED${NC}"; fi)"
    echo ""

    if [[ -n "$VLAN_SUBNETS" ]]; then
        echo "  Configured VLAN subnets:"
        IFS=',' read -ra SUBNETS <<< "$VLAN_SUBNETS"
        for subnet in "${SUBNETS[@]}"; do
            echo "    - $subnet"
        done
        echo ""
    fi

    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  1) Enable VLAN/NAT traversal"
    echo "  2) Disable VLAN/NAT traversal"
    echo "  3) Configure VLAN subnets (optional)"
    echo "  0) Back"
    echo ""
    read -p "  Select: " choice

    case $choice in
        1)
            print_info "Enabling VLAN/NAT traversal..."
            VLAN_NAT_TRAVERSAL="y"
            save_config
            generate_pjsip_conf
            asterisk -rx "pjsip reload" >/dev/null 2>&1
            echo ""
            print_success "VLAN/NAT traversal ENABLED"
            echo ""
            echo "  Asterisk will now respond to the source address of incoming"
            echo "  packets, allowing VLAN devices to connect properly."
            echo ""

            read -p "  Do you want to configure VLAN subnets now? [y/N]: " config_subnets
            if [[ "$config_subnets" =~ ^[Yy]$ ]]; then
                echo ""
                echo "  Enter VLAN subnets (comma-separated, e.g., 192.168.10.0/24,192.168.20.0/24)"
                echo "  Leave empty to skip:"
                read -p "  > " subnets
                if [[ -n "$subnets" ]]; then
                    VLAN_SUBNETS="$subnets"
                    save_config
                    generate_pjsip_conf
                    asterisk -rx "pjsip reload" >/dev/null 2>&1
                    print_success "VLAN subnets configured"
                fi
            fi
            ;;
        2)
            print_info "Disabling VLAN/NAT traversal..."
            VLAN_NAT_TRAVERSAL="n"
            VLAN_SUBNETS=""
            save_config
            generate_pjsip_conf
            asterisk -rx "pjsip reload" >/dev/null 2>&1
            echo ""
            print_success "VLAN/NAT traversal DISABLED"
            echo ""
            echo "  Configuration restored to default (flat network only)."
            ;;
        3)
            echo ""
            echo "  Current subnets: ${VLAN_SUBNETS:-none}"
            echo ""
            echo "  Enter VLAN subnets (comma-separated, e.g., 192.168.10.0/24,192.168.20.0/24)"
            echo "  Leave empty to clear:"
            read -p "  > " subnets
            VLAN_SUBNETS="$subnets"
            save_config

            if [[ "$VLAN_NAT_TRAVERSAL" == "y" ]]; then
                generate_pjsip_conf
                asterisk -rx "pjsip reload" >/dev/null 2>&1
                print_success "VLAN subnets updated and applied"
            else
                print_success "VLAN subnets saved (will apply when traversal is enabled)"
            fi
            ;;
        0)
            return
            ;;
    esac

    echo ""
    read -p "Press Enter to continue..."
}

configure_coturn_menu() {
    print_header "Configure COTURN"
    
    if [[ "$INSTALLED_COTURN" == "y" ]]; then
        echo -e "Status: ${GREEN}Installed${NC}"
        echo "User:   ${TURN_USER}"
        echo "Pass:   ${TURN_PASS}"
        echo ""
        echo "  1) Update Credentials"
        echo "  2) Reinstall"
        echo "  3) Update IP"
        echo "  4) Show config"
        echo "  5) Uninstall"
        echo "  0) Back"
        read -p "Select: " choice
        case $choice in
            1)
                read -p "Username [${TURN_USER}]: " t_user
                TURN_USER="${t_user:-$TURN_USER}"
                read -p "Password [generate]: " t_pass
                TURN_PASS="${t_pass:-$(generate_password)}"
                sed -i '/^user=/d' "$COTURN_CONFIG"
                echo "user=${TURN_USER}:${TURN_PASS}" >> "$COTURN_CONFIG"
                systemctl restart coturn
                save_config
                print_success "Credentials updated"
                ;;
            2) install_coturn ;;
            3)
                local new_ip=$(get_public_ip)
                if [[ -n "$new_ip" ]]; then
                    sed -i "s/^external-ip=.*/external-ip=${new_ip}/" "$COTURN_CONFIG"
                    systemctl restart coturn
                    CURRENT_PUBLIC_IP="$new_ip"
                    save_config
                    print_success "IP updated to $new_ip"
                fi
                ;;
            4)
                echo "Status: $(systemctl is-active coturn)"
                echo "IP: $CURRENT_PUBLIC_IP"
                echo "Credentials: ${TURN_USER}:${TURN_PASS}"
                ;;
            5)
                systemctl stop coturn 2>/dev/null
                systemctl disable coturn 2>/dev/null
                apt purge -y coturn 2>/dev/null
                INSTALLED_COTURN="n"
                USE_COTURN="n"
                save_config
                print_success "COTURN uninstalled"
                ;;
        esac
    else
        echo "COTURN is not installed."
        read -p "Install now? [Y/n]: " install
        [[ ! "$install" =~ ^[Nn]$ ]] && install_coturn
    fi
}

# ================================================================
# 4. DEVICE MANAGEMENT
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
        [[ "$rtype" == "page" ]] && type_text="PAGE"
        echo -e "  ${CYAN}$index)${NC} ${BOLD}$rname${NC} ($rext) - $type_text"
        echo "      Members: $rmem"
        ((index++))
    done < "$ROOMS_FILE"
    echo ""
    echo "  1) Add Room"
    echo "  2) Edit Room"
    echo "  3) Delete Room"
    echo "  0) Back"
    read -p "Select: " choice
    case $choice in
        1)
            read -p "Extension: " new_ext
            read -p "Name: " new_name
            echo "  1) Ring Group"
            echo "  2) Page/Intercom"
            read -p "Type [1]: " type_sel
            local rtype="ring"
            [[ "$type_sel" == "2" ]] && rtype="page"
            read -p "Members (e.g. 101,102): " members
            echo "${new_ext}|${new_name}|${members}|60|${rtype}" >> "$ROOMS_FILE"
            rebuild_dialplan
            print_success "Room created"
            ;;
        2)
            read -p "Room #: " rnum
            local count=0
            while IFS='|' read -r rext rname rmem rtime rtype; do
                [[ "$rext" =~ ^# ]] && continue
                [[ -z "$rext" ]] && continue
                ((count++))
                if [[ $count -eq $rnum ]]; then
                    echo "Current members: $rmem"
                    read -p "New members: " new_mem
                    sed -i "/^${rext}|/d" "$ROOMS_FILE"
                    echo "${rext}|${rname}|${new_mem}|${rtime}|${rtype}" >> "$ROOMS_FILE"
                    rebuild_dialplan
                    print_success "Room updated"
                    break
                fi
            done < "$ROOMS_FILE"
            ;;
        3)
            read -p "Room #: " rnum
            local count=0
            while IFS='|' read -r rext rrest; do
                [[ "$rext" =~ ^# ]] && continue
                [[ -z "$rext" ]] && continue
                ((count++))
                if [[ $count -eq $rnum ]]; then
                    sed -i "/^${rext}|/d" "$ROOMS_FILE"
                    rebuild_dialplan
                    print_success "Room deleted"
                    break
                fi
            done < "$ROOMS_FILE"
            ;;
    esac
}

add_device_menu() {
    print_header "Add Device"
    load_config
    
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
        print_error "Extension exists!"
        return
    fi
    
    read -p "Name: " name
    name="${name:-Device $ext}"
    local pass=$(generate_password)
    
    # CONNECTION TYPE SELECTION
    local conn_type="lan"
    local transport_block=""
    local encryption_block=""
    local ice_block=""
    local display_server=""
    local display_port="5060"
    local display_transport="UDP"
    local display_encryption="None"
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "  HOW WILL THIS DEVICE CONNECT?"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "  1) ${GREEN}LAN/VPN${NC} - Same network or VPN tunnel (UDP)"
    if [[ "$FQDN_ENABLED" == "y" && -n "$DOMAIN_NAME" ]]; then
        echo -e "  2) ${CYAN}FQDN${NC} - Internet or cross-VLAN via ${DOMAIN_NAME} (TLS)"
    else
        echo -e "  2) ${YELLOW}FQDN${NC} - Not configured (run 'Setup FQDN Access' first)"
    fi
    echo ""
    read -p "  Select [1]: " conn_choice
    conn_choice="${conn_choice:-1}"
    
    if [[ "$conn_choice" == "1" ]]; then
        # LAN/VPN - let user pick which IP
        select_server_ip
        display_server="$SELECTED_IP"
        display_port="5060"
        display_transport="UDP"
        display_encryption="None"
    elif [[ "$conn_choice" == "2" ]]; then
        if [[ "$FQDN_ENABLED" != "y" || -z "$DOMAIN_NAME" ]]; then
            print_error "FQDN access not configured. Run 'Setup FQDN Access' first."
            return
        fi
        conn_type="fqdn"
        transport_block="transport=transport-tls"
        encryption_block="media_encryption=sdes"
        ice_block="ice_support=yes"
        display_server="$DOMAIN_NAME"
        display_port="5061"
        display_transport="TLS"
        display_encryption="SRTP (SDES)"
    fi
    
    # Auto-answer override
    local override_tag=""
    if [[ "$auto_answer" == "no" ]]; then
        read -p "Force AUTO-ANSWER? [y/N]: " force_aa
        [[ "$force_aa" =~ ^[Yy]$ ]] && override_tag="[AA:yes]" && auto_answer="yes"
    elif [[ "$auto_answer" == "yes" ]]; then
        read -p "Force RING? [y/N]: " force_ring
        [[ "$force_ring" =~ ^[Yy]$ ]] && override_tag="[AA:no]" && auto_answer="no"
    fi

    backup_config "/etc/asterisk/pjsip.conf"

    # Build endpoint config
    local endpoint_extras=""
    if [[ "$conn_type" == "fqdn" ]]; then
        endpoint_extras="${encryption_block}
${transport_block}
${ice_block}"
    fi

    cat >> /etc/asterisk/pjsip.conf << EOF

; === Device: $name ($cat_id) [CONN:${conn_type}] $override_tag ===
[${ext}]
type=endpoint
context=intercom
disallow=all
allow=opus
allow=ulaw
allow=alaw
allow=g722
direct_media=no
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
auth=${ext}
aors=${ext}
callerid="${name}" <${ext}>
${endpoint_extras}

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

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  DEVICE ADDED"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  ${BOLD}Client Configuration:${NC}"
    echo "  Server:     ${display_server}"
    echo "  Port:       ${display_port}"
    echo "  Transport:  ${display_transport}"
    echo "  Extension:  ${ext}"
    echo "  Password:   ${pass}"
    echo "  Encryption: ${display_encryption}"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
}

remove_device() {
    print_header "Remove Device"
    declare -A REMOVE_MAP
    local count=1
    echo "Select device to remove:"
    echo ""
    local dev_name=""
    while IFS= read -r line; do
        if [[ "$line" == *"; === Device:"* ]]; then
            local temp="${line#*; === Device: }"
            temp="${temp% ===}"
            temp=$(echo "$temp" | sed 's/ \[CONN:[^]]*\]//' | sed 's/ \[AA:[^]]*\]//')
            dev_name="${temp% (*)}"
        fi
        if [[ "$line" =~ ^\[([0-9]+)\] ]]; then
            local ext="${BASH_REMATCH[1]}"
            if [[ -n "$dev_name" ]]; then
                echo "  ${count}) Ext ${ext} - ${dev_name}"
                REMOVE_MAP[$count]=$ext
                ((count++))
                dev_name=""
            fi
        fi
    done < /etc/asterisk/pjsip.conf
    echo ""
    echo "  98) DELETE ALL"
    echo "  0) Cancel"
    echo ""
    read -p "Select: " choice
    
    if [[ "$choice" == "98" ]]; then
        read -p "Type 'DELETE ALL' to confirm: " confirm
        if [[ "$confirm" == "DELETE ALL" ]]; then
            backup_config "/etc/asterisk/pjsip.conf"
            sed -i '/^; === Device:/,/^$/d' /etc/asterisk/pjsip.conf
            sed -i '/^\[[0-9]\{3\}\]/,/^$/d' /etc/asterisk/pjsip.conf
            asterisk -rx "pjsip reload" 2>/dev/null
            rebuild_dialplan
            print_success "All devices deleted"
        fi
        return
    fi
    
    [[ "$choice" == "0" || -z "${REMOVE_MAP[$choice]}" ]] && return
    
    local ext="${REMOVE_MAP[$choice]}"
    read -p "Remove $ext? [y/N]: " confirm
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
    load_config
    
    printf "${CYAN}%-6s %-18s %-10s %-8s %-10s %-12s${NC}\n" "Ext" "Name" "Category" "Type" "Status" "Password"
    echo "────────────────────────────────────────────────────────────────────────────"
    local dev_name="" dev_cat="" dev_conn=""
    while IFS= read -r line; do
        if [[ "$line" == *"; === Device:"* ]]; then
            local temp="${line#*; === Device: }"
            temp="${temp% ===}"
            # Extract connection type
            if [[ "$temp" == *"[CONN:fqdn]"* ]]; then
                dev_conn="FQDN"
            else
                dev_conn="LAN"
            fi
            temp=$(echo "$temp" | sed 's/ \[CONN:[^]]*\]//' | sed 's/ \[AA:[^]]*\]//')
            dev_cat="${temp##* (}"; dev_cat="${dev_cat%)}"
            dev_name="${temp% (*)}" 
        fi
        if [[ "$line" =~ ^\[([0-9]+)\] ]]; then
            local ext="${BASH_REMATCH[1]}"
            if [[ -n "$dev_name" ]]; then
                local status="Offline"
                local status_color="${RED}"
                local avail=$(asterisk -rx "pjsip show endpoint ${ext}" 2>/dev/null | grep -E "Contact:.*(Avail|NonQual)" || true)
                if [[ -n "$avail" ]]; then
                    status="Online"
                    status_color="${GREEN}"
                fi
                local password=$(grep -A 10 "^\[$ext\]" /etc/asterisk/pjsip.conf | grep "password=" | head -1 | cut -d= -f2)
                local conn_color="${GREEN}"
                [[ "$dev_conn" == "FQDN" ]] && conn_color="${CYAN}"
                printf "%-6s %-18s %-10s ${conn_color}%-8s${NC} ${status_color}%-10s${NC} %-12s\n" "$ext" "${dev_name:0:16}" "$dev_cat" "$dev_conn" "$status" "$password"
                dev_name=""
            fi
        fi
    done < /etc/asterisk/pjsip.conf
    echo ""
    echo "Connection Info:"
    echo "  LAN/VPN:  Use server IP + port 5060 (UDP)"
    if [[ "$FQDN_ENABLED" == "y" && -n "$DOMAIN_NAME" ]]; then
        echo "  FQDN:     ${DOMAIN_NAME}:5061 (TLS)"
    fi
}

# ================================================================
# 5. PTT HANDLER
# ================================================================

configure_ptt_menu() {
    print_header "Configure PTT Button"
    
    if ! command -v evtest &>/dev/null; then
        apt install -y evtest >/dev/null 2>&1
    fi
    
    [[ -n "$KIOSK_USER" ]] && usermod -aG input "$KIOSK_USER" 2>/dev/null || true
    
    print_info "Scanning input devices..."
    echo ""
    
    declare -a SUGGESTED_DEVICES SUGGESTED_NAMES OTHER_DEVICES OTHER_NAMES
    
    for dev in /dev/input/event*; do
        [[ -e "$dev" ]] || continue
        local name=$(cat "/sys/class/input/$(basename $dev)/device/name" 2>/dev/null || echo "Unknown")
        local lname=$(echo "$name" | tr '[:upper:]' '[:lower:]')
        
        # Skip system devices
        if [[ "$lname" =~ (power.button|sleep.button|lid.switch|virtual|video.bus|hdmi|dp,pcm|hotkey|touchpad|touchscreen) ]]; then
            continue
        # Prioritize keyboards, USB HID devices, pedals
        elif [[ "$lname" =~ (keyboard|sayo.*nano$|pedal|foot|^hid|usb) ]]; then
            SUGGESTED_DEVICES+=("$dev")
            SUGGESTED_NAMES+=("$name")
        else
            OTHER_DEVICES+=("$dev")
            OTHER_NAMES+=("$name")
        fi
    done
    
    # Display suggested devices first
    if [[ ${#SUGGESTED_DEVICES[@]} -gt 0 ]]; then
        echo -e "${GREEN}Recommended (keyboards/USB buttons):${NC}"
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
    local ALL_NAMES=("${SUGGESTED_NAMES[@]}" "${OTHER_NAMES[@]}")
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
    local dev_name="${ALL_NAMES[$((selection-1))]}"
    echo ""
    print_success "Selected: $dev_name"
    echo "          ($PTT_DEVICE)"
    echo ""
    
    # Key detection loop
    while true; do
        echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}  DO NOT PRESS YET - wait for countdown${NC}"
        echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}"
        
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
    
    # Ensure input group
    if [[ -n "$KIOSK_USER" ]]; then
        if ! id -nG "$KIOSK_USER" | grep -qw "input"; then
            print_info "Adding $KIOSK_USER to input group..."
            usermod -aG input "$KIOSK_USER"
            echo ""
            print_warn "User added to 'input' group - LOG OUT AND BACK IN for PTT to work!"
            read -p "Press Enter to acknowledge..."
        fi
    fi
    
    save_config
    
    print_success "PTT configured: $PTT_KEYNAME on $(basename $PTT_DEVICE)"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  PTT Configuration Complete"
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Device:  $PTT_DEVICE"
    echo "  Button:  $PTT_KEYNAME (code $PTT_KEYCODE)"
    echo "  User:    ${KIOSK_USER:-not set}"
    echo ""
    echo "  To test: journalctl -t kiosk-ptt -f"
    echo "═══════════════════════════════════════════════════════════════"
    
    # Restart PTT service
    if [[ "$INSTALLED_CLIENT" == "y" && -n "$KIOSK_USER" && -n "$KIOSK_UID" ]]; then
        local user_dbus="XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}"
        print_info "Restarting PTT service..."
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user daemon-reload 2>/dev/null
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user enable kiosk-ptt 2>/dev/null
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user restart kiosk-ptt 2>/dev/null || true
        sleep 2
        journalctl -t kiosk-ptt -n 3 --no-pager 2>/dev/null || true
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

[[ -z "$XDG_RUNTIME_DIR" ]] && export XDG_RUNTIME_DIR="/run/user/${KIOSK_UID:-$(id -u)}"

# Wait for audio
for i in {1..30}; do
    pactl info >/dev/null 2>&1 && pactl list sources short | grep -q . && break
    sleep 1
done

# Mute on start
pactl set-source-mute @DEFAULT_SOURCE@ 1 2>/dev/null
logger -t kiosk-ptt "PTT started, mic muted"

evtest --grab "$PTT_DEVICE" 2>/dev/null | while read -r line; do
    if [[ "$line" =~ "value 1" ]]; then
        pactl set-source-mute @DEFAULT_SOURCE@ 0 2>/dev/null
        logger -t kiosk-ptt "PTT pressed - unmuted"
    fi
    if [[ "$line" =~ "value 0" ]]; then
        pactl set-source-mute @DEFAULT_SOURCE@ 1 2>/dev/null
        logger -t kiosk-ptt "PTT released - muted"
    fi
done
PTTSCRIPT
    chmod +x /usr/local/bin/kiosk-ptt
}

# ================================================================
# 6. AUDIO HELPERS
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

ensure_audio_unmuted() {
    [[ -z "$KIOSK_USER" || -z "$KIOSK_UID" ]] && return
    [[ -f /etc/easy-asterisk/ptt-device ]] && return  # PTT manages muting
    
    local user_dbus="XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}"
    sleep 2
    sudo -u "$KIOSK_USER" $user_dbus pactl set-source-mute @DEFAULT_SOURCE@ 0 2>/dev/null || true
    sudo -u "$KIOSK_USER" $user_dbus pactl set-sink-mute @DEFAULT_SINK@ 0 2>/dev/null || true
}

fix_audio_manually() {
    print_header "Fix Audio"
    load_config
    local t_user="${KIOSK_USER:-$SUDO_USER}"
    local t_uid=$(id -u "$t_user" 2>/dev/null)
    local user_dbus="XDG_RUNTIME_DIR=/run/user/$t_uid"

    echo "Fixing audio for: $t_user"
    sudo -u "$t_user" $user_dbus systemctl --user restart pipewire pipewire-pulse 2>/dev/null || true
    sleep 2
    sudo -u "$t_user" $user_dbus pactl set-source-mute @DEFAULT_SOURCE@ 0 2>/dev/null
    sudo -u "$t_user" $user_dbus pactl set-sink-mute @DEFAULT_SINK@ 0 2>/dev/null
    sudo -u "$t_user" $user_dbus pactl set-source-volume @DEFAULT_SOURCE@ 75% 2>/dev/null
    sudo -u "$t_user" $user_dbus pactl set-sink-volume @DEFAULT_SINK@ 75% 2>/dev/null
    sudo -u "$t_user" $user_dbus systemctl --user restart baresip 2>/dev/null
    print_success "Audio fixed"
}

# ================================================================
# 7. DIAGNOSTICS
# ================================================================

show_port_requirements() {
    print_header "Port Requirements"
    echo "═══════════════════════════════════════════════════════════════"
    echo "  LAN/VPN CLIENTS - No port forwarding needed"
    echo "═══════════════════════════════════════════════════════════════"
    echo "  │ 5060/UDP       │ SIP Signaling                            │"
    echo "  │ 10000-20000/UDP│ RTP Audio                                │"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  FQDN CLIENTS - Forward these on WAN"
    echo "═══════════════════════════════════════════════════════════════"
    echo "  │ 5061/TCP       │ SIP-TLS Signaling                        │"
    echo "  │ 10000-20000/UDP│ RTP Audio                                │"
    echo ""
}

test_sip_connectivity() {
    print_header "SIP Test"
    if systemctl is-active asterisk >/dev/null; then
        print_success "Asterisk running"
    else
        print_error "Asterisk stopped"
    fi
    echo ""
    echo "Listening:"
    ss -ulnp | grep 5060 || echo "  5060/UDP: Not listening"
    ss -tlnp | grep 5061 || echo "  5061/TCP: Not listening"
}

run_client_diagnostics() {
    print_header "Client Diagnostics"
    load_config
    local t_user="${KIOSK_USER:-$SUDO_USER}"
    local t_uid=$(id -u "$t_user" 2>/dev/null)
    local user_dbus="XDG_RUNTIME_DIR=/run/user/$t_uid"

    echo "User: $t_user"
    echo ""
    
    echo "Services:"
    sudo -u "$t_user" $user_dbus systemctl --user is-active baresip >/dev/null 2>&1 && print_success "Baresip running" || print_error "Baresip stopped"
    sudo -u "$t_user" $user_dbus systemctl --user is-active pipewire >/dev/null 2>&1 && print_success "PipeWire running" || print_error "PipeWire stopped"
    
    echo ""
    echo "Audio:"
    local src_mute=$(sudo -u "$t_user" $user_dbus pactl get-source-mute @DEFAULT_SOURCE@ 2>/dev/null | awk '{print $2}')
    echo "  Microphone muted: ${src_mute:-unknown}"
    
    echo ""
    echo "Account:"
    cat "/home/$t_user/.baresip/accounts" 2>/dev/null | sed 's/auth_pass=[^;]*/auth_pass=***/' || echo "  Not found"
}

# ================================================================
# 8. ASTERISK CONFIG
# ================================================================

fix_asterisk_systemd() {
    mkdir -p /etc/systemd/system/asterisk.service.d/
    cat > /etc/systemd/system/asterisk.service.d/override.conf << 'EOF'
[Unit]
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=
ExecStart=/usr/sbin/asterisk -f -U asterisk -G asterisk
Restart=always
RestartSec=10
EOF
    systemctl daemon-reload
}

repair_core_configs() {
    mkdir -p /etc/asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk /var/run/asterisk
    
    if [[ -d "/usr/lib/x86_64-linux-gnu/asterisk/modules" ]]; then
        mkdir -p /usr/lib/asterisk/modules
        cp -rn /usr/lib/x86_64-linux-gnu/asterisk/modules/* /usr/lib/asterisk/modules/ 2>/dev/null || true
    fi
    
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

    cat > /etc/asterisk/modules.conf << EOF
[modules]
autoload=yes
noload => chan_sip.so
noload => chan_iax2.so
load => res_pjsip.so
load => res_pjsip_session.so
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
        echo -e "[general]\nenabled = no" > "/etc/asterisk/${conf}.conf"
    done

    load_config
    local ice_config="# ICE disabled - LAN only"
    if [[ "$FQDN_ENABLED" == "y" ]]; then
        ice_config="icesupport=yes
stunaddr=stun.l.google.com:19302"
    fi

    cat > /etc/asterisk/rtp.conf << EOF
[general]
rtpstart=10000
rtpend=20000
strictrtp=yes
${ice_config}
EOF
    
    cat > /etc/asterisk/logger.conf << EOF
[general]
[logfiles]
console => notice,warning,error
EOF

    chown -R asterisk:asterisk /etc/asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk 2>/dev/null || true
}

generate_pjsip_conf() {
    print_info "Generating PJSIP config..."
    load_config
    local conf_file="/etc/asterisk/pjsip.conf"
    backup_config "$conf_file"
    
    # NAT settings for FQDN mode or VLAN/NAT traversal
    local nat_settings=""
    if [[ "$FQDN_ENABLED" == "y" && -n "$CURRENT_PUBLIC_IP" ]]; then
        local local_net="${LOCAL_CIDR:-$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -1)}"
        nat_settings="external_media_address=$CURRENT_PUBLIC_IP
external_signaling_address=$CURRENT_PUBLIC_IP
local_net=$local_net"
    elif [[ "$VLAN_NAT_TRAVERSAL" == "y" ]]; then
        # VLAN/NAT traversal without FQDN - configure local networks
        local local_net="${LOCAL_CIDR:-$(ip -o -f inet addr show | awk '/scope global/ {print $4}' | head -1)}"
        nat_settings="local_net=$local_net"

        # Add user-configured VLAN subnets
        if [[ -n "$VLAN_SUBNETS" ]]; then
            IFS=',' read -ra SUBNETS <<< "$VLAN_SUBNETS"
            for subnet in "${SUBNETS[@]}"; do
                subnet=$(echo "$subnet" | xargs)  # trim whitespace
                [[ -n "$subnet" ]] && nat_settings="${nat_settings}
local_net=$subnet"
            done
        fi
    fi

    cat > "$conf_file" << EOF
; Easy Asterisk v${SCRIPT_VERSION}
[global]
type=global
user_agent=EasyAsterisk

[transport-udp]
type=transport
protocol=udp
bind=0.0.0.0:${DEFAULT_SIP_PORT}
${nat_settings}

[transport-tls]
type=transport
protocol=tls
bind=0.0.0.0:${DEFAULT_SIPS_PORT}
cert_file=/etc/asterisk/certs/server.crt
priv_key_file=/etc/asterisk/certs/server.key
ca_list_file=/etc/ssl/certs/ca-certificates.crt
method=tlsv1_2
${nat_settings}

EOF

    # Restore devices from backup
    local backup_file=$(ls -t "${conf_file}.backup-"* 2>/dev/null | head -1)
    if [[ -f "$backup_file" ]]; then
        awk '/^; === Device:/{flag=1} flag' "$backup_file" >> "$conf_file"
    fi
    chown asterisk:asterisk "$conf_file"
}

rebuild_dialplan() {
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

    local dev_name="" dev_auto=""
    while IFS= read -r line; do
        if [[ "$line" == *"; === Device:"* ]]; then
            local temp="${line#*; === Device: }"
            temp="${temp% ===}"
            local aa_override=""
            [[ "$temp" == *"[AA:yes]"* ]] && aa_override="yes"
            [[ "$temp" == *"[AA:no]"* ]] && aa_override="no"
            temp=$(echo "$temp" | sed 's/ \[CONN:[^]]*\]//' | sed 's/ \[AA:[^]]*\]//')
            local dev_cat="${temp##* (}"; dev_cat="${dev_cat%)}"
            dev_name="${temp% (*)}"
            dev_auto="no"
            local cat_data=$(grep "^${dev_cat}|" "$CATEGORIES_FILE" 2>/dev/null || true)
            [[ -n "$cat_data" && "$(echo "$cat_data" | cut -d'|' -f3)" == "yes" ]] && dev_auto="yes"
            [[ "$aa_override" == "yes" ]] && dev_auto="yes"
            [[ "$aa_override" == "no" ]] && dev_auto="no"
        fi
        if [[ "$line" =~ ^\[([0-9]+)\] && -n "$dev_name" ]]; then
            local ext="${BASH_REMATCH[1]}"
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
    done < /etc/asterisk/pjsip.conf

    # Add rooms
    if [[ -f "$ROOMS_FILE" ]]; then
        while IFS='|' read -r rext rname rmem rtime rtype; do
            [[ "$rext" =~ ^# || -z "$rext" ]] && continue
            local dial_list=""
            IFS=',' read -ra EXTS <<< "$rmem"
            for e in "${EXTS[@]}"; do
                e=$(echo "$e" | tr -d ' ')
                [[ -n "$dial_list" ]] && dial_list="${dial_list}&"
                dial_list="${dial_list}PJSIP/${e}"
            done
            if [[ "$rtype" == "page" ]]; then
                cat >> "$conf_file" << EOF
exten => ${rext},1,NoOp(Page ${rname})
 same => n,Set(PJSIP_HEADER(add,Call-Info)=\;answer-after=0)
 same => n,Page(${dial_list},i,${rtime})
 same => n,Hangup()

EOF
            else
                cat >> "$conf_file" << EOF
exten => ${rext},1,NoOp(Ring ${rname})
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
    id asterisk >/dev/null 2>&1 || useradd -r -s /bin/false -d /var/lib/asterisk asterisk 2>/dev/null
    
    fix_asterisk_systemd
    initialize_default_categories
    repair_core_configs
    
    # Create default cert if none exists
    mkdir -p /etc/asterisk/certs
    if [[ ! -f /etc/asterisk/certs/server.crt ]]; then
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout /etc/asterisk/certs/server.key \
            -out /etc/asterisk/certs/server.crt \
            -subj "/CN=asterisk-local" 2>/dev/null
        chown asterisk:asterisk /etc/asterisk/certs/server.*
        chmod 644 /etc/asterisk/certs/server.crt
        chmod 600 /etc/asterisk/certs/server.key
    fi
    
    generate_pjsip_conf
    rebuild_dialplan
    restart_asterisk_safe
    systemctl enable asterisk
}

restart_asterisk_safe() {
    print_info "Restarting Asterisk..."
    systemctl stop asterisk 2>/dev/null || true
    sleep 2
    pkill -9 -x asterisk 2>/dev/null || true
    rm -f /var/run/asterisk/asterisk.pid 2>/dev/null
    systemctl start asterisk
    sleep 3

    if systemctl is-active asterisk >/dev/null; then
        print_success "Asterisk running"
    else
        print_error "Asterisk failed to start"
        echo ""
        echo "Recent log entries:"
        journalctl -u asterisk -n 20 --no-pager
        echo ""
        echo "Checking configuration files..."

        # Check if pjsip.conf has syntax errors
        if asterisk -rx "pjsip show version" &>/dev/null; then
            echo "PJSIP module OK"
        else
            echo "PJSIP may have configuration errors"
        fi

        # Check certificate files
        if [[ -f /etc/asterisk/certs/server.crt ]]; then
            echo "Certificate file exists"
        else
            echo "WARNING: Missing /etc/asterisk/certs/server.crt"
        fi

        if [[ -f /etc/asterisk/certs/server.key ]]; then
            echo "Private key exists"
        else
            echo "WARNING: Missing /etc/asterisk/certs/server.key"
        fi

        echo ""
        echo "To debug further, run: sudo asterisk -cvvv"
        echo ""
    fi
}

# ================================================================
# 9. CLIENT CONFIG
# ================================================================

configure_baresip() {
    local baresip_dir="/home/${KIOSK_USER}/.baresip"
    mkdir -p "$baresip_dir"
    
    local found_iface=""
    for target in 8.8.8.8 1.1.1.1; do
        found_iface=$(ip route get "$target" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
        [[ -n "$found_iface" ]] && break
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
    
    local transport="udp"
    local mediaenc=""
    # Check if connecting to FQDN (contains letters)
    if [[ "$ASTERISK_HOST" =~ [a-zA-Z] ]]; then 
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
    cat > /usr/local/bin/easy-asterisk-launcher << LAUNCHER
#!/bin/bash
logger -t baresip-launcher "Starting"
for i in {1..6}; do
    IFACE=\$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i=="dev") print \$(i+1)}' | head -1)
    [[ -n "\$IFACE" ]] && break
    sleep 5
done
exec /usr/bin/baresip -f "/home/${KIOSK_USER}/.baresip"
LAUNCHER
    chmod +x /usr/local/bin/easy-asterisk-launcher
}

enable_client_services() {
    local systemd_dir="/home/${KIOSK_USER}/.config/systemd/user"
    mkdir -p "$systemd_dir"

    usermod -aG audio "$KIOSK_USER" 2>/dev/null || true
    usermod -aG input "$KIOSK_USER" 2>/dev/null || true

    cat > "${systemd_dir}/baresip.service" << EOF
[Unit]
Description=Baresip SIP Client
After=pipewire-pulse.service
Requires=pipewire-pulse.service

[Service]
ExecStartPre=/bin/sleep 5
ExecStart=/usr/local/bin/easy-asterisk-launcher
Restart=always
RestartSec=10
Environment=XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${KIOSK_UID}/bus

[Install]
WantedBy=default.target
EOF

    cat > "${systemd_dir}/kiosk-ptt.service" << EOF
[Unit]
Description=PTT Handler
After=baresip.service
ConditionPathExists=/etc/easy-asterisk/ptt-device

[Service]
ExecStartPre=/bin/sleep 8
ExecStart=/usr/local/bin/kiosk-ptt
Restart=always
RestartSec=10
Environment=XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}
Environment=KIOSK_UID=${KIOSK_UID}

[Install]
WantedBy=default.target
EOF

    chown -R ${KIOSK_USER}:${KIOSK_USER} "/home/${KIOSK_USER}/.config"

    loginctl enable-linger $KIOSK_USER 2>/dev/null || true
    local user_dbus="XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}"

    sudo -u "$KIOSK_USER" $user_dbus systemctl --user daemon-reload
    sudo -u "$KIOSK_USER" $user_dbus systemctl --user enable pipewire pipewire-pulse baresip 2>/dev/null || true
    sudo -u "$KIOSK_USER" $user_dbus systemctl --user restart pipewire pipewire-pulse 2>/dev/null || true
    sleep 2
    sudo -u "$KIOSK_USER" $user_dbus systemctl --user restart baresip 2>/dev/null || true

    [[ -f /etc/easy-asterisk/ptt-device ]] && sudo -u "$KIOSK_USER" $user_dbus systemctl --user enable kiosk-ptt 2>/dev/null
    
    ensure_audio_unmuted
}

configure_local_client() {
    print_header "Configure Local Client"
    load_config

    if [[ -n "$KIOSK_USER" ]]; then
        echo "Current user: $KIOSK_USER"
        read -p "Change? [y/N]: " change
        [[ "$change" =~ ^[Yy]$ ]] && KIOSK_USER="" && KIOSK_UID=""
    fi

    if [[ -z "$KIOSK_USER" ]]; then
        select_user || return 1
    else
        KIOSK_UID=$(id -u "$KIOSK_USER" 2>/dev/null)
    fi

    if [[ ! -d "/home/${KIOSK_USER}/.baresip" ]]; then
        read -p "Baresip not installed. Install now? [Y/n]: " install_it
        if [[ ! "$install_it" =~ ^[Nn]$ ]]; then
            install_baresip_packages
            INSTALLED_CLIENT="y"
        else
            return
        fi
    fi
    
    echo ""
    echo "  How will this client connect?"
    echo "    1) LAN/VPN (via IP)"
    echo "    2) FQDN (via domain)"
    read -p "  Select [1]: " conn_type
    
    local server=""
    if [[ "$conn_type" == "2" ]]; then
        read -p "  Domain: " server
    else
        read -p "  Server IP (LAN or VPN IP of server): " server
    fi
    
    read -p "Extension: " ext
    read -p "Password: " pass
    
    echo "Answer mode: 1) Manual  2) Auto"
    read -p "Select [2]: " amode
    local answermode="auto"
    [[ "$amode" == "1" ]] && answermode="manual"
    
    ASTERISK_HOST="$server"
    KIOSK_EXTENSION="$ext"
    SIP_PASSWORD="$pass"
    CLIENT_ANSWERMODE="$answermode"
    
    configure_baresip
    enable_client_services
    save_config

    print_success "Client configured"
}

# ================================================================
# 10. CERTIFICATE SYNC
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
    load_config
    local domain=${DOMAIN_NAME:-sip.example.com}
    
    if [[ "$mode" == "force" ]]; then
        print_header "Caddy Cert Sync"
        read -p "Domain [$domain]: " input_domain
        domain="${input_domain:-$domain}"
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
    )
    local caddy_cert="" caddy_key=""

    for base_path in "${search_paths[@]}"; do
        sudo test -d "$base_path" 2>/dev/null || continue
        
        local candidates=$(sudo find "$base_path" -maxdepth 5 -type f \( -name "fullchain.pem" -o -name "*.crt" \) 2>/dev/null)
        
        for cert in $candidates; do
            sudo cp "$cert" /tmp/cert_check.pem 2>/dev/null || continue
            if check_cert_coverage "/tmp/cert_check.pem" "$domain" "$base_domain"; then
                caddy_cert="$cert"
                local dir=$(dirname "$cert")
                local name=$(basename "$cert")
                [[ "$name" == "fullchain.pem" ]] && caddy_key="${dir}/privkey.pem" || caddy_key=$(echo "$cert" | sed 's/\.crt/\.key/')
                sudo test -f "$caddy_key" && rm -f /tmp/cert_check.pem && break 2
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
        FQDN_ENABLED="y"
        save_config
        
        [[ "$INSTALLED_SERVER" == "y" ]] && generate_pjsip_conf && restart_asterisk_safe
        
        print_success "Certificates installed for $domain"
        return 0
    else
        [[ "$mode" == "force" ]] && print_warn "No matching certificates found"
        return 1
    fi
}

# ================================================================
# 11. INSTALLATION
# ================================================================

install_full() {
    print_header "Full Installation"
    
    local default_user="${SUDO_USER:-$USER}"
    read -p "Client User [$default_user]: " target_user
    KIOSK_USER="${target_user:-$default_user}"
    KIOSK_UID=$(id -u "$KIOSK_USER")
    
    SIP_PASSWORD=$(generate_password)
    read -p "Extension [101]: " KIOSK_EXTENSION
    KIOSK_EXTENSION="${KIOSK_EXTENSION:-101}"
    KIOSK_NAME="kiosk-${KIOSK_EXTENSION}"
    
    SERVER_LAN_IP=$(hostname -I | awk '{print $1}')
    ASTERISK_HOST="$SERVER_LAN_IP"
    FQDN_ENABLED="n"
    
    install_asterisk_packages
    install_baresip_packages
    
    INSTALLED_SERVER="y"
    INSTALLED_CLIENT="y"
    
    configure_asterisk
    configure_baresip
    enable_client_services
    open_firewall_ports
    save_config

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    print_success "Installation complete"
    echo ""
    echo "  Server:    ${SERVER_LAN_IP}:5060 (UDP)"
    echo "  Extension: ${KIOSK_EXTENSION}"
    echo "  Password:  ${SIP_PASSWORD}"
    echo ""
    echo "  LAN/VPN clients can connect now."
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    read -p "Will any clients connect via FQDN (internet/cross-VLAN)? [y/N]: " setup_fqdn
    [[ "$setup_fqdn" =~ ^[Yy]$ ]] && setup_fqdn_access
}

install_server_only() {
    print_header "Server Installation"
    
    SERVER_LAN_IP=$(hostname -I | awk '{print $1}')
    ASTERISK_HOST="$SERVER_LAN_IP"
    FQDN_ENABLED="n"
    
    install_asterisk_packages
    configure_asterisk
    open_firewall_ports
    
    INSTALLED_SERVER="y"
    save_config

    echo ""
    print_success "Server installed: ${SERVER_LAN_IP}:5060"
    echo ""
    read -p "Will any clients connect via FQDN? [y/N]: " setup_fqdn
    [[ "$setup_fqdn" =~ ^[Yy]$ ]] && setup_fqdn_access
}

install_client_only() {
    print_header "Client Installation"
    
    select_user || return 1
    
    echo ""
    echo "  How will this client connect?"
    echo "    1) LAN/VPN (via IP)"
    echo "    2) FQDN (via domain)"
    read -p "  Select [1]: " conn_type
    
    if [[ "$conn_type" == "2" ]]; then
        read -p "  Server Domain: " ASTERISK_HOST
    else
        read -p "  Server IP (LAN or VPN IP of server): " ASTERISK_HOST
    fi
    
    read -p "  Extension [101]: " KIOSK_EXTENSION
    KIOSK_EXTENSION="${KIOSK_EXTENSION:-101}"
    read -p "  Password: " SIP_PASSWORD
    
    echo "  Answer mode: 1) Auto  2) Manual"
    read -p "  Select [1]: " aa_sel
    CLIENT_ANSWERMODE="auto"
    [[ "$aa_sel" == "2" ]] && CLIENT_ANSWERMODE="manual"

    install_baresip_packages
    INSTALLED_CLIENT="y"
    configure_baresip
    enable_client_services
    save_config

    print_success "Client installed"
}

install_asterisk_packages() {
    echo "exit 101" > /usr/sbin/policy-rc.d
    chmod +x /usr/sbin/policy-rc.d
    apt update
    apt install -y asterisk asterisk-core-sounds-en-gsm asterisk-modules openssl curl tcpdump || true
    rm -f /usr/sbin/policy-rc.d
    fix_asterisk_systemd
}

install_baresip_packages() {
    apt update
    apt install -y baresip baresip-core pipewire pipewire-alsa pipewire-pulse wireplumber alsa-utils evtest || true
}

uninstall_menu() {
    print_header "Uninstall"
    load_config

    # Build menu based on what's installed
    local has_server=$([[ "$INSTALLED_SERVER" == "y" ]] && echo "y" || echo "n")
    local has_client=$([[ "$INSTALLED_CLIENT" == "y" ]] && echo "y" || echo "n")

    if [[ "$has_server" == "y" && "$has_client" == "y" ]]; then
        echo "  1) Remove Everything"
        echo "  2) Asterisk Only"
        echo "  3) Baresip Only"
    elif [[ "$has_server" == "y" ]]; then
        echo "  1) Remove Asterisk"
    elif [[ "$has_client" == "y" ]]; then
        echo "  1) Remove Baresip"
    else
        print_warn "Nothing installed"
        return
    fi

    echo "  0) Cancel"
    read -p "Select: " ch

    case $ch in
        1)
            if [[ "$has_server" == "y" && "$has_client" == "y" ]]; then
                # Remove everything
                systemctl stop asterisk 2>/dev/null
                apt purge -y asterisk* baresip baresip-core 2>/dev/null
                rm -rf /etc/asterisk /var/lib/asterisk /etc/easy-asterisk
                [[ -n "$KIOSK_USER" ]] && rm -rf "/home/${KIOSK_USER}/.baresip"
                systemctl daemon-reload
                print_success "Removed all"
            elif [[ "$has_server" == "y" ]]; then
                # Remove server only
                systemctl stop asterisk 2>/dev/null
                apt purge -y asterisk* 2>/dev/null
                rm -rf /etc/asterisk /var/lib/asterisk /etc/easy-asterisk
                systemctl daemon-reload
                print_success "Removed Asterisk"
            elif [[ "$has_client" == "y" ]]; then
                # Remove client only
                apt purge -y baresip baresip-core 2>/dev/null
                [[ -n "$KIOSK_USER" ]] && rm -rf "/home/${KIOSK_USER}/.baresip"
                rm -rf /etc/easy-asterisk
                print_success "Removed Baresip"
            fi
            ;;
        2)
            if [[ "$has_server" == "y" && "$has_client" == "y" ]]; then
                systemctl stop asterisk 2>/dev/null
                apt purge -y asterisk* 2>/dev/null
                rm -rf /etc/asterisk /var/lib/asterisk
                INSTALLED_SERVER="n"
                save_config
                print_success "Removed Asterisk"
            fi
            ;;
        3)
            if [[ "$has_server" == "y" && "$has_client" == "y" ]]; then
                apt purge -y baresip baresip-core 2>/dev/null
                [[ -n "$KIOSK_USER" ]] && rm -rf "/home/${KIOSK_USER}/.baresip"
                INSTALLED_CLIENT="n"
                save_config
                print_success "Removed Baresip"
            fi
            ;;
    esac
}

# ================================================================
# 12. MENU SYSTEM
# ================================================================

show_main_menu() {
    clear
    print_header "Easy Asterisk v${SCRIPT_VERSION}"
    
    load_config
    echo "  Status:"
    if [[ "$INSTALLED_SERVER" == "y" ]]; then
        echo -e "    Server:   ${GREEN}Installed${NC}"
        echo "    LAN/VPN:  (use server IP):5060"
        if [[ "$FQDN_ENABLED" == "y" ]]; then
            echo -e "    FQDN:     ${GREEN}${DOMAIN_NAME}:5061${NC}"
        else
            echo -e "    FQDN:     ${YELLOW}Not configured${NC}"
        fi
    else
        echo -e "    Server:   ${YELLOW}Not installed${NC}"
    fi
    if [[ "$INSTALLED_CLIENT" == "y" ]]; then
        echo -e "    Client:   ${GREEN}Installed${NC}"
    else
        echo -e "    Client:   ${YELLOW}Not installed${NC}"
    fi
    echo ""
    
    local count=1
    declare -A menu_map
    
    echo "  ${count}) Install"; menu_map[$count]="submenu_install"; ((count++))
    if [[ "$INSTALLED_SERVER" == "y" ]]; then
        echo "  ${count}) Setup FQDN Access"; menu_map[$count]="setup_fqdn_access"; ((count++))
        echo "  ${count}) Device Management"; menu_map[$count]="submenu_devices"; ((count++))
        echo "  ${count}) Server Tools"; menu_map[$count]="submenu_server"; ((count++))
    fi
    if [[ "$INSTALLED_CLIENT" == "y" ]]; then
        echo "  ${count}) Client Settings"; menu_map[$count]="submenu_client"; ((count++))
    fi
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
    echo "  1) Full (server + client)"
    echo "  2) Server only"
    echo "  3) Client only"
    echo "  4) Uninstall"
    echo "  0) Back"
    read -p "  Select: " choice
    case $choice in
        1) install_full; read -p "Press Enter..." ;;
        2) install_server_only; read -p "Press Enter..." ;;
        3) install_client_only; read -p "Press Enter..." ;;
        4) uninstall_menu; read -p "Press Enter..." ;;
    esac
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

submenu_server() {
    clear
    print_header "Server Tools"
    echo "  1) Sync Caddy certs"
    echo "  2) Port requirements"
    echo "  3) Test connectivity"
    echo "  4) Show registrations (live)"
    echo "  5) Configure COTURN"
    echo "  6) Restart Asterisk"
    echo "  7) Watch SIP traffic"
    echo "  8) VLAN/NAT traversal"
    echo "  0) Back"
    read -p "  Select: " choice
    case $choice in
        1) setup_caddy_cert_sync "force" ;;
        2) show_port_requirements ;;
        3) test_sip_connectivity ;;
        4) show_registrations ;;
        5) configure_coturn_menu ;;
        6) restart_asterisk_safe ;;
        7) watch_sip_traffic ;;
        8) toggle_vlan_nat_traversal ;;
        0) return ;;
    esac
    [[ "$choice" != "0" ]] && read -p "Press Enter..."
    [[ "$choice" != "0" ]] && submenu_server
}

show_registrations() {
    print_header "SIP Registrations"
    
    echo "═══════════════════════════════════════════════════════════════"
    echo "  REGISTERED CONTACTS"
    echo "═══════════════════════════════════════════════════════════════"
    asterisk -rx "pjsip show contacts" 2>/dev/null || echo "  Unable to query Asterisk"
    echo ""
    
    echo "═══════════════════════════════════════════════════════════════"
    echo "  ENDPOINT STATUS"
    echo "═══════════════════════════════════════════════════════════════"
    asterisk -rx "pjsip show endpoints" 2>/dev/null | grep -E "^(Endpoint|Contact|[0-9])" || echo "  No endpoints"
    echo ""
    
    echo "═══════════════════════════════════════════════════════════════"
    echo "  SERVER IPs (clients should connect to one of these)"
    echo "═══════════════════════════════════════════════════════════════"
    while IFS= read -r line; do
        local iface=$(echo "$line" | awk '{print $2}' | tr -d ':')
        local ip=$(echo "$line" | awk '{print $4}' | cut -d'/' -f1)
        [[ "$iface" =~ ^(lo|docker|br-|veth|virbr) ]] && continue
        [[ -z "$ip" ]] && continue
        local label="LAN"
        [[ "$iface" =~ ^tailscale ]] && label="VPN-Tailscale"
        [[ "$iface" =~ ^(wg[0-9]) ]] && label="VPN-WireGuard"
        [[ "$iface" =~ ^(wt[0-9]|utun) ]] && label="VPN-Netbird"
        [[ "$iface" =~ ^tun ]] && label="VPN-OpenVPN"
        [[ "$iface" =~ ^zt ]] && label="VPN-ZeroTier"
        printf "  %-15s %-18s (%s)\n" "$iface" "$ip" "$label"
    done < <(ip -o -4 addr show 2>/dev/null)
}

watch_sip_traffic() {
    print_header "SIP Traffic Monitor"
    echo "This will show live SIP packets. Press Ctrl+C to stop."
    echo ""
    
    if command -v sngrep &>/dev/null; then
        echo "Starting sngrep (visual SIP analyzer)..."
        sngrep -c
    elif command -v tcpdump &>/dev/null; then
        echo "Starting tcpdump on ports 5060/5061..."
        tcpdump -i any -n "port 5060 or port 5061" -v
    else
        print_error "Neither sngrep nor tcpdump installed"
        echo "Install with: apt install sngrep"
    fi
}

submenu_client() {
    clear
    print_header "Client Settings"
    echo "  1) Configure client"
    echo "  2) Configure PTT button"
    echo "  3) Diagnostics (logs, restart, status)"
    echo "  4) Fix audio (unmute & set volume)"
    echo "  5) Restart Baresip now"
    echo "  0) Back"
    read -p "  Select: " choice
    case $choice in
        1) configure_local_client ;;
        2) configure_ptt_menu ;;
        3) run_client_diagnostics ;;
        4) fix_audio_manually ;;
        5) restart_baresip_now ;;
        0) return ;;
    esac
    [[ "$choice" != "0" ]] && read -p "Press Enter..."
    [[ "$choice" != "0" ]] && submenu_client
}

restart_baresip_now() {
    load_config
    local t_user="${KIOSK_USER:-$SUDO_USER}"
    t_user="${t_user:-$USER}"
    local t_uid=$(id -u "$t_user" 2>/dev/null)
    local user_dbus="XDG_RUNTIME_DIR=/run/user/$t_uid"
    
    print_info "Restarting Baresip for $t_user..."
    sudo -u "$t_user" $user_dbus systemctl --user restart baresip 2>/dev/null
    sleep 3
    
    if sudo -u "$t_user" $user_dbus systemctl --user is-active baresip >/dev/null 2>&1; then
        print_success "Baresip running"
        echo ""
        echo "Recent log:"
        sudo -u "$t_user" $user_dbus journalctl --user -u baresip -n 5 --no-pager 2>/dev/null
    else
        print_error "Baresip failed to start"
        echo ""
        echo "Error log:"
        sudo -u "$t_user" $user_dbus journalctl --user -u baresip -n 15 --no-pager 2>/dev/null
    fi
}

main() {
    check_root
    load_config
    show_main_menu
}

main "$@"