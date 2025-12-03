#!/bin/bash
# ================================================================
# Easy Asterisk - Interactive Installer v1.28
#
# UPDATES in v1.28:
# - FIXED: Device display now correctly shows UDP/5060 for LAN-only installs
# - FIXED: Device display shows TLS/5061 only when internet/certs configured
# - FIXED: SRTP shown as "Required" only with TLS, "Not required" for UDP
# - FIXED: ICE support only enabled for FQDN/internet calling, not LAN-only
# - FIXED: RTP config - icesupport and STUN only enabled for FQDN setups
# - ADDED: Informative message after server install before internet setup prompt
# - ADDED: load_config call in add_device_menu to properly read saved settings
#
# This fixes the issue where LAN-only servers incorrectly showed TLS/SRTP
# requirements when adding devices, preventing proper UDP registration.
#
# RETAINED from v1.23:
# - Router Guide separates VLAN (Allow) vs WAN (NAT)
# - Caddy Helper generates snippets for both SIP and TURN domains
# - PTT Mute-default, Audio Ducking, Device Management
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

select_user() {
    # Scan /home for real users (exclude system accounts)
    local -a users=()
    local -a user_ids=()
    local count=0

    echo "Scanning for users..."
    echo ""

    # Get users from /home with valid shells
    while IFS=: read -r username _ uid _ _ homedir shell; do
        # Only include users with UID >= 1000 and valid shell
        if [[ $uid -ge 1000 && -d "$homedir" && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
            ((count++))
            users+=("$username")
            user_ids+=("$uid")
            echo "  ${count}) ${username} (UID: ${uid}, Home: ${homedir})"
        fi
    done < /etc/passwd

    # Add option to manually enter username
    ((count++))
    echo "  ${count}) Enter username manually"
    echo ""

    # Suggest default based on SUDO_USER or first user found
    local default_choice=""
    local default_user="${SUDO_USER:-}"
    if [[ -z "$default_user" ]]; then
        default_user="${users[0]:-}"
        default_choice="1"
    else
        # Find index of SUDO_USER
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

    # Validate choice
    if [[ "$choice" =~ ^[0-9]+$ && "$choice" -le "${#users[@]}" && "$choice" -gt 0 ]]; then
        local idx=$((choice - 1))
        KIOSK_USER="${users[$idx]}"
        KIOSK_UID="${user_ids[$idx]}"
        echo ""
        print_success "Selected user: $KIOSK_USER (UID: $KIOSK_UID)"
        return 0
    elif [[ "$choice" == "$count" ]]; then
        # Manual entry
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
TURN_SECRET="$TURN_SECRET"
TURN_USER="$TURN_USER"
TURN_PASS="$TURN_PASS"
CURRENT_PUBLIC_IP="$CURRENT_PUBLIC_IP"
PTT_DEVICE="$PTT_DEVICE"
PTT_KEYCODE="$PTT_KEYCODE"
LOCAL_CIDR="$LOCAL_CIDR"
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
# 2. COTURN SETUP & DYNAMIC IP
# ================================================================

get_public_ip() {
    local ip=$(curl -s -4 --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s -4 --connect-timeout 5 icanhazip.com 2>/dev/null || echo "")
    echo "$ip"
}

install_coturn() {
    print_header "Installing COTURN"
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
    
    print_info "Public IP: $public_ip"
    
    # Enable coturn
    sed -i 's/#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' /etc/default/coturn 2>/dev/null || true
    
    # Configure coturn
    backup_config "$COTURN_CONFIG"
    cat > "$COTURN_CONFIG" << EOF
# Easy Asterisk COTURN Configuration
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
cipher-list="ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384"
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
        echo "COTURN is not installed."
        read -p "Install now? [Y/n]: " install
        if [[ ! "$install" =~ ^[Nn]$ ]]; then
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
    load_config  # Load saved configuration to check ENABLE_TLS, DOMAIN_NAME, etc.
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

    # ICE support only for FQDN/internet calling
    local ice_block=""
    if [[ -n "$DOMAIN_NAME" ]]; then
        ice_block="ice_support=yes"
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
${ice_block}
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
    if [[ "$ENABLE_TLS" == "y" ]]; then
        echo "  Transport: TLS (port 5061)"
        echo "  SRTP:      Required"
    else
        echo "  Transport: UDP (port 5060)"
        echo "  SRTP:      Not required"
    fi
    if [[ "$USE_COTURN" == "y" ]]; then
        echo "  TURN:      ${TURN_DOMAIN:-${DOMAIN_NAME:-$CURRENT_PUBLIC_IP}}:${DEFAULT_TURN_PORT}"
    fi
    echo ""
    echo "  Config: ENABLE_TLS=$ENABLE_TLS, DOMAIN_NAME=${DOMAIN_NAME:-<not set>}"
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

# Exit if no PTT device configured - leave audio unmuted for normal kiosk operation
[[ -z "$PTT_DEVICE" ]] && exit 0

# PTT mode: Mute audio source on start, unmute only when button pressed
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

ensure_audio_unmuted() {
    [[ -z "$KIOSK_USER" ]] && return
    [[ -z "$KIOSK_UID" ]] && return

    # Only unmute if PTT is not configured
    if [[ ! -f /etc/easy-asterisk/ptt-device ]]; then
        local user_dbus="XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}"

        # Wait a moment for PipeWire to initialize
        sleep 2

        # Unmute all sources and sinks
        sudo -u "$KIOSK_USER" $user_dbus pactl set-source-mute @DEFAULT_SOURCE@ 0 2>/dev/null || true
        sudo -u "$KIOSK_USER" $user_dbus pactl set-sink-mute @DEFAULT_SINK@ 0 2>/dev/null || true

        # Set reasonable volume levels if they're at 0
        local source_vol=$(sudo -u "$KIOSK_USER" $user_dbus pactl get-source-volume @DEFAULT_SOURCE@ 2>/dev/null | grep -oP '\d+%' | head -1 | tr -d '%')
        local sink_vol=$(sudo -u "$KIOSK_USER" $user_dbus pactl get-sink-volume @DEFAULT_SINK@ 2>/dev/null | grep -oP '\d+%' | head -1 | tr -d '%')

        [[ -n "$source_vol" && "$source_vol" -lt 50 ]] && sudo -u "$KIOSK_USER" $user_dbus pactl set-source-volume @DEFAULT_SOURCE@ 75% 2>/dev/null || true
        [[ -n "$sink_vol" && "$sink_vol" -lt 50 ]] && sudo -u "$KIOSK_USER" $user_dbus pactl set-sink-volume @DEFAULT_SINK@ 75% 2>/dev/null || true
    fi
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
    echo "If ALL clients and server are on a VPN (Tailscale/Wireguard), you DO NOT"
    echo "need port forwarding or COTURN. Just bind Asterisk to the VPN IP."
}

show_firewall_guide() {
    print_header "Interactive Firewall Guide (Hand-holding Mode)"
    echo "For: OPNsense, pfSense, or Advanced Routers"
    echo ""
    echo "=== SCENARIO A: INTERNAL ONLY (VLAN to VLAN) ==="
    echo "Example: Kiosks on VLAN 10, Server on VLAN 20"
    echo "GOAL: Allow Kiosks to talk to Server."
    echo ""
    echo "STEP 1: Log in to Router. Go to Firewall > Rules > VLAN 10 Interface."
    echo "        (Do NOT use 'Port Forwarding' for internal VLANs!)"
    echo ""
    echo "STEP 2: Create Rule 1 (Signaling)"
    echo "   - Action: Pass (Allow)"
    echo "   - Protocol: UDP/TCP"
    echo "   - Source: VLAN 10 Net"
    echo "   - Dest:   ${CURRENT_PUBLIC_IP:-Server_IP}"
    echo "   - Port:   3478"
    echo ""
    echo "STEP 3: Create Rule 2 (The Relay Range - CRITICAL)"
    echo "   - Action: Pass (Allow)"
    echo "   - Protocol: UDP"
    echo "   - Source: VLAN 10 Net"
    echo "   - Dest:   ${CURRENT_PUBLIC_IP:-Server_IP}"
    echo "   - Port Range:"
    echo "       From: 49152"
    echo "       To:   65535"
    echo "     (Note: Type these numbers in the Start/End boxes)"
    echo ""
    echo "================================================"
    echo ""
    echo "=== SCENARIO B: EXTERNAL ACCESS (Internet to LAN) ==="
    echo "Example: Remote phone connecting from a hotel."
    echo "GOAL: Forward traffic from Internet to Server."
    echo ""
    echo "STEP 1: Go to Firewall > NAT > Port Forwarding."
    echo "STEP 2: Create Rule."
    echo "   - Interface: WAN"
    echo "   - Protocol: UDP"
    echo "   - Dest. Port: 3478 (and 49152-65535)"
    echo "   - Redirect IP: ${CURRENT_PUBLIC_IP:-Server_IP}"
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

    # If KIOSK_USER already set from config, show and ask if want to change
    if [[ -n "$KIOSK_USER" ]]; then
        echo "Current configured user: $KIOSK_USER"
        read -p "Change user? [y/N]: " change_user
        if [[ "$change_user" =~ ^[Yy]$ ]]; then
            KIOSK_USER=""
            KIOSK_UID=""
        fi
    fi

    # If still no user, select one
    if [[ -z "$KIOSK_USER" ]]; then
        echo ""
        echo "Select the user to configure:"
        echo ""
        if ! select_user; then
            print_error "User selection failed"
            return 1
        fi
    else
        # Ensure KIOSK_UID is set
        KIOSK_UID=$(id -u "$KIOSK_USER" 2>/dev/null)
    fi

    echo ""

    if [[ ! -d "/home/${KIOSK_USER}/.baresip" ]]; then
        print_error "Baresip not installed for $KIOSK_USER"
        echo ""
        read -p "Install Baresip client now? [Y/n]: " install_it
        if [[ ! "$install_it" =~ ^[Nn]$ ]]; then
            install_baresip_packages
            configure_baresip
            enable_client_services
            INSTALLED_CLIENT="y"
            save_config
            print_success "Baresip installed"
            echo ""
            echo "Audio configured for $KIOSK_USER"
            echo "If audio doesn't work, log out and back in or reboot."
            echo ""
        else
            return
        fi
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

    echo "Audio Services:"
    local user_dbus="XDG_RUNTIME_DIR=/run/user/$t_uid"
    if sudo -u "$t_user" $user_dbus systemctl --user is-active pipewire >/dev/null 2>&1; then
        print_success "PipeWire RUNNING"
    else
        print_error "PipeWire STOPPED"
    fi
    if sudo -u "$t_user" $user_dbus systemctl --user is-active pipewire-pulse >/dev/null 2>&1; then
        print_success "PipeWire-Pulse RUNNING"
    else
        print_error "PipeWire-Pulse STOPPED"
    fi

    echo ""
    echo "Audio Status:"
    local src_mute=$(sudo -u "$t_user" $user_dbus pactl get-source-mute @DEFAULT_SOURCE@ 2>/dev/null | awk '{print $2}')
    local sink_mute=$(sudo -u "$t_user" $user_dbus pactl get-sink-mute @DEFAULT_SINK@ 2>/dev/null | awk '{print $2}')
    local src_vol=$(sudo -u "$t_user" $user_dbus pactl get-source-volume @DEFAULT_SOURCE@ 2>/dev/null | grep -oP '\d+%' | head -1)
    local sink_vol=$(sudo -u "$t_user" $user_dbus pactl get-sink-volume @DEFAULT_SINK@ 2>/dev/null | grep -oP '\d+%' | head -1)

    echo "  Microphone: ${src_mute:-unknown} (Volume: ${src_vol:-unknown})"
    echo "  Speaker:    ${sink_mute:-unknown} (Volume: ${sink_vol:-unknown})"

    if [[ "$src_mute" == "yes" ]]; then
        echo ""
        print_error "MICROPHONE IS MUTED - No audio will be sent!"
        echo "  To fix: pactl set-source-mute @DEFAULT_SOURCE@ 0"
    fi

    echo ""
    echo "PTT Configuration:"
    if [[ -f /etc/easy-asterisk/ptt-device ]]; then
        echo "  PTT Mode: ENABLED"
        source /etc/easy-asterisk/ptt-device 2>/dev/null
        echo "  Device: ${PTT_DEVICE:-not set}"
    else
        echo "  PTT Mode: DISABLED (normal intercom mode)"
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

    # ICE and STUN only for FQDN/internet calling
    load_config
    local ice_stun_config=""
    if [[ -n "$DOMAIN_NAME" ]]; then
        ice_stun_config="icesupport=yes
stunaddr=stun.l.google.com:19302"
    else
        ice_stun_config="# icesupport disabled - LAN only mode"
    fi

    cat > /etc/asterisk/rtp.conf << EOF
[general]
rtpstart=10000
rtpend=20000
strictrtp=yes
${ice_stun_config}
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
; Easy Asterisk v1.23
[global]
type=global
user_agent=EasyAsterisk

[transport-udp]
type=transport
protocol=udp
bind=0.0.0.0:${DEFAULT_SIP_PORT}
${nat_settings}

[transport-tcp]
type=transport
protocol=tcp
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

    # Ensure audio group membership
    if ! id -nG "$KIOSK_USER" | grep -qw "audio"; then
        usermod -aG audio "$KIOSK_USER"
    fi

    # Baresip service
    cat > "${systemd_dir}/baresip.service" << EOF
[Unit]
Description=Baresip SIP Client
After=pipewire.service pipewire-pulse.service network-online.target
Wants=network-online.target pipewire.service pipewire-pulse.service

[Service]
Type=simple
ExecStart=/usr/local/bin/easy-asterisk-launcher
Restart=always
RestartSec=5
Environment=XDG_RUNTIME_DIR=/run/user/${KIOSK_UID}

[Install]
WantedBy=default.target
EOF

    # PTT service - only create if PTT is configured
    cat > "${systemd_dir}/kiosk-ptt.service" << EOF
[Unit]
Description=PTT Button Handler
After=pipewire.service
ConditionPathExists=/etc/easy-asterisk/ptt-device

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

        # Enable and start PipeWire services for the user
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user daemon-reload
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user enable pipewire pipewire-pulse 2>/dev/null || true
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user restart pipewire pipewire-pulse 2>/dev/null || true

        # Enable baresip
        sudo -u "$KIOSK_USER" $user_dbus systemctl --user enable baresip

        # Only enable PTT if configured
        if [[ -f /etc/easy-asterisk/ptt-device ]]; then
            sudo -u "$KIOSK_USER" $user_dbus systemctl --user enable kiosk-ptt
            sudo -u "$KIOSK_USER" $user_dbus systemctl --user restart baresip kiosk-ptt
        else
            sudo -u "$KIOSK_USER" $user_dbus systemctl --user restart baresip
            # Ensure audio is unmuted for normal kiosk operation
            ensure_audio_unmuted
        fi
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
    if [[ "$mode" == "force" ]]; then
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
        "/data/caddy"
        "/root/.local/share/caddy/certificates"
    )
    local caddy_cert="" caddy_key=""

    [[ "$mode" == "force" ]] && echo "Searching for certificates..."
    
    for base_path in "${search_paths[@]}"; do
        if ! sudo test -d "$base_path" 2>/dev/null; then continue; fi
        [[ "$mode" == "force" ]] && echo "  Checking: $base_path"
        
        local candidates=$(sudo find "$base_path" -maxdepth 5 -type f \( -name "fullchain.pem" -o -name "*.crt" \) 2>/dev/null)
        
        for cert in $candidates; do
            sudo cp "$cert" /tmp/cert_check.pem 2>/dev/null || continue
            if check_cert_coverage "/tmp/cert_check.pem" "$domain" "$base_domain"; then
                [[ "$mode" == "force" ]] && print_success "Found matching cert: $cert"
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
        ENABLE_TLS="y"
        ASTERISK_HOST="$domain"
        save_config
        
        generate_pjsip_conf
        restart_asterisk_safe
        
        [[ "$mode" == "force" ]] && print_success "Certificates installed for $domain"
        return 0
    else
        [[ "$mode" == "force" ]] && print_warn "No matching certificates found"
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
    echo "Do you have a separate domain for TURN? (e.g., turn.example.com)"
    read -p "Enter TURN domain (leave empty to use $DOMAIN_NAME): " t_dom
    TURN_DOMAIN="${t_dom:-$DOMAIN_NAME}"
    
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
    
    ENABLE_TLS="y"
    save_config
    generate_pjsip_conf
    restart_asterisk_safe
    print_success "Internet access configuration complete"
}

# ================================================================
# 10. INSTALLATION
# ================================================================

install_full() {
    print_header "Full Installation"
    local default_user="${SUDO_USER:-$USER}"
    read -p "Client User [$default_user]: " target_user
    KIOSK_USER="${target_user:-$default_user}"
    KIOSK_UID=$(id -u "$KIOSK_USER")
    
    if ! collect_common_config; then return; fi
    collect_client_config
    install_dependencies
    INSTALLED_SERVER="y"
    INSTALLED_CLIENT="y"
    ENABLE_TLS="n"  # LAN-only by default, set to "y" only if internet/certs setup is run
    configure_asterisk
    configure_baresip
    enable_client_services
    open_firewall_ports
    save_config

    echo ""
    echo "════════════════════════════════════════════════════════"
    print_success "Local network install complete"
    echo ""
    echo "Server and devices are reachable over internal LAN network only."
    echo "To add internet calling capability, continue with the setup below."
    echo "════════════════════════════════════════════════════════"
    echo ""
    read -p "Run Internet/Certificate Setup wizard now? [Y/n]: " run_setup
    [[ ! "$run_setup" =~ ^[Nn]$ ]] && setup_internet_access

    print_success "Installation complete"
}

install_server_only() {
    print_header "Server Installation"
    ASTERISK_HOST="127.0.0.1"
    ENABLE_TLS="n"  # LAN-only by default, set to "y" only if internet/certs setup is run
    install_asterisk_packages
    configure_asterisk
    open_firewall_ports
    INSTALLED_SERVER="y"
    save_config

    echo ""
    echo "════════════════════════════════════════════════════════"
    print_success "Local network install complete"
    echo ""
    echo "Server and devices are reachable over internal LAN network only."
    echo "To add internet calling capability, continue with the setup below."
    echo "════════════════════════════════════════════════════════"
    echo ""
    read -p "Run Internet/Certificate Setup wizard now? [Y/n]: " run_setup
    [[ ! "$run_setup" =~ ^[Nn]$ ]] && setup_internet_access

    print_success "Server installed"
}

install_client_only() {
    print_header "Client Installation"
    echo "Select the user to install the kiosk client for:"
    echo ""

    if ! select_user; then
        print_error "User selection failed"
        return 1
    fi

    echo ""
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
    save_config

    print_success "Client installed"
    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  IMPORTANT: Audio Configuration"
    echo "════════════════════════════════════════════════════════"
    echo "  User: $KIOSK_USER"
    echo "  - Audio group: Added"
    echo "  - PipeWire services: Enabled"
    echo "  - Microphone: Unmuted (for intercom mode)"
    echo ""
    echo "  If audio doesn't work immediately:"
    echo "  1. Log out and log back in as '$KIOSK_USER'"
    echo "  2. Or reboot the system"
    echo "  3. Check audio with: pactl list sources short"
    echo ""
    echo "  PTT Mode: Not configured (normal intercom operation)"
    echo "  To configure PTT: Main Menu > Configure PTT"
    echo "════════════════════════════════════════════════════════"
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
    print_header "Easy Asterisk v1.23"
    
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

submenu_server() {
    clear
    print_header "Server Settings"
    echo "  1) Setup Internet Access (TLS/Certs/NAT)"
    echo "  2) Force re-sync Caddy certs"
    echo "  3) Show port/firewall requirements"
    echo "  4) Interactive Firewall Guide (OPNsense/pfSense)"
    echo "  5) Test SIP connectivity"
    echo "  6) Verify CIDR/NAT config"
    echo "  7) Watch Live Logs"
    echo "  8) Router Doctor"
    echo "  9) Configure TURN Server (COTURN)"
    echo "  0) Back"
    read -p "  Select: " choice
    case $choice in
        1) setup_internet_access ;;
        2) setup_caddy_cert_sync "force" ;;
        3) show_port_requirements ;;
        4) show_firewall_guide ;;
        5) test_sip_connectivity ;;
        6) verify_cidr_config ;;
        7) watch_live_logs ;;
        8) router_doctor ;;
        9) configure_coturn_menu ;;
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
    echo "  0) Back"
    read -p "  Select: " choice
    case $choice in
        1) run_audio_test ;;
        2) verify_audio_setup ;;
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
