#!/bin/bash

# Debian 12 and Ubuntu Server Hardening Interactive Script
# Version: 3.9 | 2025-06-26
# Compatible with: Debian 12 (Bookworm), Ubuntu 20.04 LTS, 22.04 LTS, 24.04 LTS
#
# Description:
# This script provisions and hardens a fresh Debian 12 or Ubuntu server with essential security
# configurations, user management, SSH hardening, firewall setup, and optional features
# like Docker and Tailscale. It is designed to be idempotent, safe, and suitable for
# production environments.
#
# Prerequisites:
# - Run as root on a fresh Debian 12 or Ubuntu server (e.g., sudo ./setup_harden_debian_ubuntu.sh).
# - Internet connectivity is required for package installation.
#
# Usage:
#   Download: wget https://raw.githubusercontent.com/buildplan/setup_harden_server/refs/heads/main/setup_harden_debian_ubuntu.sh
#   Make it executable: chmod +x setup_harden_debian_ubuntu.sh
#   Run it: sudo ./setup_harden_debian_ubuntu.sh [--quiet]
#
# Options:
#   --quiet: Suppress non-critical output for automation.
#
# Notes:
# - The script creates a log file in /var/log/setup_harden_debian_ubuntu_*.log.
# - Critical configurations are backed up before modification. Backup files are at /root/setup_harden_backup_*.
# - A new admin user is created with a mandatory password or SSH key for authentication.
# - Root SSH login is disabled; all access is via the new user with sudo privileges.
# - The user will be prompted to select a timezone, swap size, and custom firewall ports.
# - A reboot is recommended at the end to apply all changes.
# - Test the script in a VM before production use.
#
# Troubleshooting:
# - Check the log file for errors if the script fails.
# - If SSH access is lost, use the server console to restore /etc/ssh/sshd_config.backup_*.
# - Ensure sufficient disk space (>2GB) for swap file creation.

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# --- GLOBAL VARIABLES & CONFIGURATION ---

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/setup_harden_debian_ubuntu_$(date +%Y%m%d_%H%M%S).log"
VERBOSE=true
BACKUP_DIR="/root/setup_harden_backup_$(date +%Y%m%d_%H%M%S)"
IS_CONTAINER=false
SSHD_BACKUP_FILE=""
LOCAL_KEY_ADDED=false
SSH_SERVICE=""
ID="" # This will be populated from /etc/os-release

# --- PARSE ARGUMENTS ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --quiet) VERBOSE=false; shift ;;
        *) shift ;;
    esac
done

# --- LOGGING & PRINT FUNCTIONS ---

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

print_header() {
    [[ $VERBOSE == false ]] && return
    echo -e "${CYAN}╔═════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                 ║${NC}"
    echo -e "${CYAN}║       DEBIAN/UBUNTU SERVER SETUP AND HARDENING SCRIPT           ║${NC}"
    echo -e "${CYAN}║                      v3.9 | 2025-06-26                          ║${NC}"
    echo -e "${CYAN}╚═════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

print_section() {
    [[ $VERBOSE == false ]] && return
    echo -e "\n${BLUE}▓▓▓ $1 ▓▓▓${NC}" | tee -a "$LOG_FILE"
    echo -e "${BLUE}$(printf '═%.0s' {1..65})${NC}"
}

print_success() {
    [[ $VERBOSE == false ]] && return
    echo -e "${GREEN}✓ $1${NC}" | tee -a "$LOG_FILE"
}

print_error() {
    echo -e "${RED}✗ $1${NC}" | tee -a "$LOG_FILE"
}

print_warning() {
    [[ $VERBOSE == false ]] && return
    echo -e "${YELLOW}⚠ $1${NC}" | tee -a "$LOG_FILE"
}

print_info() {
    [[ $VERBOSE == false ]] && return
    echo -e "${PURPLE}ℹ $1${NC}" | tee -a "$LOG_FILE"
}

# --- USER INTERACTION ---

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local response

    [[ $VERBOSE == false ]] && return 0

    if [[ $default == "y" ]]; then
        prompt="$prompt [Y/n]: "
    else
        prompt="$prompt [y/N]: "
    fi

    while true; do
        read -rp "$(echo -e "${CYAN}$prompt${NC}")" response
        response=${response,,}

        if [[ -z $response ]]; then
            response=$default
        fi

        case $response in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) echo -e "${RED}Please answer yes or no.${NC}" ;;
        esac
    done
}

# --- VALIDATION FUNCTIONS ---

validate_username() {
    local username="$1"
    [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ && ${#username} -le 32 ]]
}

validate_hostname() {
    local hostname="$1"
    [[ "$hostname" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$ && ! "$hostname" =~ \.\. ]]
}

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1024 && "$port" -le 65535 ]]
}

validate_ssh_key() {
    local key="$1"
    [[ -n "$key" && "$key" =~ ^(ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-ed25519)\  ]]
}

validate_timezone() {
    local tz="$1"
    [[ -e "/usr/share/zoneinfo/$tz" ]]
}

validate_swap_size() {
    local size_upper="${1^^}" # Convert to uppercase for case-insensitivity
    [[ "$size_upper" =~ ^[0-9]+[MG]$ && "${size_upper%[MG]}" -ge 1 ]]
}

validate_ufw_port() {
    local port="$1"
    # Matches port (e.g., 8080) or port/protocol (e.g., 8080/tcp, 123/udp)
    [[ "$port" =~ ^[0-9]+(/tcp|/udp)?$ ]]
}

convert_to_bytes() {
    local size_upper="${1^^}" # Convert to uppercase for case-insensitivity
    local unit="${size_upper: -1}"
    local value="${size_upper%[MG]}"
    if [[ "$unit" == "G" ]]; then
        echo $((value * 1024 * 1024 * 1024))
    elif [[ "$unit" == "M" ]]; then
        echo $((value * 1024 * 1024))
    else
        echo 0
    fi
}

# --- CORE FUNCTIONS ---

check_dependencies() {
    print_section "Checking Dependencies"
    local missing_deps=()
    command -v curl >/dev/null || missing_deps+=("curl")
    command -v sudo >/dev/null || missing_deps+=("sudo")
    command -v gpg >/dev/null || missing_deps+=("gpg")

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_info "Installing missing dependencies: ${missing_deps[*]}"
        if ! apt-get update -qq || ! apt-get install -y -qq "${missing_deps[@]}"; then
            print_error "Failed to install dependencies: ${missing_deps[*]}"
            exit 1
        fi
        print_success "Dependencies installed."
    else
        print_success "All essential dependencies are installed."
    fi
    log "Dependency check completed."
}

check_system() {
    print_section "System Compatibility Check"

    if [[ $(id -u) -ne 0 ]]; then
        print_error "This script must be run as root (e.g., sudo ./setup_harden_debian_ubuntu.sh)."
        exit 1
    fi
    print_success "Running with root privileges."

    if [[ -f /proc/1/cgroup ]] && grep -qE '(docker|lxc|kubepod)' /proc/1/cgroup; then
        IS_CONTAINER=true
        print_warning "Container environment detected. Some features (like swap) will be skipped."
    fi

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ $ID == "debian" && $VERSION_ID == "12" ]] || \
           [[ $ID == "ubuntu" && $VERSION_ID =~ ^(20.04|22.04|24.04)$ ]]; then
            print_success "Compatible OS detected: $PRETTY_NAME"
        else
            print_warning "Script not tested on $PRETTY_NAME. This is for Debian 12 or Ubuntu 20.04/22.04/24.04 LTS."
            if ! confirm "Continue anyway?"; then exit 1; fi
        fi
    else
        print_error "This does not appear to be a Debian or Ubuntu system."
        exit 1
    fi

    # Preliminary SSH service check
    if ! dpkg -l openssh-server | grep -q ^ii; then
        print_warning "openssh-server not installed. It will be installed in the next step."
    else
        if systemctl is-enabled ssh.service >/dev/null 2>&1 || systemctl is-active ssh.service >/dev/null 2>&1; then
            print_info "Preliminary check: ssh.service detected."
        elif systemctl is-enabled sshd.service >/dev/null 2>&1 || systemctl is-active sshd.service >/dev/null 2>&1; then
            print_info "Preliminary check: sshd.service detected."
        elif ps aux | grep -q "[s]shd"; then
            print_warning "Preliminary check: SSH daemon running but no standard service detected."
        else
            print_warning "No SSH service or daemon detected. Ensure SSH is working after package installation."
        fi
    fi

    if curl -s --head https://deb.debian.org >/dev/null || curl -s --head https://archive.ubuntu.com >/dev/null; then
        print_success "Internet connectivity confirmed."
    else
        print_error "No internet connectivity. Please check your network."
        exit 1
    fi

    if [[ ! -w /var/log ]]; then
        print_error "Failed to write to /var/log. Cannot create log file."
        exit 1
    fi

    # Check /etc/shadow permissions
    if [[ ! -w /etc/shadow ]]; then
        print_error "/etc/shadow is not writable. Check permissions (should be 640, root:shadow)."
        exit 1
    fi
    local SHADOW_PERMS
    SHADOW_PERMS=$(stat -c %a /etc/shadow)
    if [[ "$SHADOW_PERMS" != "640" ]]; then
        print_info "Fixing /etc/shadow permissions to 640..."
        chmod 640 /etc/shadow
        chown root:shadow /etc/shadow
        log "Fixed /etc/shadow permissions to 640."
    fi

    log "System compatibility check completed."
}

collect_config() {
    print_section "Configuration Setup"
    while true; do
        read -rp "$(echo -e "${CYAN}Enter username for new admin user: ${NC}")" USERNAME
        if validate_username "$USERNAME"; then
            if id "$USERNAME" &>/dev/null; then
                print_warning "User '$USERNAME' already exists."
                if confirm "Use this existing user?"; then USER_EXISTS=true; break; fi
            else
                USER_EXISTS=false; break
            fi
        else
            print_error "Invalid username. Use lowercase letters, numbers, hyphens, underscores (max 32 chars)."
        fi
    done
    while true; do
        read -rp "$(echo -e "${CYAN}Enter server hostname: ${NC}")" SERVER_NAME
        if validate_hostname "$SERVER_NAME"; then break; else print_error "Invalid hostname."; fi
    done
    read -rp "$(echo -e "${CYAN}Enter a 'pretty' hostname (optional): ${NC}")" PRETTY_NAME
    [[ -z "$PRETTY_NAME" ]] && PRETTY_NAME="$SERVER_NAME"
    while true; do
        read -rp "$(echo -e "${CYAN}Enter custom SSH port (1024-65535) [2222]: ${NC}")" SSH_PORT
        SSH_PORT=${SSH_PORT:-2222}
        if validate_port "$SSH_PORT"; then break; else print_error "Invalid port number."; fi
    done
    SERVER_IP=$(curl -s https://ifconfig.me 2>/dev/null || echo "unknown")
    print_info "Detected server IP: $SERVER_IP"
    echo -e "\n${YELLOW}Configuration Summary:${NC}"
    echo -e "  Username:   $USERNAME"
    echo -e "  Hostname:   $SERVER_NAME"
    echo -e "  SSH Port:   $SSH_PORT"
    echo -e "  Server IP:  $SERVER_IP"
    if ! confirm "\nContinue with this configuration?" "y"; then print_info "Exiting."; exit 0; fi
    log "Configuration collected: USER=$USERNAME, HOST=$SERVER_NAME, PORT=$SSH_PORT"
}

install_packages() {
    print_section "Package Installation"
    print_info "Updating package lists and upgrading system..."
    if ! apt-get update -qq || ! DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq; then
        print_error "Failed to update or upgrade system packages."
        exit 1
    fi
    print_info "Installing essential packages..."
    if ! apt-get install -y -qq \
        ufw fail2ban unattended-upgrades chrony \
        rsync wget vim htop iotop nethogs ncdu tree \
        rsyslog cron jq gawk coreutils perl skopeo git \
        openssh-client openssh-server; then
        print_error "Failed to install one or more essential packages."
        exit 1
    fi
    print_success "Essential packages installed."
    log "Package installation completed."
}

setup_user() {
    print_section "User Management"
    local USER_HOME SSH_DIR AUTH_KEYS PASS1 PASS2 SSH_PUBLIC_KEY

    if [[ $USER_EXISTS == false ]]; then
        print_info "Creating user '$USERNAME'..."
        if ! adduser --disabled-password --gecos "" "$USERNAME"; then
            print_error "Failed to create user '$USERNAME'."
            exit 1
        fi
        if ! id "$USERNAME" &>/dev/null; then
            print_error "User '$USERNAME' creation verification failed."
            exit 1
        fi
        print_info "Set a password for '$USERNAME' (required for sudo, or press Enter twice to skip for key-only access):"
        while true; do
            read -sp "$(echo -e "${CYAN}New password: ${NC}")" PASS1
            echo
            read -sp "$(echo -e "${CYAN}Retype new password: ${NC}")" PASS2
            echo
            if [[ -z "$PASS1" && -z "$PASS2" ]]; then
                print_warning "Password skipped. Relying on SSH key authentication."
                log "Password setting skipped for '$USERNAME'."
                break
            elif [[ "$PASS1" == "$PASS2" ]]; then
                # **SECURITY FIX**: Do not tee chpasswd output to log file.
                if echo "$USERNAME:$PASS1" | chpasswd >/dev/null 2>&1; then
                    print_success "Password for '$USERNAME' updated."
                    break
                else
                    print_error "Failed to set password. This could be a permissions issue."
                    print_info "Try again or press Enter twice to skip."
                    log "Failed to set password for '$USERNAME'."
                fi
            else
                print_error "Passwords do not match. Please try again."
            fi
        done

        USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
        SSH_DIR="$USER_HOME/.ssh"
        AUTH_KEYS="$SSH_DIR/authorized_keys"

        if confirm "Add an SSH public key from your local machine now?"; then
            while true; do
                read -rp "$(echo -e "${CYAN}Paste your full SSH public key: ${NC}")" SSH_PUBLIC_KEY
                if validate_ssh_key "$SSH_PUBLIC_KEY"; then
                    mkdir -p "$SSH_DIR"
                    chmod 700 "$SSH_DIR"
                    echo "$SSH_PUBLIC_KEY" >> "$AUTH_KEYS"
                    # De-duplicate keys
                    awk '!seen[$0]++' "$AUTH_KEYS" > "$AUTH_KEYS.tmp" && mv "$AUTH_KEYS.tmp" "$AUTH_KEYS"
                    chmod 600 "$AUTH_KEYS"
                    chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
                    print_success "SSH public key added."
                    log "Added SSH public key for '$USERNAME'."
                    LOCAL_KEY_ADDED=true
                    break
                else
                    print_error "Invalid SSH key format. It should start with 'ssh-rsa', 'ecdsa-*', or 'ssh-ed25519'."
                    if ! confirm "Try again?"; then print_info "Skipping SSH key addition."; break; fi
                fi
            done
        fi
        print_success "User '$USERNAME' created."
    else
        print_info "Using existing user: $USERNAME"
        USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
        SSH_DIR="$USER_HOME/.ssh"
        AUTH_KEYS="$SSH_DIR/authorized_keys"
    fi

    print_info "Adding '$USERNAME' to sudo group..."
    if ! groups "$USERNAME" | grep -qw sudo; then
        if ! usermod -aG sudo "$USERNAME"; then
            print_error "Failed to add '$USERNAME' to sudo group."
            exit 1
        fi
        print_success "User added to sudo group."
    else
        print_info "User '$USERNAME' is already in the sudo group."
    fi

    if getent group sudo | grep -qw "$USERNAME"; then
        print_success "Sudo group membership confirmed for '$USERNAME'."
    else
        print_warning "Sudo group membership verification failed. Please check manually with 'sudo -l' as $USERNAME."
    fi
    log "User management completed."
}

configure_system() {
    print_section "System Configuration"
    mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
    cp /etc/hosts "$BACKUP_DIR/hosts.backup"
    cp /etc/fstab "$BACKUP_DIR/fstab.backup"
    cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.backup" 2>/dev/null || true

    print_info "Configuring timezone..."
    while true; do
        read -rp "$(echo -e "${CYAN}Enter desired timezone (e.g., Etc/UTC, America/New_York) [Etc/UTC]: ${NC}")" TIMEZONE
        TIMEZONE=${TIMEZONE:-Etc/UTC}
        if validate_timezone "$TIMEZONE"; then
            if [[ $(timedatectl status | grep "Time zone" | awk '{print $3}') != "$TIMEZONE" ]]; then
                timedatectl set-timezone "$TIMEZONE"
                print_success "Timezone set to $TIMEZONE."
                log "Timezone set to $TIMEZONE."
            else
                print_info "Timezone already set to $TIMEZONE."
            fi
            break
        else
            print_error "Invalid timezone. View list with 'timedatectl list-timezones'."
        fi
    done

    if confirm "Configure system locales interactively?"; then
        dpkg-reconfigure locales
    else
        print_info "Skipping locale configuration."
    fi

    print_info "Configuring hostname..."
    if [[ $(hostnamectl --static) != "$SERVER_NAME" ]]; then
        hostnamectl set-hostname "$SERVER_NAME"
        hostnamectl set-hostname "$PRETTY_NAME" --pretty
        if grep -q "^127.0.1.1" /etc/hosts; then
            sed -i "s/^127.0.1.1.*/127.0.1.1\t$SERVER_NAME/" /etc/hosts
        else
            echo "127.0.1.1 $SERVER_NAME" >> /etc/hosts
        fi
        print_success "Hostname configured: $SERVER_NAME"
    else
        print_info "Hostname already set to $SERVER_NAME."
    fi
    log "System configuration completed."
}

configure_ssh() {
    print_section "SSH Hardening"
    local CURRENT_SSH_PORT USER_HOME SSH_DIR SSH_KEY AUTH_KEYS NEW_SSH_CONFIG

    # Ensure openssh-server is installed
    if ! dpkg -l openssh-server | grep -q ^ii; then
        print_error "openssh-server package is not installed. Please ensure it is installed."
        exit 1
    fi

    # Detect SSH service name and handle socket activation
    if [[ $ID == "ubuntu" ]] && { systemctl is-enabled ssh.service >/dev/null 2>&1 || systemctl is-active ssh.service >/dev/null 2>&1; }; then
        SSH_SERVICE="ssh.service"
    elif systemctl is-enabled sshd.service >/dev/null 2>&1 || systemctl is-active sshd.service >/dev/null 2>&1; then
        SSH_SERVICE="sshd.service"
    elif ps aux | grep -q "[s]shd"; then
        print_warning "SSH daemon running but no standard service detected. Checking for socket activation..."
        if systemctl is-active ssh.socket >/dev/null 2>&1; then
            print_info "Disabling ssh.socket to enable ssh.service..."
            systemctl disable --now ssh.socket
        fi
        SSH_SERVICE="ssh.service"
        if ! systemctl enable --now "$SSH_SERVICE" >/dev/null 2>&1; then
            print_error "Failed to enable and start $SSH_SERVICE. Attempting manual start..."
            if ! /usr/sbin/sshd; then
                print_error "Failed to start SSH daemon manually. Please check openssh-server installation."
                exit 1
            fi
            print_success "SSH daemon started manually."
        fi
    else
        print_error "No SSH service or daemon detected. Please verify openssh-server installation and daemon status."
        exit 1
    fi
    print_info "Using SSH service: $SSH_SERVICE"
    log "Detected SSH service: $SSH_SERVICE"

    # Ensure SSH service is enabled and running
    if ! systemctl is-enabled "$SSH_SERVICE" >/dev/null 2>&1; then
        if ! systemctl enable "$SSH_SERVICE" >/dev/null 2>&1; then
            print_error "Failed to enable $SSH_SERVICE. Please check service status."
            exit 1
        fi
        print_success "SSH service enabled: $SSH_SERVICE"
    fi
    if ! systemctl is-active "$SSH_SERVICE" >/dev/null 2>&1; then
        if ! systemctl start "$SSH_SERVICE" >/dev/null 2>&1; then
            print_error "Failed to start $SSH_SERVICE. Attempting manual start..."
            if ! /usr/sbin/sshd; then
                print_error "Failed to start SSH daemon manually."
                exit 1
            fi
            print_success "SSH daemon started manually."
        fi
    fi

    CURRENT_SSH_PORT=$(ss -tuln | grep -E ":(22|.*$SSH_SERVICE.*)" | awk '{print $5}' | cut -d':' -f2 | head -n1 || echo "22")
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
    SSH_DIR="$USER_HOME/.ssh"
    SSH_KEY="$SSH_DIR/id_ed25519"
    AUTH_KEYS="$SSH_DIR/authorized_keys"

    if [[ $LOCAL_KEY_ADDED == false ]] && [[ ! -s "$AUTH_KEYS" ]]; then
        print_info "No local key provided and no existing keys found. Generating new SSH key..."
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
        sudo -u "$USERNAME" ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q
        cat "$SSH_KEY.pub" >> "$AUTH_KEYS"
        chmod 600 "$AUTH_KEYS"
        chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
        print_success "SSH key generated."
        echo -e "${YELLOW}Public key for remote access:${NC}"
        cat "$SSH_KEY.pub" | tee -a "$LOG_FILE"
        echo -e "${YELLOW}Copy this key to your local ~/.ssh/authorized_keys or use 'ssh-copy-id -p $CURRENT_SSH_PORT $USERNAME@$SERVER_IP' from your local machine.${NC}"
    else
        print_info "SSH key(s) already present or added. Skipping key generation."
    fi

    print_warning "SSH Key Authentication Required for Next Steps!"
    echo -e "${CYAN}Test SSH access from a SEPARATE terminal now: ssh -p $CURRENT_SSH_PORT $USERNAME@$SERVER_IP${NC}"
    
    if ! confirm "Can you successfully log in using your SSH key?"; then
        print_error "SSH key authentication is mandatory to proceed. Please fix and re-run."
        exit 1
    fi

    print_info "Backing up original SSH config..."
    SSHD_BACKUP_FILE="$BACKUP_DIR/sshd_config.backup_$(date +%Y%m%d_%H%M%S)"
    cp /etc/ssh/sshd_config "$SSHD_BACKUP_FILE"

    # Check if SSH config needs updating
    NEW_SSH_CONFIG=$(mktemp)
    tee "$NEW_SSH_CONFIG" > /dev/null <<EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
X11Forwarding no
PrintMotd no
Banner /etc/issue.net
EOF
    if [[ -f /etc/ssh/sshd_config.d/99-hardening.conf ]] && cmp -s "$NEW_SSH_CONFIG" /etc/ssh/sshd_config.d/99-hardening.conf; then
        print_info "SSH configuration already hardened. Skipping."
        rm -f "$NEW_SSH_CONFIG"
    else
        print_info "Creating or updating hardened SSH configuration..."
        mkdir -p /etc/ssh/sshd_config.d
        mv "$NEW_SSH_CONFIG" /etc/ssh/sshd_config.d/99-hardening.conf
        chmod 644 /etc/ssh/sshd_config.d/99-hardening.conf
        tee /etc/issue.net > /dev/null <<'EOF'
******************************************************************************
                        AUTHORIZED ACCESS ONLY
            ════ all attempts are logged and reviewed ════
******************************************************************************
EOF
    fi

    print_info "Testing and restarting SSH service..."
    if sshd -t; then
        if ! systemctl restart "$SSH_SERVICE"; then
            print_error "SSH service failed to restart! Reverting changes..."
            cp "$SSHD_BACKUP_FILE" /etc/ssh/sshd_config
            rm -f /etc/ssh/sshd_config.d/99-hardening.conf
            systemctl restart "$SSH_SERVICE" || /usr/sbin/sshd || true
            exit 1
        fi
        # Wait a moment for the service to potentially fail
        sleep 2
        if systemctl is-active --quiet "$SSH_SERVICE"; then
            print_success "SSH service restarted on port $SSH_PORT."
        else
            print_error "SSH service failed to start! Reverting changes..."
            cp "$SSHD_BACKUP_FILE" /etc/ssh/sshd_config
            rm -f /etc/ssh/sshd_config.d/99-hardening.conf
            systemctl restart "$SSH_SERVICE" || /usr/sbin/sshd || true
            exit 1
        fi
    else
        print_error "SSH config test failed! Reverting changes..."
        cp "$SSHD_BACKUP_FILE" /etc/ssh/sshd_config
        rm -f "$NEW_SSH_CONFIG"
        exit 1
    fi

    # Verify root SSH is disabled
    print_info "Verifying root SSH login is disabled..."
    if ssh -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 root@localhost true 2>/dev/null; then
        print_error "Root SSH login is still possible! Check SSH configuration."
        exit 1
    else
        print_success "Confirmed: Root SSH login is disabled."
    fi

    print_warning "CRITICAL: Test new SSH connection in a SEPARATE terminal NOW!"
    print_info "Use: ssh -p $SSH_PORT $USERNAME@$SERVER_IP"

    if ! confirm "Was the new SSH connection successful?"; then
        print_error "Aborting. Restoring original SSH configuration."
        cp "$SSHD_BACKUP_FILE" /etc/ssh/sshd_config
        rm -f /etc/ssh/sshd_config.d/99-hardening.conf
        systemctl restart "$SSH_SERVICE" || /usr/sbin/sshd || true
        exit 1
    fi
    log "SSH hardening completed."
}

configure_firewall() {
    print_section "Firewall Configuration (UFW)"
    if ufw status | grep -q "Status: active"; then
        print_info "UFW already enabled."
    else
        print_info "Configuring UFW default policies..."
        ufw default deny incoming
        ufw default allow outgoing
    fi
    if ! ufw status | grep -qw "$SSH_PORT/tcp"; then
        print_info "Adding SSH rule for port $SSH_PORT..."
        ufw allow "$SSH_PORT"/tcp comment 'Custom SSH'
    else
        print_info "SSH rule for port $SSH_PORT already exists."
    fi
    if confirm "Allow HTTP traffic (port 80)?"; then
        if ! ufw status | grep -qw "80/tcp"; then
            ufw allow http comment 'HTTP'
            print_success "HTTP traffic allowed."
        else
            print_info "HTTP rule already exists."
        fi
    fi
    if confirm "Allow HTTPS traffic (port 443)?"; then
        if ! ufw status | grep -qw "443/tcp"; then
            ufw allow https comment 'HTTPS'
            print_success "HTTPS traffic allowed."
        else
            print_info "HTTPS rule already exists."
        fi
    fi
    if confirm "Add additional custom ports (e.g., 8080/tcp, 123/udp)?"; then
        while true; do
            local CUSTOM_PORTS # Make variable local to the loop
            read -rp "$(echo -e "${CYAN}Enter ports (space-separated, e.g., 8080/tcp 123/udp): ${NC}")" CUSTOM_PORTS
            if [[ -z "$CUSTOM_PORTS" ]]; then
                print_info "No custom ports entered. Skipping."
                break
            fi
            local valid=true
            for port in $CUSTOM_PORTS; do
                if ! validate_ufw_port "$port"; then
                    print_error "Invalid port format: $port. Use <port>[/tcp|/udp]."
                    valid=false
                    break
                fi
            done
            if [[ "$valid" == true ]]; then
                for port in $CUSTOM_PORTS; do
                    if ufw status | grep -qw "$port"; then
                        print_info "Rule for $port already exists."
                    else
                        ufw allow "$port" comment "Custom port $port"
                        print_success "Added rule for $port."
                        log "Added UFW rule for $port."
                    fi
                done
                break
            else
                print_info "Please try again."
            fi
        done
    fi
    print_info "Enabling firewall..."
    if ! ufw --force enable; then
        print_error "Failed to enable UFW. Check 'journalctl -u ufw' for details."
        exit 1
    fi
    if ufw status | grep -q "Status: active"; then
        print_success "Firewall is active."
    else
        print_error "UFW failed to activate. Check 'journalctl -u ufw' for details."
        exit 1
    fi
    print_warning "ACTION REQUIRED: Check your VPS provider's edge firewall to allow opened ports (e.g., $SSH_PORT/tcp)."
    ufw status verbose | tee -a "$LOG_FILE"
    log "Firewall configuration completed."
}

configure_fail2ban() {
    print_section "Fail2Ban Configuration"
    
    # Set the SSH port for Fail2Ban to monitor.
    local SSH_PORTS_TO_MONITOR="$SSH_PORT"
    local NEW_FAIL2BAN_CONFIG

    NEW_FAIL2BAN_CONFIG=$(mktemp)
    tee "$NEW_FAIL2BAN_CONFIG" > /dev/null <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
backend = auto
[sshd]
enabled = true
port = $SSH_PORTS_TO_MONITOR
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF
    if [[ -f /etc/fail2ban/jail.local ]] && cmp -s "$NEW_FAIL2BAN_CONFIG" /etc/fail2ban/jail.local; then
        print_info "Fail2Ban configuration already correct. Skipping."
        rm -f "$NEW_FAIL2BAN_CONFIG"
    elif [[ -f /etc/fail2ban/jail.local ]] && grep -q "\[sshd\]" /etc/fail2ban/jail.local; then
        print_info "Fail2Ban jail.local exists. Updating SSH port..."
        sed -i "s/^\(port\s*=\s*\).*/\1$SSH_PORTS_TO_MONITOR/" /etc/fail2ban/jail.local
        rm -f "$NEW_FAIL2BAN_CONFIG"
    else
        print_info "Creating Fail2Ban local jail configuration..."
        mv "$NEW_FAIL2BAN_CONFIG" /etc/fail2ban/jail.local
        chmod 644 /etc/fail2ban/jail.local
    fi
    print_info "Enabling and restarting Fail2Ban..."
    systemctl enable fail2ban
    systemctl restart fail2ban
    sleep 2
    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2Ban is active and monitoring port(s) $SSH_PORTS_TO_MONITOR."
        fail2ban-client status sshd | tee -a "$LOG_FILE"
    else
        print_error "Fail2Ban service failed to start."
        exit 1
    fi
    log "Fail2Ban configuration completed."
}

configure_auto_updates() {
    print_section "Automatic Security Updates"
    if confirm "Enable automatic security updates via unattended-upgrades?"; then
        if ! dpkg -l unattended-upgrades | grep -q ^ii; then
            print_error "unattended-upgrades package is not installed."
            exit 1
        fi
        print_info "Configuring unattended upgrades..."
        echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
        DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive unattended-upgrades
        print_success "Automatic security updates enabled."
    else
        print_info "Skipping automatic security updates."
    fi
    log "Automatic updates configuration completed."
}

install_docker() {
    if ! confirm "Install Docker Engine (Optional)?"; then
        print_info "Skipping Docker installation."
        return 0
    fi
    print_section "Docker Installation"
    if command -v docker >/dev/null 2>&1; then
        print_info "Docker already installed."
        return 0
    fi
    print_info "Removing old container runtimes..."
    apt-get remove -y -qq docker docker-engine docker.io containerd runc 2>/dev/null || true
    print_info "Adding Docker's official GPG key and repository..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/${ID}/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
    print_info "Installing Docker packages..."
    if ! apt-get update -qq || ! apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
        print_error "Failed to install Docker packages."
        exit 1
    fi
    print_info "Adding '$USERNAME' to docker group..."
    getent group docker >/dev/null || groupadd docker
    if ! groups "$USERNAME" | grep -qw docker; then
        usermod -aG docker "$USERNAME"
        print_success "User '$USERNAME' added to docker group."
    else
        print_info "User '$USERNAME' is already in docker group."
    fi
    print_info "Configuring Docker daemon..."
    local NEW_DOCKER_CONFIG
    NEW_DOCKER_CONFIG=$(mktemp)
    # **BUG FIX**: Corrected typo from >¼ to >
    tee "$NEW_DOCKER_CONFIG" > /dev/null <<EOF
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "live-restore": true
}
EOF
    mkdir -p /etc/docker
    if [[ -f /etc/docker/daemon.json ]] && cmp -s "$NEW_DOCKER_CONFIG" /etc/docker/daemon.json; then
        print_info "Docker daemon configuration already correct. Skipping."
        rm -f "$NEW_DOCKER_CONFIG"
    else
        mv "$NEW_DOCKER_CONFIG" /etc/docker/daemon.json
        chmod 644 /etc/docker/daemon.json
    fi
    systemctl daemon-reload
    systemctl enable --now docker
    print_info "Running Docker sanity check..."
    if sudo -u "$USERNAME" docker run --rm hello-world 2>&1 | tee -a "$LOG_FILE" | grep -q "Hello from Docker"; then
        print_success "Docker sanity check passed."
    else
        print_error "Docker hello-world test failed. Please verify installation."
        exit 1
    fi
    print_warning "NOTE: '$USERNAME' must log out and back in to use Docker without sudo."
    log "Docker installation completed."
}

install_tailscale() {
    if ! confirm "Install Tailscale VPN (Optional)?"; then
        print_info "Skipping Tailscale installation."
        return 0
    fi
    print_section "Tailscale VPN Installation"
    if command -v tailscale >/dev/null 2>&1; then
        print_info "Tailscale already installed."
        return 0
    fi
    print_info "Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh -o /tmp/tailscale_install.sh
    chmod +x /tmp/tailscale_install.sh
    # Simple sanity check on the downloaded script
    if ! grep -q "tailscale" /tmp/tailscale_install.sh; then
        print_error "Downloaded Tailscale install script appears invalid."
        rm -f /tmp/tailscale_install.sh
        exit 1
    fi
    if ! /tmp/tailscale_install.sh; then
        print_error "Failed to install Tailscale."
        rm -f /tmp/tailscale_install.sh
        exit 1
    fi
    rm -f /tmp/tailscale_install.sh
    print_warning "ACTION REQUIRED: Run 'sudo tailscale up' after script finishes."
    print_success "Tailscale installation complete."
    log "Tailscale installation completed."
}

configure_swap() {
    if [[ $IS_CONTAINER == true ]]; then
        print_info "Swap configuration skipped in container."
        return 0
    fi
    print_section "Swap Configuration"
    local existing_swap
    existing_swap=$(swapon --show --noheadings | awk '{print $1}' || true)
    if [[ -n "$existing_swap" ]]; then
        local current_size
        current_size=$(ls -lh "$existing_swap" | awk '{print $5}')
        print_info "Existing swap file found: $existing_swap ($current_size)"
        if confirm "Modify existing swap file size?"; then
            local SWAP_SIZE
            while true; do
                read -rp "$(echo -e "${CYAN}Enter new swap size (e.g., 2G, 512M) [current: $current_size]: ${NC}")" SWAP_SIZE
                SWAP_SIZE=${SWAP_SIZE:-$current_size}
                if validate_swap_size "$SWAP_SIZE"; then
                    break
                else
                    print_error "Invalid size. Use format like '2G' or '512M'."
                fi
            done
            local REQUIRED_SPACE
            REQUIRED_SPACE=$(convert_to_bytes "$SWAP_SIZE")
            local AVAILABLE_SPACE
            AVAILABLE_SPACE=$(df -k / | tail -n 1 | awk '{print $4}')
            if (( AVAILABLE_SPACE < REQUIRED_SPACE / 1024 )); then
                print_error "Insufficient disk space for $SWAP_SIZE swap file. Available: $((AVAILABLE_SPACE / 1024))MB"
                exit 1
            fi
            print_info "Disabling existing swap file..."
            swapoff "$existing_swap" || { print_error "Failed to disable swap file."; exit 1; }
            print_info "Resizing swap file to $SWAP_SIZE..."
            if ! fallocate -l "$SWAP_SIZE" "$existing_swap" || ! chmod 600 "$existing_swap" || ! mkswap "$existing_swap" || ! swapon "$existing_swap"; then
                print_error "Failed to resize or enable swap file."
                exit 1
            fi
            print_success "Swap file resized to $SWAP_SIZE."
        else
            print_info "Keeping existing swap file."
            return 0
        fi
    else
        if ! confirm "Configure a swap file (recommended for < 4GB RAM)?"; then
            print_info "Skipping swap configuration."
            return 0
        fi
        local SWAP_SIZE
        while true; do
            read -rp "$(echo -e "${CYAN}Enter swap file size (e.g., 2G, 512M) [2G]: ${NC}")" SWAP_SIZE
            SWAP_SIZE=${SWAP_SIZE:-2G}
            if validate_swap_size "$SWAP_SIZE"; then
                break
            else
                print_error "Invalid size. Use format like '2G' or '512M'."
            fi
        done
        local REQUIRED_SPACE
        REQUIRED_SPACE=$(convert_to_bytes "$SWAP_SIZE")
        local AVAILABLE_SPACE
        AVAILABLE_SPACE=$(df -k / | tail -n 1 | awk '{print $4}')
        if (( AVAILABLE_SPACE < REQUIRED_SPACE / 1024 )); then
            print_error "Insufficient disk space for $SWAP_SIZE swap file. Available: $((AVAILABLE_SPACE / 1024))MB"
            exit 1
        fi
        print_info "Creating $SWAP_SIZE swap file..."
        if ! fallocate -l "$SWAP_SIZE" /swapfile || ! chmod 600 /swapfile || ! mkswap /swapfile || ! swapon /swapfile; then
            print_error "Failed to create or enable swap file."
            rm -f /swapfile || true
            exit 1
        fi
        if ! grep -q '^/swapfile ' /etc/fstab; then
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi
        print_success "Swap file created: $SWAP_SIZE"
    fi
    print_info "Optimizing swap settings..."
    local NEW_SWAP_CONFIG
    NEW_SWAP_CONFIG=$(mktemp)
    tee "$NEW_SWAP_CONFIG" > /dev/null <<EOF
vm.swappiness=10
vm.vfs_cache_pressure=50
EOF
    if [[ -f /etc/sysctl.d/99-swap.conf ]] && cmp -s "$NEW_SWAP_CONFIG" /etc/sysctl.d/99-swap.conf; then
        print_info "Swap settings already correct. Skipping."
        rm -f "$NEW_SWAP_CONFIG"
    else
        mv "$NEW_SWAP_CONFIG" /etc/sysctl.d/99-swap.conf
        chmod 644 /etc/sysctl.d/99-swap.conf
        sysctl -p /etc/sysctl.d/99-swap.conf >/dev/null
    fi
    print_success "Swap configured successfully."
    swapon --show | tee -a "$LOG_FILE"
    free -h | tee -a "$LOG_FILE"
    log "Swap configuration completed."
}

configure_time_sync() {
    print_section "Time Synchronization"
    print_info "Ensuring chrony is active..."
    systemctl enable --now chrony
    sleep 2
    if systemctl is-active --quiet chrony; then
        print_success "Chrony is active for time synchronization."
        chronyc tracking | tee -a "$LOG_FILE"
    else
        print_error "Chrony service failed to start."
        exit 1
    fi
    log "Time synchronization completed."
}

final_cleanup() {
    print_section "Final System Cleanup"
    print_info "Running final system update and cleanup..."
    if ! apt-get update -qq; then
        print_warning "Failed to update package lists during final cleanup."
    fi
    if ! apt-get upgrade -y -qq || ! apt-get --purge autoremove -y -qq || ! apt-get autoclean -y -qq; then
        print_warning "Final system cleanup failed on one or more commands."
    fi
    systemctl daemon-reload
    print_success "Final system update and cleanup complete."
    log "Final system cleanup completed."
}

generate_summary() {
    print_section "Setup Complete!"
    print_info "Checking critical services..."
    for service in "$SSH_SERVICE" fail2ban chrony; do
        if systemctl is-active --quiet "$service"; then
            print_success "Service $service is active."
        else
            print_error "Service $service is NOT active."
        fi
    done
    if ufw status | grep -q "Status: active"; then
        print_success "Service ufw is active."
    else
        print_error "Service ufw is NOT active."
    fi
    if command -v docker >/dev/null 2>&1; then
        if systemctl is-active --quiet docker; then
            print_success "Service docker is active."
        else
            print_error "Service docker is NOT active."
        fi
    fi
    echo -e "\n${GREEN}Server setup and hardening script has finished successfully.${NC}"
    echo
    echo -e "${YELLOW}Configuration Summary:${NC}"
    echo -e "  Admin User:   $USERNAME"
    echo -e "  Hostname:     $SERVER_NAME"
    echo -e "  SSH Port:     $SSH_PORT"
    echo -e "  Server IP:    $SERVER_IP"
    echo
    echo -e "${PURPLE}Log File: ${LOG_FILE}${NC}"
    echo -e "${PURPLE}Backups:  ${BACKUP_DIR}${NC}"
    echo
    echo -e "${CYAN}Post-Reboot Verification Steps:${NC}"
    echo -e "  - SSH access:         ssh -p $SSH_PORT $USERNAME@$SERVER_IP"
    echo -e "  - Firewall rules:     sudo ufw status verbose"
    echo -e "  - Time sync:          chronyc tracking"
    echo -e "  - Fail2Ban status:    sudo fail2ban-client status sshd"
    echo -e "  - Swap status:        sudo swapon --show && free -h"
    if command -v docker >/dev/null 2>&1; then
        echo -e "  - Docker status:      docker ps"
    fi
    if command -v tailscale >/dev/null 2>&1; then
        echo -e "  - Tailscale status:   tailscale status"
    fi
    print_warning "\nA reboot is required to apply all changes cleanly."
    if [[ $VERBOSE == true ]]; then
        if confirm "Reboot now?" "y"; then
            print_info "Rebooting now..."
            sleep 3
            reboot
        else
            print_warning "Please reboot manually with 'sudo reboot'."
        fi
    else
        print_warning "Quiet mode enabled. Please reboot manually with 'sudo reboot'."
    fi
    log "Script finished successfully."
}

handle_error() {
    local exit_code=$?
    local line_no="$1"
    print_error "An error occurred on line $line_no (exit code: $exit_code)."
    print_info "Log file: $LOG_FILE"
    print_info "Backups: $BACKUP_DIR"
    exit $exit_code
}

main() {
    trap 'handle_error $LINENO' ERR
    touch "$LOG_FILE" && chmod 600 "$LOG_FILE"
    log "Starting Debian/Ubuntu hardening script."
    
    print_header
    check_dependencies
    check_system
    collect_config
    install_packages
    setup_user
    configure_system
    configure_ssh
    configure_firewall
    configure_fail2ban
    configure_auto_updates
    configure_time_sync
    install_docker
    install_tailscale
    configure_swap
    final_cleanup
    generate_summary
}

# Run main function
main "$@"
