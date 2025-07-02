#!/bin/bash

# Debian 12 and Ubuntu Server Hardening Interactive Script
# Version: 0.54 | 2025-07-02
# Changelog:
# - v0.54: Fix for rollback_ssh_changes() - more reliable on newer Ubuntu
#	   Better error message if script is executed by non-root or without sudo
# - v0.53: Fix for test_backup() - was failing if run as non root sudo user
# - v0.52: Roll-back SSH config on failure to configure SSH port, confirmed SSH config support for Ubuntu 24.10
# - v0.51: corrected repo links
# - v0.50: versioning format change and repo name change
# - v4.3: Add SHA256 integrity verification
# - v4.2: Added Security Audit Tools (Integrating Lynis and Optionally Debsecan) & option to do Backup Testing
#	  Fixed debsecan compatibility (Debian-only), added global BACKUP_LOG, added backup testing
# - v4.1: Added tailscale config to connect to tailscale or headscale server
# - v4.0: Added automated backup config. Mainly for Hetzner Storage Box but can be used for any rsync/SSH enabled remote solution.
# - v3.*: Improvements to script flow and fixed bugs which were found in tests at Oracle Cloud
#
# Description:
# This script provisions and hardens a fresh Debian 12 or Ubuntu server with essential security
# configurations, user management, SSH hardening, firewall setup, and optional features
# like Docker and Tailscale and automated backups to Hetzner storage box or any rsync location.
# It is designed to be idempotent, safe.
# README at GitHub: https://github.com/buildplan/du_setup/blob/main/README.md
#
# Prerequisites:
# - Run as root on a fresh Debian 12 or Ubuntu server (e.g., sudo ./du_setup.sh or run as root -E ./du_setup.sh).
# - Internet connectivity is required for package installation.
#
# Usage:
#   Download: wget https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.sh
#   Make it executable: chmod +x du_setup.sh
#   Run it: sudo -E ./du_setup.sh [--quiet]
#
# Options:
#   --quiet: Suppress non-critical output for automation. (Not recommended always best to review all the options)
#
# Notes:
# - The script creates a log file in /var/log/du_setup_*.log.
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
LOG_FILE="/var/log/du_setup_$(date +%Y%m%d_%H%M%S).log"
BACKUP_LOG="/var/log/backup_rsync.log"
VERBOSE=true
BACKUP_DIR="/root/setup_harden_backup_$(date +%Y%m%d_%H%M%S)"
IS_CONTAINER=false
SSHD_BACKUP_FILE=""
LOCAL_KEY_ADDED=false
SSH_SERVICE=""
ID="" # This will be populated from /etc/os-release
FAILED_SERVICES=()

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
    echo -e "${CYAN}║                      v0.54 | 2025-07-02                         ║${NC}"
    echo -e "${CYAN}║                                                                 ║${NC}"
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

validate_backup_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]
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
        print_error "This script must be run as root (e.g., sudo ./du_setup.sh)."
        exit 1
    fi
    print_success "Running with root privileges."

    if [[ -f /proc/1/cgroup ]] && grep -qE '(docker|lxc|kubepod)' /proc/1/cgroup; then
        IS_CONTAINER=true
        print_warning "Container environment detected. Some features (like swap) will be skipped."
    fi

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        ID=$ID  # Populate global ID variable
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
        rsync wget vim htop iotop nethogs netcat-traditional ncdu \
        tree rsyslog cron jq gawk coreutils perl skopeo git \
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

        if confirm "Add SSH public key(s) from your local machine now?"; then
        while true; do # Loop to allow adding multiple keys
            local SSH_PUBLIC_KEY # Declare locally to avoid issues
            read -rp "$(echo -e "${CYAN}Paste your full SSH public key: ${NC}")" SSH_PUBLIC_KEY

            if validate_ssh_key "$SSH_PUBLIC_KEY"; then
                mkdir -p "$SSH_DIR"
                chmod 700 "$SSH_DIR"
                echo "$SSH_PUBLIC_KEY" >> "$AUTH_KEYS"
                # De-duplicate keys after adding the new one
                awk '!seen[$0]++' "$AUTH_KEYS" > "$AUTH_KEYS.tmp" && mv "$AUTH_KEYS.tmp" "$AUTH_KEYS"
                chmod 600 "$AUTH_KEYS"
                chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
                print_success "SSH public key added."
                log "Added SSH public key for '$USERNAME'."
                LOCAL_KEY_ADDED=true # Set this flag to true since at least one key was added
            else
                print_error "Invalid SSH key format. It should start with 'ssh-rsa', 'ecdsa-*', or 'ssh-ed25519'."
            fi

            if ! confirm "Do you have another SSH public key to add?" "n"; then
                print_info "Finished adding SSH keys."
                break # User answered 'n', break the loop
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

cleanup_and_exit() {
    local exit_code=$?
    if [[ $exit_code -ne 0 && $(type -t rollback_ssh_changes) == "function" ]]; then
        print_error "An error occurred. Rolling back SSH changes to port $PREVIOUS_SSH_PORT..."
        rollback_ssh_changes
        if [[ $? -ne 0 ]]; then
            print_error "Rollback failed. SSH may not be accessible. Please check 'systemctl status $SSH_SERVICE' and 'journalctl -u $SSH_SERVICE'."
        fi
    fi
    exit $exit_code
}

configure_ssh() {
    trap cleanup_and_exit ERR

    print_section "SSH Hardening"
    local CURRENT_SSH_PORT USER_HOME SSH_DIR SSH_KEY AUTH_KEYS NEW_SSH_CONFIG PREVIOUS_SSH_PORT

    # Ensure openssh-server is installed
    if ! dpkg -l openssh-server | grep -q ^ii; then
        print_error "openssh-server package is not installed."
        return 1
    fi

    # Detect SSH service name
    if [[ $ID == "ubuntu" ]] && systemctl is-active ssh.socket >/dev/null 2>&1; then
        SSH_SERVICE="ssh.socket"
        print_info "Using SSH socket activation: $SSH_SERVICE"
    elif [[ $ID == "ubuntu" ]] && { systemctl is-enabled ssh.service >/dev/null 2>&1 || systemctl is-active ssh.service >/dev/null 2>&1; }; then
        SSH_SERVICE="ssh.service"
    elif systemctl is-enabled sshd.service >/dev/null 2>&1 || systemctl is-active sshd.service >/dev/null 2>&1; then
        SSH_SERVICE="sshd.service"
    else
        print_error "No SSH service or daemon detected."
        return 1
    fi
    print_info "Using SSH service: $SSH_SERVICE"
    log "Detected SSH service: $SSH_SERVICE"

    # Store the current active port as the previous port
    PREVIOUS_SSH_PORT=$(ss -tuln | grep -E ":(22|.*$SSH_SERVICE.*)" | awk '{print $5}' | cut -d':' -f2 | head -n1 || echo "22")
    CURRENT_SSH_PORT=$PREVIOUS_SSH_PORT
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
    SSH_DIR="$USER_HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"

    if [[ $LOCAL_KEY_ADDED == false ]] && [[ ! -s "$AUTH_KEYS" ]]; then
        print_info "No local key provided. Generating new SSH key..."
        mkdir -p "$SSH_DIR"; chmod 700 "$SSH_DIR"
        sudo -u "$USERNAME" ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519" -N "" -q
        cat "$SSH_DIR/id_ed25519.pub" >> "$AUTH_KEYS"
        chmod 600 "$AUTH_KEYS"; chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
        print_success "SSH key generated."
        echo -e "${YELLOW}Public key for remote access:${NC}"; cat "$SSH_DIR/id_ed25519.pub"
    fi

    print_warning "SSH Key Authentication Required for Next Steps!"
    echo -e "${CYAN}Test SSH access from a SEPARATE terminal now: ssh -p $CURRENT_SSH_PORT $USERNAME@$SERVER_IP${NC}"
    if ! confirm "Can you successfully log in using your SSH key?"; then
        print_error "SSH key authentication is mandatory to proceed."
        return 1
    fi

    print_info "Backing up original SSH config..."
    SSHD_BACKUP_FILE="$BACKUP_DIR/sshd_config.backup_$(date +%Y%m%d_%H%M%S)"
    cp /etc/ssh/sshd_config "$SSHD_BACKUP_FILE"

    # Apply port override
    if [[ $ID == "ubuntu" ]] && dpkg --compare-versions "$(lsb_release -rs)" ge "24.04"; then
        print_info "Updating SSH port in /etc/ssh/sshd_config for Ubuntu 24.04+..."
        if ! grep -q "^Port" /etc/ssh/sshd_config; then echo "Port $SSH_PORT" >> /etc/ssh/sshd_config; else sed -i "s/^Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config; fi
    elif [[ "$SSH_SERVICE" == "ssh.socket" ]]; then
        print_info "Configuring SSH socket to listen on port $SSH_PORT..."
        mkdir -p /etc/systemd/system/ssh.socket.d
        echo -e "[Socket]\nListenStream=\nListenStream=$SSH_PORT" > /etc/systemd/system/ssh.socket.d/override.conf
    else
        print_info "Configuring SSH service to listen on port $SSH_PORT..."
        mkdir -p /etc/systemd/system/${SSH_SERVICE}.d
        echo -e "[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -p $SSH_PORT" > /etc/systemd/system/${SSH_SERVICE}.d/override.conf
    fi

    # Apply additional hardening
    mkdir -p /etc/ssh/sshd_config.d
    tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null <<EOF
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
X11Forwarding no
PrintMotd no
Banner /etc/issue.net
EOF
    tee /etc/issue.net > /dev/null <<'EOF'
******************************************************************************
                       🔒AUTHORIZED ACCESS ONLY
            ════ all attempts are logged and reviewed ════
******************************************************************************
EOF

    print_info "Reloading systemd and restarting SSH service..."
    systemctl daemon-reload
    systemctl restart "$SSH_SERVICE"
    sleep 5
    if ! ss -tuln | grep -q ":$SSH_PORT"; then
        print_error "SSH not listening on port $SSH_PORT after restart!"
        return 1
    fi
    print_success "SSH service restarted on port $SSH_PORT."

    # Verify root SSH is disabled
    print_info "Verifying root SSH login is disabled..."
    if ssh -p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@localhost true 2>/dev/null; then
        print_error "Root SSH login is still possible! Check configuration."
        return 1
    else
        print_success "Confirmed: Root SSH login is disabled."
    fi

    print_warning "CRITICAL: Test new SSH connection in a SEPARATE terminal NOW!"
    print_info "Use: ssh -p $SSH_PORT $USERNAME@$SERVER_IP"

    # Retry loop for SSH connection test
    local retry_count=0
    local max_retries=3
    while (( retry_count < max_retries )); do
        if confirm "Was the new SSH connection successful?"; then
            print_success "SSH hardening confirmed and finalized."
            break
        else
            (( retry_count++ ))
            if (( retry_count < max_retries )); then
                print_info "Retrying SSH connection test ($retry_count/$max_retries)..."
                sleep 5
            else
                print_error "All retries failed. Initiating rollback to port $PREVIOUS_SSH_PORT..."
                rollback_ssh_changes
                if ! ss -tuln | grep -q ":$PREVIOUS_SSH_PORT"; then
                    print_error "Rollback failed. SSH not restored on original port $PREVIOUS_SSH_PORT."
                else
                    print_success "Rollback successful. SSH restored on original port $PREVIOUS_SSH_PORT."
                fi
                return 1
            fi
        fi
    done

    trap - ERR
    log "SSH hardening completed."
}

rollback_ssh_changes() {
    print_info "Rolling back SSH configuration changes to port $PREVIOUS_SSH_PORT..."

    # Ensure SSH_SERVICE is set and valid
    local SSH_SERVICE=${SSH_SERVICE:-"sshd.service"}
    local USE_SOCKET=false
    # Check if socket activation is used
    if systemctl list-units --full -all --no-pager | grep -E "[[:space:]]ssh.socket[[:space:]]" >/dev/null 2>&1; then
        USE_SOCKET=true
        SSH_SERVICE="ssh.socket"
        print_info "Detected SSH socket activation: using ssh.socket."
        log "Rollback: Using ssh.socket for SSH service."
    elif ! systemctl list-units --full -all --no-pager | grep -E "[[:space:]]$SSH_SERVICE[[:space:]]" >/dev/null 2>&1; then
        SSH_SERVICE="ssh.service" # Fallback for Ubuntu
        print_warning "SSH service $SSH_SERVICE not found, falling back to ssh.service."
        log "Rollback warning: Using fallback SSH service ssh.service."
        # Verify fallback service exists
        if ! systemctl list-units --full -all --no-pager | grep -E "[[:space:]]ssh.service[[:space:]]" >/dev/null 2>&1; then
            print_error "No valid SSH service (sshd.service or ssh.service) found."
            log "Rollback failed: No valid SSH service detected."
            print_info "Action: Verify SSH service with 'systemctl list-units --full -all | grep ssh' and manually configure /etc/ssh/sshd_config."
            return 0
        fi
    fi

    # Remove systemd overrides for both service and socket
    local OVERRIDE_DIR="/etc/systemd/system/${SSH_SERVICE}.d"
    local SOCKET_OVERRIDE_DIR="/etc/systemd/system/ssh.socket.d"
    local SERVICE_OVERRIDE_DIR="/etc/systemd/system/ssh.service.d"
    if ! rm -rf "$OVERRIDE_DIR" "$SOCKET_OVERRIDE_DIR" "$SERVICE_OVERRIDE_DIR" 2>/dev/null; then
        print_warning "Failed to remove systemd overrides at $OVERRIDE_DIR, $SOCKET_OVERRIDE_DIR, or $SERVICE_OVERRIDE_DIR."
        log "Rollback warning: Failed to remove systemd overrides."
    else
        log "Removed systemd overrides: $OVERRIDE_DIR, $SOCKET_OVERRIDE_DIR, $SERVICE_OVERRIDE_DIR"
    fi

    # Remove custom SSH configuration
    if ! rm -f /etc/ssh/sshd_config.d/99-hardening.conf 2>/dev/null; then
        print_warning "Failed to remove /etc/ssh/sshd_config.d/99-hardening.conf."
        log "Rollback warning: Failed to remove /etc/ssh/sshd_config.d/99-hardening.conf."
    else
        log "Removed /etc/ssh/sshd_config.d/99-hardening.conf"
    fi

    # Restore original sshd_config
    if [[ -f "$SSHD_BACKUP_FILE" ]]; then
        if ! cp "$SSHD_BACKUP_FILE" /etc/ssh/sshd_config 2>/dev/null; then
            print_error "Failed to restore sshd_config from $SSHD_BACKUP_FILE."
            log "Rollback failed: Cannot copy $SSHD_BACKUP_FILE to /etc/ssh/sshd_config."
            print_info "Action: Manually restore with 'cp $SSHD_BACKUP_FILE /etc/ssh/sshd_config' and verify with 'sshd -t'."
            return 0
        fi
        print_info "Restored original sshd_config from $SSHD_BACKUP_FILE."
        log "Restored sshd_config from $SSHD_BACKUP_FILE."
    else
        print_error "Backup file not found at $SSHD_BACKUP_FILE."
        log "Rollback failed: $SSHD_BACKUP_FILE not found."
        print_info "Action: Manually configure /etc/ssh/sshd_config to use port $PREVIOUS_SSH_PORT and verify with 'sshd -t'."
        return 0
    fi

    # Validate restored sshd_config
    if ! /usr/sbin/sshd -t >/tmp/sshd_config_test.log 2>&1; then
        print_error "Restored sshd_config is invalid. Check /tmp/sshd_config_test.log for details."
        log "Rollback failed: Invalid sshd_config after restoration. See /tmp/sshd_config_test.log."
        print_info "Action: Fix /etc/ssh/sshd_config manually and test with 'sshd -t', then restart with 'systemctl restart ssh.service'."
        return 0
    fi

    # Reload systemd
    print_info "Reloading systemd..."
    if ! systemctl daemon-reload 2>/dev/null; then
        print_warning "Failed to reload systemd. Continuing with restart attempt..."
        log "Rollback warning: Failed to reload systemd."
    fi

    # Handle socket activation or direct service restart
    if [[ "$USE_SOCKET" == true ]]; then
        # Stop ssh.socket to avoid conflicts
        if systemctl is-active --quiet ssh.socket; then
            if ! systemctl stop ssh.socket 2>/tmp/ssh_socket_stop.log; then
                print_warning "Failed to stop ssh.socket. May affect port binding."
                log "Rollback warning: Failed to stop ssh.socket. See /tmp/ssh_socket_stop.log."
            else
                log "Stopped ssh.socket to ensure correct port binding."
            fi
        fi
        # Restart ssh.service to ensure sshd starts
        print_info "Restarting ssh.service..."
        if ! systemctl restart ssh.service 2>/tmp/sshd_restart.log; then
            print_warning "Failed to restart ssh.service. Attempting manual start..."
            log "Rollback warning: Failed to restart ssh.service. See /tmp/sshd_restart.log."
            # Ensure no other sshd processes are running
            pkill -f "sshd:.*" 2>/dev/null || true
            # Manual start in foreground to verify
            timeout 5 /usr/sbin/sshd -D -f /etc/ssh/sshd_config >/tmp/sshd_manual_start.log 2>&1
            local TIMEOUT_EXIT=$?
            if [[ $TIMEOUT_EXIT -eq 0 || $TIMEOUT_EXIT -eq 124 ]]; then
                log "Manual SSH start succeeded (exit code $TIMEOUT_EXIT)."
                # Restart ssh.service to ensure systemd management
                if ! systemctl restart ssh.service 2>/tmp/sshd_restart_manual.log; then
                    print_error "Failed to restart ssh.service after manual start."
                    log "Rollback failed: Failed to restart ssh.service after manual start. See /tmp/sshd_restart_manual.log."
                    print_info "Action: Check service status with 'systemctl status ssh.service' and logs with 'journalctl -u ssh.service'."
                    return 0
                fi
            else
                print_error "Manual SSH start failed (exit code $TIMEOUT_EXIT). Check /tmp/sshd_manual_start.log."
                log "Rollback failed: Manual SSH start failed (exit code $TIMEOUT_EXIT). See /tmp/sshd_manual_start.log."
                print_info "Action: Check service status with 'systemctl status ssh.service' and logs with 'journalctl -u ssh.service'."
                return 0
            fi
        fi
        # Restart ssh.socket to re-enable socket activation
        print_info "Restarting ssh.socket..."
        if ! systemctl restart ssh.socket 2>/tmp/ssh_socket_restart.log; then
            print_warning "Failed to restart ssh.socket. SSH service may still be running."
            log "Rollback warning: Failed to restart ssh.socket. See /tmp/ssh_socket_restart.log."
        else
            log "Restarted ssh.socket for socket activation."
        fi
    else
        # Direct service restart for non-socket systems
        print_info "Restarting $SSH_SERVICE..."
        if ! systemctl restart "$SSH_SERVICE" 2>/tmp/sshd_restart.log; then
            print_warning "Failed to restart $SSH_SERVICE. Attempting manual start..."
            log "Rollback warning: Failed to restart $SSH_SERVICE. See /tmp/sshd_restart.log."
            # Ensure no other sshd processes are running
            pkill -f "sshd:.*" 2>/dev/null || true
            # Manual start in foreground to verify
            timeout 5 /usr/sbin/sshd -D -f /etc/ssh/sshd_config >/tmp/sshd_manual_start.log 2>&1
            local TIMEOUT_EXIT=$?
            if [[ $TIMEOUT_EXIT -eq 0 || $TIMEOUT_EXIT -eq 124 ]]; then
                log "Manual SSH start succeeded (exit code $TIMEOUT_EXIT)."
                # Restart service to ensure systemd management
                if ! systemctl restart "$SSH_SERVICE" 2>/tmp/sshd_restart_manual.log; then
                    print_error "Failed to restart $SSH_SERVICE after manual start."
                    log "Rollback failed: Failed to restart $SSH_SERVICE after manual start. See /tmp/sshd_restart_manual.log."
                    print_info "Action: Check service status with 'systemctl status $SSH_SERVICE' and logs with 'journalctl -u $SSH_SERVICE'."
                    return 0
                fi
            else
                print_error "Manual SSH start failed (exit code $TIMEOUT_EXIT). Check /tmp/sshd_manual_start.log."
                log "Rollback failed: Manual SSH start failed (exit code $TIMEOUT_EXIT). See /tmp/sshd_manual_start.log."
                print_info "Action: Check service status with 'systemctl status $SSH_SERVICE' and logs with 'journalctl -u $SSH_SERVICE'."
                return 0
            fi
        fi
    fi

    # Verify rollback with retries
    local rollback_verified=false
    print_info "Verifying SSH rollback to port $PREVIOUS_SSH_PORT..."
    for ((i=1; i<=10; i++)); do
        if ss -tuln | grep -q ":$PREVIOUS_SSH_PORT "; then
            rollback_verified=true
            break
        fi
        log "Rollback verification attempt $i/10: SSH not listening on port $PREVIOUS_SSH_PORT."
        sleep 3
    done

    if [[ $rollback_verified == true ]]; then
        print_success "Rollback successful. SSH is now listening on port $PREVIOUS_SSH_PORT."
        log "Rollback successful: SSH listening on port $PREVIOUS_SSH_PORT."
    else
        print_error "Rollback failed. SSH service is not listening on port $PREVIOUS_SSH_PORT."
        log "Rollback failed: SSH not listening on port $PREVIOUS_SSH_PORT. See /tmp/sshd_config_test.log, /tmp/sshd_restart.log, /tmp/sshd_manual_start.log, /tmp/ssh_socket_restart.log."
        print_info "Action: Check service status with 'systemctl status ssh.service' or 'systemctl status ssh.socket', logs with 'journalctl -u ssh.service' or 'journalctl -u ssh.socket', and test config with 'sshd -t'."
        print_info "Manually verify port with 'ss -tuln | grep :$PREVIOUS_SSH_PORT'."
        print_info "Try starting SSH with 'sudo systemctl start ssh.service'."
    fi

    return 0
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
    if confirm "Allow Tailscale traffic (UDP 41641)?"; then
        if ! ufw status | grep -qw "41641/udp"; then
            ufw allow 41641/udp comment 'Tailscale VPN'
            print_success "Tailscale traffic (UDP 41641) allowed."
            log "Added UFW rule for Tailscale (41641/udp)."
        else
            print_info "Tailscale rule (UDP 41641) already exists."
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
                        local CUSTOM_COMMENT
                        read -rp "$(echo -e "${CYAN}Enter comment for $port (e.g., 'My App Port'): ${NC}")" CUSTOM_COMMENT
                        if [[ -z "$CUSTOM_COMMENT" ]]; then
                            CUSTOM_COMMENT="Custom port $port"
                        fi
                        # Sanitize comment to avoid breaking UFW command
                        CUSTOM_COMMENT=$(echo "$CUSTOM_COMMENT" | tr -d "'\"\\")
                        ufw allow "$port" comment "$CUSTOM_COMMENT"
                        print_success "Added rule for $port with comment '$CUSTOM_COMMENT'."
                        log "Added UFW rule for $port with comment '$CUSTOM_COMMENT'."
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
    print_warning "ACTION REQUIRED: Check your VPS provider's edge firewall to allow opened ports (e.g., $SSH_PORT/tcp, 41641/udp for Tailscale)."
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
        # Check for existing unattended-upgrades configuration
        if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]] && grep -q "Unattended-Upgrade::Allowed-Origins" /etc/apt/apt.conf.d/50unattended-upgrades; then
            print_info "Existing unattended-upgrades configuration found. Verify with 'cat /etc/apt/apt.conf.d/50unattended-upgrades'."
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
    if ! confirm "Install and configure Tailscale VPN (Optional)?"; then
        print_info "Skipping Tailscale installation."
        log "Tailscale installation skipped by user."
        return 0
    fi
    print_section "Tailscale VPN Installation and Configuration"
    if command -v tailscale >/dev/null 2>&1; then
        print_info "Tailscale already installed."
        if systemctl is-active --quiet tailscaled && tailscale ip >/dev/null 2>&1; then
            local TS_IPS TS_IPV4
            TS_IPS=$(tailscale ip 2>/dev/null || echo "Unknown")
            TS_IPV4=$(echo "$TS_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo "Unknown")
            print_success "Tailscale service is active and connected. Node IPv4 in tailnet: $TS_IPV4"
            echo "$TS_IPS" > /tmp/tailscale_ips.txt
            return 0
        else
            print_warning "Tailscale installed but service is not active or not connected."
        fi
    else
        print_info "Installing Tailscale..."
        curl -fsSL https://tailscale.com/install.sh -o /tmp/tailscale_install.sh
        chmod +x /tmp/tailscale_install.sh
        if ! grep -q "tailscale" /tmp/tailscale_install.sh; then
            print_error "Downloaded Tailscale install script appears invalid."
            rm -f /tmp/tailscale_install.sh
            log "Tailscale installation failed: Invalid install script."
            return 0
        fi
        if ! /tmp/tailscale_install.sh; then
            print_error "Failed to install Tailscale."
            rm -f /tmp/tailscale_install.sh
            log "Tailscale installation failed."
            return 0
        fi
        rm -f /tmp/tailscale_install.sh
        print_success "Tailscale installation complete."
        log "Tailscale installation completed."
    fi

    # --- Configure Tailscale Connection ---
    if systemctl is-active --quiet tailscaled && tailscale ip >/dev/null 2>&1; then
        local TS_IPS TS_IPV4
        TS_IPS=$(tailscale ip 2>/dev/null || echo "Unknown")
        TS_IPV4=$(echo "$TS_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo "Unknown")
        print_info "Tailscale is already connected. Node IPv4 in tailnet: $TS_IPV4"
        echo "$TS_IPS" > /tmp/tailscale_ips.txt
        return 0
    fi
    print_info "Configuring Tailscale connection..."
    echo -e "${CYAN}Choose Tailscale connection method:${NC}"
    echo -e "  1) Standard Tailscale (requires pre-auth key from https://login.tailscale.com/admin)"
    echo -e "  2) Custom Tailscale server (requires server URL and pre-auth key)"
    read -rp "$(echo -e "${CYAN}Enter choice (1-2) [1]: ${NC}")" TS_CONNECTION
    TS_CONNECTION=${TS_CONNECTION:-1}
    local AUTH_KEY LOGIN_SERVER=""
    if [[ "$TS_CONNECTION" == "2" ]]; then
        while true; do
            read -rp "$(echo -e "${CYAN}Enter Tailscale server URL (e.g., https://ts.mydomain.cloud): ${NC}")" LOGIN_SERVER
            if [[ "$LOGIN_SERVER" =~ ^https://[a-zA-Z0-9.-]+(:[0-9]+)?$ ]]; then break; else print_error "Invalid URL. Must start with https://. Try again."; fi
        done
    fi
    while true; do
        read -rp "$(echo -e "${CYAN}Enter Tailscale pre-auth key: ${NC}")" AUTH_KEY
        if [[ "$TS_CONNECTION" == "1" && "$AUTH_KEY" =~ ^tskey-auth- ]]; then break
        elif [[ "$TS_CONNECTION" == "2" && -n "$AUTH_KEY" ]]; then
            print_warning "Ensure the pre-auth key is valid for your custom Tailscale server ($LOGIN_SERVER)."
            break
        else
            print_error "Invalid key format. For standard connection, key must start with 'tskey-auth-'. For custom server, key cannot be empty."
        fi
    done
    local TS_COMMAND="tailscale up"
    if [[ "$TS_CONNECTION" == "2" ]]; then
        TS_COMMAND="$TS_COMMAND --login-server=$LOGIN_SERVER"
    fi
    TS_COMMAND="$TS_COMMAND --auth-key=$AUTH_KEY --operator=$USERNAME"
    print_info "Connecting to Tailscale with: $TS_COMMAND"
    if ! $TS_COMMAND; then
        print_warning "Failed to connect to Tailscale. Possible issues: invalid pre-auth key, network restrictions, or server unavailability."
        print_info "Please run the following command manually after resolving the issue:"
        echo -e "${CYAN}  $TS_COMMAND${NC}"
        log "Tailscale connection failed: $TS_COMMAND"
    else
        # Verify connection status with retries
        local RETRIES=3
        local DELAY=5
        local CONNECTED=false
        local TS_IPS TS_IPV4
        for ((i=1; i<=RETRIES; i++)); do
            if tailscale ip >/dev/null 2>&1; then
                TS_IPS=$(tailscale ip 2>/dev/null || echo "Unknown")
                TS_IPV4=$(echo "$TS_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo "Unknown")
                if [[ -n "$TS_IPV4" && "$TS_IPV4" != "Unknown" ]]; then
                    CONNECTED=true
                    break
                fi
            fi
            print_info "Waiting for Tailscale to connect ($i/$RETRIES)..."
            sleep $DELAY
        done
        if $CONNECTED; then
            print_success "Tailscale connected successfully. Node IPv4 in tailnet: $TS_IPV4"
            log "Tailscale connected: $TS_COMMAND"
            # Store connection details for summary
            echo "${LOGIN_SERVER:-https://controlplane.tailscale.com}" > /tmp/tailscale_server
            echo "$TS_IPS" > /tmp/tailscale_ips.txt
            echo "None" > /tmp/tailscale_flags
        else
            print_warning "Tailscale connection attempt succeeded, but no IPs assigned."
            print_info "Please verify with 'tailscale ip' and run the following command manually if needed:"
            echo -e "${CYAN}  $TS_COMMAND${NC}"
            log "Tailscale connection not verified: $TS_COMMAND"
            tailscale status > /tmp/tailscale_status.txt 2>&1
            log "Tailscale status output saved to /tmp/tailscale_status.txt for debugging"
        fi
    fi

    # --- Configure Additional Flags ---
    print_info "Select additional Tailscale options to configure (comma-separated, e.g., 1,3):"
    echo -e "${CYAN}  1) SSH (--ssh) - WARNING: May restrict server access to Tailscale connections only${NC}"
    echo -e "${CYAN}  2) Advertise as Exit Node (--advertise-exit-node)${NC}"
    echo -e "${CYAN}  3) Accept DNS (--accept-dns)${NC}"
    echo -e "${CYAN}  4) Accept Routes (--accept-routes)${NC}"
    echo -e "${CYAN}  Enter numbers (1-4) or leave blank to skip:${NC}"
    read -rp "  " TS_FLAG_CHOICES
    local TS_FLAGS=""
    if [[ -n "$TS_FLAG_CHOICES" ]]; then
        if echo "$TS_FLAG_CHOICES" | grep -q "1"; then
            TS_FLAGS="$TS_FLAGS --ssh"
        fi
        if echo "$TS_FLAG_CHOICES" | grep -q "2"; then
            TS_FLAGS="$TS_FLAGS --advertise-exit-node"
        fi
        if echo "$TS_FLAG_CHOICES" | grep -q "3"; then
            TS_FLAGS="$TS_FLAGS --accept-dns"
        fi
        if echo "$TS_FLAG_CHOICES" | grep -q "4"; then
            TS_FLAGS="$TS_FLAGS --accept-routes"
        fi
        if [[ -n "$TS_FLAGS" ]]; then
            TS_COMMAND="tailscale up"
            if [[ "$TS_CONNECTION" == "2" ]]; then
                TS_COMMAND="$TS_COMMAND --login-server=$LOGIN_SERVER"
            fi
            TS_COMMAND="$TS_COMMAND --auth-key=$AUTH_KEY --operator=$USERNAME $TS_FLAGS"
            print_info "Reconfiguring Tailscale with additional options: $TS_COMMAND"
            if ! $TS_COMMAND; then
                print_warning "Failed to reconfigure Tailscale with additional options."
                print_info "Please run the following command manually after resolving the issue:"
                echo -e "${CYAN}  $TS_COMMAND${NC}"
                log "Tailscale reconfiguration failed: $TS_COMMAND"
            else
                # Verify reconfiguration status with retries
                local RETRIES=3
                local DELAY=5
                local CONNECTED=false
                local TS_IPS TS_IPV4
                for ((i=1; i<=RETRIES; i++)); do
                    if tailscale ip >/dev/null 2>&1; then
                        TS_IPS=$(tailscale ip 2>/dev/null || echo "Unknown")
                        TS_IPV4=$(echo "$TS_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo "Unknown")
                        if [[ -n "$TS_IPV4" && "$TS_IPV4" != "Unknown" ]]; then
                            CONNECTED=true
                            break
                        fi
                    fi
                    print_info "Waiting for Tailscale to connect ($i/$RETRIES)..."
                    sleep $DELAY
                done
                if $CONNECTED; then
                    print_success "Tailscale reconfigured with additional options. Node IPv4 in tailnet: $TS_IPV4"
                    log "Tailscale reconfigured: $TS_COMMAND"
		    # Store flags and IPs for summary
                    echo "$TS_FLAGS" | sed 's/ --/ /g' | sed 's/^ *//' > /tmp/tailscale_flags
                    echo "$TS_IPS" > /tmp/tailscale_ips.txt
                else
                    print_warning "Tailscale reconfiguration attempt succeeded, but no IPs assigned."
                    print_info "Please verify with 'tailscale ip' and run the following command manually if needed:"
                    echo -e "${CYAN}  $TS_COMMAND${NC}"
                    log "Tailscale reconfiguration not verified: $TS_COMMAND"
                    tailscale status > /tmp/tailscale_status.txt 2>&1
                    log "Tailscale status output saved to /tmp/tailscale_status.txt for debugging"
                fi
            fi
        else
            print_info "No valid Tailscale options selected."
            log "No valid Tailscale options selected."
        fi
    else
        print_info "No additional Tailscale options selected."
        log "No additional Tailscale options applied."
    fi
    print_success "Tailscale setup complete."
    print_info "Verify status: tailscale ip"
    log "Tailscale setup completed."
}

setup_backup() {
    print_section "Backup Configuration (rsync over SSH)"

    if ! confirm "Configure rsync-based backups to a remote SSH server?"; then
        print_info "Skipping backup configuration."
        log "Backup configuration skipped by user."
        return 0
    fi

    # --- Pre-flight Check ---
    if [[ -z "$USERNAME" ]] || ! id "$USERNAME" >/dev/null 2>&1; then
        print_error "Cannot configure backup: valid admin user ('$USERNAME') not found."
        log "Backup configuration failed: USERNAME variable not set or user does not exist."
        return 1
    fi

    local ROOT_SSH_DIR="/root/.ssh"
    local ROOT_SSH_KEY="$ROOT_SSH_DIR/id_ed25519"
    local BACKUP_SCRIPT_PATH="/root/run_backup.sh"
    local EXCLUDE_FILE_PATH="/root/rsync_exclude.txt"
    local CRON_MARKER="#-*- managed by setup_harden script -*-"

    # --- Generate SSH Key for Root ---
    if [[ ! -f "$ROOT_SSH_KEY" ]]; then
        print_info "Generating a dedicated SSH key for root's backup job..."
        mkdir -p "$ROOT_SSH_DIR" && chmod 700 "$ROOT_SSH_DIR"
        ssh-keygen -t ed25519 -f "$ROOT_SSH_KEY" -N "" -q
        chown -R root:root "$ROOT_SSH_DIR"
        print_success "Root SSH key generated at $ROOT_SSH_KEY"
        log "Generated root SSH key for backups."
    else
        print_info "Existing root SSH key found at $ROOT_SSH_KEY."
    fi

    # --- Collect Backup Destination Details with Retry Loops ---
    local BACKUP_DEST BACKUP_PORT REMOTE_BACKUP_PATH SSH_COPY_ID_FLAGS=""

    while true; do
        read -rp "$(echo -e "${CYAN}Enter backup destination (e.g., u12345@u12345.your-storagebox.de): ${NC}")" BACKUP_DEST
        if [[ "$BACKUP_DEST" =~ ^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$ ]]; then break; else print_error "Invalid format. Expected user@host. Please try again."; fi
    done

    while true; do
        read -rp "$(echo -e "${CYAN}Enter destination SSH port (Hetzner uses 23) [22]: ${NC}")" BACKUP_PORT
        BACKUP_PORT=${BACKUP_PORT:-22}
        if [[ "$BACKUP_PORT" =~ ^[0-9]+$ && "$BACKUP_PORT" -ge 1 && "$BACKUP_PORT" -le 65535 ]]; then break; else print_error "Invalid port. Must be between 1 and 65535. Please try again."; fi
    done

    while true; do
        read -rp "$(echo -e "${CYAN}Enter remote backup path (e.g., /home/my_backups/): ${NC}")" REMOTE_BACKUP_PATH
        if [[ "$REMOTE_BACKUP_PATH" =~ ^/[^[:space:]]*/$ ]]; then break; else print_error "Invalid path. Must start and end with '/' and contain no spaces. Please try again."; fi
    done

    print_info "Backup target set to: ${BACKUP_DEST}:${REMOTE_BACKUP_PATH} on port ${BACKUP_PORT}"

    # --- Hetzner Specific Handling ---
    if confirm "Is this backup destination a Hetzner Storage Box (requires special -s flag for key copy)?"; then
        SSH_COPY_ID_FLAGS="-s"
        print_info "Hetzner Storage Box mode enabled. Using '-s' for ssh-copy-id."
    fi

    # --- Handle SSH Key Copy ---
    echo -e "${CYAN}Choose how to copy the root SSH key:${NC}"
    echo -e "  1) Automate with password (requires sshpass, password stored briefly in memory)"
    echo -e "  2) Manual copy (recommended)"
    read -rp "$(echo -e "${CYAN}Enter choice (1-2) [2]: ${NC}")" KEY_COPY_CHOICE
    KEY_COPY_CHOICE=${KEY_COPY_CHOICE:-2}
    if [[ "$KEY_COPY_CHOICE" == "1" ]]; then
        if ! command -v sshpass >/dev/null 2>&1; then
            print_info "Installing sshpass for automated key copying..."
            apt-get update -qq && apt-get install -y -qq sshpass || { print_warning "Failed to install sshpass. Falling back to manual copy."; KEY_COPY_CHOICE=2; }
        fi
        if [[ "$KEY_COPY_CHOICE" == "1" ]]; then
            read -sp "$(echo -e "${CYAN}Enter password for $BACKUP_DEST: ${NC}")" BACKUP_PASSWORD; echo
            # Ensure ~/.ssh/ exists on remote for Hetzner
            if [[ -n "$SSH_COPY_ID_FLAGS" ]]; then
                ssh -p "$BACKUP_PORT" "$BACKUP_DEST" "mkdir -p ~/.ssh && chmod 700 ~/.ssh" 2>/dev/null || print_warning "Failed to create ~/.ssh on remote server."
            fi
            if SSHPASS="$BACKUP_PASSWORD" sshpass -e ssh-copy-id -p "$BACKUP_PORT" -i "$ROOT_SSH_KEY.pub" $SSH_COPY_ID_FLAGS "$BACKUP_DEST" 2>&1 | tee /tmp/ssh-copy-id.log; then
                print_success "SSH key copied successfully."
            else
                print_error "Automated SSH key copy failed. Error details in /tmp/ssh-copy-id.log."
                print_info "Please verify the password and ensure ~/.ssh/authorized_keys is writable on the remote server."
                KEY_COPY_CHOICE=2
            fi
        fi
    fi
    if [[ "$KEY_COPY_CHOICE" == "2" ]]; then
        print_warning "ACTION REQUIRED: Copy the root SSH key to the backup destination."
        echo -e "This will allow the root user to connect without a password for automated backups."
        echo -e "${YELLOW}The root user's public key is:${NC}"; cat "${ROOT_SSH_KEY}.pub"; echo
        echo -e "${YELLOW}Run the following command from this server's terminal to copy the key:${NC}"
        echo -e "${CYAN}ssh-copy-id -p \"${BACKUP_PORT}\" -i \"${ROOT_SSH_KEY}.pub\" ${SSH_COPY_ID_FLAGS} \"${BACKUP_DEST}\"${NC}"; echo
        if [[ -n "$SSH_COPY_ID_FLAGS" ]]; then
            print_info "For Hetzner, ensure ~/.ssh/ exists on the remote server: ssh -p \"$BACKUP_PORT\" \"$BACKUP_DEST\" \"mkdir -p ~/.ssh && chmod 700 ~/.ssh\""
        fi
    fi

    # --- SSH Connection Test ---
    if confirm "Test SSH connection to the backup destination (recommended)?"; then
        print_info "Testing SSH connection (timeout: 10 seconds)..."
        if [[ ! -f "$ROOT_SSH_DIR/known_hosts" ]] || ! grep -q "$BACKUP_DEST" "$ROOT_SSH_DIR/known_hosts"; then
            print_warning "SSH key may not be copied yet. Connection test may fail."
        fi
        local test_command="ssh -p \"$BACKUP_PORT\" -o BatchMode=yes -o ConnectTimeout=10 \"$BACKUP_DEST\" true"
        if [[ -n "$SSH_COPY_ID_FLAGS" ]]; then
            test_command="sftp -P \"$BACKUP_PORT\" -o BatchMode=yes -o ConnectTimeout=10 \"$BACKUP_DEST\" <<< 'quit'"
        fi
        if eval "$test_command" 2>/dev/null; then
            print_success "SSH connection to backup destination successful!"
        else
            print_error "SSH connection test failed. Please ensure the key was copied correctly and the port is open."
            print_info "  - Copy key: ssh-copy-id -p \"$BACKUP_PORT\" -i \"$ROOT_SSH_KEY.pub\" $SSH_COPY_ID_FLAGS \"$BACKUP_DEST\""
            print_info "  - Check port: nc -zv $(echo \"$BACKUP_DEST\" | cut -d'@' -f2) \"$BACKUP_PORT\""
            print_info "  - Ensure key is in ~/.ssh/authorized_keys on the backup server."
            if [[ -n "$SSH_COPY_ID_FLAGS" ]]; then
                print_info "  - For Hetzner, ensure ~/.ssh/ exists: ssh -p \"$BACKUP_PORT\" \"$BACKUP_DEST\" \"mkdir -p ~/.ssh && chmod 700 ~/.ssh\""
            fi
        fi
    fi

    # --- Create Exclude File ---
    print_info "Creating rsync exclude file at $EXCLUDE_FILE_PATH..."
    tee "$EXCLUDE_FILE_PATH" > /dev/null <<'EOF'
# Default Exclusions
.cache/
.docker/
.local/
.npm/
.vscode-server/
*.log
*.tmp
node_modules/
.bash_history
.wget-hsts
EOF
    if confirm "Add more directories/files to the exclude list?"; then
        read -rp "$(echo -e "${CYAN}Enter items separated by spaces (e.g., Videos/ 'My Documents/'): ${NC}")" -a extra_excludes
        for item in "${extra_excludes[@]}"; do echo "$item" >> "$EXCLUDE_FILE_PATH"; done
    fi
    chmod 600 "$EXCLUDE_FILE_PATH"
    print_success "Rsync exclude file created."

    # --- Collect Cron Schedule ---
    local CRON_SCHEDULE="5 3 * * *"
    print_info "Enter a cron schedule for the backup. Use https://crontab.guru for help."
    read -rp "$(echo -e "${CYAN}Enter schedule (default: daily at 3:05 AM) [${CRON_SCHEDULE}]: ${NC}")" input
    CRON_SCHEDULE="${input:-$CRON_SCHEDULE}"
    if ! echo "$CRON_SCHEDULE" | grep -qE '^((\*\/)?[0-9,-]+|\*)\s+(((\*\/)?[0-9,-]+|\*)\s+){3}((\*\/)?[0-9,-]+|\*|[0-6])$'; then
        print_error "Invalid cron expression. Using default: ${CRON_SCHEDULE}"
    fi

    # --- Collect Notification Details ---
    local NOTIFICATION_SETUP="none" NTFY_URL="" NTFY_TOKEN="" DISCORD_WEBHOOK=""
    if confirm "Enable backup status notifications?"; then
        echo -e "${CYAN}Select notification method: 1) ntfy.sh  2) Discord  [1]: ${NC}"; read -r n_choice
        if [[ "$n_choice" == "2" ]]; then
            NOTIFICATION_SETUP="discord"
            read -rp "$(echo -e "${CYAN}Enter Discord Webhook URL: ${NC}")" DISCORD_WEBHOOK
            if [[ ! "$DISCORD_WEBHOOK" =~ ^https://discord.com/api/webhooks/ ]]; then
                print_error "Invalid Discord webhook URL."
                log "Invalid Discord webhook URL provided."
                return 1
            fi
        else
            NOTIFICATION_SETUP="ntfy"
            read -rp "$(echo -e "${CYAN}Enter ntfy URL/topic (e.g., https://ntfy.sh/my-backups): ${NC}")" NTFY_URL
            read -rp "$(echo -e "${CYAN}Enter ntfy Access Token (optional): ${NC}")" NTFY_TOKEN
            if [[ ! "$NTFY_URL" =~ ^https?:// ]]; then
                print_error "Invalid ntfy URL."
                log "Invalid ntfy URL provided."
                return 1
            fi
        fi
    fi

    # --- Generate the Backup Script ---
    print_info "Generating the backup script at $BACKUP_SCRIPT_PATH..."
    if ! tee "$BACKUP_SCRIPT_PATH" > /dev/null <<EOF
#!/bin/bash
# Generated by server setup script on $(date)
set -Euo pipefail; umask 077
# --- CONFIGURATION ---
LOCAL_DIR="/home/${USERNAME}/"
REMOTE_DEST="${BACKUP_DEST}"
REMOTE_PATH="${REMOTE_BACKUP_PATH}"
SSH_PORT="${BACKUP_PORT}"
EXCLUDE_FILE="${EXCLUDE_FILE_PATH}"
LOG_FILE="/var/log/backup_rsync.log"
LOCK_FILE="/tmp/backup_rsync.lock"
HOSTNAME="\$(hostname -f)"
NOTIFICATION_SETUP="${NOTIFICATION_SETUP}"
NTFY_URL="${NTFY_URL}"
NTFY_TOKEN="${NTFY_TOKEN}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK}"
EOF
    then
        print_error "Failed to create backup script at $BACKUP_SCRIPT_PATH."
        log "Failed to create backup script at $BACKUP_SCRIPT_PATH."
        return 1
    fi
    if ! tee -a "$BACKUP_SCRIPT_PATH" > /dev/null <<'EOF'
# --- BACKUP SCRIPT LOGIC ---
send_notification() {
    local status="$1" message="$2" title color
    if [[ "$status" == "SUCCESS" ]]; then title="✅ Backup SUCCESS: $HOSTNAME"; color=3066993; else title="❌ Backup FAILED: $HOSTNAME"; color=15158332; fi
    if [[ "$NOTIFICATION_SETUP" == "ntfy" ]]; then
        curl -s -H "Title: $title" ${NTFY_TOKEN:+-H "Authorization: Bearer $NTFY_TOKEN"} -d "$message" "$NTFY_URL" > /dev/null 2>&1
    elif [[ "$NOTIFICATION_SETUP" == "discord" ]]; then
        local escaped_message=$(echo "$message" | sed 's/"/\\"/g' | sed 's/\\/\\\\/g' | sed ':a;N;$!ba;s/\n/\\n/g')
        local json_payload=$(printf '{"embeds": [{"title": "%s", "description": "%s", "color": %d}]}' "$title" "$escaped_message" "$color")
        curl -s -H "Content-Type: application/json" -d "$json_payload" "$DISCORD_WEBHOOK" > /dev/null 2>&1
    fi
}
# --- DEPENDENCY & LOCKING ---
for cmd in rsync flock numfmt awk; do if ! command -v "$cmd" &>/dev/null; then send_notification "FAILURE" "FATAL: '$cmd' not found."; exit 10; fi; done
exec 200>"$LOCK_FILE"; flock -n 200 || { echo "Backup already running."; exit 1; }
# --- LOG ROTATION ---
touch "$LOG_FILE"; chmod 600 "$LOG_FILE"; if [[ -f "$LOG_FILE" && $(stat -c%s "$LOG_FILE") -gt 10485760 ]]; then mv "$LOG_FILE" "${LOG_FILE}.1"; fi
echo "--- Starting Backup at $(date) ---" >> "$LOG_FILE"
# --- RSYNC COMMAND ---
rsync_output=$(rsync -avz --delete --stats --exclude-from="$EXCLUDE_FILE" -e "ssh -p $SSH_PORT" "$LOCAL_DIR" "${REMOTE_DEST}:${REMOTE_PATH}" 2>&1)
rsync_exit_code=$?; echo "$rsync_output" >> "$LOG_FILE"
# --- NOTIFICATION ---
if [[ $rsync_exit_code -eq 0 ]]; then
    data_transferred=$(echo "$rsync_output" | grep 'Total transferred file size' | awk '{print $5}' | sed 's/,//g')
    human_readable=$(numfmt --to=iec-i --suffix=B --format="%.2f" "$data_transferred" 2>/dev/null || echo "0 B")
    message="Backup completed successfully.\nData Transferred: ${human_readable}"
    send_notification "SUCCESS" "$message"
else
    message="rsync failed with exit code ${rsync_exit_code}. Check log for details."
    send_notification "FAILURE" "$message"
fi
EOF
    then
        print_error "Failed to append to backup script at $BACKUP_SCRIPT_PATH."
        log "Failed to append to backup script at $BACKUP_SCRIPT_PATH."
        return 1
    fi
    if ! chmod 700 "$BACKUP_SCRIPT_PATH"; then
        print_error "Failed to set permissions on $BACKUP_SCRIPT_PATH."
        log "Failed to set permissions on $BACKUP_SCRIPT_PATH."
        return 1
    fi
    print_success "Backup script created."

    # --- Backup test ---
    test_backup

    # --- Configure Cron Job ---
    print_info "Configuring root cron job..."
    # Ensure crontab is writable
    local CRON_DIR="/var/spool/cron/crontabs"
    mkdir -p "$CRON_DIR"
    chmod 1730 "$CRON_DIR"
    chown root:crontab "$CRON_DIR"
    # Validate inputs
    if [[ -z "$CRON_SCHEDULE" || -z "$BACKUP_SCRIPT_PATH" ]]; then
        print_error "Cron schedule or backup script path is empty."
        log "Cron configuration failed: CRON_SCHEDULE='$CRON_SCHEDULE', BACKUP_SCRIPT_PATH='$BACKUP_SCRIPT_PATH'"
        return 1
    fi
    if [[ ! -f "$BACKUP_SCRIPT_PATH" ]]; then
        print_error "Backup script $BACKUP_SCRIPT_PATH does not exist."
        log "Cron configuration failed: Backup script $BACKUP_SCRIPT_PATH not found."
        return 1
    fi
    # Create temporary cron file
    local TEMP_CRON
    TEMP_CRON=$(mktemp)
    if ! crontab -u root -l 2>/dev/null | grep -v "$CRON_MARKER" > "$TEMP_CRON"; then
        print_warning "No existing crontab found or error reading crontab. Creating new one."
        : > "$TEMP_CRON" # Create empty file
    fi
    echo "$CRON_SCHEDULE $BACKUP_SCRIPT_PATH $CRON_MARKER" >> "$TEMP_CRON"
    if ! crontab -u root "$TEMP_CRON" 2>&1 | tee -a "$LOG_FILE"; then
        print_error "Failed to configure cron job."
        log "Cron configuration failed: Error updating crontab."
        rm -f "$TEMP_CRON"
        return 1
    fi
    rm -f "$TEMP_CRON"
    print_success "Backup cron job scheduled: $CRON_SCHEDULE"
    log "Backup configuration completed."
}

test_backup() {
    print_section "Backup Configuration Test"

    # Ensure script is running with effective root privileges
    if [[ $(id -u) -ne 0 ]]; then
        print_error "Backup test must be run as root. Re-run with 'sudo -E' or as root."
        log "Backup test failed: Script not run as root (UID $(id -u))."
        print_info "Action: Run the script with 'sudo -E ./du_setup.sh' or as the root user."
        return 0
    fi

    # Check if backup script exists and is readable
    local BACKUP_SCRIPT_PATH="/root/run_backup.sh"
    if [[ ! -f "$BACKUP_SCRIPT_PATH" ]]; then
        print_error "Backup script not found at $BACKUP_SCRIPT_PATH."
        log "Backup test failed: $BACKUP_SCRIPT_PATH not found."
        print_info "Action: Ensure the backup script exists at $BACKUP_SCRIPT_PATH and is accessible."
        return 0
    fi
    if [[ ! -r "$BACKUP_SCRIPT_PATH" ]]; then
        print_error "Cannot read backup script at $BACKUP_SCRIPT_PATH. Check permissions."
        log "Backup test failed: $BACKUP_SCRIPT_PATH not readable."
        print_info "Action: Run 'chmod u+r $BACKUP_SCRIPT_PATH' as root to fix permissions."
        return 0
    fi

    # Check if timeout command is available
    if ! command -v timeout >/dev/null 2>&1; then
        print_error "The 'timeout' command is not available. Please install coreutils."
        log "Backup test failed: 'timeout' command not found."
        print_info "Action: Install coreutils with 'apt install coreutils' or equivalent."
        return 0
    fi

    if ! confirm "Run a test backup to verify configuration?"; then
        print_info "Skipping backup test."
        log "Backup test skipped by user."
        return 0
    fi

    # Extract backup configuration from script
    local BACKUP_DEST REMOTE_BACKUP_PATH BACKUP_PORT SSH_COPY_ID_FLAGS
    BACKUP_DEST=$(grep "^REMOTE_DEST=" "$BACKUP_SCRIPT_PATH" | cut -d'"' -f2 2>/dev/null || echo "unknown")
    BACKUP_PORT=$(grep "^SSH_PORT=" "$BACKUP_SCRIPT_PATH" | cut -d'"' -f2 2>/dev/null || echo "22")
    REMOTE_BACKUP_PATH=$(grep "^REMOTE_PATH=" "$BACKUP_SCRIPT_PATH" | cut -d'"' -f2 2>/dev/null || echo "unknown")
    SSH_COPY_ID_FLAGS=$(grep "^SSH_COPY_ID_FLAGS=" "$BACKUP_SCRIPT_PATH" | cut -d'"' -f2 2>/dev/null || echo "")
    local BACKUP_LOG="/var/log/backup_rsync.log"

    if [[ "$BACKUP_DEST" == "unknown" || "$REMOTE_BACKUP_PATH" == "unknown" ]]; then
        print_error "Invalid backup configuration in $BACKUP_SCRIPT_PATH."
        log "Backup test failed: Invalid configuration in $BACKUP_SCRIPT_PATH."
        print_info "Action: Check $BACKUP_SCRIPT_PATH for valid REMOTE_DEST and REMOTE_PATH variables."
        return 0
    fi

    # Ensure backup log is writable
    if ! touch "$BACKUP_LOG" 2>/dev/null || ! chmod 600 "$BACKUP_LOG" 2>/dev/null; then
        print_error "Cannot create or write to $BACKUP_LOG."
        log "Backup test failed: Cannot write to $BACKUP_LOG."
        print_info "Action: Ensure /var/log/ is writable by root and try again."
        return 0
    fi

    # Check SSH key existence
    local SSH_KEY="/root/.ssh/id_ed25519"
    if [[ ! -f "$SSH_KEY" || ! -r "$SSH_KEY" ]]; then
        print_error "SSH key $SSH_KEY not found or not readable."
        log "Backup test failed: SSH key not found or not readable."
        print_info "Action: Create or fix permissions for $SSH_KEY with 'chmod 600 $SSH_KEY'."
        return 0
    fi

    # Create a temporary test directory
    local TEST_DIR="/root/test_backup_$(date +%Y%m%d_%H%M%S)"
    if ! mkdir -p "$TEST_DIR" 2>/dev/null; then
        print_error "Failed to create test directory $TEST_DIR."
        log "Backup test failed: Cannot create $TEST_DIR."
        print_info "Action: Ensure /root/ is writable by root and try again."
        return 0
    fi
    if ! echo "Test file for backup verification" > "$TEST_DIR/test.txt" 2>/dev/null; then
        print_error "Failed to create test file in $TEST_DIR."
        log "Backup test failed: Cannot create test file in $TEST_DIR."
        print_info "Action: Ensure /root/ is writable by root and try again."
        rm -rf "$TEST_DIR" 2>/dev/null
        return 0
    fi
    if ! chmod 600 "$TEST_DIR/test.txt" 2>/dev/null; then
        print_error "Failed to set permissions on $TEST_DIR/test.txt."
        log "Backup test failed: Cannot set permissions on $TEST_DIR/test.txt."
        print_info "Action: Ensure /root/ is writable by root and try again."
        rm -rf "$TEST_DIR" 2>/dev/null
        return 0
    fi

    print_info "Running test backup to $BACKUP_DEST:$REMOTE_BACKUP_PATH..."
    local RSYNC_OUTPUT RSYNC_EXIT_CODE TIMEOUT_DURATION=120
    local SSH_COMMAND="ssh -p $BACKUP_PORT -i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no"
    if [[ -n "$SSH_COPY_ID_FLAGS" ]]; then
        SSH_COMMAND="sftp -P $BACKUP_PORT -i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no"
    fi
    RSYNC_OUTPUT=$(timeout "$TIMEOUT_DURATION" rsync -avz --delete -e "$SSH_COMMAND" "$TEST_DIR/" "${BACKUP_DEST}:${REMOTE_BACKUP_PATH}test_backup/" 2>&1)
    RSYNC_EXIT_CODE=$?
    echo "--- Test Backup at $(date) ---" >> "$BACKUP_LOG"
    echo "$RSYNC_OUTPUT" >> "$BACKUP_LOG"

    if [[ $RSYNC_EXIT_CODE -eq 0 ]]; then
        print_success "Test backup successful! Check $BACKUP_LOG for details."
        log "Test backup successful."
    else
        if [[ $RSYNC_EXIT_CODE -eq 124 ]]; then
            print_error "Test backup timed out after $TIMEOUT_DURATION seconds. Check network connectivity or increase timeout."
            log "Test backup failed: Timeout after $TIMEOUT_DURATION seconds."
            print_info "Action: Verify network connectivity to $BACKUP_DEST and retry."
        else
            print_error "Test backup failed (exit code: $RSYNC_EXIT_CODE). Check $BACKUP_LOG for details."
            log "Test backup failed with exit code $RSYNC_EXIT_CODE."
            print_info "Troubleshooting steps:"
            print_info "  - Verify SSH key: cat $SSH_KEY.pub"
            print_info "  - Copy key: ssh-copy-id -p \"$BACKUP_PORT\" -i $SSH_KEY.pub $SSH_COPY_ID_FLAGS \"$BACKUP_DEST\""
            print_info "  - Test SSH: ssh -p \"$BACKUP_PORT\" -i $SSH_KEY \"$BACKUP_DEST\" true"
            if [[ -n "$SSH_COPY_ID_FLAGS" ]]; then
                print_info "  - For Hetzner, ensure ~/.ssh/ exists: ssh -p \"$BACKUP_PORT\" \"$BACKUP_DEST\" \"mkdir -p ~/.ssh && chmod 700 ~/.ssh\""
            fi
        fi
    fi

    # Clean up test directory
    if ! rm -rf "$TEST_DIR" 2>/dev/null; then
        print_warning "Failed to clean up test directory $TEST_DIR."
        log "Cleanup of $TEST_DIR failed."
        print_info "Action: Manually remove $TEST_DIR with 'rm -rf $TEST_DIR' as root."
    fi

    print_success "Backup test completed."
    log "Backup test completed."
    return 0
}

configure_swap() {
    if [[ $IS_CONTAINER == true ]]; then
        print_info "Swap configuration skipped in container."
        return 0
    fi
    print_section "Swap Configuration"
    # Check for existing swap partition
    if lsblk -r | grep -q '\[SWAP\]'; then
        print_warning "Existing swap partition found. Verify with 'lsblk -f'. Proceed with caution."
    fi
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
        # Check for existing swap entry in /etc/fstab to prevent duplicates
        if grep -q '^/swapfile ' /etc/fstab; then
            print_info "Swap entry already exists in /etc/fstab. Skipping."
        else
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
            print_success "Swap entry added to /etc/fstab."
        fi
        print_success "Swap file created: $SWAP_SIZE"
    fi
    print_info "Configuring swap settings..."
    local SWAPPINESS=10
    local CACHE_PRESSURE=50
    if confirm "Customize swap settings (vm.swappiness and vm.vfs_cache_pressure)?"; then
        while true; do
            read -rp "$(echo -e "${CYAN}Enter vm.swappiness (0-100) [default: $SWAPPINESS]: ${NC}")" INPUT_SWAPPINESS
            INPUT_SWAPPINESS=${INPUT_SWAPPINESS:-$SWAPPINESS}
            if [[ "$INPUT_SWAPPINESS" =~ ^[0-9]+$ && "$INPUT_SWAPPINESS" -ge 0 && "$INPUT_SWAPPINESS" -le 100 ]]; then
                SWAPPINESS=$INPUT_SWAPPINESS
                break
            else
                print_error "Invalid value for vm.swappiness. Must be between 0 and 100."
            fi
        done
        while true; do
            read -rp "$(echo -e "${CYAN}Enter vm.vfs_cache_pressure (1-1000) [default: $CACHE_PRESSURE]: ${NC}")" INPUT_CACHE_PRESSURE
            INPUT_CACHE_PRESSURE=${INPUT_CACHE_PRESSURE:-$CACHE_PRESSURE}
            if [[ "$INPUT_CACHE_PRESSURE" =~ ^[0-9]+$ && "$INPUT_CACHE_PRESSURE" -ge 1 && "$INPUT_CACHE_PRESSURE" -le 1000 ]]; then
                CACHE_PRESSURE=$INPUT_CACHE_PRESSURE
                break
            else
                print_error "Invalid value for vm.vfs_cache_pressure. Must be between 1 and 1000."
            fi
        done
    else
        print_info "Using default swap settings (vm.swappiness=$SWAPPINESS, vm.vfs_cache_pressure=$CACHE_PRESSURE)."
    fi
    local NEW_SWAP_CONFIG
    NEW_SWAP_CONFIG=$(mktemp)
    tee "$NEW_SWAP_CONFIG" > /dev/null <<EOF
vm.swappiness=$SWAPPINESS
vm.vfs_cache_pressure=$CACHE_PRESSURE
EOF
    # Check if sysctl settings are already correct to prevent duplicates
    if [[ -f /etc/sysctl.d/99-swap.conf ]] && cmp -s "$NEW_SWAP_CONFIG" /etc/sysctl.d/99-swap.conf; then
        print_info "Swap settings already correct in /etc/sysctl.d/99-swap.conf. Skipping."
        rm -f "$NEW_SWAP_CONFIG"
    else
        # Check for conflicting settings in /etc/sysctl.conf or other sysctl files
        local sysctl_conflicts=false
        for file in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
            if [[ -f "$file" && "$file" != "/etc/sysctl.d/99-swap.conf" ]]; then
                if grep -E '^(vm\.swappiness|vm\.vfs_cache_pressure)=' "$file" >/dev/null; then
                    print_warning "Existing swap settings found in $file. Manual review recommended."
                    sysctl_conflicts=true
                fi
            fi
        done
        mv "$NEW_SWAP_CONFIG" /etc/sysctl.d/99-swap.conf
        chmod 644 /etc/sysctl.d/99-swap.conf
        sysctl -p /etc/sysctl.d/99-swap.conf >/dev/null
        if [[ $sysctl_conflicts == true ]]; then
            print_warning "Potential conflicting sysctl settings detected. Verify with 'sysctl -a | grep -E \"vm\.swappiness|vm\.vfs_cache_pressure\"'."
        else
            print_success "Swap settings applied to /etc/sysctl.d/99-swap.conf."
        fi
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

configure_security_audit() {
    print_section "Security Audit Configuration"
    if ! confirm "Run a security audit with Lynis (and optionally debsecan on Debian)?"; then
        print_info "Security audit skipped."
        log "Security audit skipped by user."
        AUDIT_RAN=false
        return 0
    fi

    AUDIT_LOG="/var/log/setup_harden_security_audit_$(date +%Y%m%d_%H%M%S).log"
    touch "$AUDIT_LOG" && chmod 600 "$AUDIT_LOG"
    AUDIT_RAN=true
    HARDENING_INDEX=""
    DEBSECAN_VULNS="Not run"

    # Install and run Lynis
    print_info "Installing Lynis..."
    if ! apt-get update -qq; then
        print_error "Failed to update package lists. Cannot install Lynis."
        log "apt-get update failed for Lynis installation."
        return 1
    elif ! apt-get install -y -qq lynis; then
        print_warning "Failed to install Lynis. Skipping Lynis audit."
        log "Lynis installation failed."
    else
        print_info "Running Lynis audit (non-interactive mode, this will take a few minutes)..."
	print_warning "Review audit results in $AUDIT_LOG for security recommendations."
        if lynis audit system --quick >> "$AUDIT_LOG" 2>&1; then
            print_success "Lynis audit completed. Check $AUDIT_LOG for details."
            log "Lynis audit completed successfully."
            # Extract hardening index
            HARDENING_INDEX=$(grep -oP "Hardening index : \K\d+" "$AUDIT_LOG" || echo "Unknown")
            # Append Lynis system log for persistence
            cat /var/log/lynis.log >> "$AUDIT_LOG" 2>/dev/null
        else
            print_error "Lynis audit failed. Check $AUDIT_LOG for details."
            log "Lynis audit failed."
        fi
    fi

    # Check if system is Debian before running debsecan
    source /etc/os-release
    if [[ "$ID" == "debian" ]]; then
        if confirm "Also run debsecan to check for package vulnerabilities?"; then
            print_info "Installing debsecan..."
            if ! apt-get install -y -qq debsecan; then
                print_warning "Failed to install debsecan. Skipping debsecan audit."
                log "debsecan installation failed."
            else
                print_info "Running debsecan audit..."
                if debsecan --suite "$VERSION_CODENAME" >> "$AUDIT_LOG" 2>&1; then
                    DEBSECAN_VULNS=$(grep -c "CVE-" "$AUDIT_LOG" || echo "0")
                    print_success "debsecan audit completed. Found $DEBSECAN_VULNS vulnerabilities."
                    log "debsecan audit completed with $DEBSECAN_VULNS vulnerabilities."
                else
                    print_error "debsecan audit failed. Check $AUDIT_LOG for details."
                    log "debsecan audit failed."
                    DEBSECAN_VULNS="Failed"
                fi
            fi
        else
            print_info "debsecan audit skipped."
            log "debsecan audit skipped by user."
        fi
    else
        print_info "debsecan is not supported on Ubuntu. Skipping debsecan audit."
        log "debsecan audit skipped (Ubuntu detected)."
        DEBSECAN_VULNS="Not supported on Ubuntu"
    fi

    print_warning "Review audit results in $AUDIT_LOG for security recommendations."
    log "Security audit configuration completed."
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
            FAILED_SERVICES+=("$service")
        fi
    done
    if ufw status | grep -q "Status: active"; then
        print_success "Service ufw is active."
    else
        print_error "Service ufw is NOT active."
        FAILED_SERVICES+=("ufw")
    fi
    if command -v docker >/dev/null 2>&1; then
        if systemctl is-active --quiet docker; then
            print_success "Service docker is active."
        else
            print_error "Service docker is NOT active."
            FAILED_SERVICES+=("docker")
        fi
    fi
    local TS_COMMAND=""
    if command -v tailscale >/dev/null 2>&1; then
        if systemctl is-active --quiet tailscaled && tailscale ip >/dev/null 2>&1; then
            local TS_IPS TS_IPV4
            TS_IPS=$(tailscale ip 2>/dev/null || echo "Unknown")
            TS_IPV4=$(echo "$TS_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo "Unknown")
            print_success "Service tailscaled is active and connected."
            echo "$TS_IPS" > /tmp/tailscale_ips.txt
        else
            print_error "Service tailscaled is NOT active"
            FAILED_SERVICES+=("tailscaled")
            TS_COMMAND=$(grep "Tailscale connection failed: tailscale up" "$LOG_FILE" | tail -1 | sed 's/.*Tailscale connection failed: //')
            TS_COMMAND=${TS_COMMAND:-"tailscale up --operator=$USERNAME"}
        fi
    fi
    if [[ "$AUDIT_RAN" == true ]]; then
        print_success "Security audit performed."
    else
        print_info "Security audit not performed."
    fi
    echo -e "\n${GREEN}Server setup and hardening script has finished successfully.${NC}\n"
    echo -e "${YELLOW}Configuration Summary:${NC}"
    printf "  %-16s%s\n" "Admin User:" "$USERNAME"
    printf "  %-16s%s\n" "Hostname:" "$SERVER_NAME"
    printf "  %-16s%s\n" "SSH Port:" "$SSH_PORT"
    printf "  %-16s%s\n" "Server IP:" "$SERVER_IP"
    if [[ -f /root/run_backup.sh ]]; then
        local CRON_SCHEDULE=$(crontab -u root -l 2>/dev/null | grep -F "/root/run_backup.sh" | awk '{print $1, $2, $3, $4, $5}' || echo "Not configured")
        local NOTIFICATION_STATUS="None"
        local BACKUP_DEST=$(grep "^REMOTE_DEST=" /root/run_backup.sh | cut -d'"' -f2 || echo "Unknown")
        local BACKUP_PORT=$(grep "^SSH_PORT=" /root/run_backup.sh | cut -d'"' -f2 || echo "Unknown")
        local REMOTE_BACKUP_PATH=$(grep "^REMOTE_PATH=" /root/run_backup.sh | cut -d'"' -f2 || echo "Unknown")
        if grep -q "NTFY_URL=" /root/run_backup.sh && ! grep -q 'NTFY_URL=""' /root/run_backup.sh; then
            NOTIFICATION_STATUS="ntfy"
        elif grep -q "DISCORD_WEBHOOK=" /root/run_backup.sh && ! grep -q 'DISCORD_WEBHOOK=""' /root/run_backup.sh; then
            NOTIFICATION_STATUS="Discord"
        fi
        echo -e "  Remote Backup:   ${GREEN}Enabled${NC}"
        printf "    %-16s%s\n" "- Backup Script:" "/root/run_backup.sh"
        printf "    %-16s%s\n" "- Destination:" "$BACKUP_DEST"
        printf "    %-16s%s\n" "- SSH Port:" "$BACKUP_PORT"
        printf "    %-16s%s\n" "- Remote Path:" "$REMOTE_BACKUP_PATH"
        printf "    %-16s%s\n" "- Cron Schedule:" "$CRON_SCHEDULE"
        printf "    %-16s%s\n" "- Notifications:" "$NOTIFICATION_STATUS"
        if [[ -f "$BACKUP_LOG" ]] && grep -q "Test backup successful" "$BACKUP_LOG" 2>/dev/null; then
            printf "    %-16s%s\n" "- Test Status:" "${GREEN}Successful${NC}"
        elif [[ -f "$BACKUP_LOG" ]]; then
            printf "    %-16s%s\n" "- Test Status:" "Failed (check $BACKUP_LOG)"
        else
            printf "    %-16s%s\n" "- Test Status:" "Not run"
        fi
    else
        echo -e "  Remote Backup:   ${RED}Not configured${NC}"
    fi
    if command -v tailscale >/dev/null 2>&1; then
        local TS_SERVER=$(cat /tmp/tailscale_server 2>/dev/null || echo "https://controlplane.tailscale.com")
        local TS_IPS_RAW=$(cat /tmp/tailscale_ips.txt 2>/dev/null || echo "Not connected")
        # --- FIX: Format IPs to be on a single line ---
        local TS_IPS=$(echo "$TS_IPS_RAW" | paste -sd ", " -)
        local TS_FLAGS=$(cat /tmp/tailscale_flags 2>/dev/null || echo "None")
        echo -e "  Tailscale:       ${GREEN}Enabled${NC}"
        printf "    %-16s%s\n" "- Server:" "$TS_SERVER"
        printf "    %-16s%s\n" "- Tailscale IPs:" "$TS_IPS"
        printf "    %-16s%s\n" "- Flags:" "$TS_FLAGS"
    else
        echo -e "  Tailscale:       ${RED}Not configured${NC}"
    fi
    if [[ "$AUDIT_RAN" == true ]]; then
        echo -e "  Security Audit:  ${GREEN}Performed${NC}"
        printf "    %-16s%s\n" "- Audit Log:" "$AUDIT_LOG"
        printf "    %-16s%s\n" "- Hardening Index:" "${HARDENING_INDEX:-Unknown}"
        printf "    %-16s%s\n" "- Vulnerabilities:" "$DEBSECAN_VULNS"
    else
        echo -e "  Security Audit:  ${RED}Not run${NC}"
    fi
    echo
    printf "${PURPLE}%-16s%s${NC}\n" "Log File:" "$LOG_FILE"
    printf "${PURPLE}%-16s%s${NC}\n" "Backups:" "$BACKUP_DIR"
    echo
    echo -e "${YELLOW}Post-Reboot Verification Steps:${NC}"
    printf "  %-20s${CYAN}%s${NC}\n" "- SSH access:" "ssh -p $SSH_PORT $USERNAME@$SERVER_IP"
    printf "  %-20s${CYAN}%s${NC}\n" "- Firewall rules:" "sudo ufw status verbose"
    printf "  %-20s${CYAN}%s${NC}\n" "- Time sync:" "chronyc tracking"
    printf "  %-20s${CYAN}%s${NC}\n" "- Fail2Ban status:" "sudo fail2ban-client status sshd"
    printf "  %-20s${CYAN}%s${NC}\n" "- Swap status:" "sudo swapon --show && free -h"
    printf "  %-20s${CYAN}%s${NC}\n" "- Hostname:" "hostnamectl"
    if command -v docker >/dev/null 2>&1; then
        printf "  %-20s${CYAN}%s${NC}\n" "- Docker status:" "docker ps"
    fi
    if command -v tailscale >/dev/null 2>&1; then
        printf "  %-20s${CYAN}%s${NC}\n" "- Tailscale status:" "tailscale status"
    fi
    if [[ -f /root/run_backup.sh ]]; then
        echo -e "  Remote Backup:"
        printf "    %-18s${CYAN}%s${NC}\n" "- Verify SSH key:" "sudo cat /root/.ssh/id_ed25519.pub"
        printf "    %-18s${CYAN}%s${NC}\n" "- Copy key if needed:" "ssh-copy-id -p $BACKUP_PORT -s $BACKUP_DEST"
        printf "    %-18s${CYAN}%s${NC}\n" "- Test backup:" "sudo /root/run_backup.sh"
        printf "    %-18s${CYAN}%s${NC}\n" "- Check logs:" "sudo less $BACKUP_LOG"
    fi
    if [[ "$AUDIT_RAN" == true ]]; then
        echo -e "  Security Audit:"
        printf "    %-18s${CYAN}%s${NC}\n" "- Check results:" "sudo less $AUDIT_LOG"
    fi
    if [[ ${#FAILED_SERVICES[@]} -gt 0 ]]; then
        print_warning "ACTION REQUIRED: The following services failed: ${FAILED_SERVICES[*]}. Verify with 'systemctl status <service>'."
    fi
    if [[ -n "$TS_COMMAND" ]]; then
        print_warning "ACTION REQUIRED: Tailscale connection failed. Run the following command to connect manually:"
        echo -e "${CYAN}  $TS_COMMAND${NC}"
    fi
    if [[ -f /root/run_backup.sh && "$KEY_COPY_CHOICE" == "2" ]]; then
        print_warning "ACTION REQUIRED: Ensure the root SSH key (/root/.ssh/id_ed25519.pub) is copied to $BACKUP_DEST."
    fi
    print_warning "ACTION REQUIRED: If remote backup is enabled, ensure the root SSH key is copied to the destination server."
    print_warning "A reboot is required to apply all changes cleanly."
    if [[ $VERBOSE == true ]]; then
        if confirm "Reboot now?" "y"; then
            print_info "Rebooting, bye!..."
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

    # --- Root Check ---
    if [[ $(id -u) -ne 0 ]]; then
        echo -e "\n${RED}✗ Error: This script must be run with root privileges.${NC}"
        echo "You are running as user '$(whoami)', but root is required for system changes."
        echo -e "Please re-run the script using 'sudo -E':"
        echo -e "  ${CYAN}sudo -E ./du_setup.sh${NC}\n"
        exit 1
    fi

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
    setup_backup
    configure_swap
    configure_security_audit
    final_cleanup
    generate_summary
}

# Run main function
main "$@"
