#!/bin/bash

# Debian 12 and Ubuntu Server Hardening Interactive Script
# Version: 0.62 | 2025-08-04
# Changelog:
# - v0.62: Added modular execution with interactive menu and --tasks flag
# - v0.61: Display Lynis suggestions in summary, hide tailscale auth key, cleanup temp files
# - v0.60: CI for shellcheck
# - v0.59: Added sysctl security settings and self-update check
# - v0.58: Improved fail2ban to parse ufw logs
# - v0.57: Fixed silent failure in test_backup()
# - v0.56: Made tailscale config optional
# - v0.55: Improved setup_user() with ssh-keygen options
# - v0.54: Enhanced rollback_ssh_changes() for Ubuntu
# - v0.53: Fixed test_backup() for non-root sudo users
# - v0.52: Added SSH rollback for Ubuntu 24.10
# - v0.51: Corrected repo links
# - v0.50: Versioning format change
# - v4.3: Added SHA256 integrity verification
# - v4.2: Added Lynis and debsecan, backup testing
# - v4.1: Added Tailscale configuration
# - v4.0: Added automated backup configuration
#
# Description:
# Provisions and hardens a fresh Debian 12 or Ubuntu server with security configurations,
# user management, SSH hardening, firewall, and optional features like Docker, Tailscale,
# and backups. Supports modular execution via --tasks or interactive menu.
#
# Usage:
#   sudo -E ./du_setup.sh [--quiet] [--tasks=<task1,task2,...]
#
# Options:
#   --quiet: Suppress non-critical output
#   --tasks: Comma-separated tasks (e.g., ssh,firewall,swap)
#
# Notes:
# - Run as root on Debian 12 or Ubuntu 20.04/22.04/24.04.
# - Logs to /var/log/du_setup_*.log, backups to /root/setup_harden_backup_*.
# - Test in a VM before production use.

set -euo pipefail

# --- Update Configuration ---
CURRENT_VERSION="0.61"
SCRIPT_URL="https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.sh"
CHECKSUM_URL="${SCRIPT_URL}.sha256"

# --- Global Variables ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/du_setup_$(date +%Y%m%d_%H%M%S).log"
BACKUP_LOG="/var/log/backup_rsync.log"
REPORT_FILE="/var/log/du_setup_report_$(date +%Y%m%d_%H%M%S).txt"
VERBOSE=true
BACKUP_DIR="/root/setup_harden_backup_$(date +%Y%m%d_%H%M%S)"
IS_CONTAINER=false
SSHD_BACKUP_FILE=""
LOCAL_KEY_ADDED=false
SSH_SERVICE=""
ID=""
FAILED_SERVICES=()
SELECTED_TASKS=()

# --- Parse Arguments ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --quiet) VERBOSE=false; shift ;;
        --tasks=*) 
            IFS=',' read -r -a SELECTED_TASKS <<< "${1#*=}"
            shift
            ;;
        *) shift ;;
    esac
done

# --- Colors for Output ---
if command -v tput >/dev/null 2>&1 && tput setaf 1 >/dev/null 2>&1; then
    RED=$(tput setaf 1)
    GREEN=$(tput setaf 2)
    YELLOW="$(tput bold)$(tput setaf 3)"
    BLUE=$(tput setaf 4)
    PURPLE=$(tput setaf 5)
    CYAN=$(tput setaf 6)
    BOLD=$(tput bold)
    NC=$(tput sgr0)
else
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    NC='\033[0m'
    BOLD=''
fi

# --- Logging & Print Functions ---
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

print_header() {
    [[ $VERBOSE == false ]] && return
    echo -e "${CYAN}╔═════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       DEBIAN/UBUNTU SERVER SETUP AND HARDENING SCRIPT           ║${NC}"
    echo -e "${CYAN}║                      v0.21 | 2025-08-43                         ║${NC}"
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

# --- User Interaction ---
confirm() {
    local prompt="$1" default="${2:-n}" response
    [[ $VERBOSE == false ]] && return 0
    prompt="$prompt [${default^^}/$( [[ $default == "y" ]] && echo "n" || echo "y" )]: "
    while true; do
        read -rp "$(echo -e "${CYAN}$prompt${NC}")" response
        response=${response,,}
        response=${response:-$default}
        case $response in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) echo -e "${RED}Please answer yes or no.${NC}" ;;
        esac
    done
}

# --- Validation Functions ---
validate_username() {
    [[ "$1" =~ ^[a-z_][a-z0-9_-]*$ && ${#1} -le 32 ]]
}

validate_hostname() {
    [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,253}[a-zA-Z0-9]$ && ! "$1" =~ \.\. ]]
}

validate_port() {
    [[ "$1" =~ ^[0-9]+$ && "$1" -ge 1024 && "$1" -le 65535 ]]
}

validate_backup_port() {
    [[ "$1" =~ ^[0-9]+$ && "$1" -ge 1 && "$1" -le 65535 ]]
}

validate_ssh_key() {
    [[ -n "$1" && "$1" =~ ^(ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-ed25519)\  ]]
}

validate_timezone() {
    [[ -e "/usr/share/zoneinfo/$1" ]]
}

validate_swap_size() {
    [[ "${1^^}" =~ ^[0-9]+[MG]$ && "${1%[MG]}" -ge 1 ]]
}

validate_ufw_port() {
    [[ "$1" =~ ^[0-9]+(/tcp|/udp)?$ ]]
}

validate_cron_schedule() {
    local schedule="$1" temp_cron
    temp_cron=$(mktemp)
    echo "$schedule /bin/true" > "$temp_cron"
    if crontab -u root "$temp_cron" 2>/dev/null; then
        rm -f "$temp_cron"
        return 0
    else
        rm -f "$temp_cron"
        return 1
    fi
}

convert_to_bytes() {
    local size_upper="${1^^}" unit="${size_upper: -1}" value="${size_upper%[MG]}"
    if [[ "$unit" == "G" ]]; then
        echo $((value * 1024 * 1024 * 1024))
    elif [[ "$unit" == "M" ]]; then
        echo $((value * 1024 * 1024))
    else
        echo 0
    fi
}

# --- Task Selection Function ---
select_tasks_interactive() {
    print_section "Task Selection"
    echo -e "${CYAN}Select tasks to run (use numbers, comma-separated, e.g., 1,3,5):${NC}"
    echo -e "${YELLOW}Available tasks:${NC}"
    echo -e "  ${BOLD}1)${NC} Update Check - Check for script updates"
    echo -e "  ${BOLD}2)${NC} Dependency Check - Ensure required tools are installed"
    echo -e "  ${BOLD}3)${NC} System Check - Verify OS compatibility and root privileges"
    echo -e "  ${BOLD}4)${NC} Configuration Collection - Set up username, hostname, SSH port"
    echo -e "  ${BOLD}5)${NC} Package Installation - Install essential packages"
    echo -e "  ${BOLD}6)${NC} User Setup - Create admin user and configure SSH keys"
    echo -e "  ${BOLD}7)${NC} System Configuration - Set timezone, hostname, and locales"
    echo -e "  ${BOLD}8)${NC} SSH Hardening - Configure SSH with key-based auth and custom port"
    echo -e "  ${BOLD}9)${NC} Firewall Setup - Configure UFW with custom rules"
    echo -e "  ${BOLD}10)${NC} Fail2Ban Setup - Configure Fail2Ban for intrusion prevention"
    echo -e "  ${BOLD}11)${NC} Auto Updates - Enable unattended-upgrades"
    echo -e "  ${BOLD}12)${NC} Time Synchronization - Configure chrony for NTP"
    echo -e "  ${BOLD}13)${NC} Kernel Hardening - Apply sysctl security settings"
    echo -e "  ${BOLD}14)${NC} Docker Installation - Install Docker (optional)"
    echo -e "  ${BOLD}15)${NC} Tailscale Installation - Set up Tailscale VPN (optional)"
    echo -e "  ${BOLD}16)${NC} Backup Configuration - Set up rsync-based backups"
    echo -e "  ${BOLD}17)${NC} Swap Configuration - Configure swap file"
    echo -e "  ${BOLD}18)${NC} Security Audit - Run Lynis and debsecan (Debian only)"
    echo -e "  ${BOLD}19)${NC} Final Cleanup - Update system and clean up"
    echo -e "  ${BOLD}20)${NC} Generate Summary - Create final report"
    echo -e "${CYAN}Enter numbers (e.g., 1,3,5) or 'all' for all tasks:${NC}"
    read -rp "  " task_choices
    if [[ "$task_choices" == "all" ]]; then
        SELECTED_TASKS=("update" "deps" "system" "config" "packages" "user" "system_config" "ssh" "firewall" "fail2ban" "auto_updates" "time_sync" "kernel" "docker" "tailscale" "backup" "swap" "audit" "cleanup" "summary")
    else
        IFS=',' read -r -a task_array <<< "$task_choices"
        SELECTED_TASKS=()
        for task_num in "${task_array[@]}"; do
            case $task_num in
                1) SELECTED_TASKS+=("update") ;;
                2) SELECTED_TASKS+=("deps") ;;
                3) SELECTED_TASKS+=("system") ;;
                4) SELECTED_TASKS+=("config") ;;
                5) SELECTED_TASKS+=("packages") ;;
                6) SELECTED_TASKS+=("user") ;;
                7) SELECTED_TASKS+=("system_config") ;;
                8) SELECTED_TASKS+=("ssh") ;;
                9) SELECTED_TASKS+=("firewall") ;;
                10) SELECTED_TASKS+=("fail2ban") ;;
                11) SELECTED_TASKS+=("auto_updates") ;;
                12) SELECTED_TASKS+=("time_sync") ;;
                13) SELECTED_TASKS+=("kernel") ;;
                14) SELECTED_TASKS+=("docker") ;;
                15) SELECTED_TASKS+=("tailscale") ;;
                16) SELECTED_TASKS+=("backup") ;;
                17) SELECTED_TASKS+=("swap") ;;
                18) SELECTED_TASKS+=("audit") ;;
                19) SELECTED_TASKS+=("cleanup") ;;
                20) SELECTED_TASKS+=("summary") ;;
                *) print_error "Invalid task number: $task_num. Skipping." ;;
            esac
        done
    fi
    if [[ ${#SELECTED_TASKS[@]} -eq 0 ]]; then
        print_error "No valid tasks selected. Exiting."
        exit 1
    fi
    print_info "Selected tasks: ${SELECTED_TASKS[*]}"
    log "Selected tasks for execution: ${SELECTED_TASKS[*]}"
}

# --- Update Check ---
run_update_check() {
    print_section "Checking for Script Updates"
    local latest_version
    if ! latest_version=$(curl -sL "$SCRIPT_URL" | grep '^CURRENT_VERSION=' | head -n 1 | awk -F'"' '{print $2}'); then
        print_warning "Could not check for updates. Check internet connection."
        log "Update check failed: Could not fetch script."
        return
    fi
    if [[ -z "$latest_version" ]]; then
        print_warning "Failed to parse version from remote script."
        log "Update check failed: Could not parse version."
        return
    fi
    if [[ "$(printf '%s\n' "$CURRENT_VERSION" "$latest_version" | sort -V | head -n 1)" == "$CURRENT_VERSION" && "$CURRENT_VERSION" != "$latest_version" ]]; then
        print_success "A new version ($latest_version) is available!"
        if ! confirm "Update to version $latest_version now?"; then
            return
        fi
        local temp_dir=$(mktemp -d)
        trap 'rm -rf -- "$temp_dir"' EXIT
        local temp_script="$temp_dir/du_setup.sh" temp_checksum="$temp_dir/checksum.sha256"
        print_info "Downloading new script version..."
        if ! curl -sL "$SCRIPT_URL" -o "$temp_script"; then
            print_error "Failed to download new script. Update aborted."
            exit 1
        fi
        print_info "Downloading checksum..."
        if ! curl -sL "$CHECKSUM_URL" -o "$temp_checksum"; then
            print_error "Failed to download checksum file. Update aborted."
            exit 1
        fi
        print_info "Verifying checksum..."
        if ! (cd "$temp_dir" && sha256sum -c "checksum.sha256" --quiet); then
            print_error "Checksum verification failed. Update aborted."
            exit 1
        fi
        print_info "Checking script syntax..."
        if ! bash -n "$temp_script"; then
            print_error "Downloaded script has syntax error. Update aborted."
            exit 1
        fi
        if ! mv "$temp_script" "$0" || ! chmod +x "$0"; then
            print_error "Failed to replace script file."
            exit 1
        fi
        trap - EXIT
        rm -rf -- "$temp_dir"
        print_success "Update successful. Please rerun the script."
        exit 0
    else
        print_info "Running latest version ($CURRENT_VERSION)."
    fi
}

# --- Dependency Check ---
check_dependencies() {
    print_section "Checking Dependencies"
    local missing_deps=()
    for dep in curl sudo gpg coreutils; do
        command -v "$dep" >/dev/null || missing_deps+=("$dep")
    done
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_info "Installing missing dependencies: ${missing_deps[*]}"
        if ! apt-get update -qq || ! apt-get install -y -qq "${missing_deps[@]}"; then
            print_error "Failed to install dependencies: ${missing_deps[*]}"
            exit 1
        fi
    fi
    print_success "All dependencies installed."
    log "Dependency check completed."
}

# --- System Check ---
check_system() {
    print_section "System Compatibility Check"
    if [[ $(id -u) -ne 0 ]]; then
        print_error "This script must be run as root."
        exit 1
    fi
    print_success "Running with root privileges."
    if [[ -f /proc/1/cgroup ]] && grep -qE '(docker|lxc|kubepod)' /proc/1/cgroup; then
        IS_CONTAINER=true
        print_warning "Container environment detected. Some features will be skipped."
    fi
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        ID=$ID
        if [[ $ID == "debian" && $VERSION_ID == "12" ]] || \
           [[ $ID == "ubuntu" && $VERSION_ID =~ ^(20.04|22.04|24.04)$ ]]; then
            print_success "Compatible OS: $PRETTY_NAME"
        else
            print_warning "Untested OS: $PRETTY_NAME. Designed for Debian 12 or Ubuntu 20.04/22.04/24.04."
            if ! confirm "Continue anyway?"; then exit 1; fi
        fi
    else
        print_error "Not a Debian or Ubuntu system."
        exit 1
    fi
    if ! dpkg -l openssh-server | grep -q ^ii; then
        print_warning "openssh-server not installed. Will be installed."
    fi
    if curl -s --head https://deb.debian.org >/dev/null || curl -s --head https://archive.ubuntu.com >/dev/null; then
        print_success "Internet connectivity confirmed."
    else
        print_error "No internet connectivity."
        exit 1
    fi
    if [[ ! -w /var/log ]]; then
        print_error "Cannot write to /var/log."
        exit 1
    fi
    if [[ ! -w /etc/shadow ]]; then
        print_error "/etc/shadow not writable."
        exit 1
    fi
    if [[ $(stat -c %a /etc/shadow) != "640" ]]; then
        chmod 640 /etc/shadow
        chown root:shadow /etc/shadow
        print_info "Fixed /etc/shadow permissions to 640."
    fi
    log "System check completed."
}

# --- Configuration Collection ---
collect_config() {
    print_section "Configuration Setup"
    while true; do
        read -rp "$(echo -e "${CYAN}Enter username for new admin user: ${NC}")" USERNAME
        if validate_username "$USERNAME"; then
            if id "$USERNAME" &>/dev/null; then
                print_warning "User '$USERNAME' exists."
                if confirm "Use existing user?"; then USER_EXISTS=true; break; fi
            else
                USER_EXISTS=false; break
            fi
        else
            print_error "Invalid username (lowercase, numbers, hyphens, underscores, max 32 chars)."
        fi
    done
    while true; do
        read -rp "$(echo -e "${CYAN}Enter server hostname: ${NC}")" SERVER_NAME
        if validate_hostname "$SERVER_NAME"; then break; else print_error "Invalid hostname."; fi
    done
    read -rp "$(echo -e "${CYAN}Enter pretty hostname (optional): ${NC}")" PRETTY_NAME
    PRETTY_NAME=${PRETTY_NAME:-$SERVER_NAME}
    while true; do
        read -rp "$(echo -e "${CYAN}Enter custom SSH port (1024-65535) [2222]: ${NC}")" SSH_PORT
        SSH_PORT=${SSH_PORT:-2222}
        if validate_port "$SSH_PORT"; then break; else print_error "Invalid port."; fi
    done
    SERVER_IP=$(curl -s https://ifconfig.me 2>/dev/null || echo "unknown")
    print_info "Detected server IP: $SERVER_IP"
    echo -e "\n${YELLOW}Configuration Summary:${NC}"
    echo -e "  Username:   $USERNAME"
    echo -e "  Hostname:   $SERVER_NAME"
    echo -e "  SSH Port:   $SSH_PORT"
    echo -e "  Server IP:  $SERVER_IP"
    if ! confirm "Continue with this configuration?" "y"; then exit 0; fi
    log "Configuration: USER=$USERNAME, HOST=$SERVER_NAME, PORT=$SSH_PORT"
}

# --- Package Installation ---
install_packages() {
    print_section "Package Installation"
    print_info "Updating package lists and upgrading system..."
    if ! apt-get update -qq || ! DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq; then
        print_error "Failed to update/upgrade packages."
        exit 1
    fi
    print_info "Installing essential packages..."
    if ! apt-get install -y -qq ufw fail2ban unattended-upgrades chrony rsync wget vim htop iotop nethogs netcat-traditional ncdu tree rsyslog cron jq gawk coreutils perl skopeo git openssh-client openssh-server; then
        print_error "Failed to install packages."
        exit 1
    fi
    print_success "Packages installed."
    log "Package installation completed."
}

# --- User Setup ---
setup_user() {
    print_section "User Management"
    if [[ -z "$USERNAME" ]]; then
        print_error "USERNAME not set."
        exit 1
    fi
    if [[ $USER_EXISTS == false ]]; then
        print_info "Creating user '$USERNAME'..."
        if ! adduser --disabled-password --gecos "" "$USERNAME"; then
            print_error "Failed to create user '$USERNAME'."
            exit 1
        fi
        while true; do
            read -sp "$(echo -e "${CYAN}New password for '$USERNAME' (Enter twice to skip): ${NC}")" PASS1
            echo
            read -sp "$(echo -e "${CYAN}Retype password: ${NC}")" PASS2
            echo
            if [[ -z "$PASS1" && -z "$PASS2" ]]; then
                print_warning "Password skipped. Using SSH key only."
                break
            elif [[ "$PASS1" == "$PASS2" ]]; then
                if echo "$USERNAME:$PASS1" | chpasswd; then
                    print_success "Password set."
                    break
                else
                    print_error "Failed to set password."
                fi
            else
                print_error "Passwords do not match."
            fi
        done
        USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
        SSH_DIR="$USER_HOME/.ssh"
        AUTH_KEYS="$SSH_DIR/authorized_keys"
        if [[ ! -w "$USER_HOME" ]]; then
            chown "$USERNAME:$USERNAME" "$USER_HOME"
            chmod 700 "$USER_HOME"
        fi
        if confirm "Add SSH public key(s)?"; then
            while true; do
                read -rp "$(echo -e "${CYAN}Paste SSH public key: ${NC}")" SSH_PUBLIC_KEY
                if validate_ssh_key "$SSH_PUBLIC_KEY"; then
                    mkdir -p "$SSH_DIR"
                    chmod 700 "$SSH_DIR"
                    chown "$USERNAME:$USERNAME" "$SSH_DIR"
                    echo "$SSH_PUBLIC_KEY" >> "$AUTH_KEYS"
                    awk '!seen[$0]++' "$AUTH_KEYS" > "$AUTH_KEYS.tmp" && mv "$AUTH_KEYS.tmp" "$AUTH_KEYS"
                    chmod 600 "$AUTH_KEYS"
                    chown "$USERNAME:$USERNAME" "$AUTH_KEYS"
                    print_success "SSH key added."
                    LOCAL_KEY_ADDED=true
                else
                    print_error "Invalid SSH key format."
                fi
                if ! confirm "Add another key?" "n"; then break; fi
            done
        else
            print_info "Generating SSH key pair..."
            mkdir -p "$SSH_DIR"
            chmod 700 "$SSH_DIR"
            chown "$USERNAME:$USERNAME" "$SSH_DIR"
            sudo -u "$USERNAME" ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519_user" -N "" -q
            cat "$SSH_DIR/id_ed25519_user.pub" >> "$AUTH_KEYS"
            chmod 600 "$AUTH_KEYS"
            chown "$USERNAME:$USERNAME" "$AUTH_KEYS"
            TEMP_KEY_FILE="/tmp/${USERNAME}_ssh_key_$(date +%s)"
            trap 'rm -f "$TEMP_KEY_FILE"' EXIT
            cp "$SSH_DIR/id_ed25519_user" "$TEMP_KEY_FILE"
            chmod 600 "$TEMP_KEY_FILE"
            echo -e "${YELLOW}Save PRIVATE key to ~/.ssh/${USERNAME}_key:${NC}"
            cat "$TEMP_KEY_FILE"
            echo -e "${CYAN}PUBLIC key:${NC}"
            cat "$SSH_DIR/id_ed25519_user.pub"
            echo -e "${CYAN}Set permissions: chmod 600 ~/.ssh/${USERNAME}_key${NC}"
            echo -e "${CYAN}Connect with: ssh -i ~/.ssh/${USERNAME}_key -p $SSH_PORT $USERNAME@$SERVER_IP${NC}"
            read -rp "$(echo -e "${CYAN}Press Enter after saving keys...${NC}")"
            print_success "SSH key generated."
            LOCAL_KEY_ADDED=true
        fi
    else
        print_info "Using existing user: $USERNAME"
        USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
        AUTH_KEYS="$USER_HOME/.ssh/authorized_keys"
        if [[ ! -s "$AUTH_KEYS" ]]; then
            print_warning "No valid SSH keys found in $AUTH_KEYS."
        fi
    fi
    if ! groups "$USERNAME" | grep -qw sudo; then
        usermod -aG sudo "$USERNAME"
        print_success "User added to sudo group."
    else
        print_info "User already in sudo group."
    fi
    log "User setup completed."
}

# --- System Configuration ---
configure_system() {
    print_section "System Configuration"
    mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
    cp /etc/hosts "$BACKUP_DIR/hosts.backup"
    cp /etc/fstab "$BACKUP_DIR/fstab.backup"
    cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.backup" 2>/dev/null || true
    while true; do
        read -rp "$(echo -e "${CYAN}Enter timezone (e.g., Europe/London) [Etc/UTC]: ${NC}")" TIMEZONE
        TIMEZONE=${TIMEZONE:-Etc/UTC}
        if validate_timezone "$TIMEZONE"; then
            if [[ $(timedatectl status | grep "Time zone" | awk '{print $3}') != "$TIMEZONE" ]]; then
                timedatectl set-timezone "$TIMEZONE"
                print_success "Timezone set to $TIMEZONE."
            else
                print_info "Timezone already set."
            fi
            break
        else
            print_error "Invalid timezone."
        fi
    done
    if confirm "Configure locales interactively?"; then
        dpkg-reconfigure locales
    fi
    if [[ $(hostnamectl --static) != "$SERVER_NAME" ]]; then
        hostnamectl set-hostname "$SERVER_NAME"
        hostnamectl set-hostname "$PRETTY_NAME" --pretty
        if grep -q "^127.0.1.1" /etc/hosts; then
            sed -i "s/^127.0.1.1.*/127.0.1.1\t$SERVER_NAME/" /etc/hosts
        else
            echo "127.0.1.1 $SERVER_NAME" >> /etc/hosts
        fi
        print_success "Hostname set to $SERVER_NAME."
    else
        print_info "Hostname already set."
    fi
    log "System configuration completed."
}

# --- SSH Hardening ---
configure_ssh() {
    trap cleanup_and_exit ERR
    print_section "SSH Hardening"
    if ! dpkg -l openssh-server | grep -q ^ii; then
        print_error "openssh-server not installed."
        return 1
    fi
    if [[ $ID == "ubuntu" ]] && systemctl is-active ssh.socket >/dev/null 2>&1; then
        SSH_SERVICE="ssh.socket"
    elif systemctl is-enabled sshd.service >/dev/null 2>&1 || systemctl is-active sshd.service >/dev/null 2>&1; then
        SSH_SERVICE="sshd.service"
    else
        SSH_SERVICE="ssh.service"
    fi
    PREVIOUS_SSH_PORT=$(ss -tuln | grep -E ":(22|.*$SSH_SERVICE.*)" | awk '{print $5}' | cut -d':' -f2 | head -n1 || echo "22")
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
    AUTH_KEYS="$USER_HOME/.ssh/authorized_keys"
    if [[ $LOCAL_KEY_ADDED == false && ! -s "$AUTH_KEYS" ]]; then
        print_info "Generating SSH key..."
        mkdir -p "$USER_HOME/.ssh"
        chmod 700 "$USER_HOME/.ssh"
        chown "$USERNAME:$USERNAME" "$USER_HOME/.ssh"
        sudo -u "$USERNAME" ssh-keygen -t ed25519 -f "$USER_HOME/.ssh/id_ed25519" -N "" -q
        cat "$USER_HOME/.ssh/id_ed25519.pub" >> "$AUTH_KEYS"
        chmod 600 "$AUTH_KEYS"
        chown "$USERNAME:$USERNAME" "$AUTH_KEYS"
        print_success "SSH key generated."
        echo -e "${YELLOW}Public key:${NC}"
        cat "$USER_HOME/.ssh/id_ed25519.pub"
        LOCAL_KEY_ADDED=true
    fi
    print_warning "Test SSH: ssh -p $PREVIOUS_SSH_PORT $USERNAME@$SERVER_IP"
    if ! confirm "SSH connection successful?"; then
        print_error "SSH key authentication required."
        return 1
    fi
    SSHD_BACKUP_FILE="$BACKUP_DIR/sshd_config.backup_$(date +%Y%m%d_%H%M%S)"
    cp /etc/ssh/sshd_config "$SSHD_BACKUP_FILE"
    if [[ $ID == "ubuntu" ]] && dpkg --compare-versions "$(lsb_release -rs)" ge "24.04"; then
        sed -i "s/^Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config || echo "Port $SSH_PORT" >> /etc/ssh/sshd_config
    elif [[ "$SSH_SERVICE" == "ssh.socket" ]]; then
        mkdir -p /etc/systemd/system/ssh.socket.d
        echo -e "[Socket]\nListenStream=\nListenStream=$SSH_PORT" > /etc/systemd/system/ssh.socket.d/override.conf
    else
        mkdir -p /etc/systemd/system/${SSH_SERVICE}.d
        echo -e "[Service]\nExecStart=\nExecStart=/usr/sbin/sshd -D -p $SSH_PORT" > /etc/systemd/system/${SSH_SERVICE}.d/override.conf
    fi
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
    systemctl daemon-reload
    systemctl restart "$SSH_SERVICE"
    sleep 5
    if ! ss -tuln | grep -q ":$SSH_PORT"; then
        print_error "SSH not listening on port $SSH_PORT."
        rollback_ssh_changes
        return 1
    fi
    if ssh -p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@localhost true 2>/dev/null; then
        print_error "Root SSH login still possible."
        rollback_ssh_changes
        return 1
    fi
    print_warning "Test new SSH: ssh -p $SSH_PORT $USERNAME@$SERVER_IP"
    for ((i=1; i<=3; i++)); do
        if confirm "New SSH connection successful?"; then
            print_success "SSH hardening completed."
            trap - ERR
            log "SSH hardening completed."
            return 0
        fi
        print_info "Retry $i/3..."
        sleep 5
    done
    print_error "SSH connection failed. Rolling back..."
    rollback_ssh_changes
    return 1
}

# --- SSH Rollback ---
rollback_ssh_changes() {
    print_info "Rolling back SSH to port $PREVIOUS_SSH_PORT..."
    rm -rf /etc/systemd/system/${SSH_SERVICE}.d /etc/systemd/system/ssh.socket.d /etc/ssh/sshd_config.d/99-hardening.conf 2>/dev/null
    if [[ -f "$SSHD_BACKUP_FILE" ]]; then
        cp "$SSHD_BACKUP_FILE" /etc/ssh/sshd_config
        print_info "Restored sshd_config."
    else
        print_error "Backup file $SSHD_BACKUP_FILE not found."
        return 1
    fi
    if ! /usr/sbin/sshd -t >/tmp/sshd_config_test.log 2>&1; then
        print_error "Restored sshd_config invalid. Check /tmp/sshd_config_test.log."
        return 1
    fi
    systemctl daemon-reload
    if [[ "$SSH_SERVICE" == "ssh.socket" ]]; then
        systemctl stop ssh.socket 2>/dev/null
        systemctl restart ssh.service
        systemctl restart ssh.socket
    else
        systemctl restart "$SSH_SERVICE"
    fi
    for ((i=1; i<=10; i++)); do
        if ss -tuln | grep -q ":$PREVIOUS_SSH_PORT"; then
            print_success "Rollback successful."
            return 0
        fi
        sleep 3
    done
    print_error "Rollback failed. Check systemctl status $SSH_SERVICE."
    return 1
}

# --- Firewall Configuration ---
configure_firewall() {
    print_section "Firewall Configuration (UFW)"
    if ufw status | grep -q "Status: active"; then
        print_info "UFW already enabled."
    else
        ufw default deny incoming
        ufw default allow outgoing
    fi
    if ! ufw status | grep -qw "$SSH_PORT/tcp"; then
        ufw allow "$SSH_PORT"/tcp comment 'Custom SSH'
        print_success "SSH rule added for port $SSH_PORT."
    fi
    if confirm "Allow HTTP (port 80)?"; then
        ufw allow http comment 'HTTP'
        print_success "HTTP allowed."
    fi
    if confirm "Allow HTTPS (port 443)?"; then
        ufw allow https comment 'HTTPS'
        print_success "HTTPS allowed."
    fi
    if confirm "Allow Tailscale (UDP 41641)?"; then
        ufw allow 41641/udp comment 'Tailscale VPN'
        print_success "Tailscale allowed."
    fi
    if confirm "Add custom ports?"; then
        while true; do
            read -rp "$(echo -e "${CYAN}Enter ports (e.g., 8080/tcp 123/udp): ${NC}")" CUSTOM_PORTS
            if [[ -z "$CUSTOM_PORTS" ]]; then break; fi
            local valid=true
            for port in $CUSTOM_PORTS; do
                if ! validate_ufw_port "$port"; then
                    print_error "Invalid port: $port."
                    valid=false
                fi
            done
            if [[ "$valid" == true ]]; then
                for port in $CUSTOM_PORTS; do
                    ufw allow "$port" comment "Custom port $port"
                    print_success "Added rule for $port."
                done
                break
            fi
        done
    fi
    if ! ufw status | grep -q "Status: active"; then
        ufw --force enable
        print_success "UFW enabled."
    fi
    print_success "Firewall configured."
    ufw status | tee -a "$LOG_FILE"
    log "Firewall configuration completed."
}

# --- Fail2Ban Configuration ---
configure_fail2ban() {
    print_section "Fail2Ban Configuration"
    if systemctl is-active --quiet fail2ban; then
        print_info "Fail2Ban already active."
    else
        systemctl enable --now fail2ban
    fi
    if ! [[ -f /etc/fail2ban/jail.d/sshd.conf ]]; then
        tee /etc/fail2ban/jail.d/sshd.conf > /dev/null <<EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 5
bantime = 3600
findtime = 600
EOF
        print_success "Fail2Ban SSH jail configured."
    fi
    if ! [[ -f /etc/fail2ban/jail.d/ufw-probes.conf ]]; then
        tee /etc/fail2ban/jail.d/ufw-probes.conf > /dev/null <<EOF
[ufw-probes]
enabled = true
banaction = ufw
port = 0:65535
filter = ufw
logpath = /var/log/ufw.log
maxretry = 5
bantime = 3600
findtime = 600
EOF
        print_success "Fail2Ban UFW jail configured."
    fi
    systemctl restart fail2ban
    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2Ban configured."
    else
        print_error "Fail2Ban service failed."
        exit 1
    fi
    log "Fail2Ban configuration completed."
}

# --- Auto Updates ---
configure_auto_updates() {
    print_section "Automatic Updates"
    if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
        print_info "Unattended-upgrades already configured."
    else
        tee /etc/apt/apt.conf.d/50unattended-upgrades > /dev/null <<EOF
Unattended-Upgrades::Allowed-Origins {
    "${ID} ${VERSION_CODENAME}:security";
    "${ID} ${VERSION_CODENAME}-security";
};
Unattended-Upgrades::Package-Blacklist { };
Unattended-Upgrades::AutoFixInterruptedDpkg "true";
Unattended-Upgrades::MinimalSteps "true";
Unattended-Upgrades::InstallOnShutdown "false";
Unattended-Upgrades::Remove-Unused-Dependencies "true";
Unattended-Upgrades::Automatic-Reboot "false";
EOF
        tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
        systemctl enable --now unattended-upgrades
        print_success "Unattended-upgrades configured."
    fi
    if systemctl is-active --quiet unattended-upgrades; then
        print_success "Automatic updates enabled."
    else
        print_error "Unattended-upgrades failed."
        exit 1
    fi
    log "Automatic updates configured."
}

# --- Time Synchronization ---
configure_time_sync() {
    print_section "Time Synchronization"
    systemctl enable --now chrony
    sleep 2
    if systemctl is-active --quiet chrony; then
        print_success "Chrony active."
        chronyc tracking | tee -a "$LOG_FILE"
    else
        print_error "Chrony failed to start."
        exit 1
    fi
    log "Time synchronization completed."
}

# --- Kernel Hardening ---
configure_kernel_hardening() {
    print_section "Kernel Hardening"
    if [[ -f /etc/sysctl.d/99-du-hardening.conf ]]; then
        print_info "Kernel hardening already applied."
        return 0
    fi
    tee /etc/sysctl.d/99-du-hardening.conf > /dev/null <<EOF
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=1
fs.protected_symlinks=1
fs.protected_hardlinks=1
kernel.core_pattern=|/bin/false
kernel.modules_disabled=0
kernel.randomize_va_space=2
kernel.dmesg_restrict=1
kernel.perf_event_paranoid=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF
    sysctl -p /etc/sysctl.d/99-du-hardening.conf >/dev/null
    print_success "Kernel hardening applied."
    log "Kernel hardening completed."
}

# --- Docker Installation ---
install_docker() {
    print_section "Docker Installation"
    if command -v docker >/dev/null 2>&1; then
        print_info "Docker already installed."
        return 0
    fi
    if ! confirm "Install Docker?"; then
        print_info "Skipping Docker installation."
        return 0
    fi
    print_info "Installing Docker..."
    if ! apt-get update -qq || ! apt-get install -y -qq apt-transport-https ca-certificates curl gnupg lsb-release; then
        print_error "Failed to install Docker prerequisites."
        exit 1
    fi
    curl -fsSL https://download.docker.com/linux/${ID}/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
    if ! apt-get update -qq || ! apt-get install -y -qq docker-ce docker-ce-cli containerd.io; then
        print_error "Failed to install Docker."
        exit 1
    fi
    systemctl enable --now docker
    if systemctl is-active --quiet docker; then
        print_success "Docker installed and running."
    else
        print_error "Docker service failed."
        exit 1
    fi
    log "Docker installation completed."
}

# --- Tailscale Installation ---
install_tailscale() {
    print_section "Tailscale Installation"
    if command -v tailscale >/dev/null 2>&1; then
        print_info "Tailscale already installed."
        return 0
    fi
    if ! confirm "Install Tailscale VPN?"; then
        print_info "Skipping Tailscale installation."
        return 0
    fi
    curl -fsSL https://pkgs.tailscale.com/stable/${ID}/${VERSION_CODENAME}/tailscale.list > /etc/apt/sources.list.d/tailscale.list
    curl -fsSL https://pkgs.tailscale.com/stable/${ID}/${VERSION_CODENAME}/tailscale.asc | apt-key add -
    if ! apt-get update -qq || ! apt-get install -y -qq tailscale; then
        print_error "Failed to install Tailscale."
        exit 1
    fi
    systemctl enable --now tailscaled
    print_info "Configuring Tailscale..."
    read -rp "$(echo -e "${CYAN}Enter Tailscale auth key: ${NC}")" AUTH_KEY
    if [[ -z "$AUTH_KEY" ]]; then
        print_error "Tailscale auth key required."
        return 1
    fi
    TS_COMMAND="tailscale up --auth-key=$AUTH_KEY --operator=$USERNAME"
    if ! $TS_COMMAND; then
        print_warning "Tailscale connection failed. Run manually: $TS_COMMAND"
        return 0
    fi
    for ((i=1; i<=3; i++)); do
        if TS_IPS=$(tailscale ip 2>/dev/null); then
            TS_IPV4=$(echo "$TS_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
            if [[ -n "$TS_IPV4" ]]; then
                print_success "Tailscale connected. IPv4: $TS_IPV4"
                log "Tailscale connected: $TS_IPV4"
                return 0
            fi
        fi
        print_info "Waiting for Tailscale ($i/3)..."
        sleep 5
    done
    print_warning "Tailscale connection not verified."
    log "Tailscale connection not verified."
}

# --- Backup Configuration ---
setup_backup() {
    print_section "Backup Configuration"
    if [[ -f /etc/cron.d/du-backup ]]; then
        print_info "Backup cron job already configured."
        return 0
    fi
    if ! confirm "Configure automated backups?"; then
        print_info "Skipping backup configuration."
        return 0
    fi
    read -rp "$(echo -e "${CYAN}Enter backup server hostname: ${NC}")" BACKUP_HOST
    read -rp "$(echo -e "${CYAN}Enter backup server SSH port [22]: ${NC}")" BACKUP_PORT
    BACKUP_PORT=${BACKUP_PORT:-22}
    if ! validate_backup_port "$BACKUP_PORT"; then
        print_error "Invalid backup port."
        return 1
    fi
    read -rp "$(echo -e "${CYAN}Enter backup server username: ${NC}")" BACKUP_USER
    read -rp "$(echo -e "${CYAN}Enter remote backup path (e.g., /backups/server1): ${NC}")" REMOTE_BACKUP_PATH
    read -rp "$(echo -e "${CYAN}Enter local directories to back up (space-separated): ${NC}")" BACKUP_DIRS
    read -rp "$(echo -e "${CYAN}Enter cron schedule (e.g., '0 2 * * *' for daily at 2 AM): ${NC}")" CRON_SCHEDULE
    if ! validate_cron_schedule "$CRON_SCHEDULE"; then
        print_error "Invalid cron schedule."
        return 1
    fi
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
    SSH_DIR="$USER_HOME/.ssh"
    SSH_KEY="$SSH_DIR/id_ed25519_backup"
    if [[ ! -f "$SSH_KEY" ]]; then
        sudo -u "$USERNAME" ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q
        print_success "Backup SSH key generated."
        echo -e "${YELLOW}Add this public key to the backup server's authorized_keys:${NC}"
        cat "$SSH_KEY.pub"
        read -rp "$(echo -e "${CYAN}Press Enter after adding the key...${NC}")"
    fi
    SSH_COMMAND="ssh -i $SSH_KEY -p $BACKUP_PORT -o StrictHostKeyChecking=no"
    print_info "Testing backup connection..."
    TEST_DIR=$(mktemp -d)
    timeout 10 rsync -avz --delete -e "$SSH_COMMAND" "$TEST_DIR/" "${BACKUP_USER}@${BACKUP_HOST}:${REMOTE_BACKUP_PATH}/test_backup/" >/tmp/backup_test.log 2>&1
    if [[ $? -eq 0 ]]; then
        print_success "Backup test successful."
        rm -rf "$TEST_DIR"
    else
        print_error "Backup test failed. Check /tmp/backup_test.log."
        return 1
    fi
    tee /usr/local/bin/backup.sh > /dev/null <<EOF
#!/bin/bash
rsync -avz --delete -e "$SSH_COMMAND" $BACKUP_DIRS "${BACKUP_USER}@${BACKUP_HOST}:${REMOTE_BACKUP_PATH}/" >> "$BACKUP_LOG" 2>&1
EOF
    chmod +x /usr/local/bin/backup.sh
    tee /etc/cron.d/du-backup > /dev/null <<EOF
$CRON_SCHEDULE $USERNAME /usr/local/bin/backup.sh
EOF
    print_success "Backup configured."
    log "Backup configuration completed."
}

# --- Swap Configuration ---
configure_swap() {
    print_section "Swap Configuration"
    if [[ $IS_CONTAINER == true ]]; then
        print_warning "Swap not supported in containers."
        return 0
    fi
    if [[ -f /swapfile ]]; then
        print_info "Swap file already exists."
        return 0
    fi
    read -rp "$(echo -e "${CYAN}Enter swap size (e.g., 2G, 512M): ${NC}")" SWAP_SIZE
    if ! validate_swap_size "$SWAP_SIZE"; then
        print_error "Invalid swap size."
        return 1
    fi
    SWAP_BYTES=$(convert_to_bytes "$SWAP_SIZE")
    print_info "Creating swap file of $SWAP_SIZE..."
    fallocate -l "$SWAP_BYTES" /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    print_success "Swap configured."
    log "Swap configuration completed."
}

# --- Security Audit ---
run_security_audit() {
    print_section "Security Audit"
    if ! command -v lynis >/dev/null 2>&1; then
        print_info "Installing Lynis..."
        if [[ $ID == "debian" ]]; then
            apt-get install -y -qq apt-transport-https
            echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" > /etc/apt/sources.list.d/lynis.list
            curl -s https://packages.cisofy.com/keys/cisofy-software-rpms-public.key | apt-key add -
        else
            apt-get install -y -qq lynis
        fi
        apt-get update -qq && apt-get install -y -qq lynis
    fi
    print_info "Running Lynis audit..."
    lynis audit system --quiet > /tmp/lynis_report.txt
    print_success "Lynis audit completed. Report: /tmp/lynis_report.txt"
    if [[ $ID == "debian" ]] && ! command -v debsecan >/dev/null 2>&1; then
        apt-get install -y -qq debsecan
        debsecan --suite "${VERSION_CODENAME}" > /tmp/debsecan_report.txt
        print_success "debsecan report generated: /tmp/debsecan_report.txt"
    fi
    log "Security audit completed."
}

# --- Cleanup and Exit ---
cleanup_and_exit() {
    local exit_code=$?
    if [[ $exit_code -ne 0 && $(type -t rollback_ssh_changes) == "function" ]]; then
        print_error "Error occurred. Rolling back SSH..."
        rollback_ssh_changes
    fi
    exit $exit_code
}

# --- Final Cleanup ---
final_cleanup() {
    print_section "Final Cleanup"
    apt-get update -qq && apt-get upgrade -y -qq
    apt-get autoremove -y -qq
    apt-get autoclean -qq
    print_success "System updated and cleaned."
    log "Final cleanup completed."
}

# --- Generate Summary ---
generate_summary() {
    print_section "Generating Summary"
    {
        echo "Setup Report - $(date '+%Y-%m-%d %H:%M:%S')"
        echo "==================================="
        echo "Username: $USERNAME"
        echo "Hostname: $SERVER_NAME"
        echo "SSH Port: $SSH_PORT"
        echo "Server IP: $SERVER_IP"
        echo "Timezone: $TIMEZONE"
        echo "Tasks Executed: ${SELECTED_TASKS[*]}"
        if [[ -n "${FAILED_SERVICES[*]}" ]]; then
            echo "Failed Services: ${FAILED_SERVICES[*]}"
        else
            echo "Failed Services: None"
        fi
        if [[ -f /tmp/lynis_report.txt ]]; then
            echo "Lynis Suggestions:"
            grep "suggestion" /tmp/lynis_report.txt || echo "  None"
        fi
        if [[ -f /tmp/debsecan_report.txt ]]; then
            echo "debsecan Vulnerabilities:"
            head -n 10 /tmp/debsecan_report.txt || echo "  None"
        fi
        echo "Log File: $LOG_FILE"
        echo "Backup Directory: $BACKUP_DIR"
        echo "==================================="
        echo "Connect to server with: ssh -p $SSH_PORT $USERNAME@$SERVER_IP"
        echo "Reboot recommended to apply all changes."
    } > "$REPORT_FILE"
    print_success "Summary generated: $REPORT_FILE"
    cat "$REPORT_FILE"
    log "Summary generated: $REPORT_FILE"
}

# --- Main Function ---
main() {
    print_header
    mkdir -p /var/log
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    if [[ ${#SELECTED_TASKS[@]} -eq 0 ]]; then
        select_tasks_interactive
    fi
    for task in "${SELECTED_TASKS[@]}"; do
        case $task in
            update) run_update_check ;;
            deps) check_dependencies ;;
            system) check_system ;;
            config) collect_config ;;
            packages) install_packages ;;
            user) setup_user ;;
            system_config) configure_system ;;
            ssh) configure_ssh ;;
            firewall) configure_firewall ;;
            fail2ban) configure_fail2ban ;;
            auto_updates) configure_auto_updates ;;
            time_sync) configure_time_sync ;;
            kernel) configure_kernel_hardening ;;
            docker) install_docker ;;
            tailscale) install_tailscale ;;
            backup) setup_backup ;;
            swap) configure_swap ;;
            audit) run_security_audit ;;
            cleanup) final_cleanup ;;
            summary) generate_summary ;;
            *) print_error "Unknown task: $task" ;;
        esac
    done
    print_success "Setup completed. Review $REPORT_FILE for details."
    if confirm "Reboot now to apply changes?"; then
        reboot
    fi
}

# --- Execute Main ---
main
