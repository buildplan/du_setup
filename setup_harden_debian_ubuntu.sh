#!/bin/bash

# Debian/Ubuntu Server Setup and Hardening Script
# Version: 4.0 | 2025-06-26
# Compatible with: Debian 12 (Bookworm), Ubuntu 20.04 LTS, 22.04 LTS, 24.04 LTS, 24.10 (experimental)
#
# See README.md for full documentation.

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
CONFIG_FILE=""
BACKUP_DIR="/root/setup_harden_backup_$(date +%Y%m%d_%H%M%S)"
IS_CONTAINER=false
SSHD_BACKUP_FILE=""
LOCAL_KEY_ADDED=false
SSH_SERVICE=""
ID=""
SKIPPED_SETTINGS=()
PROMPTED_SETTINGS=()

# --- PARSE ARGUMENTS ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --quiet) VERBOSE=false; shift ;;
        --config) CONFIG_FILE="$2"; shift 2 ;;
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
    echo -e "${CYAN}║         DEBIAN/UBUNTU SERVER SETUP AND HARDENING SCRIPT         ║${NC}"
    echo -e "${CYAN}║                       v4.0 | 2025-06-26                         ║${NC}"
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
    local size="$1"
    [[ "$size" =~ ^[0-9]+[MG]$ ]] && [[ "${size%[MG]}" -ge 1 ]]
}

validate_ufw_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+(/tcp|/udp)?$ ]]
}

validate_url() {
    local url="$1"
    [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$ ]]
}

validate_email() {
    local email="$1"
    [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

validate_smtp_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ && "$port" =~ ^(25|2525|8025|587|80|465|8465|443)$ ]]
}

validate_ntfy_token() {
    local token="$1"
    [[ "$token" =~ ^tk_[a-zA-Z0-9_-]+$ || -z "$token" ]]
}

convert_to_bytes() {
    local size="$1"
    local unit="${size: -1}"
    local value="${size%[MG]}"
    if [[ "$unit" == "G" ]]; then
        echo $((value * 1024 * 1024 * 1024))
    elif [[ "$unit" == "M" ]]; then
        echo $((value * 1024 * 1024))
    else
        echo 0
    fi
}

# --- CONFIG FILE LOADING ---

load_config() {
    local config_file="$1"
    if [[ ! -f "$config_file" ]]; then
        print_error "Config file $config_file not found."
        return 1
    fi
    print_info "Loaded configuration from $config_file"
    log "Loaded configuration from $config_file"
    source "$config_file"

    # Initialize defaults
    USERNAME="${USERNAME:-}"
    HOSTNAME="${HOSTNAME:-}"
    SSH_PORT="${SSH_PORT:-5595}"
    TIMEZONE="${TIMEZONE:-Etc/UTC}"
    SWAP_SIZE="${SWAP_SIZE:-2G}"
    UFW_PORTS="${UFW_PORTS:-}"
    AUTO_UPDATES="${AUTO_UPDATES:-no}"
    INSTALL_DOCKER="${INSTALL_DOCKER:-no}"
    INSTALL_TAILSCALE="${INSTALL_TAILSCALE:-no}"
    TAILSCALE_LOGIN_SERVER="${TAILSCALE_LOGIN_SERVER:-}"
    TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
    TAILSCALE_OPERATOR="${TAILSCALE_OPERATOR:-${USERNAME:-}}"
    TAILSCALE_ACCEPT_DNS="${TAILSCALE_ACCEPT_DNS:-yes}"
    TAILSCALE_ACCEPT_ROUTES="${TAILSCALE_ACCEPT_ROUTES:-yes}"
    SMTP_SERVER="${SMTP_SERVER:-}"
    SMTP_PORT="${SMTP_PORT:-}"
    SMTP_USER="${SMTP_USER:-}"
    SMTP_PASS="${SMTP_PASS:-}"
    SMTP_FROM="${SMTP_FROM:-}"
    SMTP_TO="${SMTP_TO:-}"
    NTFY_SERVER="${NTFY_SERVER:-}"
    NTFY_TOKEN="${NTFY_TOKEN:-}"

    # Validate required fields
    local errors=()
    if [[ -z "$USERNAME" ]]; then
        errors+=("Missing USERNAME")
    elif ! validate_username "$USERNAME"; then
        errors+=("Invalid USERNAME")
    fi
    if [[ -z "$HOSTNAME" ]]; then
        errors+=("Missing HOSTNAME")
    elif ! validate_hostname "$HOSTNAME"; then
        errors+=("Invalid HOSTNAME")
    fi
    if [[ -z "$SSH_PORT" ]]; then
        errors+=("Missing SSH_PORT")
    elif ! validate_port "$SSH_PORT"; then
        errors+=("Invalid SSH_PORT")
    fi
    if [[ -z "$TIMEZONE" ]]; then
        errors+=("Missing TIMEZONE")
    elif ! validate_timezone "$TIMEZONE"; then
        errors+=("Invalid TIMEZONE")
    fi
    if [[ -n "$SWAP_SIZE" && ! "$SWAP_SIZE" =~ ^[0-9]+[MG]$ ]]; then
        errors+=("Invalid SWAP_SIZE")
    fi
    if [[ -n "$UFW_PORTS" ]]; then
        for port in ${UFW_PORTS//,/ }; do
            if ! validate_ufw_port "$port"; then
                errors+=("Invalid UFW_PORTS format: $port")
            fi
        done
    fi
    if [[ -n "$AUTO_UPDATES" && ! "$AUTO_UPDATES" =~ ^(yes|no)$ ]]; then
        errors+=("Invalid AUTO_UPDATES (must be yes/no)")
    fi
    if [[ -n "$INSTALL_DOCKER" && ! "$INSTALL_DOCKER" =~ ^(yes|no)$ ]]; then
        errors+=("Invalid INSTALL_DOCKER (must be yes/no)")
    fi
    if [[ -n "$INSTALL_TAILSCALE" && ! "$INSTALL_TAILSCALE" =~ ^(yes|no)$ ]]; then
        errors+=("Invalid INSTALL_TAILSCALE (must be yes/no)")
    fi
    if [[ "$INSTALL_TAILSCALE" == "yes" && -n "$TAILSCALE_LOGIN_SERVER" ]]; then
        if ! validate_url "$TAILSCALE_LOGIN_SERVER"; then
            errors+=("Invalid TAILSCALE_LOGIN_SERVER")
        fi
        if [[ -z "$TAILSCALE_AUTH_KEY" ]]; then
            errors+=("Missing TAILSCALE_AUTH_KEY")
        fi
        if [[ -z "$TAILSCALE_OPERATOR" ]]; then
            errors+=("Missing TAILSCALE_OPERATOR")
        elif ! validate_username "$TAILSCALE_OPERATOR"; then
            errors+=("Invalid TAILSCALE_OPERATOR")
        fi
        if [[ -n "$TAILSCALE_ACCEPT_DNS" && ! "$TAILSCALE_ACCEPT_DNS" =~ ^(yes|no)$ ]]; then
            errors+=("Invalid TAILSCALE_ACCEPT_DNS")
        fi
        if [[ -n "$TAILSCALE_ACCEPT_ROUTES" && ! "$TAILSCALE_ACCEPT_ROUTES" =~ ^(yes|no)$ ]]; then
            errors+=("Invalid TAILSCALE_ACCEPT_ROUTES")
        fi
    fi
    if [[ -n "$SMTP_SERVER" ]]; then
        if [[ ! "$SMTP_SERVER" =~ ^[a-zA-Z0-9.-]+$ ]]; then
            errors+=("Invalid SMTP_SERVER")
        fi
        if [[ -z "$SMTP_PORT" ]]; then
            errors+=("Missing SMTP_PORT")
        elif ! validate_smtp_port "$SMTP_PORT"; then
            errors+=("Invalid SMTP_PORT")
        fi
        if [[ -z "$SMTP_USER" ]]; then
            errors+=("Missing SMTP_USER")
        fi
        if [[ -z "$SMTP_PASS" ]]; then
            errors+=("Missing SMTP_PASS")
        fi
        if [[ -z "$SMTP_FROM" ]]; then
            errors+=("Missing SMTP_FROM")
        elif ! validate_email "$SMTP_FROM"; then
            errors+=("Invalid SMTP_FROM")
        fi
        if [[ -z "$SMTP_TO" ]]; then
            errors+=("Missing SMTP_TO")
        elif ! validate_email "$SMTP_TO"; then
            errors+=("Invalid SMTP_TO")
        fi
    fi
    if [[ -n "$NTFY_SERVER" ]]; then
        if ! validate_url "$NTFY_SERVER"; then
            errors+=("Invalid NTFY_SERVER")
        fi
        if [[ -z "$NTFY_TOKEN" && "$VERBOSE" == false ]]; then
            errors+=("Missing NTFY_TOKEN (skipping ntfy in quiet mode)")
            SKIPPED_SETTINGS+=("ntfy")
            NTFY_SERVER=""
            NTFY_TOKEN=""
        elif [[ -n "$NTFY_TOKEN" && ! "$NTFY_TOKEN" =~ ^tk_[a-zA-Z0-9_-]+$ ]]; then
            errors+=("Invalid NTFY_TOKEN")
        fi
    fi

    if [[ ${#errors[@]} -gt 0 ]]; then
        for error in "${errors[@]}"; do
            print_error "$error"
        done
        if [[ $VERBOSE == true ]]; then
            print_info "Prompting for missing/invalid required settings..."
            [[ -z "$USERNAME" || ! $(validate_username "$USERNAME") ]] && prompt_username
            [[ -z "$HOSTNAME" || ! $(validate_hostname "$HOSTNAME") ]] && prompt_hostname
            [[ -z "$SSH_PORT" || ! $(validate_port "$SSH_PORT") ]] && prompt_ssh_port
            [[ -z "$TIMEZONE" || ! $(validate_timezone "$TIMEZONE") ]] && prompt_timezone
            [[ -n "$SWAP_SIZE" && ! $(validate_swap_size "$SWAP_SIZE") ]] && prompt_swap_size
            if [[ -n "$UFW_PORTS" ]]; then
                local valid_ports=true
                for port in ${UFW_PORTS//,/ }; do
                    if ! validate_ufw_port "$port"; then
                        valid_ports=false
                        break
                    fi
                done
                [[ "$valid_ports" == false ]] && prompt_ufw_ports
            fi
            [[ -n "$AUTO_UPDATES" && ! "$AUTO_UPDATES" =~ ^(yes|no)$ ]] && prompt_auto_updates
            [[ -n "$INSTALL_DOCKER" && ! "$INSTALL_DOCKER" =~ ^(yes|no)$ ]] && prompt_install_docker
            [[ -n "$INSTALL_TAILSCALE" && ! "$INSTALL_TAILSCALE" =~ ^(yes|no)$ ]] && prompt_install_tailscale
            if [[ "$INSTALL_TAILSCALE" == "yes" && -n "$TAILSCALE_LOGIN_SERVER" ]]; then
                [[ ! $(validate_url "$TAILSCALE_LOGIN_SERVER") ]] && prompt_tailscale_login_server
                [[ -z "$TAILSCALE_AUTH_KEY" ]] && prompt_tailscale_auth_key
                [[ -z "$TAILSCALE_OPERATOR" || ! $(validate_username "$TAILSCALE_OPERATOR") ]] && prompt_tailscale_operator
                [[ -n "$TAILSCALE_ACCEPT_DNS" && ! "$TAILSCALE_ACCEPT_DNS" =~ ^(yes|no)$ ]] && prompt_tailscale_accept_dns
                [[ -n "$TAILSCALE_ACCEPT_ROUTES" && ! "$TAILSCALE_ACCEPT_ROUTES" =~ ^(yes|no)$ ]] && prompt_tailscale_accept_routes
            fi
            if [[ -n "$SMTP_SERVER" ]]; then
                [[ ! "$SMTP_SERVER" =~ ^[a-zA-Z0-9.-]+$ ]] && prompt_smtp_server
                [[ -z "$SMTP_PORT" || ! $(validate_smtp_port "$SMTP_PORT") ]] && prompt_smtp_port
                [[ -z "$SMTP_USER" ]] && prompt_smtp_user
                [[ -z "$SMTP_PASS" ]] && prompt_smtp_pass
                [[ -z "$SMTP_FROM" || ! $(validate_email "$SMTP_FROM") ]] && prompt_smtp_from
                [[ -z "$SMTP_TO" || ! $(validate_email "$SMTP_TO") ]] && prompt_smtp_to
            fi
            if [[ -n "$NTFY_SERVER" ]]; then
                [[ ! $(validate_url "$NTFY_SERVER") ]] && prompt_ntfy_server
                [[ -z "$NTFY_TOKEN" || ! $(validate_ntfy_token "$NTFY_TOKEN") ]] && prompt_ntfy_token
            fi
            return 0
        else
            print_error "Invalid or missing configuration in quiet mode. Exiting."
            exit 1
        fi
    fi
    return 0
}

# --- USER PROMPT FUNCTIONS ---

prompt_username() {
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
    PROMPTED_SETTINGS+=("USERNAME")
}

prompt_hostname() {
    while true; do
        read -rp "$(echo -e "${CYAN}Enter server hostname: ${NC}")" HOSTNAME
        if validate_hostname "$HOSTNAME"; then
            SERVER_NAME="$HOSTNAME"
            PRETTY_NAME="${PRETTY_NAME:-$HOSTNAME}"
            break
        else
            print_error "Invalid hostname."
        fi
    done
    PROMPTED_SETTINGS+=("HOSTNAME")
}

prompt_ssh_port() {
    while true; do
        read -rp "$(echo -e "${CYAN}Enter custom SSH port (1024-65535) [5595]: ${NC}")" SSH_PORT
        SSH_PORT=${SSH_PORT:-5595}
        if validate_port "$SSH_PORT"; then break; else print_error "Invalid port number."; fi
    done
    PROMPTED_SETTINGS+=("SSH_PORT")
}

prompt_timezone() {
    while true; do
        read -rp "$(echo -e "${CYAN}Enter desired timezone (e.g., Etc/UTC, America/New_York) [Etc/UTC]: ${NC}")" TIMEZONE
        TIMEZONE=${TIMEZONE:-Etc/UTC}
        if validate_timezone "$TIMEZONE"; then break; else print_error "Invalid timezone."; fi
    done
    PROMPTED_SETTINGS+=("TIMEZONE")
}

prompt_swap_size() {
    while true; do
        read -rp "$(echo -e "${CYAN}Enter swap file size (e.g., 2G, 512M) [2G]: ${NC}")" SWAP_SIZE
        SWAP_SIZE=${SWAP_SIZE:-2G}
        if validate_swap_size "$SWAP_SIZE"; then break; else print_error "Invalid size. Use format like '2G' or '512M'."; fi
    done
    PROMPTED_SETTINGS+=("SWAP_SIZE")
}

prompt_ufw_ports() {
    if confirm "Add custom UFW ports (e.g., 80/tcp, 443/tcp)?"; then
        while true; do
            read -rp "$(echo -e "${CYAN}Enter ports (comma-separated, e.g., 80/tcp,443/tcp): ${NC}")" UFW_PORTS
            if [[ -z "$UFW_PORTS" ]]; then
                print_info "No custom ports entered. Skipping."
                UFW_PORTS=""
                break
            fi
            local valid=true
            for port in ${UFW_PORTS//,/ }; do
                if ! validate_ufw_port "$port"; then
                    print_error "Invalid port format: $port. Use <port>[/tcp|/udp]."
                    valid=false
                    break
                fi
            done
            if [[ "$valid" == true ]]; then break; fi
        done
        PROMPTED_SETTINGS+=("UFW_PORTS")
    else
        UFW_PORTS=""
    fi
}

prompt_auto_updates() {
    AUTO_UPDATES="no"
    confirm "Enable automatic security updates?" && AUTO_UPDATES="yes"
    PROMPTED_SETTINGS+=("AUTO_UPDATES")
}

prompt_install_docker() {
    INSTALL_DOCKER="no"
    confirm "Install Docker Engine?" && INSTALL_DOCKER="yes"
    PROMPTED_SETTINGS+=("INSTALL_DOCKER")
}

prompt_install_tailscale() {
    INSTALL_TAILSCALE="no"
    confirm "Install Tailscale VPN?" && INSTALL_TAILSCALE="yes"
    PROMPTED_SETTINGS+=("INSTALL_TAILSCALE")
}

prompt_tailscale_login_server() {
    read -rp "$(echo -e "${CYAN}Enter Tailscale login server (e.g., https://hs.mydomain.com, press Enter to skip): ${NC}")" TAILSCALE_LOGIN_SERVER
    if [[ -n "$TAILSCALE_LOGIN_SERVER" && ! $(validate_url "$TAILSCALE_LOGIN_SERVER") ]]; then
        print_error "Invalid Tailscale login server URL."
        TAILSCALE_LOGIN_SERVER=""
    fi
    PROMPTED_SETTINGS+=("TAILSCALE_LOGIN_SERVER")
}

prompt_tailscale_auth_key() {
    read -rp "$(echo -e "${CYAN}Enter Tailscale auth key: ${NC}")" TAILSCALE_AUTH_KEY
    PROMPTED_SETTINGS+=("TAILSCALE_AUTH_KEY")
}

prompt_tailscale_operator() {
    read -rp "$(echo -e "${CYAN}Enter Tailscale operator username [$USERNAME]: ${NC}")" TAILSCALE_OPERATOR
    TAILSCALE_OPERATOR=${TAILSCALE_OPERATOR:-$USERNAME}
    if [[ -n "$TAILSCALE_OPERATOR" && ! $(validate_username "$TAILSCALE_OPERATOR") ]]; then
        print_error "Invalid Tailscale operator username."
        TAILSCALE_OPERATOR="$USERNAME"
    fi
    PROMPTED_SETTINGS+=("TAILSCALE_OPERATOR")
}

prompt_tailscale_accept_dns() {
    TAILSCALE_ACCEPT_DNS="yes"
    confirm "Accept Tailscale DNS?" "y" || TAILSCALE_ACCEPT_DNS="no"
    PROMPTED_SETTINGS+=("TAILSCALE_ACCEPT_DNS")
}

prompt_tailscale_accept_routes() {
    TAILSCALE_ACCEPT_ROUTES="yes"
    confirm "Accept Tailscale routes?" "y" || TAILSCALE_ACCEPT_ROUTES="no"
    PROMPTED_SETTINGS+=("TAILSCALE_ACCEPT_ROUTES")
}

prompt_smtp_server() {
    read -rp "$(echo -e "${CYAN}Enter SMTP server [mail.smtp2go.com]: ${NC}")" SMTP_SERVER
    SMTP_SERVER=${SMTP_SERVER:-mail.smtp2go.com}
    if [[ ! "$SMTP_SERVER" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        print_error "Invalid SMTP server."
        SMTP_SERVER=""
    fi
    PROMPTED_SETTINGS+=("SMTP_SERVER")
}

prompt_smtp_port() {
    read -rp "$(echo -e "${CYAN}Enter SMTP port [587]: ${NC}")" SMTP_PORT
    SMTP_PORT=${SMTP_PORT:-587}
    if ! validate_smtp_port "$SMTP_PORT"; then
        print_error "Invalid SMTP port (use 25,2525,8025,587,80,465,8465,443)."
        SMTP_PORT=""
    fi
    PROMPTED_SETTINGS+=("SMTP_PORT")
}

prompt_smtp_user() {
    read -rp "$(echo -e "${CYAN}Enter SMTP username: ${NC}")" SMTP_USER
    if [[ -z "$SMTP_USER" ]]; then
        print_error "SMTP username cannot be empty."
        SMTP_USER=""
    fi
    PROMPTED_SETTINGS+=("SMTP_USER")
}

prompt_smtp_pass() {
    read -sp "$(echo -e "${CYAN}Enter SMTP password: ${NC}")" SMTP_PASS
    echo
    if [[ -z "$SMTP_PASS" ]]; then
        print_error "SMTP password cannot be empty."
        SMTP_PASS=""
    fi
    PROMPTED_SETTINGS+=("SMTP_PASS")
}

prompt_smtp_from() {
    read -rp "$(echo -e "${CYAN}Enter SMTP from email address: ${NC}")" SMTP_FROM
    if [[ -z "$SMTP_FROM" || ! $(validate_email "$SMTP_FROM") ]]; then
        print_error "Invalid SMTP from email."
        SMTP_FROM=""
    fi
    PROMPTED_SETTINGS+=("SMTP_FROM")
}

prompt_smtp_to() {
    read -rp "$(echo -e "${CYAN}Enter SMTP to email address: ${NC}")" SMTP_TO
    if [[ -z "$SMTP_TO" || ! $(validate_email "$SMTP_TO") ]]; then
        print_error "Invalid SMTP to email."
        SMTP_TO=""
    fi
    PROMPTED_SETTINGS+=("SMTP_TO")
}

prompt_ntfy_server() {
    read -rp "$(echo -e "${CYAN}Enter ntfy server URL (e.g., https://ntfy.mydomain.com/ovps, press Enter to skip): ${NC}")" NTFY_SERVER
    if [[ -n "$NTFY_SERVER" && ! $(validate_url "$NTFY_SERVER") ]]; then
        print_error "Invalid ntfy server URL."
        NTFY_SERVER=""
    fi
    PROMPTED_SETTINGS+=("NTFY_SERVER")
}

prompt_ntfy_token() {
    read -rp "$(echo -e "${CYAN}Enter ntfy token: ${NC}")" NTFY_TOKEN
    if [[ -n "$NTFY_TOKEN" && ! $(validate_ntfy_token "$NTFY_TOKEN") ]]; then
        print_error "Invalid ntfy token (must start with tk_)."
        NTFY_TOKEN=""
    fi
    PROMPTED_SETTINGS+=("NTFY_TOKEN")
}

# --- CORE FUNCTIONS ---

check_dependencies() {
    print_section "Checking Dependencies"
    local missing_deps=()
    command -v curl >/dev/null || missing_deps+=("curl")
    command -v sudo >/dev/null || missing_deps+=("sudo")
    command -v gpg >/dev/null || missing_deps+=("gpg")
    command -v postmap >/dev/null || missing_deps+=("postfix")

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
        ID="$ID"
        if [[ $ID == "debian" && $VERSION_ID == "12" ]] || \
           [[ $ID == "ubuntu" && $VERSION_ID =~ ^(20.04|22.04|24.04|24.10)$ ]]; then
            print_success "Compatible OS detected: $PRETTY_NAME"
        else
            print_warning "Script not tested on $PRETTY_NAME. This is for Debian 12 or Ubuntu 20.04/22.04/24.04 LTS."
            if ! confirm "Continue anyway?"; then exit 1; fi
        fi
    else
        print_error "This does not appear to be a Debian or Ubuntu system."
        exit 1
    fi

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

    if [[ -n "$CONFIG_FILE" || -f "/etc/setup_harden.conf" ]]; then
        CONFIG_FILE=${CONFIG_FILE:-/etc/setup_harden.conf}
        if ! load_config "$CONFIG_FILE"; then
            if [[ $VERBOSE == false ]]; then
                print_error "Configuration file invalid in quiet mode. Exiting."
                exit 1
            else
                print_info "Falling back to interactive mode due to config issues."
                full_interactive_config
            fi
        fi
    else
        full_interactive_config
    fi

    SERVER_IP=$(curl -s https://ifconfig.me 2>/dev/null || echo "unknown")
    print_info "Detected server IP: $SERVER_IP"
    echo -e "\n${YELLOW}Configuration Summary:${NC}"
    echo -e "  Username:    $USERNAME"
    echo -e "  Hostname:    $SERVER_NAME"
    echo -e "  SSH Port:    $SSH_PORT"
    echo -e "  Server IP:   $SERVER_IP"
    if [[ ${#PROMPTED_SETTINGS[@]} -gt 0 ]]; then
        echo -e "  Prompted:    ${PROMPTED_SETTINGS[*]}"
    fi
    if [[ ${#SKIPPED_SETTINGS[@]} -gt 0 ]]; then
        echo -e "  Skipped:     ${SKIPPED_SETTINGS[*]}"
    fi
    if [[ "$VERBOSE" == true ]]; then
        if ! confirm "\nContinue with this configuration?" "y"; then print_info "Exiting."; exit 0; fi
    fi
    log "Configuration collected: USER=$USERNAME, HOST=$SERVER_NAME, PORT=$SSH_PORT"
}

full_interactive_config() {
    prompt_username
    prompt_hostname
    read -rp "$(echo -e "${CYAN}Enter a 'pretty' hostname (optional): ${NC}")" PRETTY_NAME
    [[ -z "$PRETTY_NAME" ]] && PRETTY_NAME="$SERVER_NAME"
    prompt_ssh_port
    prompt_timezone
    prompt_auto_updates
    prompt_install_docker
    prompt_install_tailscale
    if [[ "$INSTALL_TAILSCALE" == "yes" ]]; then
        prompt_tailscale_login_server
        if [[ -n "$TAILSCALE_LOGIN_SERVER" ]]; then
            prompt_tailscale_auth_key
            prompt_tailscale_operator
            prompt_tailscale_accept_dns
            prompt_tailscale_accept_routes
        fi
    fi
    if confirm "Configure system monitoring with SMTP and/or ntfy?"; then
        prompt_smtp_server
        if [[ -n "$SMTP_SERVER" ]]; then
            prompt_smtp_port
            prompt_smtp_user
            prompt_smtp_pass
            prompt_smtp_from
            prompt_smtp_to
        fi
        prompt_ntfy_server
        if [[ -n "$NTFY_SERVER" ]]; then
            prompt_ntfy_token
        fi
    fi
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
        openssh-client openssh-server postfix libsasl2-modules curl; then
        print_error "Failed to install one or more essential packages."
        exit 1
    fi
    print_success "Essential packages installed."
    log "Package installation completed."
}

setup_user() {
    print_section "User Management"

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
        print_info "Set a password for '$USERNAME' (required, or press Enter twice to skip for key-only access):"
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
                if echo "$USERNAME:$PASS1" | chpasswd 2>&1 | tee -a "$LOG_FILE"; then
                    print_success "Password for '$USERNAME' updated."
                    break
                else
                    print_error "Failed to set password. Check log file for details."
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
    if [[ $(timedatectl status | grep "Time zone" | awk '{print $3}') != "$TIMEZONE" ]]; then
        timedatectl set-timezone "$TIMEZONE"
        print_success "Timezone set to $TIMEZONE."
        log "Timezone set to $TIMEZONE."
    else
        print_info "Timezone already set to $TIMEZONE."
    fi

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

    if ! dpkg -l openssh-server | grep -q ^ii; then
        print_error "openssh-server package is not installed. Please ensure it is installed."
        exit 1
    fi

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
        print_error "No SSH service or daemon detected. Please verify openssh-server installation."
        exit 1
    fi
    print_info "Using SSH service: $SSH_SERVICE"
    log "Detected SSH service: $SSH_SERVICE"
    systemctl status "$SSH_SERVICE" --no-pager >> "$LOG_FILE" 2>&1
    ps aux | grep "[s]shd" >> "$LOG_FILE" 2>&1

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
        mv "$NEW_SSH_CONFIG" /etc/ssh/sshd_config.d/99thor-hardening.conf
        chmod 644 /etc/ssh/sshd_config.d/99-hardening.conf
        tee /etc/issue.net > /dev/null <<'EOF'
******************************************************************************
                        AUTHORIZED ACCESS ONLY
             ═════ all attempts are logged and reviewed ═════
******************************************************************************
EOF
    fi

    print_info "Testing and restarting SSH service..."
    if sshd -t; then
        if ! systemctl restart "$SSH_SERVICE"; then
            print_error "SSH service failed to restart! Reverting changes..."
            cp "$SSHD_BACKUP_FILE" /etc/ssh/sshd_config
            systemctl restart "$SSH_SERVICE" || /usr/sbin/sshd || true
            exit 1
        fi
        if systemctl is-active --quiet "$SSH_SERVICE"; then
            print_success "SSH service restarted on port $SSH_PORT."
        else
            print_error "SSH service failed to start! Reverting changes..."
            cp "$SSHD_BACKUP_FILE" /etc/ssh/sshd_config
            systemctl restart "$SSH_SERVICE" || /usr/sbin/sshd || true
            exit 1
        fi
    else
        print_error "SSH config test failed! Reverting changes..."
        cp "$SSHD_BACKUP_FILE" /etc/ssh/sshd_config
        systemctl restart "$SSH_SERVICE" || /usr/sbin/sshd || true
        rm -f "$NEW_SSH_CONFIG"
        exit 1
    fi

    print_info "Verifying root SSH login is disabled..."
    if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config.d/99-hardening.conf; then
        print_success "Root SSH login is disabled."
    else
        print_error "Failed to disable root SSH login. Please check /etc/ssh/sshd_config.d/99-hardening.conf."
        exit 1
    fi
    if ssh -p "$SSH_PORT" -o BatchMode=yes -o ConnectTimeout=5 root@localhost true 2>/dev/null; then
        print_error "Root SSH login is still possible! Please check SSH configuration."
        exit 1
    else
        print_success "Confirmed: Root SSH login is disabled."
    fi

    print_warning "CRITICAL: Test new SSH connection in a SEPARATE terminal NOW!"
    print_info "Use: ssh -p $SSH_PORT $USERNAME@$SERVER_IP"

    if ! confirm "Was the new SSH connection successful?"; then
        print_error "Aborting. Restoring original SSH configuration."
        cp "$SSHD_BACKUP_FILE" /etc/ssh/sshd_config
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
    if [[ -n "${UFW_PORTS:-}" ]]; then
        for port in ${UFW_PORTS//,/ }; do
            if ufw status | grep -qw "$port"; then
                print_info "Rule for $port already exists."
            else
                ufw allow "$port" comment "Custom port $port"
                print_success "Added rule for $port."
                log "Added UFW rule for $port."
            fi
        done
    elif [[ $VERBOSE == true ]]; then
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
                read -rp "$(echo -e "${CYAN}Enter ports (space-separated, e.g., 8080/tcp 123/udp): ${NC}")" CUSTOM_PORTS
                if [[ -z "$CUSTOM_PORTS" ]]; then
                    print_info "No custom ports entered. Skipping."
                    break
                fi
                valid=true
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
    fi
    if [[ "$INSTALL_TAILSCALE" == "yes" ]]; then
        if ! ufw status | grep -qw "41641/udp"; then
            ufw allow 41641/udp comment 'Tailscale'
            print_success "Tailscale port 41641/udp allowed."
        else
            print_info "Tailscale port 41641/udp rule already exists."
        fi
    fi
    if [[ -n "${SMTP_PORT:-}" ]]; then
        if ! ufw status | grep -qw "$SMTP_PORT/tcp"; then
            ufw allow "$SMTP_PORT"/tcp comment 'SMTP'
            print_success "SMTP port $SMTP_PORT/tcp allowed."
        else
            print_info "SMTP port $SMTP_PORT/tcp rule already exists."
        fi
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
    print_info " - DigitalOcean: Configure Firewall in Control Panel -> Networking -> Firewalls."
    print_info " - AWS: Update Security Groups in EC2 Dashboard."
    print_info " - GCP: Update Firewall Rules in VPC Network -> Firewall."
    print_info " - Oracle: Configure Security Lists in Virtual Cloud Network."
    ufw status verbose | tee -a "$LOG_FILE"
    iptables -L >> "$LOG_FILE" 2>&1
    log "Firewall configuration completed."
}

configure_fail2ban() {
    print_section "Fail2Ban Configuration"
    if ! dpkg -l fail2ban | grep -q ^ii; then
        print_error "fail2ban package is not installed."
        exit 1
    fi
    print_info "Configuring Fail2Ban..."
    local jail_config="/etc/fail2ban/jail.d/custom.conf"
    mkdir -p /etc/fail2ban/jail.d
    cp /etc/fail2ban/jail.conf "$BACKUP_DIR/jail.conf.backup" 2>/dev/null || true
    NEW_JAIL_CONFIG=$(mktemp)
    tee "$NEW_JAIL_CONFIG" > /dev/null <<EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 3
findtime = 600
bantime = 3600
EOF
    if [[ -n "${UFW_PORTS:-}" ]]; then
        for port in ${UFW_PORTS//,/ }; do
            if [[ "$port" =~ ^[0-9]+/tcp$ ]]; then
                port_num="${port%/tcp}"
                echo -e "[custom-$port_num]\nenabled = true\nport = $port_num\nmaxretry = 5\nfindtime = 600\nbantime = 3600" >> "$NEW_JAIL_CONFIG"
            fi
        done
    fi
    if [[ -f "$jail_config" ]] && cmp -s "$jail_config" "$NEW_JAIL_CONFIG"; then
        print_info "Fail2Ban configuration already correct. Skipping."
    else
        mv "$NEW_JAIL_CONFIG" "$jail_config"
        chmod 644 "$jail_config"
        systemctl restart fail2ban
        if systemctl is-active --quiet fail2ban; then
            print_success "Fail2Ban configured and running."
            fail2ban-client status sshd | tee -a "$LOG_FILE"
        else
            print_error "Failed to start Fail2Ban service. Check 'journalctl -u fail2ban'."
            exit 1
        fi
    fi
    rm -f "$NEW_JAIL_CONFIG"
    log "Fail2Ban configuration completed."
}

configure_auto_updates() {
    print_section "Automatic Updates Configuration"
    if [[ "$AUTO_UPDATES" != "yes" ]]; then
        print_info "Skipping automatic updates configuration."
        SKIPPED_SETTINGS+=("automatic updates")
        return 0
    fi
    if ! dpkg -l unattended-upgrades | grep -q ^ii; then
        print_error "unattended-upgrades package is not installed."
        exit 1
    fi
    print_info "Configuring unattended-upgrades..."
    local config_file="/etc/apt/apt.conf.d/50unattended-upgrades"
    cp "$config_file" "$BACKUP_DIR/50unattended-upgrades.backup" 2>/dev/null || true
    if ! grep -q "Unattended-Upgrade::Automatic-Reboot" "$config_file"; then
        echo 'Unattended-Upgrade::Automatic-Reboot "true";' >> "$config_file"
        echo 'Unattended-Upgrade::Automatic-Reboot-Time "02:00";' >> "$config_file"
    fi
    if ! grep -q "Unattended-Upgrade::Mail" "$config_file"; then
        if [[ -n "${SMTP_TO:-}" ]]; then
            echo "Unattended-Upgrade::Mail \"$SMTP_TO\";" >> "$config_file"
            echo 'Unattended-Upgrade::MailReport "on-change";' >> "$config_file"
        fi
    fi
    systemctl restart unattended-upgrades
    if systemctl is-active --quiet unattended-upgrades; then
        print_success "Automatic updates configured."
    else
        print_error "Failed to start unattended-upgrades service."
        exit 1
    fi
    log "Automatic updates configuration completed."
}

configure_monitoring() {
    print_section "System Monitoring Configuration"
    if [[ -n "${SMTP_SERVER:-}" || -n "${NTFY_SERVER:-}" ]]; then
        if [[ -n "${SMTP_SERVER:-}" && -n "${SMTP_PORT:-}" && -n "${SMTP_USER:-}" && -n "${SMTP_PASS:-}" && -n "${SMTP_FROM:-}" && -n "${SMTP_TO:-}" ]]; then
            print_info "Configuring Postfix for SMTP2go..."
            NEW_POSTFIX_CONFIG=$(mktemp)
            tee "$NEW_POSTFIX_CONFIG" > /dev/null <<EOF
relayhost = [$SMTP_SERVER]:$SMTP_PORT
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
EOF
            if [[ -f /etc/postfix/main.cf ]] && grep -q "relayhost = \[$SMTP_SERVER\]:$SMTP_PORT" /etc/postfix/main.cf; then
                print_info "Postfix configuration already correct. Skipping."
            else
                cat "$NEW_POSTFIX_CONFIG" >> /etc/postfix/main.cf
                print_info "Creating Postfix SASL password file..."
                if [[ $VERBOSE == true && ( -z "$SMTP_USER" || -z "$SMTP_PASS" ) ]]; then
                    [[ -z "$SMTP_USER" ]] && prompt_smtp_user
                    [[ -z "$SMTP_PASS" ]] && prompt_smtp_pass
                fi
                if [[ -z "$SMTP_USER" || -z "$SMTP_PASS" ]]; then
                    print_error "SMTP credentials missing. Skipping SMTP configuration."
                    SKIPPED_SETTINGS+=("SMTP monitoring")
                    SMTP_SERVER=""
                    rm -f "$NEW_POSTFIX_CONFIG"
                    return
                fi
                echo "[$SMTP_SERVER]:$SMTP_PORT $SMTP_USER:$SMTP_PASS" > /etc/postfix/sasl_passwd
                chmod 600 /etc/postfix/sasl_passwd
                postmap /etc/postfix/sasl_passwd
                systemctl restart postfix
                print_info "Testing SMTP configuration..."
                if echo "Test email from $(hostname)" | mail -s "Test Alert" "$SMTP_TO" 2>&1 | tee -a "$LOG_FILE"; then
                    print_success "SMTP test email sent to $SMTP_TO."
                else
                    print_error "Failed to send test email. Check /var/log/mail.log."
                fi
            fi
            rm -f "$NEW_POSTFIX_CONFIG"
        else
            print_info "Incomplete SMTP configuration. Skipping SMTP."
            SKIPPED_SETTINGS+=("SMTP monitoring")
            SMTP_SERVER=""
        fi
        if [[ -n "${NTFY_SERVER:-}" && -n "${NTFY_TOKEN:-}" ]]; then
            print_info "Configuring ntfy notifications..."
            curl -s -o /dev/null -H "Authorization: Bearer $NTFY_TOKEN" "$NTFY_SERVER" || {
                print_error "Failed to connect to ntfy server. Check NTFY_SERVER and NTFY_TOKEN."
                SKIPPED_SETTINGS+=("ntfy monitoring")
                NTFY_SERVER=""
                NTFY_TOKEN=""
            }
        elif [[ -n "${NTFY_SERVER:-}" && -z "${NTFY_TOKEN:-}" && $VERBOSE == true ]]; then
            prompt_ntfy_token
            if [[ -n "${NTFY_TOKEN:-}" ]]; then
                print_info "Configuring ntfy notifications..."
                curl -s -o /dev/null -H "Authorization: Bearer $NTFY_TOKEN" "$NTFY_SERVER" || {
                    print_error "Failed to connect to ntfy server. Check NTFY_SERVER and NTFY_TOKEN."
                    SKIPPED_SETTINGS+=("ntfy monitoring")
                    NTFY_SERVER=""
                    NTFY_TOKEN=""
                }
            else
                print_info "No ntfy token provided. Skipping ntfy."
                SKIPPED_SETTINGS+=("ntfy monitoring")
                NTFY_SERVER=""
            fi
        else
            print_info "Incomplete ntfy configuration. Skipping ntfy."
            SKIPPED_SETTINGS+=("ntfy monitoring")
            NTFY_SERVER=""
        fi
        print_info "Setting up disk space monitoring and rsync backup cron jobs..."
        local cron_file="/etc/cron.d/setup_harden_monitoring"
        NEW_CRON_CONFIG=$(mktemp)
        tee "$NEW_CRON_CONFIG" > /dev/null <<'EOF'
# Disk space monitoring (alert at 90% usage)
*/15 * * * * root df -h / | awk 'NR==2 {if ($5+0 >= 90) {print "Disk usage critical on '"$(hostname)"': " $0}}' | while read -r line; do [[ -n "${SMTP_TO:-}" ]] && echo "$line" | mail -s "Disk Alert" "${SMTP_TO}"; [[ -n "${NTFY_SERVER:-}" && -n "${NTFY_TOKEN:-}" ]] && curl -s -H "Authorization: Bearer ${NTFY_TOKEN}" -d "$line" "${NTFY_SERVER}"; done
# Rsync backup to /root/backup (daily at 1am)
0 1 * * * root rsync -a --delete --exclude '/root/backup' / /root/backup && { [[ -n "${SMTP_TO:-}" ]] && echo "Rsync backup completed on $(hostname)" | mail -s "Backup Complete" "${SMTP_TO}"; [[ -n "${NTFY_SERVER:-}" && -n "${NTFY_TOKEN:-}" ]] && curl -s -H "Authorization: Bearer ${NTFY_TOKEN}" -d "Rsync backup completed on $(hostname)" "${NTFY_SERVER}"; }
EOF
        if [[ -f "$cron_file" ]] && cmp -s "$cron_file" "$NEW_CRON_CONFIG"; then
            print_info "Cron jobs already configured. Skipping."
        else
            mv "$NEW_CRON_CONFIG" "$cron_file"
            chmod 644 "$cron_file"
            print_success "Disk space and backup cron jobs configured."
        fi
        rm -f "$NEW_CRON_CONFIG"
    else
        print_info "Skipping system monitoring configuration (no SMTP or ntfy settings provided)."
        SKIPPED_SETTINGS+=("system monitoring")
    fi
    log "System monitoring configuration completed."
}

install_docker() {
    if [[ "$INSTALL_DOCKER" != "yes" ]]; then
        print_info "Skipping Docker installation."
        SKIPPED_SETTINGS+=("Docker installation")
        return 0
    fi
    print_section "Docker Installation"
    if command -v docker >/dev/null 2>&1; then
        print_info "Docker already installed."
        if ! groups "$USERNAME" | grep -qw docker; then
            print_info "Adding '$USERNAME' to docker group..."
            usermod -aG docker "$USERNAME"
            print_success "User '$USERNAME' added to docker group."
        else
            print_info "User '$USERNAME' already in docker group."
        fi
        return 0
    fi
    print_info "Installing Docker..."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    chmod +x /tmp/get-docker.sh
    if ! grep -q "docker" /tmp/get-docker.sh; then
        print_error "Downloaded Docker install script appears invalid."
        rm -f /tmp/get-docker.sh
        exit 1
    fi
    if ! sh /tmp/get-docker.sh; then
        print_error "Failed to install Docker."
        rm -f /tmp/get-docker.sh
        exit 1
    fi
    rm -f /tmp/get-docker.sh
    systemctl enable docker
    systemctl start docker
    print_info "Adding '$USERNAME' to docker group..."
    usermod -aG docker "$USERNAME"
    if groups "$USERNAME" | grep -qw docker; then
        print_success "User '$USERNAME' added to docker group."
    else
        print_error "Failed to add '$USERNAME' to docker group."
        exit 1
    fi
    if ! docker ps >/dev/null 2>&1; then
        print_error "Docker service is not running or accessible. Check 'systemctl status docker'."
        exit 1
    fi
    print_success "Docker installation completed."
    log "Docker installation and configuration completed."
}

install_tailscale() {
    if [[ "$INSTALL_TAILSCALE" != "yes" ]]; then
        print_info "Skipping Tailscale installation."
        SKIPPED_SETTINGS+=("Tailscale installation")
        return 0
    fi
    print_section "Tailscale VPN Installation"
    if command -v tailscale >/dev/null 2>&1; then
        print_info "Tailscale already installed."
        if [[ -n "${TAILSCALE_LOGIN_SERVER:-}" && -n "${TAILSCALE_AUTH_KEY:-}" && -n "${TAILSCALE_OPERATOR:-}" ]]; then
            print_info "Configuring Tailscale with Headscale..."
            local ts_cmd="tailscale up --login-server=$TAILSCALE_LOGIN_SERVER --operator=$TAILSCALE_OPERATOR"
            [[ "$TAILSCALE_ACCEPT_DNS" == "yes" ]] && ts_cmd="$ts_cmd --accept-dns"
            [[ "$TAILSCALE_ACCEPT_ROUTES" == "yes" ]] && ts_cmd="$ts_cmd --accept-routes"
            [[ -n "${TAILSCALE_AUTH_KEY:-}" ]] && ts_cmd="$ts_cmd --authkey=$TAILSCALE_AUTH_KEY"
            ts_cmd="$ts_cmd --hostname=$SERVER_NAME"
            if eval "$ts_cmd" 2>&1 | tee -a "$LOG_FILE"; then
                if tailscale status | grep -q "$SERVER_NAME"; then
                    print_success "Tailscale configured and connected."
                    tailscale status | tee -a "$LOG_FILE"
                else
                    print_error "Tailscale failed to connect. Check 'tailscale status' and log file."
                    exit 1
                fi
            else
                print_error "Failed to configure Tailscale. Check log file."
                exit 1
            fi
        else
            print_info "Tailscale configuration incomplete. Skipping configuration."
            SKIPPED_SETTINGS+=("Tailscale configuration")
        fi
        return 0
    fi
    print_info "Installing Tailscale..."
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/focal.gpg | gpg --dearmor -o /usr/share/keyrings/tailscale-archive-keyring.gpg
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/focal.list -o /etc/apt/sources.list.d/tailscale.list
    if ! apt-get update -qq || ! apt-get install -y -qq tailscale; then
        print_error "Failed to install Tailscale."
        exit 1
    fi
    systemctl enable tailscaled
    systemctl start tailscaled
    if [[ -n "${TAILSCALE_LOGIN_SERVER:-}" && -n "${TAILSCALE_AUTH_KEY:-}" && -n "${TAILSCALE_OPERATOR:-}" ]]; then
        print_info "Configuring Tailscale with Headscale..."
        local ts_cmd="tailscale up --login-server=$TAILSCALE_LOGIN_SERVER --operator=$TAILSCALE_OPERATOR"
        [[ "$TAILSCALE_ACCEPT_DNS" == "yes" ]] && ts_cmd="$ts_cmd --accept-dns"
        [[ "$TAILSCALE_ACCEPT_ROUTES" == "yes" ]] && ts_cmd="$ts_cmd --accept-routes"
        [[ -n "${TAILSCALE_AUTH_KEY:-}" ]] && ts_cmd="$ts_cmd --authkey=$TAILSCALE_AUTH_KEY"
        ts_cmd="$ts_cmd --hostname=$SERVER_NAME"
        if eval "$ts_cmd" 2>&1 | tee -a "$LOG_FILE"; then
            if tailscale status | grep -q "$SERVER_NAME"; then
                print_success "Tailscale configured and connected."
                tailscale status | tee -a "$LOG_FILE"
            else
                print_error "Tailscale failed to connect. Check 'tailscale status' and log file."
                exit 1
            fi
        else
            print_error "Failed to configure Tailscale. Check log file."
            exit 1
        fi
    else
        print_info "Tailscale installed but not configured (missing login server, auth key, or operator)."
        SKIPPED_SETTINGS+=("Tailscale configuration")
    fi
    print_success "Tailscale installation completed."
    log "Tailscale installation and configuration completed."
}

configure_swap() {
    print_section "Swap Configuration"
    if [[ "$IS_CONTAINER" == true ]]; then
        print_info "Skipping swap configuration in container environment."
        SKIPPED_SETTINGS+=("swap configuration")
        return 0
    fi
    if [[ -z "${SWAP_SIZE:-}" ]]; then
        print_info "No swap size specified. Skipping swap configuration."
        SKIPPED_SETTINGS+=("swap configuration")
        return 0
    fi
    if ! validate_swap_size "$SWAP_SIZE"; then
        print_error "Invalid SWAP_SIZE format: $SWAP_SIZE. Skipping swap configuration."
        SKIPPED_SETTINGS+=("swap configuration")
        return 0
    fi
    local swap_size_bytes=$(convert_to_bytes "$SWAP_SIZE")
    if [[ -f /swapfile ]]; then
        current_size=$(ls -l /swapfile | awk '{print $5}')
        if [[ "$current_size" -eq "$swap_size_bytes" ]]; then
            print_info "Swap file already exists with correct size ($SWAP_SIZE)."
            return 0
        else
            print_info "Removing existing swap file..."
            swapoff /swapfile 2>/dev/null || true
            rm -f /swapfile
        fi
    fi
    print_info "Creating swap file of size $SWAP_SIZE..."
    if ! fallocate -l "$swap_size_bytes" /swapfile; then
        print_error "Failed to create swap file. Check disk space."
        exit 1
    fi
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    if ! grep -q "^/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    sysctl vm.swappiness=10
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    if free | grep -q "Swap:"; then
        print_success "Swap configured: $SWAP_SIZE"
        free -h | tee -a "$LOG_FILE"
    else
        print_error "Failed to configure swap. Check 'free -h' and log file."
        exit 1
    fi
    log "Swap configuration completed."
}

configure_time() {
    print_section "Time Synchronization"
    if ! dpkg -l chrony | grep -q ^ii; then
        print_error "chrony package is not installed."
        exit 1
    fi
    print_info "Configuring time synchronization with chrony..."
    systemctl enable chrony
    systemctl start chrony
    if systemctl is-active --quiet chrony; then
        print_success "Time synchronization configured."
        chronyc tracking | tee -a "$LOG_FILE"
    else
        print_error "Failed to start chrony service. Check 'journalctl -u chrony'."
        exit 1
    fi
    log "Time synchronization configuration completed."
}

cleanup() {
    print_section "Cleanup"
    print_info "Cleaning up package cache and temporary files..."
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    rm -f /tmp/*.sh
    find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
    print_success "Cleanup completed."
    log "Cleanup completed."
}

print_summary() {
    print_section "Setup Summary"
    echo -e "${GREEN}Setup completed successfully!${NC}" | tee -a "$LOG_FILE"
    echo -e "\n${YELLOW}Configuration Applied:${NC}"
    echo -e "  Username:    $USERNAME"
    echo -e "  Hostname:    $SERVER_NAME"
    echo -e "  SSH Port:    $SSH_PORT"
    echo -e "  Server IP:   $SERVER_IP"
    echo -e "  Timezone:    $TIMEZONE"
    [[ -n "${SWAP_SIZE:-}" && "$IS_CONTAINER" == false ]] && echo -e "  Swap Size:   $SWAP_SIZE"
    [[ -n "${UFW_PORTS:-}" ]] && echo -e "  UFW Ports:   $UFW_PORTS"
    [[ "$AUTO_UPDATES" == "yes" ]] && echo -e "  Auto Updates: Enabled"
    [[ "$INSTALL_DOCKER" == "yes" ]] && echo -e "  Docker:      Installed"
    [[ "$INSTALL_TAILSCALE" == "yes" ]] && echo -e "  Tailscale:   Installed"
    [[ -n "${TAILSCALE_LOGIN_SERVER:-}" ]] && echo -e "  Tailscale Server: $TAILSCALE_LOGIN_SERVER"
    [[ -n "${SMTP_SERVER:-}" ]] && echo -e "  SMTP Server: $SMTP_SERVER"
    [[ -n "${NTFY_SERVER:-}" ]] && echo -e "  ntfy Server: $NTFY_SERVER"
    if [[ ${#PROMPTED_SETTINGS[@]} -gt 0 ]]; then
        echo -e "\n${CYAN}Prompted Settings:${NC} ${PROMPTED_SETTINGS[*]}"
    fi
    if [[ ${#SKIPPED_SETTINGS[@]} -gt 0 ]]; then
        echo -e "\n${YELLOW}Skipped Settings:${NC} ${SKIPPED_SETTINGS[*]}"
    fi
    echo -e "\n${YELLOW}Log File:${NC} $LOG_FILE"
    echo -e "${YELLOW}Backups:${NC} $BACKUP_DIR"
    echo -e "\n${YELLOW}Next Steps:${NC}"
    echo -e " 1. Verify SSH: ssh -p $SSH_PORT $USERNAME@$SERVER_IP"
    echo -e " 2. Check Firewall: sudo ufw status verbose"
    echo -e " 3. Check Services: systemctl status ssh fail2ban chrony docker tailscaled postfix"
    echo -e " 4. Reboot (recommended): sudo reboot"
    echo -e "\n${YELLOW}Note:${NC} If using a VPS (e.g., DigitalOcean, AWS), ensure the edge firewall allows port $SSH_PORT and other configured ports."
    log "Setup summary completed."
}

main() {
    print_header
    check_system
    check_dependencies
    collect_config
    install_packages
    setup_user
    configure_system
    configure_ssh
    configure_firewall
    configure_fail2ban
    configure_auto_updates
    configure_monitoring
    install_docker
    install_tailscale
    configure_swap
    configure_time
    cleanup
    print_summary
}

# Execute main function
main
```
