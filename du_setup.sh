#!/bin/bash

# Debian and Ubuntu Server Hardening Interactive Script
# Version: 0.78.3 | 2025-11-26
# Changelog:
# - v0.78.3: Update the summary to try to show the right environment detection based on finding personal VMs and cloud VPS.
#            Run update & upgrade in the final step to ensure system is fully updated after restart.
# - v0.78.2: In configure_system set choosen hostname from collect_config in the /etc/hosts
# - v0.78.1: Collect config failure fixed on IPv6 only VPS.
# - v0.78: Script tries to handles different environments: Direct Public IP, NAT/Router and Local VM only
#          The configure_ssh function provides context-aware instructions based on different environments.
#          In setup_user handle if group exists but user doesn't - attach user to existing group.
# - v0.77.2: Fixed an unbound variable for SSH when on a local virtual machine;
#            check_dependencies should come before check_system to keep minimal servers from failing.
# - v0.77.1: Auto SSH connection whitelist feat & whitelist deduplication.
# - v0.77: User-configurable ignoreip functionality for configure_fail2ban function.
#          Add a few more core packages in install_packages function.
# - v0.76: Improve the flexibility of the built-in Docker daemon.json file to prevent any potential Docker issues.
# - v0.75: Updated Docker daemon.json file to be more secure.
# - v0.74: Add optional dtop (https://github.com/amir20/dtop) after docker installation.
#.         Update .bashrc
# - v0.73: Revised/improved logic in .bashrc for memory and system updates.
# - v0.72: Added configure_custom_bashrc() function that creates and installs a feature-rich .bashrc file during user creation.
# - v0.71: Simplify test backup function to work reliably with Hetzner storagebox
# - v0.70.1: Fix SSH port validation and improve firewall handling during SSH port transitions.
# - v0.70: Option to remove cloud VPS provider packages (like cloud-init).
#          New operational modes: --cleanup-preview, --cleanup-only, --skip-cleanup.
#          Add help and usage instructions with --help flag.
#          Improve SSH port validation and rollback logic.
# - v0.69: Ensure .ssh directory ownership is set for new user.
# - v0.68: Enable UFW IPv6 support if available
# - v0.67: Do not log taiscale auth key in log file
# - v0.66: While configuring and in the summary, display both IPv6 and IPv4.
# - v0.65: If reconfigure locales - appy newly configured locale to the current environment.
# - v0.64: Tested at Debian 13 to confirm it works as expected
# - v0.63: Added ssh install in key packages
# - v0.62: Added fix for fail2ban by creating empty ufw log file
# - v0.61: Display Lynis suggestions in summary, hide tailscale auth key, cleanup temp files
# - v0.60: CI for shellcheck
# - v0.59: Add a new optional function that applies a set of recommended sysctl security settings to harden the kernel.
#          Script can now check for update and can run self-update.
# - v0.58: improved fail2ban to parse ufw logs
# - v0.57: Fix for silent failure at test_backup()
#          Option to choose which directories to back up.
# - v0.56: Make tailscale config optional
# - v0.55: Improving setup_user() - ssh-keygen replaced the option to skip ssh key
# - v0.54: Fix for rollback_ssh_changes() - more reliable on newer Ubuntu
#          Better error message if script is executed by non-root or without sudo
# - v0.53: Fix for test_backup() - was failing if run as non root sudo user
# - v0.52: Roll-back SSH config on failure to configure SSH port, confirmed SSH config support for Ubuntu 24.10
# - v0.51: corrected repo links
# - v0.50: versioning format change and repo name change
# - v4.3: Add SHA256 integrity verification
# - v4.2: Added Security Audit Tools (Integrating Lynis and Optionally Debsecan) & option to do Backup Testing
#         Fixed debsecan compatibility (Debian-only), added global BACKUP_LOG, added backup testing
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

set -euo pipefail

# --- Update Configuration ---
CURRENT_VERSION="0.78.3"
SCRIPT_URL="https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.sh"
CHECKSUM_URL="${SCRIPT_URL}.sha256"

# --- GLOBAL VARIABLES & CONFIGURATION ---

# --- Colors for output ---
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
    RED=$'\e[0;31m'
    GREEN=$'\e[0;32m'
    YELLOW=$'\e[1;33m'
    BLUE=$'\e[0;34m'
    PURPLE=$'\e[0;35m'
    CYAN=$'\e[0;36m'
    NC=$'\e[0m'
    BOLD=$'\e[1m'
fi


# Script variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/du_setup_$(date +%Y%m%d_%H%M%S).log"
BACKUP_LOG="/var/log/backup_rsync.log"
REPORT_FILE="/var/log/du_setup_report_$(date +%Y%m%d_%H%M%S).txt"
VERBOSE=true
BACKUP_DIR="/root/setup_harden_backup_$(date +%Y%m%d_%H%M%S)"
ORIGINAL_ARGS="$*"

CLEANUP_PREVIEW=false # If true, show what would be cleaned up without making changes
CLEANUP_ONLY=false # If true, only perform cleanup tasks
SKIP_CLEANUP=false # If true, skip cleanup tasks

DETECTED_VIRT_TYPE=""
DETECTED_MANUFACTURER=""
DETECTED_PRODUCT=""
IS_CONTAINER=false
ENVIRONMENT_TYPE="unknown"
DETECTED_PROVIDER_NAME=""

SERVER_IP_V4="Unknown"
SERVER_IP_V6="Not available"
LOCAL_IP_V4=""

SSHD_BACKUP_FILE=""
LOCAL_KEY_ADDED=false
SSH_SERVICE=""
ID="" # This will be populated from /etc/os-release
FAILED_SERVICES=()
PREVIOUS_SSH_PORT=""

# --- --help ---
show_usage() {
    printf "\n"
    printf "%s%s%s\n" "$CYAN" "Debian/Ubuntu Server Setup & Hardening Script" "$NC"

    printf "\n%sUsage:%s\n" "$BOLD" "$NC"
    printf "  sudo -E %s [OPTIONS]\n" "$(basename "$0")"

    printf "\n%sDescription:%s\n" "$BOLD" "$NC"
    printf "  This script provisions a fresh Debian or Ubuntu server with secure base configurations.\n"
    printf "  It handles updates, firewall, SSH hardening, user creation, and optional tools.\n"

    printf "\n%sOperational Modes:%s\n" "$BOLD" "$NC"
    printf "  %-22s %s\n" "--cleanup-preview" "Show which provider packages/users would be cleaned without making changes."
    printf "  %-22s %s\n" "--cleanup-only" "Run only the provider cleanup function (for existing servers)."

    printf "\n%sModifiers:%s\n" "$BOLD" "$NC"
    printf "  %-22s %s\n" "--skip-cleanup" "Skip provider cleanup entirely during a full setup run."
    printf "  %-22s %s\n" "--quiet" "Suppress verbose output (intended for automation)."
    printf "  %-22s %s\n" "-h, --help" "Display this help message and exit."

    printf "\n%sUsage Examples:%s\n" "$BOLD" "$NC"
    printf "  # Run the full interactive setup\n"
    printf "  %ssudo -E ./%s%s\n\n" "$YELLOW" "$(basename "$0")" "$NC"
    printf "  # Preview provider cleanup actions without applying them\n"
    printf "  %ssudo -E ./%s --cleanup-preview%s\n\n" "$YELLOW" "$(basename "$0")" "$NC"
    printf "  # Run a full setup but skip the provider cleanup step\n"
    printf "  %ssudo -E ./%s --skip-cleanup%s\n\n" "$YELLOW" "$(basename "$0")" "$NC"
    printf "  # Run in quiet mode for automation\n"
    printf "  %ssudo -E ./%s --quiet%s\n" "$YELLOW" "$(basename "$0")" "$NC"

    printf "\n%sImportant Notes:%s\n" "$BOLD" "$NC"
    printf "  - The -E flag preserves your environment variables (recommended)\n"
    printf "  - Logs are saved to %s/var/log/du_setup_*.log%s\n" "$BOLD" "$NC"
    printf "  - Backups of modified configs are in %s/root/setup_harden_backup_*%s\n" "$BOLD" "$NC"
    printf "  - For full documentation, see the project repository:\n"
    printf "    %s%s%s\n" "$CYAN" "https://github.com/buildplan/du-setup" "$NC"

    printf "\n"
    exit 0
}

# --- PARSE ARGUMENTS ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --quiet) VERBOSE=false; shift ;;
        --cleanup-preview) CLEANUP_PREVIEW=true; shift ;;
        --cleanup-only) CLEANUP_ONLY=true; shift ;;
        --skip-cleanup) SKIP_CLEANUP=true; shift ;;
        -h|--help) show_usage ;;
        *) shift ;;
    esac
done

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
    printf "\n"
    printf "%s✗ You are running as user '%s'. This script must be run as root.%s\n" "$RED" "$(whoami)" "$NC"
    printf "\n"
    printf "This script makes system-level changes including:\n"
    printf "  - Package installation/removal\n"
    printf "  - Firewall configuration\n"
    printf "  - SSH hardening\n"
    printf "  - User account management\n"
    printf "\n"
    printf "Choose one of the following methods to run this script:\n"
    printf "\n"
    printf "%s%sRun with sudo (-E preserves environment):%s\n" "$BOLD" "$GREEN" "$NC"
    if [[ -n "$ORIGINAL_ARGS" ]]; then
        printf "  %ssudo -E %s %s%s\n" "$CYAN" "$0" "$ORIGINAL_ARGS" "$NC"
    else
        printf "  %ssudo -E %s%s\n" "$CYAN" "$0" "$NC"
    fi
    printf "\n"
    printf "%s%sAlternative methods:%s\n" "$BOLD" "$YELLOW" "$NC"
    printf "  %ssudo su %s    # Switch to root\n" "$CYAN" "$NC"
    if [[ -n "$ORIGINAL_ARGS" ]]; then
        printf "  And run: %s%s %s%s\n" "$CYAN" "$0" "$ORIGINAL_ARGS" "$NC"
    else
        printf "  And run: %s%s%s\n" "$CYAN" "$0" "$NC"
    fi
    printf "\n"
    exit 1
fi

# --- LOGGING & PRINT FUNCTIONS ---

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

print_header() {
    [[ $VERBOSE == false ]] && return
    printf '\n'
    printf '%s\n' "${CYAN}╔═════════════════════════════════════════════════════════════════╗${NC}"
    printf '%s\n' "${CYAN}║                                                                 ║${NC}"
    printf '%s\n' "${CYAN}║       DEBIAN/UBUNTU SERVER SETUP AND HARDENING SCRIPT           ║${NC}"
    printf '%s\n' "${CYAN}║                      v0.78.3 | 2025-11-25                       ║${NC}"
    printf '%s\n' "${CYAN}║                                                                 ║${NC}"
    printf '%s\n' "${CYAN}╚═════════════════════════════════════════════════════════════════╝${NC}"
    printf '\n'
}

print_section() {
    [[ $VERBOSE == false ]] && return
    printf '\n%s\n' "${BLUE}▓▓▓ $1 ▓▓▓${NC}" | tee -a "$LOG_FILE"
    printf '%s\n' "${BLUE}$(printf '═%.0s' {1..65})${NC}"
}

print_success() {
    [[ $VERBOSE == false ]] && return
    printf '%s\n' "${GREEN}✓ $1${NC}" | tee -a "$LOG_FILE"
}

print_error() {
    printf '%s\n' "${RED}✗ $1${NC}" | tee -a "$LOG_FILE"
}

print_warning() {
    [[ $VERBOSE == false ]] && return
    printf '%s\n' "${YELLOW}⚠ $1${NC}" | tee -a "$LOG_FILE"
}

print_info() {
    [[ $VERBOSE == false ]] && return
    printf '%s\n' "${PURPLE}ℹ $1${NC}" | tee -a "$LOG_FILE"
}

print_separator() {
    local header_text="$1"
    local color="${2:-$YELLOW}"
    local separator_char="${3:-=}"

    printf '%s\n' "${color}${header_text}${NC}"
    printf "${separator_char}%.0s" $(seq 1 ${#header_text})
    printf '\n'
}

# --- CLEANUP HELPER FUNCTIONS ---

execute_check() {
    "$@"
}

execute_command() {
    local cmd_string="$*"

    if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
        printf '%s Would execute: %s\n' "${CYAN}[PREVIEW]${NC}" "${BOLD}$cmd_string${NC}" | tee -a "$LOG_FILE"
        return 0
    else
        "$@"
        return $?
    fi
}

# --- ENVIRONMENT DETECTION (Cloud VPS or Trusted VM) ---

detect_environment() {
    local VIRT_TYPE=""
    local MANUFACTURER=""
    local PRODUCT=""
    local IS_CLOUD_VPS=false

    # systemd-detect-virt
    if command -v systemd-detect-virt &>/dev/null; then
        VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    fi

    # dmidecode for hardware info
    if command -v dmidecode &>/dev/null && [[ $(id -u) -eq 0 ]]; then
        MANUFACTURER=$(dmidecode -s system-manufacturer 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "unknown")
        PRODUCT=$(dmidecode -s system-product-name 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "unknown")
    fi

    # Check /sys/class/dmi/id/ (fallback, doesn't require dmidecode)
    if [[ -z "$MANUFACTURER" || "$MANUFACTURER" == "unknown" ]]; then
        if [[ -r /sys/class/dmi/id/sys_vendor ]]; then
            MANUFACTURER=$(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/sys_vendor 2>/dev/null || echo "unknown")
        fi
    fi

    if [[ -z "$PRODUCT" || "$PRODUCT" == "unknown" ]]; then
        if [[ -r /sys/class/dmi/id/product_name ]]; then
            PRODUCT=$(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/product_name 2>/dev/null || echo "unknown")
        fi
    fi

    if command -v dmidecode &>/dev/null && [[ $(id -u) -eq 0 ]]; then
        DETECTED_BIOS_VENDOR=$(dmidecode -s bios-vendor 2>/dev/null | tr '[:upper:]' '[:lower:]' || echo "unknown")
    elif [[ -r /sys/class/dmi/id/bios_vendor ]]; then
        DETECTED_BIOS_VENDOR=$(tr '[:upper:]' '[:lower:]' < /sys/class/dmi/id/bios_vendor 2>/dev/null || echo "unknown")
    fi

    # Cloud provider detection patterns
    local CLOUD_PATTERNS=(
        # VPS/Cloud Providers
        "digitalocean"
        "linode"
        "vultr"
        "hetzner"
        "ovh"
        "scaleway"
        "contabo"
        "netcup"
        "ionos"
        "hostinger"
        "racknerd"
        "upcloud"
        "dreamhost"
        "kimsufi"
        "online.net"
        "equinix metal"
        "lightsail"
        "scaleway"
        # Major Cloud Platforms
        "amazon"
        "amazon ec2"
        "aws"
        "google"
        "gce"
        "google compute engine"
        "microsoft"
        "azure"
        "oracle cloud"
        "alibaba"
        "tencent"
        "rackspace"
        # Virtualization indicating cloud VPS
        "droplet"
        "linodekvm"
        "kvm"
        "openstack"
    )

    # Check if manufacturer or product matches cloud patterns
    for pattern in "${CLOUD_PATTERNS[@]}"; do
        if [[ "$MANUFACTURER" == *"$pattern"* ]] || [[ "$PRODUCT" == *"$pattern"* ]]; then
            IS_CLOUD_VPS=true
            break
        fi
    done

    # Additional checks based on virtualization type
    case "$VIRT_TYPE" in
        kvm|qemu)
            if [[ -z "$IS_CLOUD_VPS" ]] || [[ "$IS_CLOUD_VPS" == "false" ]]; then
                if [[ -d /etc/cloud/cloud.cfg.d ]] && grep -qE "(Hetzner|DigitalOcean|Vultr|OVH)" /etc/cloud/cloud.cfg.d/* 2>/dev/null; then
                    IS_CLOUD_VPS=true
                fi
            fi
            ;;
        vmware)
            IS_CLOUD_VPS=false
            ;;
        oracle|virtualbox)
            IS_CLOUD_VPS=false
            ;;
        xen)
            IS_CLOUD_VPS=true
            ;;
        hyperv|microsoft)
            if [[ "$MANUFACTURER" == *"microsoft"* ]] && [[ "$PRODUCT" == *"virtual machine"* ]]; then
                IS_CLOUD_VPS=false
            fi
            ;;
        none)
            IS_CLOUD_VPS=false
            ;;
    esac

    # Determine environment type based on detection
    if [[ "$VIRT_TYPE" == "none" ]]; then
        ENVIRONMENT_TYPE="bare-metal"
    elif [[ "$IS_CLOUD_VPS" == "true" ]]; then
        ENVIRONMENT_TYPE="commercial-cloud"
    elif [[ "$VIRT_TYPE" =~ ^(kvm|qemu)$ ]]; then
        if [[ "$MANUFACTURER" == "qemu" && "$PRODUCT" =~ ^(standard pc|pc-|pc ) ]]; then
            ENVIRONMENT_TYPE="uncertain-kvm"
        else
            ENVIRONMENT_TYPE="commercial-cloud"
        fi
    elif [[ "$VIRT_TYPE" =~ ^(vmware|virtualbox|oracle)$ ]]; then
        ENVIRONMENT_TYPE="personal-vm"
    elif [[ "$VIRT_TYPE" == "xen" ]]; then
        ENVIRONMENT_TYPE="uncertain-xen"
    else
        ENVIRONMENT_TYPE="unknown"
    fi

    DETECTED_PROVIDER_NAME=""
    case "$ENVIRONMENT_TYPE" in
        commercial-cloud)
            if [[ "$MANUFACTURER" =~ digitalocean ]]; then
                DETECTED_PROVIDER_NAME="DigitalOcean"
            elif [[ "$MANUFACTURER" =~ hetzner ]]; then
                DETECTED_PROVIDER_NAME="Hetzner Cloud"
            elif [[ "$MANUFACTURER" =~ vultr ]]; then
                DETECTED_PROVIDER_NAME="Vultr"
            elif [[ "$MANUFACTURER" =~ linode || "$PRODUCT" =~ akamai ]]; then
                DETECTED_PROVIDER_NAME="Linode/Akamai"
            elif [[ "$MANUFACTURER" =~ ovh ]]; then
                DETECTED_PROVIDER_NAME="OVH"
            elif [[ "$MANUFACTURER" =~ amazon || "$PRODUCT" =~ "ec2" ]]; then
                DETECTED_PROVIDER_NAME="Amazon Web Services (AWS)"
            elif [[ "$MANUFACTURER" =~ google ]]; then
                DETECTED_PROVIDER_NAME="Google Cloud Platform"
            elif [[ "$MANUFACTURER" =~ microsoft ]]; then
                DETECTED_PROVIDER_NAME="Microsoft Azure"
            else
                DETECTED_PROVIDER_NAME="Cloud VPS Provider"
            fi
            ;;
        personal-vm)
            if [[ "$VIRT_TYPE" == "virtualbox" || "$MANUFACTURER" =~ innotek ]]; then
                DETECTED_PROVIDER_NAME="VirtualBox"
            elif [[ "$VIRT_TYPE" == "vmware" ]]; then
                DETECTED_PROVIDER_NAME="VMware"
            else
                DETECTED_PROVIDER_NAME="Personal VM"
            fi
            ;;
        uncertain-kvm)
            DETECTED_PROVIDER_NAME="KVM/QEMU Hypervisor"
            ;;
    esac

    # Export results as global variables
    export ENVIRONMENT_TYPE
    DETECTED_VIRT_TYPE="$VIRT_TYPE"
    DETECTED_MANUFACTURER="$MANUFACTURER"
    DETECTED_PRODUCT="$PRODUCT"
    DETECTED_BIOS_VENDOR="${DETECTED_BIOS_VENDOR:-unknown}"

    log "Environment detection: VIRT=$VIRT_TYPE, MANUFACTURER=$MANUFACTURER, PRODUCT=$PRODUCT, IS_CLOUD=$IS_CLOUD_VPS, TYPE=$ENVIRONMENT_TYPE"
}

cleanup_provider_packages() {
    print_section "Provider Package Cleanup (Optional)"

    # --quiet mode check
    if [[ "$VERBOSE" == "false" ]]; then
        print_warning "Provider cleanup cannot be run in --quiet mode due to its interactive nature. Skipping."
        log "Provider cleanup skipped due to --quiet mode."
        return 0
    fi

    # Validate required variables
    if [[ -z "${LOG_FILE:-}" ]]; then
        LOG_FILE="/var/log/du_setup_$(date +%Y%m%d_%H%M%S).log"
        echo "Warning: LOG_FILE not set, using: $LOG_FILE"
    fi

    if [[ -z "${USERNAME:-}" ]]; then
        USERNAME="${SUDO_USER:-root}"
        log "USERNAME defaulted to '$USERNAME' for cleanup-only mode"
    fi

    if [[ -z "${BACKUP_DIR:-}" ]]; then
        BACKUP_DIR="/root/setup_harden_backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        log "Created backup directory: $BACKUP_DIR"
    fi

    # Ensure cleanup mode variables are set
    CLEANUP_PREVIEW="${CLEANUP_PREVIEW:-false}"
    CLEANUP_ONLY="${CLEANUP_ONLY:-false}"
    VERBOSE="${VERBOSE:-true}"

    # Detect environment first
    detect_environment

    # Display environment information
    printf '%s\n' "${CYAN}=== Environment Detection ===${NC}"
    printf 'Virtualization Type: %s\n' "${DETECTED_VIRT_TYPE:-unknown}"
    printf 'System Manufacturer: %s\n' "${DETECTED_MANUFACTURER:-unknown}"
    printf 'Product Name: %s\n' "${DETECTED_PRODUCT:-unknown}"
    printf 'Environment Type: %s\n' "${ENVIRONMENT_TYPE:-unknown}"
    if [[ -n "${DETECTED_BIOS_VENDOR}" && "${DETECTED_BIOS_VENDOR}" != "unknown" ]]; then
        printf 'BIOS Vendor: %s\n' "${DETECTED_BIOS_VENDOR}"
    fi
    if [[ -n "${DETECTED_PROVIDER_NAME}" ]]; then
        printf 'Detected Provider: %s\n' "${DETECTED_PROVIDER_NAME}"
    fi
    printf '\n'

    # Determine recommendation based on three-way detection
    local CLEANUP_RECOMMENDED=false
    local DEFAULT_ANSWER="n"
    local RECOMMENDATION_TEXT=""
    local ENVIRONMENT_CONFIDENCE="${ENVIRONMENT_CONFIDENCE:-low}"

    case "$ENVIRONMENT_TYPE" in
        commercial-cloud)
            CLEANUP_RECOMMENDED=true
            DEFAULT_ANSWER="y"
            printf '%s\n' "${YELLOW}☁  Commercial Cloud VPS Detected${NC}"
            if [[ -n "${DETECTED_PROVIDER_NAME}" ]]; then
                printf 'Provider: %s\n' "${CYAN}${DETECTED_PROVIDER_NAME}${NC}"
            fi
            printf 'This is a commercial VPS from an external provider.\n'
            RECOMMENDATION_TEXT="Provider cleanup is ${BOLD}RECOMMENDED${NC} for security."
            printf '%s\n' "$RECOMMENDATION_TEXT"
            printf 'Providers may install monitoring agents, pre-configured users, and management tools.\n'
            ;;

        uncertain-kvm)
            CLEANUP_RECOMMENDED=false
            DEFAULT_ANSWER="n"
            printf '%s\n' "${YELLOW}⚠  KVM/QEMU Virtualization Detected (Uncertain)${NC}"
            printf 'This environment could be:\n'
            printf '  %s A commercial cloud provider VPS (Hetzner, Vultr, OVH, smaller providers)\n' "${CYAN}•${NC}"
            printf '  %s A personal VM on Proxmox, KVM, or QEMU\n' "${CYAN}•${NC}"
            printf '  %s A VPS from a regional/unlisted provider\n' "${CYAN}•${NC}"
            printf '\n'
            RECOMMENDATION_TEXT="Cleanup is ${BOLD}OPTIONAL${NC} - review packages carefully before proceeding."
            printf '%s\n' "$RECOMMENDATION_TEXT"
            printf 'If this is a commercial VPS, cleanup is recommended.\n'
            printf 'If you control the hypervisor (Proxmox/KVM), cleanup is optional.\n'
            ;;

        personal-vm)
            CLEANUP_RECOMMENDED=false
            DEFAULT_ANSWER="n"
            printf '%s\n' "${CYAN}ℹ  Personal/Private Virtualization Detected${NC}"
            if [[ -n "${DETECTED_PROVIDER_NAME}" ]]; then
                printf 'Platform: %s\n' "${CYAN}${DETECTED_PROVIDER_NAME}${NC}"
            fi
            printf 'This appears to be a personal VM (VirtualBox, VMware Workstation, etc.)\n'
            RECOMMENDATION_TEXT="Provider cleanup is ${BOLD}NOT RECOMMENDED${NC} for trusted environments."
            printf '%s\n' "$RECOMMENDATION_TEXT"
            printf 'If you control the hypervisor/host, you likely don'\''t need cleanup.\n'
            ;;

        bare-metal)
            printf '%s\n' "${GREEN}✓ Bare Metal Server Detected${NC}"
            printf 'This appears to be a physical (bare metal) server.\n'
            RECOMMENDATION_TEXT="Provider cleanup is ${BOLD}NOT NEEDED${NC} for bare metal."
            printf '%s\n' "$RECOMMENDATION_TEXT"
            printf 'No virtualization layer detected - skipping cleanup.\n'
            log "Provider package cleanup skipped: bare metal server detected."
            return 0
            ;;

        uncertain-xen|unknown|*)
            CLEANUP_RECOMMENDED=false
            DEFAULT_ANSWER="n"
            printf '%s\n' "${YELLOW}⚠  Virtualization Environment: Uncertain${NC}"
            printf 'Could not definitively identify the hosting provider or environment.\n'
            RECOMMENDATION_TEXT="Cleanup is ${BOLD}OPTIONAL${NC} - proceed with caution."
            printf '%s\n' "$RECOMMENDATION_TEXT"
            printf 'Review packages carefully before removing anything.\n'
            ;;
    esac
    printf '\n'

    # Decision point based on environment and flags
    if [[ "$CLEANUP_PREVIEW" == "false" ]] && [[ "$CLEANUP_ONLY" == "false" ]]; then
        local PROMPT_TEXT=""

        if [[ "$ENVIRONMENT_TYPE" == "commercial-cloud" ]]; then
            PROMPT_TEXT="Run provider package cleanup? (Recommended for cloud VPS)"
        elif [[ "$ENVIRONMENT_TYPE" == "uncertain-kvm" ]]; then
            PROMPT_TEXT="Run provider package cleanup? (Verify your environment first)"
        else
            PROMPT_TEXT="Run provider package cleanup? (Not recommended for trusted environments)"
        fi

        if ! confirm "$PROMPT_TEXT" "$DEFAULT_ANSWER"; then
            print_info "Skipping provider package cleanup."
            log "Provider package cleanup skipped by user (environment: $ENVIRONMENT_TYPE)."
            return 0
        fi

        # Extra warning for non-cloud environments
        if [[ "$CLEANUP_RECOMMENDED" == "false" ]] && [[ "$ENVIRONMENT_TYPE" != "uncertain-kvm" ]]; then
            echo
            print_warning "⚠  You chose to run cleanup on a trusted/personal environment."
            print_warning "This may remove useful tools or break functionality."
            echo
            if ! confirm "Are you sure you want to continue?" "n"; then
                print_info "Cleanup cancelled."
                log "User cancelled cleanup after warning."
                return 0
            fi
        fi
    fi

    if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
        print_warning "=== PREVIEW MODE ENABLED ==="
        print_info "No changes will be made. This is a simulation only."
        printf '\n'
    fi

    if [[ "$CLEANUP_PREVIEW" == "false" ]]; then
        print_warning "RECOMMENDED: Create a snapshot/backup via provider dashboard before cleanup."
        if ! confirm "Have you created a backup snapshot?" "n"; then
            print_info "Please create a backup first. Exiting cleanup."
            log "User declined to proceed without backup snapshot."
            return 0
        fi
    fi

    print_warning "This will identify packages and configurations installed by your VPS provider."
    if [[ "$CLEANUP_PREVIEW" == "false" ]]; then
        print_warning "Removing critical packages can break system functionality."
    fi

    local PROVIDER_PACKAGES=()
    local PROVIDER_SERVICES=()
    local PROVIDER_USERS=()
    local ROOT_SSH_KEYS=()

    # List of common provider and virtualization packages
    local COMMON_PROVIDER_PKGS=(
        "qemu-guest-agent"
        "virtio-utils"
        "virt-what"
        "cloud-init"
        "cloud-guest-utils"
        "cloud-initramfs-growroot"
        "cloud-utils"
        "open-vm-tools"
        "xe-guest-utilities"
        "xen-tools"
        "hyperv-daemons"
        "oracle-cloud-agent"
        "aws-systems-manager-agent"
        "amazon-ssm-agent"
        "google-compute-engine"
        "google-osconfig-agent"
        "walinuxagent"
        "hetzner-needrestart"
        "digitalocean-agent"
        "do-agent"
        "linode-agent"
        "vultr-monitoring"
        "scaleway-ecosystem"
        "ovh-rtm"
        "openstack-guest-utils"
        "openstack-nova-agent"
    )

    # Common provider-created default users
    local COMMON_PROVIDER_USERS=(
        "ubuntu"
        "debian"
        "admin"
        "cloud-user"
        "ec2-user"
        "linuxuser"
    )

    print_info "Scanning for provider-installed packages..."

    for pkg in "${COMMON_PROVIDER_PKGS[@]}"; do
        if execute_check dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            PROVIDER_PACKAGES+=("$pkg")
        fi
    done

    # Detect associated services
    print_info "Scanning for provider-related services..."
    for pkg in "${PROVIDER_PACKAGES[@]}"; do
        local service_name="${pkg}.service"
        if execute_check systemctl list-unit-files "$service_name" 2>/dev/null | grep -q "$service_name"; then
            if execute_check systemctl is-enabled "$service_name" 2>/dev/null | grep -qE 'enabled|static'; then
                PROVIDER_SERVICES+=("$service_name")
            fi
        fi
    done

    # Check for provider-created users (excluding current admin user and script-managed user)
    print_info "Scanning for default provisioning users..."
    local MANAGED_USER=""
    if [[ -f /root/.du_setup_managed_user ]]; then
        MANAGED_USER=$(tr -d '[:space:]' < /root/.du_setup_managed_user 2>/dev/null)
        log "Script-managed user detected: $MANAGED_USER (will be excluded from cleanup)"
    fi

    for user in "${COMMON_PROVIDER_USERS[@]}"; do
        if execute_check id "$user" &>/dev/null && \
           [[ "$user" != "$USERNAME" ]] && \
           [[ "$user" != "$MANAGED_USER" ]]; then
            PROVIDER_USERS+=("$user")
        fi
    done

    # Audit root SSH keys
    print_info "Auditing /root/.ssh/authorized_keys for unexpected keys..."
    if [[ -f /root/.ssh/authorized_keys ]]; then
        local key_count
        key_count=$( (grep -cE '^ssh-(rsa|ed25519|ecdsa)' /root/.ssh/authorized_keys 2>/dev/null || echo 0) | tr -dc '0-9' )
        if [ "$key_count" -gt 0 ]; then
            print_warning "Found $key_count SSH key(s) in /root/.ssh/authorized_keys"
            ROOT_SSH_KEYS=("present")
        fi
    fi

    # Summary of findings
    echo
    print_info "=== Scan Results ==="
    echo "Packages found: ${#PROVIDER_PACKAGES[@]}"
    echo "Services found: ${#PROVIDER_SERVICES[@]}"
    echo "Default users found: ${#PROVIDER_USERS[@]}"
    echo "Root SSH keys: ${#ROOT_SSH_KEYS[@]}"
    echo

    if [[ ${#PROVIDER_PACKAGES[@]} -eq 0 && ${#PROVIDER_USERS[@]} -eq 0 && ${#ROOT_SSH_KEYS[@]} -eq 0 ]]; then
        print_success "No common provider packages or users detected."
        return 0
    fi

    if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
        print_info "=== PREVIEW: Showing what would be done ==="
        printf '\n'
    fi

    # Audit and optionally clean up root SSH keys
    if [[ ${#ROOT_SSH_KEYS[@]} -gt 0 ]]; then
        print_section "Root SSH Key Audit"
        print_warning "SSH keys in /root/.ssh/authorized_keys can allow provider or previous admins access."
        printf '\n'
        printf '%s\n' "${YELLOW}Current keys in /root/.ssh/authorized_keys:${NC}"
        awk '{print NR". "$0}' /root/.ssh/authorized_keys 2>/dev/null | head -20
        printf '\n'

        if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
            print_info "[PREVIEW] Would offer to review and edit /root/.ssh/authorized_keys"
            print_info "[PREVIEW] Would backup to $BACKUP_DIR/root_authorized_keys.backup.<timestamp>"

        else
            if confirm "Review and potentially remove root SSH keys?" "n"; then
                local backup_file
                backup_file="$BACKUP_DIR/root_authorized_keys.backup.$(date +%Y%m%d_%H%M%S)"
                cp /root/.ssh/authorized_keys "$backup_file"
                log "Backed up /root/.ssh/authorized_keys to $backup_file"

                print_warning "IMPORTANT: Do NOT delete ALL keys or you'll be locked out!"
                print_info "Opening /root/.ssh/authorized_keys for manual review..."
                read -rp "Press Enter to continue..."

                "${EDITOR:-nano}" /root/.ssh/authorized_keys

                if [[ ! -s /root/.ssh/authorized_keys ]]; then
                    print_error "WARNING: authorized_keys is empty! This could lock you out."
                    if [[ -f "$backup_file" ]] && confirm "Restore from backup?" "y"; then
                        cp "$backup_file" /root/.ssh/authorized_keys
                        print_info "Restored backup."
                        log "Restored /root/.ssh/authorized_keys from backup due to empty file."
                    fi
                fi

                local new_key_count
                new_key_count=$(grep -cE '^ssh-(rsa|ed25519|ecdsa)' /root/.ssh/authorized_keys 2>/dev/null || echo 0)
                print_info "Keys remaining: $new_key_count"
                log "Root SSH keys audit completed. Keys remaining: $new_key_count"
            else
                print_info "Skipping root SSH key audit."
            fi
        fi
        printf '\n'
    fi

    # Special handling for cloud-init due to its complexity
    if [[ " ${PROVIDER_PACKAGES[*]} " =~ " cloud-init " ]]; then
        print_section "Cloud-Init Management"
        printf '%s\n' "${CYAN}ℹ cloud-init${NC}"
        printf '   Purpose: Initial VM provisioning (SSH keys, hostname, network)\n'
        printf '   %s\n' "${YELLOW}Official recommendation: DISABLE rather than remove${NC}"
        printf '   Benefits of disabling vs removing:\n'
        printf '     - Can be re-enabled if needed for reprovisioning\n'
        printf '     - Safer than package removal\n'
        printf '     - No dependency issues\n'
        printf '\n'

        if [[ "$CLEANUP_PREVIEW" == "true" ]] || confirm "Disable cloud-init (recommended over removal)?" "y"; then
            print_info "Disabling cloud-init..."

            if ! [[ -f /etc/cloud/cloud-init.disabled ]]; then
                if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
                    print_info "[PREVIEW] Would create /etc/cloud/cloud-init.disabled"
                else
                    execute_command touch /etc/cloud/cloud-init.disabled
                    print_success "Created /etc/cloud/cloud-init.disabled"
                    log "Created /etc/cloud/cloud-init.disabled"
                fi
            else
                print_info "/etc/cloud/cloud-init.disabled already exists."
            fi

            local cloud_services=(
                "cloud-init.service"
                "cloud-init-local.service"
                "cloud-config.service"
                "cloud-final.service"
            )

            for service in "${cloud_services[@]}"; do
                if execute_check systemctl is-enabled "$service" &>/dev/null; then
                    if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
                        print_info "[PREVIEW] Would stop and disable $service"
                    else
                        execute_command systemctl stop "$service" 2>/dev/null || true
                        execute_command systemctl disable "$service" 2>/dev/null || true
                        print_success "Disabled $service"
                        log "Disabled $service"
                    fi
                fi
            done

            if [[ "$CLEANUP_PREVIEW" == "false" ]]; then
                print_success "cloud-init disabled successfully."
                print_info "To re-enable: sudo rm /etc/cloud/cloud-init.disabled && systemctl enable cloud-init.service"
            fi
            local filtered_packages=()
            for pkg in "${PROVIDER_PACKAGES[@]}"; do
                if [[ "$pkg" != "cloud-init" && -n "$pkg" ]]; then
                    filtered_packages+=("$pkg")
                fi
            done
            PROVIDER_PACKAGES=("${filtered_packages[@]}")
        else
            print_info "Keeping cloud-init enabled."
        fi
        printf '\n'
    fi

    # Remove identified provider packages
    if [[ ${#PROVIDER_PACKAGES[@]} -gt 0 ]]; then
        print_section "Provider Package Removal"

        for pkg in "${PROVIDER_PACKAGES[@]}"; do
            [[ -z "$pkg" ]] && continue

            case "$pkg" in
                qemu-guest-agent)
                    printf '%s\n' "${RED}⚠ $pkg${NC}"
                    printf '   Purpose: VM-host communication for snapshots and graceful shutdowns\n'
                    printf '   %s\n' "${RED}CRITICAL RISKS if removed:${NC}"
                    printf '     - Snapshot backups will FAIL or be inconsistent\n'
                    printf '     - Console access may break\n'
                    printf '     - Graceful shutdowns replaced with forced stops\n'
                    printf '     - Provider backup systems will malfunction\n'
                    printf '   %s\n' "${RED}STRONGLY RECOMMENDED to keep${NC}"
                    ;;
                *-agent|*-monitoring)
                    printf '%s\n' "${YELLOW}⚠ $pkg${NC}"
                    printf '   Purpose: Provider monitoring/management\n'
                    printf '   Risks if removed:\n'
                    printf '     - Provider dashboard metrics will disappear\n'
                    printf '     - May affect support troubleshooting\n'
                    printf '   %s\n' "${YELLOW}Remove only if you don't need provider monitoring${NC}"
                    ;;
                *)
                    printf '%s\n' "${CYAN}ℹ $pkg${NC}"
                    printf '   Purpose: Provider-specific tooling\n'
                    printf '  %s\n' "${YELLOW}Review before removing${NC}"
                    ;;
            esac
            printf '\n'

            if [[ "$CLEANUP_PREVIEW" == "true" ]] || confirm "Remove $pkg?" "n"; then
                if [[ "$pkg" == "qemu-guest-agent" && "$CLEANUP_PREVIEW" == "false" ]]; then
                    print_error "FINAL WARNING: Removing qemu-guest-agent will break backups and console access!"
                    if ! confirm "Are you ABSOLUTELY SURE?" "n"; then
                        print_info "Keeping $pkg (wise choice)."
                        continue
                    fi
                fi

                local service_name="${pkg}.service"
                if execute_check systemctl is-active "$service_name" &>/dev/null; then
                    if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
                        print_info "[PREVIEW] Would stop and disable $service_name"
                    else
                        print_info "Stopping $service_name..."
                        execute_command systemctl stop "$service_name" 2>/dev/null || true
                        execute_command systemctl disable "$service_name" 2>/dev/null || true
                        log "Stopped and disabled $service_name"
                    fi
                fi

                if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
                    print_info "[PREVIEW] Would remove package: $pkg (with --purge flag)"
                    log "[PREVIEW] Would remove provider package: $pkg"
                else
                    print_info "Removing $pkg..."
                    if execute_command apt-get remove --purge -y "$pkg" 2>&1 | tee -a "$LOG_FILE"; then
                        print_success "$pkg removed."
                        log "Removed provider package: $pkg"
                    else
                        print_error "Failed to remove $pkg. Check logs."
                        log "Failed to remove: $pkg"
                    fi
                fi
            else
                print_info "Keeping $pkg."
            fi
        done
        printf '\n'
    fi

    # Check and remove default users
    if [[ ${#PROVIDER_USERS[@]} -gt 0 ]]; then
        print_section "Provider User Cleanup"
        print_warning "Default users created during provisioning can be security risks."
        printf '\n'

        for user in "${PROVIDER_USERS[@]}"; do
            printf '%s\n' "${YELLOW}Found user: $user${NC}"

            local proc_count
            proc_count=$( (ps -u "$user" --no-headers 2>/dev/null || true) | wc -l)
            if [[ $proc_count -gt 0 ]]; then
                print_warning "User $user has $proc_count running process(es)."
            fi

            if [[ -d "/home/$user" ]] && [[ -f "/home/$user/.ssh/authorized_keys" ]]; then
                local key_count=0
                key_count=$( (grep -cE '^ssh-(rsa|ed25519|ecdsa)' "/home/$user/.ssh/authorized_keys" 2>/dev/null || echo 0) | tr -dc '0-9' )
                if [ "$key_count" -gt 0 ]; then
                    print_warning "User $user has $key_count SSH key(s) configured."
                fi
            fi

            if id -nG "$user" 2>/dev/null | grep -qwE '(sudo|admin)'; then
                print_warning "User $user has sudo/admin privileges!"
            fi

            printf '\n'

            if [[ "$CLEANUP_PREVIEW" == "true" ]] || confirm "Remove user $user and their home directory?" "n"; then
                if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
                    print_info "[PREVIEW] Would terminate processes owned by $user"
                    print_info "[PREVIEW] Would remove user $user with home directory"
                    if [[ -f "/etc/sudoers.d/$user" ]]; then
                        print_info "[PREVIEW] Would remove /etc/sudoers.d/$user"
                    fi
                    log "[PREVIEW] Would remove provider user: $user"
                else
                    if [[ $proc_count -gt 1 ]]; then
                        print_info "Terminating processes owned by $user..."

                        execute_command pkill -u "$user" 2>/dev/null || true
                        sleep 2

                        if ps -u "$user" &>/dev/null; then
                            print_warning "Some processes didn't terminate gracefully. Force killing..."
                            execute_command pkill -9 -u "$user" 2>/dev/null || true
                            sleep 1
                        fi

                        if ps -u "$user" &>/dev/null; then
                            print_error "Unable to kill all processes for $user. Manual intervention needed."
                            log "Failed to terminate all processes for user: $user"
                            continue
                        fi
                    fi

                    print_info "Removing user $user..."

                    local user_removed=false
                    if command -v deluser &>/dev/null; then
                        if execute_command deluser --remove-home "$user" 2>&1 | tee -a "$LOG_FILE"; then
                            user_removed=true
                        fi
                    else
                        if execute_command userdel -r "$user" 2>&1 | tee -a "$LOG_FILE"; then
                            user_removed=true
                        fi
                    fi

                    if [[ "$user_removed" == "true" ]]; then
                        print_success "User $user removed."
                        log "Removed provider user: $user"

                        if [[ -f "/etc/sudoers.d/$user" ]]; then
                            execute_command rm -f "/etc/sudoers.d/$user"
                            print_info "Removed sudo configuration for $user."
                        fi
                    else
                        print_error "Failed to remove user $user. Check logs."
                        log "Failed to remove user: $user"
                    fi
                fi
            else
                print_info "Keeping user $user."
            fi
        done
        printf '\n'
    fi

    # Final cleanup step
    if [[ "$CLEANUP_PREVIEW" == "true" ]] || confirm "Remove residual configuration files and unused dependencies?" "y"; then
        if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
            print_info "[PREVIEW] Would run: apt-get autoremove --purge -y"
            print_info "[PREVIEW] Would run: apt-get autoclean -y"
        else
            print_info "Cleaning up..."
            execute_command apt-get autoremove --purge -y 2>&1 | tee -a "$LOG_FILE" || true
            execute_command apt-get autoclean -y 2>&1 | tee -a "$LOG_FILE" || true
            print_success "Cleanup complete."
            log "Ran apt autoremove and autoclean."
        fi
    fi

    log "Provider package cleanup completed."

    if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
        printf '\n'
        print_success "=== PREVIEW COMPLETED ==="
        print_info "No changes were made to the system."
        print_info "Run without --cleanup-preview flag to execute these actions."
    else
        print_success "Cleanup function completed successfully."
    fi
}

configure_custom_bashrc() {
    local USER_HOME="$1"
    local USERNAME="$2"
    local BASHRC_PATH="$USER_HOME/.bashrc"
    local temp_source_bashrc=""
    local keep_temp_source_on_error=false

    trap 'rm -f "$temp_source_bashrc" 2>/dev/null' INT TERM

    if ! confirm "Replace default .bashrc for '$USERNAME' with a custom one?" "n"; then
        print_info "Skipping custom .bashrc configuration."
        log "Skipped custom .bashrc for $USERNAME."
        return 0
    fi

    print_info "Preparing custom .bashrc for '$USERNAME'..."

    temp_source_bashrc=$(mktemp "/tmp/custom_bashrc_source.XXXXXX")
    if [[ -z "$temp_source_bashrc" || ! -f "$temp_source_bashrc" ]]; then
        print_error "Failed to create temporary file for .bashrc content."
        log "Error: mktemp failed for bashrc source."
        return 0
    fi
    chmod 600 "$temp_source_bashrc"

    if ! cat > "$temp_source_bashrc" <<'EOF'
# shellcheck shell=bash
# ===================================================================
#   Universal Portable .bashrc for Modern Terminals
#   Optimized for Debian/Ubuntu servers with multi-terminal support
# ===================================================================

# If not running interactively, don't do anything.
case $- in
    *i*) ;;
      *) return;;
esac

# --- History Control ---
# Don't put duplicate lines or lines starting with space in the history.
HISTCONTROL=ignoreboth:erasedups
# Append to the history file, don't overwrite it.
shopt -s histappend
# Set history length with reasonable values for server use.
HISTSIZE=10000
HISTFILESIZE=20000
# Allow editing of commands recalled from history.
shopt -s histverify
# Add timestamp to history entries for audit trail (ISO 8601 format).
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
# Ignore common commands from history to reduce clutter.
HISTIGNORE="ls:ll:la:l:cd:pwd:exit:clear:c:history:h"

# --- General Shell Behavior & Options ---
# Check the window size after each command and update LINES and COLUMNS.
shopt -s checkwinsize
# Allow using '**' for recursive globbing (Bash 4.0+, suppress errors on older versions).
shopt -s globstar 2>/dev/null
# Allow changing to a directory by just typing its name (Bash 4.0+).
shopt -s autocd 2>/dev/null
# Autocorrect minor spelling errors in directory names (Bash 4.0+).
shopt -s cdspell 2>/dev/null
shopt -s dirspell 2>/dev/null
# Correct multi-line command editing.
shopt -s cmdhist 2>/dev/null
# Case-insensitive globbing (commented out to avoid unexpected behavior).
# shopt -s nocaseglob 2>/dev/null

# Set command-line editing mode. Emacs (default) or Vi.
set -o emacs
# For vi keybindings, uncomment the following line and comment the one above:
# set -o vi

# Make `less` more friendly for non-text input files.
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# --- Better Less Configuration ---
# Make less more friendly - R shows colors, F quits if one screen, X prevents screen clear.
export LESS='-R -F -X -i -M -w'
# Colored man pages using less (TERMCAP sequences).
export LESS_TERMCAP_mb=$'\e[1;31m'      # begin blink
export LESS_TERMCAP_md=$'\e[1;36m'      # begin bold
export LESS_TERMCAP_me=$'\e[0m'         # reset bold/blink
export LESS_TERMCAP_so=$'\e[01;44;33m'  # begin reverse video
export LESS_TERMCAP_se=$'\e[0m'         # reset reverse video
export LESS_TERMCAP_us=$'\e[1;32m'      # begin underline
export LESS_TERMCAP_ue=$'\e[0m'         # reset underline

# --- Terminal & SSH Compatibility Fixes ---
# Handle Kitty terminal over SSH - fallback to xterm-256color if terminfo unavailable.
if [[ "$TERM" == "xterm-kitty" ]]; then
    # Check if kitty terminfo is available, otherwise fallback.
    if ! infocmp xterm-kitty &>/dev/null; then
        export TERM=xterm-256color
    fi
    # Ensure the shell looks for user-specific terminfo files.
    [[ -d "$HOME/.terminfo" ]] && export TERMINFO="$HOME/.terminfo"
fi

# Fix for other modern terminals that might not be recognized on older servers.
case "$TERM" in
    alacritty|wezterm)
        if ! infocmp "$TERM" &>/dev/null; then
            export TERM=xterm-256color
        fi
        ;;
esac

# Optional: if kitty exists locally, provide a convenience alias for SSH.
# (No effect on hosts without kitty installed.)
if command -v kitty &>/dev/null; then
    alias kssh='kitty +kitten ssh'
fi

# --- Prompt Configuration ---
# Set variable identifying the chroot you work in (used in the prompt below).
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(</etc/debian_chroot)
fi

# Set a colored prompt only if the terminal has color capability.
case "$TERM" in
    xterm-color|*-256color|xterm-kitty|alacritty|wezterm) color_prompt=yes;;
esac

# Force color prompt support check using tput.
if [ -z "${color_prompt}" ] && [ -x /usr/bin/tput ] && tput setaf 1 &>/dev/null; then
    color_prompt=yes
fi

# --- Function to parse git branch only if in a git repo ---
parse_git_branch() {
    if git rev-parse --git-dir &>/dev/null; then
        git branch 2>/dev/null | sed -n '/^\*/s/* \(.*\)/\1/p'
    fi
    return 0
}

# --- Main prompt command function ---
__bash_prompt_command() {
    local rc=$?  # Capture last command exit status
    history -a
    history -n

    # --- Initialize prompt components ---
    local prompt_err="" prompt_git="" prompt_jobs="" prompt_venv=""
    local git_branch job_count

    # Error indicator
    (( rc != 0 )) && prompt_err="\[\e[31m\]✗\[\e[0m\]"

    # Git branch (dim yellow)
    git_branch=$(parse_git_branch)
    [[ -n "$git_branch" ]] && prompt_git="\[\e[2;33m\]($git_branch)\[\e[0m\]"

    # Background jobs (cyan)
    job_count=$(jobs -p | wc -l)
    (( job_count > 0 )) && prompt_jobs="\[\e[36m\]⚡${job_count}\[\e[0m\]"

    # Python virtualenv (dim green)
    [[ -n "$VIRTUAL_ENV" ]] && prompt_venv="\[\e[2;32m\][${VIRTUAL_ENV##*/}]\[\e[0m\]"

    # Ensure spacing between components
    [[ -n "$prompt_venv" ]] && prompt_venv=" $prompt_venv"
    [[ -n "$prompt_git" ]] && prompt_git=" $prompt_git"
    [[ -n "$prompt_jobs" ]] && prompt_jobs=" $prompt_jobs"
    [[ -n "$prompt_err" ]] && prompt_err=" $prompt_err"

    # --- Assemble PS1 ---
    if [ "$color_prompt" = yes ]; then
        PS1='${debian_chroot:+($debian_chroot)}\[\e[32m\]\u@\h\[\e[0m\]:\[\e[34m\]\w\[\e[0m\]'"${prompt_venv}${prompt_git}${prompt_jobs}${prompt_err}"' \$ '
    else
        PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w'"${prompt_venv}${git_branch}${prompt_jobs}${prompt_err}"' \$ '
    fi

    # --- Set Terminal Window Title ---
    case "$TERM" in
      xterm*|rxvt*|xterm-kitty|alacritty|wezterm)
        PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
        ;;
    esac
}

# --- Activate dynamic prompt ---
PROMPT_COMMAND=__bash_prompt_command

# --- Editor Configuration ---
if command -v vim &>/dev/null; then
    export EDITOR=vim
    export VISUAL=vim
elif command -v nano &>/dev/null; then
    export EDITOR=nano
    export VISUAL=nano
else
    export EDITOR=vi
    export VISUAL=vi
fi

# --- Additional Environment Variables ---
# Set default pager.
export PAGER=less
# Prevent Ctrl+S from freezing the terminal.
stty -ixon 2>/dev/null

# --- Useful Functions ---
# Create a directory and change into it.
mkcd() {
    mkdir -p "$1" && cd "$1"
}

# Create a backup of a file with timestamp.
backup() {
    if [ -f "$1" ]; then
        local backup_file; backup_file="$1.backup-$(date +%Y%m%d-%H%M%S)"
        cp "$1" "$backup_file"
        echo "Backup created: $backup_file"
    else
        echo "'$1' is not a valid file" >&2
        return 1
    fi
}

# Extract any archive file with a single command.
extract() {
    if [ -f "$1" ]; then
        case "$1" in
            *.tar.bz2)   tar xjf "$1"      ;;
            *.tar.gz)    tar xzf "$1"      ;;
            *.tar.xz)    tar xJf "$1"      ;;
            *.bz2)       bunzip2 "$1"      ;;
            *.rar)       unrar x "$1"      ;;
            *.gz)        gunzip "$1"       ;;
            *.tar)       tar xf "$1"       ;;
            *.tbz2)      tar xjf "$1"      ;;
            *.tgz)       tar xzf "$1"      ;;
            *.zip)       unzip "$1"        ;;
            *.Z)         uncompress "$1"   ;;
            *.7z)        7z x "$1"         ;;
            *.deb)       ar x "$1"         ;;
            *.tar.zst)
                if command -v zstd &>/dev/null; then
                    zstd -dc "$1" | tar xf -
                else
                    tar --zstd -xf "$1"
                fi
                ;;
            *)
                echo "'$1' cannot be extracted via extract()" >&2
                return 1 # Add return 1 for consistency
                ;;
        esac
    else
        echo "'$1' is not a valid file" >&2
        return 1
    fi
}

# Quick directory navigation up multiple levels.
up() {
    local d=""
    local limit="${1:-1}"
    for ((i=1; i<=limit; i++)); do
        d="../$d"
    done
    cd "$d" || return
}

# Find files by name in current directory tree.
ff() {
    find . -type f -iname "*$1*" 2>/dev/null
}

# Find directories by name in current directory tree.
fd() {
    find . -type d -iname "*$1*" 2>/dev/null
}

# Search for text in files recursively.
ftext() {
    grep -rnw . -e "$1" 2>/dev/null
}

# Search history easily
hgrep() { history | grep -i --color=auto "$@"; }

# Create a tarball of a directory.
targz() {
    if [ -d "$1" ]; then
        tar czf "${1%%/}.tar.gz" "${1%%/}"
        echo "Created ${1%%/}.tar.gz"
    else
        echo "'$1' is not a valid directory" >&2
        return 1
    fi
}

# Show disk usage of current directory, sorted by size.
duh() {
    du -h --max-depth=1 "${1:-.}" | sort -hr
}

# Get the size of a file or directory.
sizeof() {
    du -sh "$1" 2>/dev/null
}

# Show most used commands from history.
histop() {
    history | awk -v ig="$HISTIGNORE" 'BEGIN{OFS="\t";gsub(/:/,"|",ig);ir="^("ig")($| )";sr="(^|\\s)\\./"}
    {cmd=$4;for(i=5;i<=NF;i++)cmd=cmd" "$i}
    (cmd==""||cmd~ir||cmd~sr){next}
    {C[cmd]++;t++}
    END{if(t>0)for(a in C)printf"%d\t%.2f%%\t%s\n",C[a],(C[a]/t*100),a}' |
    sort -nr | head -n20 |
    awk 'BEGIN{
        FS="\t";
        maxc=length("COUNT");
        maxp=length("PERCENT");
    }
    {
        data[NR]=$0;
        len1=length($1);
        len2=length($2);
        if(len1>maxc)maxc=len1;
        if(len2>maxp)maxp=len2;
    }
    END{
        fmt="  %-4s %-*s  %-*s  %s\n";
        printf fmt,"RANK",maxc,"COUNT",maxp,"PERCENT","COMMAND";
        sep_c=sep_p="";
        for(i=1;i<=maxc;i++)sep_c=sep_c"-";
        for(i=1;i<=maxp;i++)sep_p=sep_p"-";
        printf fmt,"----",maxc,sep_c,maxp,sep_p,"-------";
        for(i=1;i<=NR;i++){
            split(data[i],f,"\t");
            printf fmt,i".",maxc,f[1],maxp,f[2],f[3]
        }
    }'
}

# Quick server info display
sysinfo() {
    # --- Self-Contained Color Detection ---
    local color_support=""
    case "$TERM" in
        xterm-color|*-256color|xterm-kitty|alacritty|wezterm) color_support="yes";;
    esac
    if [ -z "$color_support" ] && [ -x /usr/bin/tput ] && tput setaf 1 &>/dev/null; then
        color_support="yes"
    fi

    # --- Color Definitions ---
    if [ "$color_support" = "yes" ]; then
        local CYAN='\e[1;36m'
        local YELLOW='\e[1;33m'
        local BOLD_RED='\e[1;31m'
        local BOLD_WHITE='\e[1;37m'
        local GREEN='\e[1;32m'
        local DIM='\e[2m'
        local RESET='\e[0m'
    else
        local CYAN='' YELLOW='' BOLD_RED='' BOLD_WHITE='' GREEN='' DIM='' RESET=''
    fi

    # --- Header ---
    printf "\n${BOLD_WHITE}=== System Information ===${RESET}\n"

    # --- CPU Info ---
    local cpu_info
    cpu_info=$(lscpu | awk -F: '/Model name/ {print $2; exit}' | xargs || grep -m1 'model name' /proc/cpuinfo | cut -d ':' -f2 | xargs)
    [ -z "$cpu_info" ] && cpu_info="Unknown"

    # --- IP Detection ---
    local ip_addr public_ipv4 public_ipv6

    # Try to get public IPv4 first
    public_ipv4=$(curl -4 -s -m 2 --connect-timeout 1 https://checkip.amazonaws.com 2>/dev/null || \
                  curl -4 -s -m 2 --connect-timeout 1 https://ipconfig.io 2>/dev/null || \
                  curl -4 -s -m 2 --connect-timeout 1 https://api.ipify.org 2>/dev/null)
    # If no IPv4, try IPv6
    if [ -z "$public_ipv4" ]; then
        public_ipv6=$(curl -6 -s -m 2 --connect-timeout 1 https://ipconfig.io 2>/dev/null || \
                      curl -6 -s -m 2 --connect-timeout 1 https://icanhazip.co 2>/dev/null || \
                      curl -6 -s -m 2 --connect-timeout 1 https://api64.ipify.org 2>/dev/null)
    fi
    # Get local/internal IP as fallback
    for iface in eth0 ens3 enp0s3 enp0s6 wlan0 ens33 eno1; do
        ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1)
        [ -n "$ip_addr" ] && break
    done
    [ -z "$ip_addr" ] && ip_addr=$(ip -4 addr show scope global 2>/dev/null | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n1)

    # --- System Info ---
    if [ -n "$public_ipv4" ]; then
        # Show public IPv4 (preferred)
        printf "${CYAN}%-15s${RESET} %s  ${YELLOW}[%s]${RESET}" "Hostname:" "$(hostname)" "$public_ipv4"
        # Show local IP if different from public
        if [ -n "$ip_addr" ] && [ "$ip_addr" != "$public_ipv4" ]; then
            printf " ${DIM}(local: %s)${RESET}\n" "$ip_addr"
        else
            printf "\n"
        fi
    elif [ -n "$public_ipv6" ]; then
        # Show public IPv6 if no IPv4
        printf "${CYAN}%-15s${RESET} %s  ${YELLOW}[%s]${RESET}" "Hostname:" "$(hostname)" "$public_ipv6"
        [ -n "$ip_addr" ] && printf " ${DIM}(local: %s)${RESET}\n" "$ip_addr" || printf "\n"
    elif [ -n "$ip_addr" ]; then
        # Show local IP only
        printf "${CYAN}%-15s${RESET} %s  ${YELLOW}[%s]${RESET}\n" "Hostname:" "$(hostname)" "$ip_addr"
    else
        # No IP detected
        printf "${CYAN}%-15s${RESET} %s\n" "Hostname:" "$(hostname)"
    fi
    printf "${CYAN}%-15s${RESET} %s\n" "OS:" "$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo 'Unknown')"
    printf "${CYAN}%-15s${RESET} %s\n" "Kernel:" "$(uname -r)"
    printf "${CYAN}%-15s${RESET} %s\n" "Uptime:" "$(uptime -p 2>/dev/null || uptime | sed 's/.*up //' | sed 's/,.*//')"
    printf "${CYAN}%-15s${RESET} %s\n" "Server time:" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf "${CYAN}%-15s${RESET} %s\n" "CPU:" "$cpu_info"
    printf "${CYAN}%-15s${RESET} " "Memory:"
    free -m | awk '/Mem/ {
        used = $3; total = $2; percent = int((used/total)*100);
        if (used >= 1024) { used_fmt = sprintf("%.1fGi", used/1024); } else { used_fmt = sprintf("%dMi", used); }
        if (total >= 1024) { total_fmt = sprintf("%.1fGi", total/1024); } else { total_fmt = sprintf("%dMi", total); }
        printf "%s / %s (%d%% used)\n", used_fmt, total_fmt, percent;
    }'
    printf "${CYAN}%-15s${RESET} %s\n" "Disk (/):" "$(df -h / | awk 'NR==2 {print $3 " / " $2 " (" $5 " used)"}')"

    # --- Reboot Status ---
    if [ -f /var/run/reboot-required ]; then
        printf "${CYAN}%-15s${RESET} ${BOLD_RED}⚠ REBOOT REQUIRED${RESET}\n" "System:"
        [ -s /var/run/reboot-required.pkgs ] && \
            printf "               ${DIM}Reason:${RESET} %s\n" "$(paste -sd ' ' /var/run/reboot-required.pkgs)"
    fi

    # --- Available Updates (APT) ---
    if command -v apt-get &>/dev/null; then
        local total security
        local upgradable_all upgradable_list security_list
        if [ -x /usr/lib/update-notifier/apt-check ]; then
            local apt_check_output
            apt_check_output=$(/usr/lib/update-notifier/apt-check 2>/dev/null)
            if [ -n "$apt_check_output" ]; then
                total="${apt_check_output%%;*}"
                security="${apt_check_output##*;}"
            fi
        fi

        # Fallback if apt-check didn't provide values
        if [ -z "$total" ] && [ -r /var/lib/update-notifier/updates-available ]; then
            total=$(awk '/[0-9]+ (update|package)s? can be (updated|applied|installed)/ {print $1; exit}' /var/lib/update-notifier/updates-available 2>/dev/null)
            security=$(awk '/[0-9]+ (update|package)s? .*security/ {print $1; exit}' /var/lib/update-notifier/updates-available 2>/dev/null)
        fi

        # Final fallback
        if [ -z "$total" ]; then
            total=$(apt list --upgradable 2>/dev/null | grep -c upgradable)
            security=$(apt list --upgradable 2>/dev/null | grep -ci security)
        fi

        total="${total:-0}"
        security="${security:-0}"

        # Display updates if available
        if [ -n "$total" ] && [ "$total" -gt 0 ] 2>/dev/null; then
            printf "${CYAN}%-15s${RESET} " "Updates:"
            if [ -n "$security" ] && [ "$security" -gt 0 ] 2>/dev/null; then
                printf "${YELLOW}%s packages (%s security)${RESET}\n" "$total" "$security"
            else
                printf "%s packages available\n" "$total"
            fi

            # List upgradable packages (up to 5) and highlight security
            mapfile -t upgradable_all < <(apt list --upgradable 2>/dev/null | tail -n +2)
            upgradable_list=$(printf "%s\n" "${upgradable_all[@]}" | head -n5 | awk -F/ '{print $1}')
            security_list=$(printf "%s\n" "${upgradable_all[@]}" | grep -i security | head -n5 | awk -F/ '{print $1}')

            [ -n "$upgradable_list" ] && \
                printf "               ${DIM}Upgradable:${RESET} %s" "$(echo "$upgradable_list" | paste -sd ', ')"
            [ "$total" -gt 5 ] && printf " ... (+%s more)\n" $((total - 5)) || printf "\n"

            [ -n "$security_list" ] && \
                printf "               ${YELLOW}Security:${RESET} %s" "$(echo "$security_list" | paste -sd ', ')"
            [ "$security" -gt 5 ] && printf " ... (+%s more)\n" $((security - 5)) || printf "\n"
        fi
    fi

    # --- Docker Info ---
    if command -v docker &>/dev/null; then
        mapfile -t docker_states < <(docker ps -a --format '{{.State}}' 2>/dev/null)
        total=${#docker_states[@]}
        if (( total > 0 )); then
            running=$(printf "%s\n" "${docker_states[@]}" | grep -c '^running$')
            printf "${CYAN}%-15s${RESET} ${GREEN}%s running${RESET} / %s total containers\n" "Docker:" "$running" "$total"
        fi
    fi

    # --- Tailscale Info (if installed and connected) ---
    if command -v tailscale &>/dev/null; then
        local ts_ipv4 ts_ipv6 ts_hostname
        # Get Tailscale IPs
        ts_ipv4=$(tailscale ip -4 2>/dev/null)
        ts_ipv6=$(tailscale ip -6 2>/dev/null)
        # Only show if connected
        if [ -n "$ts_ipv4" ] || [ -n "$ts_ipv6" ]; then
            # Get hostname from status (FIXED: use head -n1 to get only first line)
            ts_hostname=$(tailscale status --self --peers=false 2>/dev/null | head -n1 | awk '{print $2}')
            printf "${CYAN}%-15s${RESET} " "Tailscale:"
            printf "${GREEN}Connected${RESET}"
            [ -n "$ts_ipv4" ] && printf " - %s" "$ts_ipv4"
            [ -n "$ts_hostname" ] && printf " ${DIM}(%s)${RESET}" "$ts_hostname"
            printf "\n"
            # Optional: Show IPv6 on second line if available
            if [ -n "$ts_ipv6" ]; then
                printf "                ${DIM}IPv6: %s${RESET}\n" "$ts_ipv6"
            fi
        fi
    fi

    printf "\n"
}

# Check for available updates
checkupdates() {
    if [ -x /usr/lib/update-notifier/apt-check ]; then
        echo "Checking for updates..."
        /usr/lib/update-notifier/apt-check --human-readable
    elif command -v apt &>/dev/null; then
        apt list --upgradable 2>/dev/null
    else
        echo "No package manager found"
        return 1
    fi
}

# Disk space alert (warns if any partition > 80%)
diskcheck() {
    df -h | awk '
        NR > 1 {
            usage = $5
            gsub(/%/, "", usage)
            if (usage > 80) {
                printf "⚠️  %s\n", $0
                found = 1
            }
        }
        END {
            if (!found) print "✓ All disks below 80%"
        }
    '
}

# Directory bookmarks
export MARKPATH=$HOME/.marks
[ -d "$MARKPATH" ] || mkdir -p "$MARKPATH"
mark() { ln -sfn "$(pwd)" "$MARKPATH/${1:-$(basename "$PWD")}"; }
jump() { cd -P "$MARKPATH/$1" 2>/dev/null || ls -l "$MARKPATH"; }

# Service status shortcut (cleaner output)
svc() { sudo systemctl status "$1" --no-pager -l | head -20; }
alias failed='systemctl --failed --no-pager'

# Show top 10 processes by CPU
topcpu() { ps aux --sort=-%cpu | head -11; }

# Show top 10 processes by memory
topmem() { ps aux --sort=-%mem | head -11; }

# Network connections summary
netsum() {
    echo "=== Active Connections ==="
    ss -s
    echo -e "\n=== Listening Ports ==="
    sudo ss -tulnp | grep LISTEN | awk '{print $5, $7}' | sort -u
}

# --- Aliases ---
# Enable color support for common commands.
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias dir='dir --color=auto'
    alias vdir='vdir --color=auto'
    alias grep='grep --color=auto'
    alias egrep='grep -E --color=auto'
    alias fgrep='grep -F --color=auto'
    alias diff='diff --color=auto'
    alias ip='ip --color=auto'
fi

# Standard ls aliases with human-readable sizes.
alias ll='ls -alFh'
alias la='ls -A'
alias l='ls -CF'
alias lt='ls -alFht'       # Sort by modification time, newest first
alias ltr='ls -alFhtr'     # Sort by modification time, oldest first
alias lS='ls -alFhS'       # Sort by size, largest first

# Last command with sudo
alias please='sudo $(history -p !!)'

# Safety aliases to prompt before overwriting.
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias ln='ln -i'

# Convenience & Navigation aliases.
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias .....='cd ../../../..'
alias -- -='cd -'           # Go to previous directory
alias ~='cd ~'
alias h='history'
alias c='clear'
alias cls='clear'
alias reload='source ~/.bashrc && echo "Bashrc reloaded!"'

# PATH printer as a function (portable, no echo -e)
unalias path 2>/dev/null
path() {
    printf '%s\n' "${PATH//:/$'\n'}"
}

# Enhanced directory listing.
alias lsd='ls -d */ 2>/dev/null'      # List only directories
alias lsf='find . -maxdepth 1 -type f -printf "%f\n"'

# System resource helpers.
alias df='df -h'
alias du='du -h'
alias free='free -h'
# psgrep as a function to accept patterns reliably
# Ensure no alias conflict before defining the function
unalias psgrep 2>/dev/null
psgrep() {
    if [ $# -eq 0 ]; then
        echo "Usage: psgrep <pattern>" >&2
        return 1
    fi
    # Build a pattern like '[n]ginx' to avoid matching the grep process itself
    local pattern
    local term="$1"
    pattern="[${term:0:1}]${term:1}"
    ps aux | grep -i "$pattern"
}
alias ports='ss -tuln'
alias listening='ss -tlnp'
alias meminfo='free -h -l -t'
alias psmem='ps auxf | sort -nr -k 4 | head -10'
alias pscpu='ps auxf | sort -nr -k 3 | head -10'
alias top10='ps aux --sort=-%mem | head -n 11'

# Quick network info.
alias myip='curl -s ifconfig.me || curl -s icanhazip.com' # Alternatives: api.ipify.org, icanhazip.co
# Show local IP address(es), excluding loopback.
localip() {
    ip -4 addr | awk '/inet/ {print $2}' | cut -d/ -f1 | grep -v '127.0.0.1'
}

alias netstat='ss'
alias ping='ping -c 5'
alias fastping='ping -c 100 -i 0.2'

# Date and time helpers.
alias now='date +"%Y-%m-%d %H:%M:%S"'
alias nowdate='date +"%Y-%m-%d"'
alias timestamp='date +%s'

# File operations.
alias count='find . -type f | wc -l'  # Count files in current directory
alias cpv='rsync -ah --info=progress2'  # Copy with progress
alias wget='wget -c'  # Resume wget by default

# Git shortcuts (if git is available).
if command -v git &>/dev/null; then
    alias gs='git status'
    alias ga='git add'
    alias gc='git commit'
    alias gp='git push'
    alias gl='git log --oneline --graph --decorate'
    alias gd='git diff'
    alias gb='git branch'
    alias gco='git checkout'
fi

# --- Docker Shortcuts and Functions ---
if command -v docker &>/dev/null; then
    # Core Docker aliases
    alias d='docker'
    alias dps='docker ps'
    alias dpsa='docker ps -a'
    alias dpsq='docker ps -q'
    alias di='docker images'
    alias dv='docker volume ls'
    alias dn='docker network ls'
    alias dex='docker exec -it'
    alias dlog='docker logs -f'
    alias dins='docker inspect'
    alias drm='docker rm'
    alias drmi='docker rmi'
    alias dpull='docker pull'

    # Docker system management
    alias dprune='docker system prune -f'
    alias dprunea='docker system prune -af'
    alias ddf='docker system df'
    alias dvprune='docker volume prune -f'
    alias diprune='docker image prune -af'

    # Docker stats
    alias dstats='docker stats --no-stream'
    alias dstatsa='docker stats'
    dst() {
        docker stats --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}'
    }

    # Safe stop all (shows command instead of executing)
    alias dstopa='echo "To stop all containers, run: docker stop \$(docker ps -q)"'
    # Start all stopped containers
    alias dstarta='docker start $(docker ps -aq)'

    # Docker Compose v2 aliases (check if the compose plugin exists)
    if docker compose version &>/dev/null; then
        alias dc='docker compose'
        alias dcup='docker compose up -d'
        alias dcdown='docker compose down'
        alias dclogs='docker compose logs -f'
        alias dcps='docker compose ps'
        alias dcex='docker compose exec'
        alias dcbuild='docker compose build'
        alias dcbn='docker compose build --no-cache'
        alias dcrestart='docker compose restart'
        alias dcrecreate='docker compose up -d --force-recreate'
        alias dcpull='docker compose pull'
        alias dcstop='docker compose stop'
        alias dcstart='docker compose start'
        alias dcconfig='docker compose config'
        alias dcvalidate='docker compose config --quiet && echo "✓ docker-compose.yml is valid" || echo "✗ docker-compose.yml has errors"'
    fi

# --- Docker Functions ---

# Enter container shell (bash or sh fallback)
dsh() {
    if [ -z "$1" ]; then
        echo "Usage: dsh <container-name-or-id>" >&2
        return 1
    fi
    docker exec -it "$1" bash 2>/dev/null || docker exec -it "$1" sh
}

# Docker Compose enter shell (bash or sh fallback)
dcsh() {
    if [ -z "$1" ]; then
        echo "Usage: dcsh <service-name>" >&2
        return 1
    fi
    docker compose exec "$1" bash 2>/dev/null || docker compose exec "$1" sh
}

# Follow logs for a specific container with tail
dfollow() {
    if [ -z "$1" ]; then
        echo "Usage: dfollow <container-name-or-id> [lines]" >&2
        return 1
    fi
    local lines="${2:-100}"
    docker logs -f --tail "$lines" "$1"
}

# Show container IP addresses
dip() {
    if [ -z "$1" ]; then
        docker ps -q | xargs -I {} docker inspect -f '{{.Name}} - {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' {} 2>/dev/null
    else
        docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null
    fi
}

# Show bind mounts for containers
dbinds() {
    if [ -z "$1" ]; then
        printf "\n\033[1;32mContainer Bind Mounts:\033[0m\n"
        printf "═══════════════════════════════════════════════════════════════\n"
        docker ps --format '{{.Names}}' | while IFS= read -r container; do
            printf "\n\033[1;32m%s\033[0m:\n" "$container"
            docker inspect "$container" --format '{{range .Mounts}}{{if eq .Type "bind"}}  {{.Source}} → {{.Destination}}{{println}}{{end}}{{end}}' 2>/dev/null
        done
        printf "\n"
    else
        printf "\nBind mounts for %s:\n" "$1"
        docker inspect "$1" --format '{{range .Mounts}}{{if eq .Type "bind"}}  {{.Source}} → {{.Destination}}{{println}}{{end}}{{end}}' 2>/dev/null
    fi
}

# Show disk usage by containers (enable size reporting)
dsize() {
    printf "\n%-40s %s\n" "Container" "Size"
    printf "═══════════════════════════════════════════════════════════════\n"
    docker ps -a --size --format '{{.Names}}\t{{.Size}}' | column -t
    printf "\n"
}

# Restart a compose service and follow logs
dcreload() {
    if [ -z "$1" ]; then
        echo "Usage: dcreload <service-name>" >&2
        return 1
    fi
    docker compose restart "$1" && docker compose logs -f "$1"
}

# Update and restart a single compose service
dcupdate() {
    if [ -z "$1" ]; then
        echo "Usage: dcupdate <service-name>" >&2
        return 1
    fi
    docker compose pull "$1" && docker compose up -d "$1" && docker compose logs -f "$1"
}

# Show Docker Compose services status with detailed info
dcstatus() {
    printf "\n=== Docker Compose Services ===\n\n"
    docker compose ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'
    printf "\n=== Resource Usage ===\n\n"
    docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}'
    printf "\n"
}

# Watch Docker Compose logs for specific service with grep
dcgrep() {
    if [ -z "$1" ] || [ -z "$2" ]; then
        echo "Usage: dcgrep <service-name> <search-pattern>" >&2
        return 1
    fi
    docker compose logs -f "$1" | grep --color=auto -i "$2"
}

# Show environment variables for a container
denv() {
    if [ -z "$1" ]; then
        echo "Usage: denv <container-name-or-id>" >&2
        return 1
    fi
    docker inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | sort
}

# Remove all stopped containers
drmall() {
    # Using the modern, direct command
    docker container prune -f
}

fi

# Systemd shortcuts.
if command -v systemctl &>/dev/null; then
    alias sysstart='sudo systemctl start'
    alias sysstop='sudo systemctl stop'
    alias sysrestart='sudo systemctl restart'
    alias sysstatus='sudo systemctl status'
    alias sysenable='sudo systemctl enable'
    alias sysdisable='sudo systemctl disable'
    alias sysreload='sudo systemctl daemon-reload'
fi

# Apt aliases for Debian/Ubuntu (only if apt is available).
if command -v apt &>/dev/null; then
    alias aptup='sudo apt update && sudo apt upgrade'
    alias aptin='sudo apt install'
    alias aptrm='sudo apt remove'
    alias aptsearch='apt search'
    alias aptshow='apt show'
    alias aptclean='sudo apt autoremove && sudo apt autoclean'
    alias aptlist='apt list --installed'
fi

# --- PATH Configuration ---
# Add user's local bin directories to PATH if they exist.
[ -d "$HOME/.local/bin" ] && export PATH="$HOME/.local/bin:$PATH"
[ -d "$HOME/bin" ] && export PATH="$HOME/bin:$PATH"

# --- Server-Specific Configuration ---
# Load hostname-specific configurations if they exist.
# This allows per-server customization without modifying the main bashrc.
if [ -f ~/.bashrc."$(hostname -s)" ]; then
    # shellcheck disable=SC1090
    source ~/.bashrc."$(hostname -s)"
fi

# --- Bash Completion & Personal Aliases ---
# Enable programmable completion features.
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
      # shellcheck disable=SC1091
      . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
      # shellcheck disable=SC1091
      . /etc/bash_completion
  fi
fi

# Source personal aliases if the file exists.
if [ -f ~/.bash_aliases ]; then
    # shellcheck disable=SC1090
    . ~/.bash_aliases
fi

# Source local machine-specific settings that shouldn't be in version control.
if [ -f ~/.bashrc.local ]; then
    # shellcheck disable=SC1090
    . ~/.bashrc.local
fi

# --- Welcome Message for SSH Sessions ---
# Show system info and context on login for SSH sessions.
if [ -n "$SSH_CONNECTION" ]; then
    # Use the existing sysinfo function for a full system overview.
    sysinfo

    # Display previous login information (skip current session)
    last_login=$(last -R "$USER" 2>/dev/null | sed -n '2p' | awk '{$1=""; print}' | xargs)
    [ -n "$last_login" ] && printf "Last login: %s\n" "$last_login"

    # Show active sessions
    printf "Active sessions: %s\n" "$(who | wc -l)"
    printf -- "-----------------------------------------------------\n\n"
fi

# --- Help System ---
# Display all custom functions and aliases with descriptions
bashhelp() {
    local category="${1:-all}"

    case "$category" in
        all|"")
            cat << 'HELPTEXT'

╔════════════════════════════════════════════════════════╗
║               .bashrc - Quick Reference                ║
╚════════════════════════════════════════════════════════╝

Usage: bashhelp [category]
Categories: navigation, files, system, docker, git, network

═══════════════════════════════════════════════════════════════════
📁 NAVIGATION & DIRECTORY
═══════════════════════════════════════════════════════════════════
  ..                Go up one directory
  ...               Go up two directories
  ....              Go up three directories
  .....             Go up four directories
  -                 Go to previous directory
  ~                 Go to home directory

  mkcd <dir>        Create directory and cd into it
  up <n>            Go up N directories (e.g., up 3)
  path              Display PATH variable (one per line)
  mark <name>       Bookmark current directory
  jump <name>       Jump to a bookmarked directory

═══════════════════════════════════════════════════════════════════
📄 FILE OPERATIONS
═══════════════════════════════════════════════════════════════════
  ll                List all files with details (human-readable)
  la                List all files including hidden
  l                 List files in column format
  lt                List by time, newest first
  ltr               List by time, oldest first
  lS                List by size, largest first
  lsd               List only directories
  lsf               List only files

  ff <name>         Find files by name (case-insensitive)
  fd <name>         Find directories by name (case-insensitive)
  ftext <text>      Search for text in files recursively

  extract <file>    Extract any archive (tar, zip, 7z, etc.)
  targz <dir>       Create tar.gz of directory
  backup <file>     Create timestamped backup of file

  sizeof <path>     Get size of file or directory
  duh [path]        Disk usage sorted by size
  count             Count files in current directory
  cpv <src> <dst>   Copy with progress bar (rsync)

═══════════════════════════════════════════════════════════════════
💻 SYSTEM & MONITORING
═══════════════════════════════════════════════════════════════════
  sysinfo           Display comprehensive system information
  checkupdates      Check for available system updates
  diskcheck         Check for disk partitions over 80%

  psgrep <pat>      Search for process by name
  topcpu            Show top 10 processes by CPU
  topmem            Show top 10 processes by Memory
  pscpu             Show top 10 processes by CPU (tree view)
  psmem             Show top 10 processes by Memory (tree view)

  ports             Show all listening ports (TCP/UDP)
  listening         Show listening ports with process info
  meminfo           Display detailed memory information

  h                 Show command history
  hgrep <pat>       Search command history
  histop            Show most used commands
  c, cls            Clear the screen
  reload            Reload bashrc configuration

═══════════════════════════════════════════════════════════════════
🐳 DOCKER & DOCKER COMPOSE
═══════════════════════════════════════════════════════════════════
Docker Commands:
  d                 docker (shortcut)
  dps               List running containers
  dpsa              List all containers
  di                List images
  dv                List volumes
  dn                List networks
  dex <id>          Execute interactive shell in container
  dlog <id>         Follow container logs

  dsh <id>          Enter container shell (bash/sh)
  dip [id]          Show container IP addresses
  dsize             Show disk usage by containers
  dbinds [id]       Show bind mounts for containers
  denv <id>         Show environment variables
  dfollow <id>      Follow logs with tail (default 100 lines)

  dstats            Container stats snapshot
  dstatsa           Container stats live
  dst               Container stats formatted table

  dprune            Prune system (remove unused data)
  dprunea           Prune all (including images)
  dvprune           Prune unused volumes
  diprune           Prune unused images
  drmall            Remove all stopped containers

Docker Compose:
  dc                docker compose (shortcut)
  dcup              Start services in background
  dcdown            Stop and remove services
  dclogs            Follow compose logs
  dcps              List compose services
  dcex <srv>        Execute command in service
  dcsh <srv>        Enter service shell (bash/sh)

  dcbuild           Build services
  dcbn              Build with no cache
  dcrestart         Restart services
  dcrecreate        Recreate services
  dcpull            Pull service images
  dcstop            Stop services
  dcstart           Start services

  dcstatus          Show service status & resource usage
  dcreload <srv>    Restart service and follow logs
  dcupdate <srv>    Pull, restart service, follow logs
  dcgrep <srv> <pattern>  Filter service logs
  dcconfig          Show resolved compose configuration
  dcvalidate        Validate compose file syntax

═══════════════════════════════════════════════════════════════════
🔀 GIT SHORTCUTS
═══════════════════════════════════════════════════════════════════
  gs                git status
  ga                git add
  gc                git commit
  gp                git push
  gl                git log (graph view)
  gd                git diff
  gb                git branch
  gco               git checkout

═══════════════════════════════════════════════════════════════════
🌐 NETWORK
═══════════════════════════════════════════════════════════════════
  myip              Show external IP address
  localip           Show local IP address(es)
  netsum            Network connections summary
  kssh              SSH wrapper for kitty terminal
  ping              Ping with 5 packets (default)
  fastping          Fast ping (100 packets, 0.2s interval)
  netstat           Show network connections (ss)

═══════════════════════════════════════════════════════════════════
⚙️  SYSTEM ADMINISTRATION
═══════════════════════════════════════════════════════════════════
Systemd:
  svc <srv>         Show service status (brief)
  failed            List failed systemd services
  sysstart <srv>    Start service
  sysstop <srv>     Stop service
  sysrestart <srv>  Restart service
  sysstatus <srv>   Show service status
  sysenable <srv>   Enable service
  sysdisable <srv>  Disable service
  sysreload         Reload systemd daemon

APT (Debian/Ubuntu):
  aptup             Update and upgrade packages
  aptin <pkg>       Install package
  aptrm <pkg>       Remove package
  aptsearch <term>  Search for packages
  aptshow <pkg>     Show package information
  aptclean          Remove unused packages
  aptlist           List installed packages

Sudo:
  please            Run last command with sudo

═══════════════════════════════════════════════════════════════════
🕒 DATE & TIME
═══════════════════════════════════════════════════════════════════
  now               Current date and time (YYYY-MM-DD HH:MM:SS)
  nowdate           Current date (YYYY-MM-DD)
  timestamp         Unix timestamp

═══════════════════════════════════════════════════════════════════
ℹ️  HELP & INFORMATION
═══════════════════════════════════════════════════════════════════
  bashhelp          Show this help (all categories)
  bh                Alias for bashhelp
  commands          List all custom functions and aliases
  bashhelp navigation Show navigation commands only
  bashhelp files    Show file operation commands
  bashhelp system   Show system monitoring commands
  bashhelp docker   Show docker commands only
  bashhelp git      Show git shortcuts
  bashhelp network  Show network commands

═══════════════════════════════════════════════════════════════════

💡 TIP: Most commands support --help or -h for more information
     The prompt shows: ✗ for failed commands, (git branch) when in repo

HELPTEXT
            ;;

        navigation)
            cat << 'HELPTEXT'

═══ NAVIGATION & DIRECTORY COMMANDS ═══

  ..                Go up one directory
  ...               Go up two directories
  ....              Go up three directories
  .....             Go up four directories
  -                 Go to previous directory
  ~                 Go to home directory

  mkcd <dir>        Create directory and cd into it
  up <n>            Go up N directories
  path              Display PATH variable
  mark <name>       Bookmark current directory
  jump <name>       Jump to a bookmarked directory

Examples:
  mkcd ~/projects/newapp    # Create and enter directory
  up 3                      # Go up 3 levels
  mark proj1                # Bookmark current dir as 'proj1'
  jump proj1                # Jump back to 'proj1'

HELPTEXT
            ;;

        files)
            cat << 'HELPTEXT'

═══ FILE OPERATION COMMANDS ═══

Listing:
  ll, la, l, lt, ltr, lS, lsd, lsf

Finding:
  ff <name>         Find files by name
  fd <name>         Find directories by name
  ftext <text>      Search text in files

Archives:
  extract <file>    Extract any archive type
  targz <dir>       Create tar.gz archive
  backup <file>     Create timestamped backup

Size Info:
  sizeof <path>     Get size of file/directory
  duh [path]        Disk usage sorted by size
  count             Count files in directory
  cpv               Copy with progress (rsync)

Examples:
  ff README         # Find files named *README*
  extract data.tar.gz
  backup ~/.bashrc

HELPTEXT
            ;;

        system)
            cat << 'HELPTEXT'

═══ SYSTEM MONITORING COMMANDS ═══

Overview:
  sysinfo           Comprehensive system info
  checkupdates      Check for package updates
  diskcheck         Check for disks > 80%

Processes:
  psgrep <pat>      Search processes
  topcpu            Top 10 by CPU
  topmem            Top 10 by Memory
  pscpu             Top 10 by CPU (tree view)
  psmem             Top 10 by Memory (tree view)

Network:
  ports             Listening ports
  listening         Ports with process info

Memory:
  meminfo           Detailed memory info
  free              Free memory (human-readable)

Shell:
  h                 Show history
  hgrep <pat>       Search history
  histop            Most used commands
  c, cls            Clear screen
  reload            Reload bashrc

Examples:
  psgrep nginx
  psmem | grep docker

HELPTEXT
            ;;

        docker)
            cat << 'HELPTEXT'

═══ DOCKER COMMANDS ═══

Basic:
  dps, dpsa, di, dv, dn, dex, dlog

Management:
  dsh <id>          Enter container shell
  dip [id]          Show IP addresses
  dsize             Show disk usage
  dbinds [id]       Show bind mounts
  denv <id>         Show environment variables
  dfollow <id>      Follow logs

Stats & Cleanup:
  dstats, dstatsa, dst
  dprune, dprunea, dvprune, diprune
  drmall            Remove stopped containers

Docker Compose:
  dcup, dcdown, dclogs, dcps, dcex, dcsh
  dcbuild, dcrestart, dcrecreate
  dcstatus          Status & resource usage
  dcreload <srv>    Restart & follow logs
  dcupdate <srv>    Pull & update service
  dcgrep <s> <p>    Filter logs
  dcvalidate        Validate compose file

Examples:
  dsh mycontainer
  dcsh web bash
  dcupdate nginx
  dcgrep app "error"

HELPTEXT
            ;;

        git)
            cat << 'HELPTEXT'

═══ GIT SHORTCUTS ═══

  gs                git status
  ga                git add
  gc                git commit
  gp                git push
  gl                git log (graph)
  gd                git diff
  gb                git branch
  gco               git checkout

Examples:
  gs                # Check status
  ga .              # Add all changes
  gc -m "Update docs"   # Commit
  gp                # Push to remote

HELPTEXT
            ;;

        network)
            cat << 'HELPTEXT'

═══ NETWORK COMMANDS ═══

  myip              Show external IP
  localip           Show local IP(s)
  netsum            Network connection summary
  kssh              SSH wrapper for kitty
  ports             Show listening ports
  listening         Ports with process info
  ping              Ping (5 packets)
  fastping          Fast ping (100 packets)
  netstat           Network connections (ss)

Examples:
  myip              # Get public IP
  listening | grep 80
  ping google.com

HELPTEXT
            ;;

        *)
            echo "Unknown category: $category"
            echo "Available categories: navigation, files, system, docker, git, network"
            echo "Use 'bashhelp' or 'bashhelp all' for complete reference"
            return 1
            ;;
    esac
}

# Preserve Bash's builtin `help` while integrating bashhelp
# This wrapper routes custom help to bashhelp, bash builtins to builtin help
help() {
    case "${1:-}" in
        ""|all|navigation|files|system|docker|git|network)
            bashhelp "$@"
            ;;
        *)
            command help "$@" 2>/dev/null || builtin help "$@"
            ;;
    esac
}

# Shorter alias for bashhelp (not for help - that's a function now)
alias bh='bashhelp'

# Quick command list (compact)
alias commands='compgen -A function -A alias | grep -v "^_" | sort | column'


# --- Performance Note ---
# This configuration is optimized for performance using built-in bash operations
# and minimizing external command calls. If startup feels slow, check:
# - ~/.bash_aliases and ~/.bashrc.local for expensive operations
# - Consider moving rarely-used functions to separate files
# - Use 'time bash -i -c exit' to measure startup time
EOF
    then
        print_error "Failed to write .bashrc content to temporary file $temp_source_bashrc."
        log "Critical error: Failed to write bashrc content to $temp_source_bashrc."
        rm -f "$temp_source_bashrc" 2>/dev/null
        return 0
    fi

    log "Successfully created temporary .bashrc source at $temp_source_bashrc"

    if [[ -f "$BASHRC_PATH" ]] && ! grep -q "generated by /usr/sbin/adduser" "$BASHRC_PATH" 2>/dev/null; then
	    local BASHRC_BACKUP
        BASHRC_BACKUP="$BASHRC_PATH.backup_$(date +%Y%m%d_%H%M%S)"
        print_info "Backing up existing non-default .bashrc to $BASHRC_BACKUP"
        cp "$BASHRC_PATH" "$BASHRC_BACKUP"
        log "Backed up existing .bashrc to $BASHRC_BACKUP"
    fi

    local temp_fallback_path="/tmp/custom_bashrc_for_${USERNAME}.txt"

    if ! tee "$BASHRC_PATH" < "$temp_source_bashrc" > /dev/null
    then
        print_error "Failed to automatically write custom .bashrc to $BASHRC_PATH."
        log "Error writing custom .bashrc for $USERNAME to $BASHRC_PATH (likely permissions issue)."

        if cp "$temp_source_bashrc" "$temp_fallback_path"; then
            chmod 644 "$temp_fallback_path"
            print_warning "ACTION REQUIRED: The custom .bashrc content has been saved to:"
            print_warning "  ${temp_fallback_path}"
            print_info "After setup, please manually copy it:"
            print_info "  sudo cp ${temp_fallback_path} ${BASHRC_PATH}"
            print_info "  sudo chown ${USERNAME}:${USERNAME} ${BASHRC_PATH}"
            print_info "  sudo chmod 644 ${BASHRC_PATH}"
            log "Saved custom .bashrc content to $temp_fallback_path for manual installation."
            keep_temp_source_on_error=true
        else
            print_error "Also failed to save custom .bashrc content to $temp_fallback_path."
            log "Critical error: Failed both writing to $BASHRC_PATH and copying $temp_source_bashrc to $temp_fallback_path."
        fi
    else
        if ! chown "$USERNAME:$USERNAME" "$BASHRC_PATH" || ! chmod 644 "$BASHRC_PATH"; then
            print_warning "Failed to set correct ownership/permissions on $BASHRC_PATH."
            log "Failed to chown/chmod $BASHRC_PATH"
            print_warning "ACTION REQUIRED: Please manually set ownership/permissions:"
            print_info "  sudo chown ${USERNAME}:${USERNAME} ${BASHRC_PATH}"
            print_info "  sudo chmod 644 ${BASHRC_PATH}"
            print_info "  (Source content is in ${temp_source_bashrc})"
            keep_temp_source_on_error=true
        else
            print_success "Custom .bashrc created for '$USERNAME'."
            log "Custom .bashrc configuration completed for $USERNAME."
            rm -f "$temp_fallback_path" 2>/dev/null
        fi
    fi

    if [[ "$keep_temp_source_on_error" == false ]]; then
        rm -f "$temp_source_bashrc" 2>/dev/null
    fi

    trap - INT TERM

    return 0
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
        read -rp "$(printf '%s' "${CYAN}$prompt${NC}")" response
        response=${response,,}

        if [[ -z $response ]]; then
            response=$default
        fi

        case $response in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) printf '%s\n' "${RED}Please answer yes or no.${NC}" ;;
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

validate_ip_or_cidr() {
    local input="$1"
    # IPv4 address (simple check)
    if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local -a octets
        IFS='.' read -ra octets <<< "$input"
        for octet in "${octets[@]}"; do
            if [[ "$octet" -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    # IPv4 CIDR (e.g., 10.0.0.0/8)
    if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local ip="${input%/*}"
        local cidr="${input##*/}"
        local -a octets
        IFS='.' read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ "$octet" -gt 255 ]]; then
                return 1
            fi
        done
        if [[ "$cidr" -ge 0 && "$cidr" -le 32 ]]; then
            return 0
        fi
        return 1
    fi
    # IPv6 address (basic check)
    if [[ "$input" =~ ^[0-9a-fA-F:]+$ && "$input" == *":"* && "$input" != *"/"* ]]; then
        return 0
    fi
    # IPv6 CIDR (permissive check, allows compressed ::)
    if [[ "$input" =~ ^[0-9a-fA-F:]+/[0-9]{1,3}$ && "$input" == *":"* ]]; then
        local cidr="${input##*/}"
        if [[ "$cidr" -ge 0 && "$cidr" -le 128 ]]; then
            return 0
        fi
        return 1
    fi
    return 1
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

# --- script update check ---
run_update_check() {
    print_section "Checking for Script Updates"
    local latest_version

    # Fetch the latest script from GitHub and parse the version number from it.
    if ! latest_version=$(curl -sL "$SCRIPT_URL" | grep '^CURRENT_VERSION=' | head -n 1 | awk -F'"' '{print $2}'); then
        print_warning "Could not check for updates. Please check your internet connection."
        log "Update check failed: Could not fetch script from $SCRIPT_URL"
        return
    fi

    if [[ -z "$latest_version" ]]; then
        print_warning "Failed to find the version number in the remote script."
        log "Update check failed: Could not parse version string from remote script."
        return
    fi

    local lower_version
    lower_version=$(printf '%s\n' "$CURRENT_VERSION" "$latest_version" | sort -V | head -n 1)

    if [[ "$lower_version" == "$CURRENT_VERSION" && "$CURRENT_VERSION" != "$latest_version" ]]; then
        print_success "A new version ($latest_version) is available!"

        if ! confirm "Would you like to update to version $latest_version now?"; then
            return
        fi

        local temp_dir
        if ! temp_dir=$(mktemp -d); then
            print_error "Failed to create temporary directory. Update aborted."
            exit 1
        fi
        trap 'rm -rf -- "$temp_dir"' EXIT

        local temp_script="$temp_dir/du_setup.sh"
        local temp_checksum="$temp_dir/checksum.sha256"

        print_info "Downloading new script version..."
        if ! curl -sL "$SCRIPT_URL" -o "$temp_script"; then
            print_error "Failed to download the new script. Update aborted."
            exit 1
        fi

        print_info "Downloading checksum..."
        if ! curl -sL "$CHECKSUM_URL" -o "$temp_checksum"; then
            print_error "Failed to download the checksum file. Update aborted."
            exit 1
        fi

        print_info "Verifying checksum..."
        if ! (cd "$temp_dir" && sha256sum -c "checksum.sha256" --quiet); then
            print_error "Checksum verification failed! The downloaded file may be corrupt. Update aborted."
            exit 1
        fi
        print_success "Checksum verified successfully."

        print_info "Checking script syntax..."
        if ! bash -n "$temp_script"; then
            print_error "Downloaded file has a syntax error. Update aborted to prevent issues."
            exit 1
        fi
        print_success "Syntax check passed."

        if ! mv "$temp_script" "$0"; then
            print_error "Failed to replace the old script file. You may need to run 'mv' manually."
            exit 1
        fi
        chmod +x "$0"

        trap - EXIT
        rm -rf -- "$temp_dir"

        print_success "Update successful. Please run the script again to use the new version."
        exit 0
    else
        print_info "You are running the latest version ($CURRENT_VERSION)."
        log "No new version found. Current: $CURRENT_VERSION, Latest: $latest_version"
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
        # shellcheck source=/dev/null
        source /etc/os-release
        ID=${ID:-unknown} # Populate global ID variable
	if [[ $ID == "debian" && $VERSION_ID =~ ^(12|13)$ ]] || \
           [[ $ID == "ubuntu" && $VERSION_ID =~ ^(20.04|22.04|24.04)$ ]]; then
            print_success "Compatible OS detected: $PRETTY_NAME"
        else
            print_warning "Script not tested on $PRETTY_NAME. This is for Debian 12/13 or Ubuntu 20.04/22.04/24.04 LTS."
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
        elif pgrep -q sshd; then
            print_warning "Preliminary check: SSH daemon running but no standard service detected."
        else
            print_warning "No SSH service or daemon detected. Ensure SSH is working after package installation."
        fi
    fi

    if curl -s --head https://deb.debian.org >/dev/null || \
       curl -s --head https://archive.ubuntu.com >/dev/null || \
       wget -q --spider https://deb.debian.org || \
       wget -q --spider https://archive.ubuntu.com; then
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
    # --- Input Collection ---
    while true; do
        read -rp "$(printf '%s' "${CYAN}Enter username for new admin user: ${NC}")" USERNAME
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
        read -rp "$(printf '%s' "${CYAN}Enter server hostname: ${NC}")" SERVER_NAME
        if validate_hostname "$SERVER_NAME"; then break; else print_error "Invalid hostname."; fi
    done
    read -rp "$(printf '%s' "${CYAN}Enter a 'pretty' hostname (optional): ${NC}")" PRETTY_NAME
    [[ -z "$PRETTY_NAME" ]] && PRETTY_NAME="$SERVER_NAME"
    # --- SSH Port Detection ---
    PREVIOUS_SSH_PORT=$(ss -tlpn | grep sshd | grep -oP ':\K\d+' | head -n 1)
    local PROMPT_DEFAULT_PORT=${PREVIOUS_SSH_PORT:-2222}
    while true; do
        read -rp "$(printf '%s' "${CYAN}Enter custom SSH port (1024-65535) [$PROMPT_DEFAULT_PORT]: ${NC}")" SSH_PORT
        SSH_PORT=${SSH_PORT:-$PROMPT_DEFAULT_PORT}
        if validate_port "$SSH_PORT" || [[ -n "$PREVIOUS_SSH_PORT" && "$SSH_PORT" == "$PREVIOUS_SSH_PORT" ]]; then
            break; else print_error "Invalid port. Choose a port between 1024-65535."; fi
    done
    # --- IP Detection ---
    print_info "Detecting network configuration..."
    # 1. Get the Local LAN IP (Explicit Check)
    # This prevents crashing on IPv6-only servers
    if ip -4 route get 8.8.8.8 >/dev/null 2>&1; then
        LOCAL_IP_V4=$(ip -4 route get 8.8.8.8 | head -1 | awk '{print $7}')
    else
        LOCAL_IP_V4=""
    fi
    # 2. Get Public IPs with timeouts
    SERVER_IP_V4=$(curl -4 -s --connect-timeout 4 --max-time 5 https://ifconfig.me 2>/dev/null || \
                   curl -4 -s --connect-timeout 4 --max-time 5 https://ip.me 2>/dev/null || \
                   curl -4 -s --connect-timeout 4 --max-time 5 https://icanhazip.com 2>/dev/null || \
                   echo "Unknown")

    SERVER_IP_V6=$(curl -6 -s --connect-timeout 4 --max-time 5 https://ifconfig.me 2>/dev/null || \
                   curl -6 -s --connect-timeout 4 --max-time 5 https://ip.me 2>/dev/null || \
                   curl -6 -s --connect-timeout 4 --max-time 5 https://icanhazip.com 2>/dev/null || \
                   echo "Not available")

    # --- Display Summary ---
    printf '\n%s\n' "${YELLOW}Configuration Summary:${NC}"
    printf "  %-22s %s\n" "Username:" "$USERNAME"
    printf "  %-22s %s\n" "Hostname:" "$SERVER_NAME"
    if [[ -n "$PREVIOUS_SSH_PORT" && "$SSH_PORT" != "$PREVIOUS_SSH_PORT" ]]; then
        printf "  %-22s %s (change from current: %s)\n" "SSH Port:" "$SSH_PORT" "$PREVIOUS_SSH_PORT"
    else
        printf "  %-22s %s\n" "SSH Port:" "$SSH_PORT"
    fi
    # --- IP Display Logic ---
    if [[ "$SERVER_IP_V4" != "Unknown" ]]; then
        if [[ "$SERVER_IP_V4" == "$LOCAL_IP_V4" ]]; then
            # 1: Direct Public IP
            printf "  %-22s %s (Direct)\n" "Server IPv4:" "$SERVER_IP_V4"
        else
            # 2: NAT
            printf "  %-22s %s (Internet)\n" "Public IPv4:" "$SERVER_IP_V4"
            if [[ -n "$LOCAL_IP_V4" ]]; then
                printf "  %-22s %s (Internal)\n" "Local IPv4:" "$LOCAL_IP_V4"
            fi
        fi
    else
        # Fallback if public check failed
        if [[ -n "$LOCAL_IP_V4" ]]; then
            printf "  %-22s %s (Local)\n" "Server IPv4:" "$LOCAL_IP_V4"
        fi
    fi
    if [[ "$SERVER_IP_V6" != "Not available" ]]; then
        printf "  %-22s %s\n" "Public IPv6:" "$SERVER_IP_V6"
    fi
    if ! confirm $'\nContinue with this configuration?' "y"; then print_info "Exiting."; exit 0; fi
    log "Configuration collected: USER=$USERNAME, HOST=$SERVER_NAME, PORT=$SSH_PORT, IPV4=$SERVER_IP_V4, IPV6=$SERVER_IP_V6, LOCAL=$LOCAL_IP_V4"
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
        apt-listchanges ca-certificates gnupg logrotate \
        ssh openssh-client openssh-server; then
        print_error "Failed to install one or more essential packages."
        exit 1
    fi
    print_success "Essential packages installed."
    log "Package installation completed."
}

setup_user() {
    print_section "User Management"
    local USER_HOME SSH_DIR AUTH_KEYS PASS1 PASS2 SSH_PUBLIC_KEY TEMP_KEY_FILE

    if [[ -z "$USERNAME" ]]; then
        print_error "USERNAME variable is not set. Cannot proceed with user setup."
        exit 1
    fi

    if [[ $USER_EXISTS == false ]]; then
        print_info "Creating user '$USERNAME'..."
        # Check if group exists but user doesn't (common with 'admin' on Ubuntu)
        local -a ADDUSER_OPTS=("--disabled-password" "--gecos" "")
        if getent group "$USERNAME" >/dev/null 2>&1; then
            print_warning "Group '$USERNAME' already exists. Attaching new user to this existing group."
            ADDUSER_OPTS+=("--ingroup" "$USERNAME")
        fi
        if ! adduser "${ADDUSER_OPTS[@]}" "$USERNAME"; then
            print_error "Failed to create user '$USERNAME'."
            exit 1
        fi
        if ! id "$USERNAME" &>/dev/null; then
            print_error "User '$USERNAME' creation verification failed."
            exit 1
        fi
        print_info "Set a password for '$USERNAME' (required for sudo, or press Enter twice to skip for key-only access):"
        while true; do
            read -rsp "$(printf '%s' "${CYAN}New password: ${NC}")" PASS1
            printf '\n'
            read -rsp "$(printf '%s' "${CYAN}Retype new password: ${NC}")" PASS2
            printf '\n'
            if [[ -z "$PASS1" && -z "$PASS2" ]]; then
                print_warning "Password skipped. Relying on SSH key authentication."
                log "Password setting skipped for '$USERNAME'."
                break
            elif [[ "$PASS1" == "$PASS2" ]]; then
                if echo "$USERNAME:$PASS1" | chpasswd >/dev/null 2>&1; then
                    print_success "Password for '$USERNAME' updated."
                    break
                else
                    print_error "Failed to set password. Possible causes:"
                    print_info "  • permissions issue or password policy restrictions."
                    print_info "  • VPS provider password requirements (min. 8-12 chars, complexity rules)"
                    printf '\n'
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

        # Check if home directory is writable
        if [[ ! -w "$USER_HOME" ]]; then
            print_error "Home directory $USER_HOME is not writable by $USERNAME."
            print_info "Attempting to fix permissions..."
            chown "$USERNAME:$USERNAME" "$USER_HOME"
            chmod 700 "$USER_HOME"
            if [[ ! -w "$USER_HOME" ]]; then
                print_error "Failed to make $USER_HOME writable. Check filesystem permissions."
                exit 1
            fi
            log "Fixed permissions for $USER_HOME."
        fi

        if confirm "Add SSH public key(s) from your local machine now?"; then
            while true; do
                local SSH_PUBLIC_KEY
                read -rp "$(printf '%s' "${CYAN}Paste your full SSH public key: ${NC}")" SSH_PUBLIC_KEY

                if validate_ssh_key "$SSH_PUBLIC_KEY"; then
                    mkdir -p "$SSH_DIR"
                    chmod 700 "$SSH_DIR"
                    chown "$USERNAME:$USERNAME" "$SSH_DIR"
                    echo "$SSH_PUBLIC_KEY" >> "$AUTH_KEYS"
                    awk '!seen[$0]++' "$AUTH_KEYS" > "$AUTH_KEYS.tmp" && mv "$AUTH_KEYS.tmp" "$AUTH_KEYS"
                    chmod 600 "$AUTH_KEYS"
                    chown "$USERNAME:$USERNAME" "$AUTH_KEYS"
                    print_success "SSH public key added."
                    log "Added SSH public key for '$USERNAME'."
                    LOCAL_KEY_ADDED=true
                else
                    print_error "Invalid SSH key format. It should start with 'ssh-rsa', 'ecdsa-*', or 'ssh-ed25519'."
                fi

                if ! confirm "Do you have another SSH public key to add?" "n"; then
                    print_info "Finished adding SSH keys."
                    break
                fi
            done
        else
            print_info "No local SSH key provided. Generating a new key pair for '$USERNAME'."
            log "User opted not to provide a local SSH key. Generating a new one."

            if ! command -v ssh-keygen >/dev/null 2>&1; then
                print_error "ssh-keygen not found. Please install openssh-client."
                exit 1
            fi
            if [[ ! -w /tmp ]]; then
                print_error "Cannot write to /tmp. Unable to create temporary key file."
                exit 1
            fi

            mkdir -p "$SSH_DIR"
            chmod 700 "$SSH_DIR"
            chown "$USERNAME:$USERNAME" "$SSH_DIR"

            # Generate user key pair for login
            if ! sudo -u "$USERNAME" ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519_user" -N "" -q; then
                print_error "Failed to generate user SSH key for '$USERNAME'."
                exit 1
            fi
            cat "$SSH_DIR/id_ed25519_user.pub" >> "$AUTH_KEYS"
            chmod 600 "$AUTH_KEYS"
            chown "$USERNAME:$USERNAME" "$AUTH_KEYS"
            print_success "SSH key generated and added to authorized_keys."
            log "Generated and added user SSH key for '$USERNAME'."

            if ! sudo -u "$USERNAME" ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519_server" -N "" -q; then
                print_error "Failed to generate server SSH key for '$USERNAME'."
                exit 1
            fi
            print_success "Server SSH key generated (not shared)."
            log "Generated server SSH key for '$USERNAME'."

            TEMP_KEY_FILE="/tmp/${USERNAME}_ssh_key_$(date +%s)"
            trap 'rm -f "$TEMP_KEY_FILE" 2>/dev/null' EXIT
            cp "$SSH_DIR/id_ed25519_user" "$TEMP_KEY_FILE"
            chmod 600 "$TEMP_KEY_FILE"
            chown root:root "$TEMP_KEY_FILE"

            printf '\n'
            printf '%s\n' "${YELLOW}⚠ SECURITY WARNING: The SSH key pair below is your only chance to access '$USERNAME' via SSH.${NC}"
            printf '%s\n' "${YELLOW}⚠ Anyone with the private key can access your server. Secure it immediately.${NC}"
            printf '\n'
            printf '%s\n' "${PURPLE}ℹ ACTION REQUIRED: Save the keys to your local machine:${NC}"
            printf '%s\n' "${CYAN}1. Save the PRIVATE key to ~/.ssh/${USERNAME}_key:${NC}"
            printf '%s\n' "${RED} vvvv PRIVATE KEY BELOW THIS LINE vvvv  ${NC}"
            cat "$TEMP_KEY_FILE"
            printf '%s\n' "${RED} ^^^^ PRIVATE KEY ABOVE THIS LINE ^^^^^ ${NC}"
            printf '\n'
            printf '%s\n' "${CYAN}2. Save the PUBLIC key to verify or use elsewhere:${NC}"
            printf '====SSH PUBLIC KEY BELOW THIS LINE====\n'
            cat "$SSH_DIR/id_ed25519_user.pub"
            printf '====SSH PUBLIC KEY END====\n'
            printf '\n'
            printf '%s\n' "${CYAN}3. On your local machine, set permissions for the private key:${NC}"
            printf '%s\n' "${CYAN}   chmod 600 ~/.ssh/${USERNAME}_key${NC}"
            printf '%s\n' "${CYAN}4. Connect to the server using:${NC}"
            if [[ "$SERVER_IP_V4" != "unknown" ]]; then
                printf '%s\n' "${CYAN}   ssh -i ~/.ssh/${USERNAME}_key -p $SSH_PORT $USERNAME@$SERVER_IP_V4${NC}"
            fi
            if [[ "$SERVER_IP_V6" != "not available" ]]; then
                printf '%s\n' "${CYAN}   ssh -i ~/.ssh/${USERNAME}_key -p $SSH_PORT $USERNAME@$SERVER_IP_V6${NC}"
            fi
            printf '\n'
            printf '%s\n' "${PURPLE}ℹ The private key file ($TEMP_KEY_FILE) will be deleted after this step.${NC}"
            read -rp "$(printf '%s' "${CYAN}Press Enter after you have saved the keys securely...${NC}")"
            rm -f "$TEMP_KEY_FILE" 2>/dev/null
            print_info "Temporary key file deleted."
            LOCAL_KEY_ADDED=true
            trap - EXIT
        fi
        print_success "User '$USERNAME' created."
        echo "$USERNAME" > /root/.du_setup_managed_user
        chmod 600 /root/.du_setup_managed_user
        log "Marked '$USERNAME' as script-managed user (excluded from provider cleanup)"
    else
        print_info "Using existing user: $USERNAME"
        if [[ ! -f /root/.du_setup_managed_user ]]; then
            echo "$USERNAME" > /root/.du_setup_managed_user
            chmod 600 /root/.du_setup_managed_user
            log "Marked existing user '$USERNAME' as script-managed"
        fi
        USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
        SSH_DIR="$USER_HOME/.ssh"
        AUTH_KEYS="$SSH_DIR/authorized_keys"
        if [[ ! -s "$AUTH_KEYS" ]] || ! grep -qE '^(ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-ed25519) ' "$AUTH_KEYS" 2>/dev/null; then
            print_warning "No valid SSH keys found in $AUTH_KEYS for existing user '$USERNAME'."
            print_info "You must manually add a public key to $AUTH_KEYS to enable SSH access."
            log "No valid SSH keys found for existing user '$USERNAME'."
        fi
    fi

    # Add custom .bashrc
    configure_custom_bashrc "$USER_HOME" "$USERNAME"

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

    # Warn about /tmp being a RAM-backed filesystem on Debian 13+
    print_info "Note: Debian 13 uses tmpfs for /tmp by default (stored in RAM)"
    print_info "Large temporary files may consume system memory"

    mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
    log "Backing up script itself for audit trail"
    cp "${SCRIPT_DIR}/$(basename "$0")" "$BACKUP_DIR/du_setup_v${CURRENT_VERSION}.sh"
    cp /etc/hosts "$BACKUP_DIR/hosts.backup"
    cp /etc/fstab "$BACKUP_DIR/fstab.backup"
    cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.backup" 2>/dev/null || true

    print_info "Configuring timezone..."
    while true; do
        read -rp "$(printf '%s' "${CYAN}Enter desired timezone (e.g., Europe/London, America/New_York) [Etc/UTC]: ${NC}")" TIMEZONE
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
        print_info "Applying new locale settings to the current session..."
        if [[ -f /etc/default/locale ]]; then
            # shellcheck disable=SC1091
            . /etc/default/locale
            # shellcheck disable=SC2046
            export $(grep -v '^#' /etc/default/locale | cut -d= -f1)
            print_success "Locale environment updated for this session."
            log "Sourced /etc/default/locale to update script's environment."
        else
            print_warning "Could not find /etc/default/locale to update session environment."
        fi
    else
        print_info "Skipping locale configuration."
    fi

    print_info "Configuring hostname..."

    # System Hostname
    if [[ $(hostnamectl --static) != "$SERVER_NAME" ]]; then
        hostnamectl set-hostname "$SERVER_NAME"
        hostnamectl set-hostname "$PRETTY_NAME" --pretty
        print_success "Hostname updated to: $SERVER_NAME"
    else
        print_info "Hostname is already set to $SERVER_NAME."
    fi
    if [[ -d /etc/cloud/cloud.cfg.d ]]; then
        print_info "Disabling cloud-init host management via override file..."
        echo "manage_etc_hosts: false" > /etc/cloud/cloud.cfg.d/99-du-setup-hosts.cfg
        echo "preserve_hostname: true" >> /etc/cloud/cloud.cfg.d/99-du-setup-hosts.cfg
        log "Created /etc/cloud/cloud.cfg.d/99-du-setup-hosts.cfg"
    elif [[ -f /etc/cloud/cloud.cfg ]]; then
        if grep -q "manage_etc_hosts: true" /etc/cloud/cloud.cfg; then
            print_info "Disabling cloud-init 'manage_etc_hosts' in main config..."
            sed -i 's/manage_etc_hosts: true/manage_etc_hosts: false/g' /etc/cloud/cloud.cfg
            log "Disabled manage_etc_hosts in /etc/cloud/cloud.cfg"
        fi
    fi

    # Stop cloud-init from overwriting /etc/hosts
    local TEMPLATE_FILE=""
    if [[ -n "$ID" && -f "/etc/cloud/templates/hosts.${ID}.tmpl" ]]; then
        TEMPLATE_FILE="/etc/cloud/templates/hosts.${ID}.tmpl"
    elif [[ -f "/etc/cloud/templates/hosts.tmpl" ]]; then
        TEMPLATE_FILE="/etc/cloud/templates/hosts.tmpl"
    fi
    if [[ -n "$TEMPLATE_FILE" ]]; then
        print_info "Patching cloud-init hosts template ($TEMPLATE_FILE) to enforce persistence..."
        cp "$TEMPLATE_FILE" "$BACKUP_DIR/$(basename "$TEMPLATE_FILE").backup"
        sed -i "s/^127.0.1.1.*/127.0.1.1\t$SERVER_NAME/g" "$TEMPLATE_FILE"
        log "Hardcoded hostname into $TEMPLATE_FILE"
    else
        if [[ -d /etc/cloud/templates ]]; then
            print_warning "Could not locate a standard hosts template in /etc/cloud/templates."
            log "Warning: Cloud-init template patching skipped (no matching template found)."
        fi
    fi

    if grep -q "^127.0.1.1" /etc/hosts; then
        if ! grep -qE "^127.0.1.1[[:space:]]+$SERVER_NAME" /etc/hosts; then
             sed -i "s/^127.0.1.1.*/127.0.1.1\t$SERVER_NAME/" /etc/hosts
             print_success "Fixed /etc/hosts to map 127.0.1.1 to $SERVER_NAME."
        else
             print_info "/etc/hosts is already correct."
        fi
    else
        echo "127.0.1.1 $SERVER_NAME" >> /etc/hosts
        print_success "Added missing 127.0.1.1 entry to /etc/hosts."
    fi

    log "System configuration completed."
}

cleanup_and_exit() {
    local exit_code=$?
    if [[ $exit_code -ne 0 && $(type -t rollback_ssh_changes) == "function" ]]; then
        print_error "An error occurred. Rolling back SSH changes to port $PREVIOUS_SSH_PORT..."
        print_info "Rolling back firewall rules..."
        ufw delete allow "$SSH_PORT"/tcp 2>/dev/null || true
        if [[ -n "$PREVIOUS_SSH_PORT" ]]; then
            ufw allow "$PREVIOUS_SSH_PORT"/tcp comment 'SSH Rollback' 2>/dev/null || true
            print_info "Firewall rolled back to allow port $PREVIOUS_SSH_PORT."
        else
            print_warning "Could not determine previous SSH port for firewall rollback."
        fi
        if ! rollback_ssh_changes; then
            print_error "Rollback failed. SSH may not be accessible. Please check 'systemctl status $SSH_SERVICE' and 'journalctl -u $SSH_SERVICE'."
        fi
    fi
    trap - ERR
    exit $exit_code
}

configure_ssh() {
    trap cleanup_and_exit ERR

    print_section "SSH Hardening"
    local CURRENT_SSH_PORT USER_HOME SSH_DIR SSH_KEY AUTH_KEYS

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

    print_info "Backing up original SSH config..."
    SSHD_BACKUP_FILE="$BACKUP_DIR/sshd_config.backup_$(date +%Y%m%d_%H%M%S)"
    cp /etc/ssh/sshd_config "$SSHD_BACKUP_FILE"

    # Check globally detected port, falling back to 22 if detection failed
    if [[ -z "$PREVIOUS_SSH_PORT" ]]; then
        print_warning "Could not detect an active SSH port. Assuming port 22 for the initial test."
        log "Could not detect active SSH port, fell back to 22."
        PREVIOUS_SSH_PORT="22"
    fi
    CURRENT_SSH_PORT=$PREVIOUS_SSH_PORT
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
    SSH_DIR="$USER_HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"

    if [[ $LOCAL_KEY_ADDED == false ]] && [[ ! -s "$AUTH_KEYS" ]]; then
        print_info "No local key provided. Generating new SSH key..."
        mkdir -p "$SSH_DIR"; chmod 700 "$SSH_DIR"; chown "$USERNAME:$USERNAME" "$SSH_DIR"
        sudo -u "$USERNAME" ssh-keygen -t ed25519 -f "$SSH_DIR/id_ed25519" -N "" -q
        cat "$SSH_DIR/id_ed25519.pub" >> "$AUTH_KEYS"
        # Verify the key was added
        if [[ ! -s "$AUTH_KEYS" ]]; then
            print_error "Failed to create authorized_keys file."
            return 1
        fi
        chmod 600 "$AUTH_KEYS"; chown -R "$USERNAME:$USERNAME" "$SSH_DIR"
        print_success "SSH key generated."
        printf '%s\n' "${YELLOW}Public key for remote access:${NC}"; cat "$SSH_DIR/id_ed25519.pub"
    fi

    print_warning "SSH Key Authentication Required for Next Steps!"
    printf '%s\n' "${CYAN}Test SSH access from a SEPARATE terminal now.${NC}"

    # --- Connection Display Function ---
    show_connection_options() {
        local port="$1"
        local public_ip="$2"

        local TS_IP=""
        if command -v tailscale >/dev/null 2>&1 && tailscale ip >/dev/null 2>&1; then
            TS_IP=$(tailscale ip -4 2>/dev/null)
        fi

        printf "\n"

        # 1. Public IP (Internet)
        # Only show if valid and not "Unknown"
        if [[ -n "$public_ip" && "$public_ip" != "Unknown" ]]; then
             printf "  %-20s ${CYAN}ssh -p %s %s@%s${NC}\n" "Public (Internet):" "$port" "$USERNAME" "$public_ip"
        fi

        # 2. Internal/LAN IPs
        # scan all interfaces. exclude the Public IP (already shown) and Loopback.
        local found_internal=false
        while read -r ip_addr; do
            # Remove subnet mask if present
            local clean_ip="${ip_addr%/*}"

            # Skip if empty, loopback, or matches the Public IP we just displayed
            if [[ -n "$clean_ip" && "$clean_ip" != "127.0.0.1" && "$clean_ip" != "$public_ip" ]]; then
                 printf "  %-20s ${CYAN}ssh -p %s %s@%s${NC}\n" "Internal/Private:" "$port" "$USERNAME" "$clean_ip"
                 found_internal=true
            fi
        done < <(ip -4 -o addr show scope global | awk '{print $4}')

        # Fallback: If we found NO internal IPs and NO Public IP (local VM offline?),
        # show the detected local IP from route (Home VM scenario)
        if [[ "$found_internal" == false && "$public_ip" == "Unknown" ]]; then
             local fallback_ip
             fallback_ip=$(ip -4 route get 8.8.8.8 2>/dev/null | head -1 | awk '{print $7}')
             if [[ -n "$fallback_ip" ]]; then
                printf "  %-20s ${CYAN}ssh -p %s %s@%s${NC}\n" "Local (LAN):" "$port" "$USERNAME" "$fallback_ip"
             fi
        fi

        # 3. IPv6
        if [[ -n "$SERVER_IP_V6" && "$SERVER_IP_V6" != "Not available" ]]; then
            printf "  %-20s ${CYAN}ssh -p %s %s@%s${NC}\n" "IPv6:" "$port" "$USERNAME" "$SERVER_IP_V6"
        fi

        # 4. Tailscale IP (VPN)
        if [[ -n "$TS_IP" ]]; then
            printf "  %-20s ${CYAN}ssh -p %s %s@%s${NC}\n" "Tailscale (VPN):" "$port" "$USERNAME" "$TS_IP"
        fi
        printf "\n"
    }

    # Show options for CURRENT port
    show_connection_options "$CURRENT_SSH_PORT" "$SERVER_IP_V4"

    if ! confirm "Can you successfully log in using your SSH key?"; then
        print_error "SSH key authentication is mandatory to proceed."
        return 1
    fi

    # Apply port override
    if [[ $ID == "ubuntu" ]] && dpkg --compare-versions "$(lsb_release -rs)" ge "24.04"; then
        print_info "Updating SSH port in /etc/ssh/sshd_config for Ubuntu 24.04+..."
        if ! grep -q "^Port" /etc/ssh/sshd_config; then echo "Port $SSH_PORT" >> /etc/ssh/sshd_config; else sed -i "s/^Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config; fi
    elif [[ "$SSH_SERVICE" == "ssh.socket" ]]; then
        print_info "Configuring SSH socket to listen on port $SSH_PORT..."
        mkdir -p /etc/systemd/system/ssh.socket.d
        printf '%s\n' "[Socket]" "ListenStream=" "ListenStream=$SSH_PORT" > /etc/systemd/system/ssh.socket.d/override.conf
    else
        print_info "Configuring SSH service to listen on port $SSH_PORT..."
        mkdir -p /etc/systemd/system/${SSH_SERVICE}.d
        printf '%s\n' "[Service]" "ExecStart=" "ExecStart=/usr/sbin/sshd -D -p $SSH_PORT" > /etc/systemd/system/${SSH_SERVICE}.d/override.conf
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
    print_info "Testing SSH configuration syntax..."
	if ! sshd -t 2>&1 | tee -a "$LOG_FILE"; then
        print_warning "SSH configuration test detected potential issues (see above)."
        print_info "This may be due to existing configuration files on the system."
        if ! confirm "Continue despite configuration warnings?"; then
            print_error "Aborting SSH configuration."
            rm -f /etc/ssh/sshd_config.d/99-hardening.conf
            rm -f /etc/issue.net
            rm -f /etc/systemd/system/ssh.socket.d/override.conf
            rm -f /etc/systemd/system/ssh.service.d/override.conf
            rm -f /etc/systemd/system/sshd.service.d/override.conf
            systemctl daemon-reload
            return 1
        fi
    fi
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
    sleep 2
    if ssh -p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@localhost true 2>/dev/null; then
        print_error "Root SSH login is still possible! Check configuration."
        return 1
    else
        print_success "Confirmed: Root SSH login is disabled."
    fi

    print_warning "CRITICAL: Test new SSH connection in a SEPARATE terminal NOW!"
    print_warning "ACTION REQUIRED: Check your VPS provider's edge/network firewall to allow $SSH_PORT/tcp."

    # Show options for NEW port
    show_connection_options "$SSH_PORT" "$SERVER_IP_V4"

    # Retry loop for SSH connection test
    local retry_count=0
    local max_retries=3
    while (( retry_count < max_retries )); do
        if confirm "Was the new SSH connection successful?"; then
            print_success "SSH hardening confirmed and finalized."
            # Remove temporary UFW rule
            if [[ -n "$PREVIOUS_SSH_PORT" && "$PREVIOUS_SSH_PORT" != "$SSH_PORT" ]]; then
                print_info "Removing temporary UFW rule for old SSH port $PREVIOUS_SSH_PORT..."
                ufw delete allow "$PREVIOUS_SSH_PORT"/tcp 2>/dev/null || true
            fi
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
    elif ! systemctl list-units --full -all --no-pager | grep -E "[[:space:]]${SSH_SERVICE}[[:space:]]" >/dev/null 2>&1; then
        local initial_service_check="$SSH_SERVICE"
        SSH_SERVICE="ssh.service" # Fallback for Ubuntu
        print_warning "SSH service '$initial_service_check' not found, falling back to '$SSH_SERVICE'."
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
    if ! rm -rf /etc/systemd/system/ssh.service.d /etc/systemd/system/sshd.service.d /etc/systemd/system/ssh.socket.d 2>/dev/null; then
        print_warning "Could not remove one or more systemd override directories."
        log "Rollback warning: Failed to remove systemd overrides."
    else
        log "Removed all potential systemd override directories for SSH."
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
        # Ensure correct port rollback if already using custom port
        print_info "Applying a systemd override to ensure rollback to port $PREVIOUS_SSH_PORT..."
        log "Rollback: Creating override to enforce port $PREVIOUS_SSH_PORT."
        if [[ "$USE_SOCKET" == true ]]; then
            mkdir -p /etc/systemd/system/ssh.socket.d
            printf '%s\n' "[Socket]" "ListenStream=" "ListenStream=$PREVIOUS_SSH_PORT" > /etc/systemd/system/ssh.socket.d/override.conf
        else
            local service_for_rollback="ssh.service"
            if systemctl list-units --full -all --no-pager | grep -qE "[[:space:]]sshd.service[[:space:]]"; then
                service_for_rollback="sshd.service"
            fi
            mkdir -p "/etc/systemd/system/${service_for_rollback}.d"
            printf '%s\n' "[Service]" "ExecStart=" "ExecStart=/usr/sbin/sshd -D -p $PREVIOUS_SSH_PORT" > "/etc/systemd/system/${service_for_rollback}.d/override.conf"
        fi
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
            read -rp "$(printf '%s' "${CYAN}Enter ports (space-separated, e.g., 8080/tcp 123/udp): ${NC}")" CUSTOM_PORTS
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
                        read -rp "$(printf '%s' "${CYAN}Enter comment for $port (e.g., 'My App Port'): ${NC}")" CUSTOM_COMMENT
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

    # --- Enable IPv6 Support if Available ---
    if [[ -f /proc/net/if_inet6 ]]; then
        print_info "IPv6 detected. Ensuring UFW is configured for IPv6..."
        if grep -q '^IPV6=yes' /etc/default/ufw; then
            print_info "UFW IPv6 support is already enabled."
        else
            sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
            if ! grep -q '^IPV6=yes' /etc/default/ufw; then
                echo "IPV6=yes" >> /etc/default/ufw
            fi
            print_success "Enabled IPv6 support in /etc/default/ufw."
            log "Enabled UFW IPv6 support."
        fi
    else
        print_info "No IPv6 detected on this system. Skipping UFW IPv6 configuration."
        log "UFW IPv6 configuration skipped as no kernel support was detected."
    fi

    # Add temporary rule for current SSH port
    if [[ -n "$PREVIOUS_SSH_PORT" && "$PREVIOUS_SSH_PORT" != "$SSH_PORT" ]]; then
        print_info "Temporarily adding UFW rule for current SSH port $PREVIOUS_SSH_PORT for transition..."
        if ! ufw status | grep -qw "$PREVIOUS_SSH_PORT/tcp"; then
            ufw allow "$PREVIOUS_SSH_PORT"/tcp comment 'Temporary SSH for transition'
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
    print_warning "ACTION REQUIRED: Check your VPS provider's edge firewall to allow opened ports (e.g., $SSH_PORT/tcp, 41641/udp for Tailscale)."
    ufw status verbose | tee -a "$LOG_FILE"
    log "Firewall configuration completed."
}

configure_fail2ban() {
    print_section "Fail2Ban Configuration"

    # --- Collect User IPs to Ignore ---
    local -a IGNORE_IPS=("127.0.0.1/8" "::1") # Array for easier dedup.
    local -a INVALID_IPS=()
    local prompt_change=""

    # Auto-detect and offer to whitelist current SSH connection
    local DETECTED_IP=""
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        DETECTED_IP="${SSH_CONNECTION%% *}"
    fi
    if [[ -z "$DETECTED_IP" ]]; then
        local WHO_IP
        WHO_IP=$(who -m 2>/dev/null | awk '{print $NF}' | tr -d '()')
        if validate_ip_or_cidr "$WHO_IP"; then
            DETECTED_IP="$WHO_IP"
        fi
    fi
    if [[ -z "$DETECTED_IP" ]]; then
        local SS_IP
        SS_IP=$(ss -tnH state established '( dport = :22 or sport = :22 )' 2>/dev/null | head -n 1 | awk '{print $NF}' | cut -d: -f1 | cut -d] -f1)
        if validate_ip_or_cidr "$SS_IP"; then
             DETECTED_IP="$SS_IP"
        fi
    fi
    if [[ -n "$DETECTED_IP" ]]; then
        print_info "Detected SSH connection from: $DETECTED_IP"

        if confirm "Whitelist your current IP ($DETECTED_IP) in Fail2Ban?"; then
            IGNORE_IPS+=("$DETECTED_IP")
            print_success "Added your current IP to whitelist."
            log "Auto-whitelisted SSH connection IP: $DETECTED_IP"
        fi
        prompt_change=" additional"
    else
        print_warning "Could not auto-detect current SSH IP. (This is normal in some VM/sudo environments)"
        print_info "You can manually add your IP in the next step."
    fi

    if [[ $VERBOSE != false ]] && \
        confirm "Add$prompt_change IP addresses or CIDR ranges to Fail2Ban ignore list (e.g., Tailscale)?"; then
        while true; do
            local -a WHITELIST_IPS=()
            log "Prompting user for IP addresses or CIDR ranges to whitelist via Fail2Ban ignore list..."
            printf '%s\n' "${CYAN}Enter IP addresses or CIDR ranges to whitelist, separated by spaces.${NC}"
            printf '%s\n' "Examples:"
            printf '  %-24s %s\n' "Single IP:" "192.168.1.100"
            printf '  %-24s %s\n' "CIDR Range:" "10.0.0.0/8"
            printf '  %-24s %s\n' "IPv6 Address:" "2606:4700::1111"
            printf '  %-24s %s\n' "Tailscale Range:" "100.64.0.0/10"
            read -ra WHITELIST_IPS -p "  > "
            if (( ${#WHITELIST_IPS[@]} == 0 )); then
                print_info "No IP addresses entered. Skipping."
                break
            fi
            local valid=true
            INVALID_IPS=()
            for ip in "${WHITELIST_IPS[@]}"; do
                if ! validate_ip_or_cidr "$ip"; then
                    valid=false
                    INVALID_IPS+=("$ip")
                fi
            done
            if [[ "$valid" == true ]]; then
                IGNORE_IPS+=( "${WHITELIST_IPS[@]}" )
                break
            else
                local s=""
                (( ${#INVALID_IPS[@]} > 1 )) && s="s" # Plural if > 1
                print_error "Invalid IP$s: ${INVALID_IPS[*]}"
                printf '%s\n\n' "Please try again. Leave blank to skip."
            fi
        done
    fi
    # Deduplicate final IGNORE_IPS
    if (( ${#IGNORE_IPS[@]} > 0 )); then
        local -A seen=()
        local -a unique=()
        for ip in "${IGNORE_IPS[@]}"; do
            if [[ ! -v seen[$ip] ]]; then
                seen[$ip]=1
                unique+=( "$ip" )
            fi
        done
        IGNORE_IPS=( "${unique[@]}" )
    fi
    if (( ${#IGNORE_IPS[@]} > 2 )); then
        local WHITELIST_STR
        printf -v WHITELIST_STR "Whitelisting:\n"
        for ip in "${IGNORE_IPS[@]:2}"; do # Skip first two entries in console output ("127.0.0.1/8" "::1").
            printf -v WHITELIST_STR "%s  %s\n" "$WHITELIST_STR" "$ip"
        done
        print_info "$WHITELIST_STR"
    fi

    # --- Define Desired Configurations ---
    local UFW_PROBES_CONFIG
    UFW_PROBES_CONFIG=$(cat <<'EOF'
[Definition]
# This regex looks for the standard "[UFW BLOCK]" message in /var/log/ufw.log
failregex = \[UFW BLOCK\] IN=.* OUT=.* SRC=<HOST>
ignoreregex =
EOF
)

    local JAIL_LOCAL_CONFIG
    JAIL_LOCAL_CONFIG=$(cat <<EOF
[DEFAULT]
ignoreip = ${IGNORE_IPS[*]}
bantime = 1d
findtime = 10m
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = $SSH_PORT

# This jail monitors UFW logs for rejected packets (port scans, etc.).
[ufw-probes]
enabled = true
port = all
filter = ufw-probes
logpath = /var/log/ufw.log
maxretry = 3
EOF
)

    local UFW_FILTER_PATH="/etc/fail2ban/filter.d/ufw-probes.conf"
    local JAIL_LOCAL_PATH="/etc/fail2ban/jail.local"

    # --- Idempotency Check ---
    if [[ -f "$UFW_FILTER_PATH" && -f "$JAIL_LOCAL_PATH" ]] && \
       cmp -s "$UFW_FILTER_PATH" <<<"$UFW_PROBES_CONFIG" && \
       cmp -s "$JAIL_LOCAL_PATH" <<<"$JAIL_LOCAL_CONFIG"; then
        print_info "Fail2Ban is already configured correctly. Skipping."
        log "Fail2Ban configuration is already correct."
        return 0
    fi

    # --- Apply Configuration ---
    print_info "Applying new Fail2Ban configuration..."
    mkdir -p /etc/fail2ban/filter.d
    echo "$UFW_PROBES_CONFIG" > "$UFW_FILTER_PATH"
    echo "$JAIL_LOCAL_CONFIG" > "$JAIL_LOCAL_PATH"

    # --- Ensure the log file exists BEFORE restarting the service ---
    if [[ ! -f /var/log/ufw.log ]]; then
        touch /var/log/ufw.log
        print_info "Created empty /var/log/ufw.log to ensure Fail2Ban starts correctly."
    fi

    # --- Restart and Verify Fail2ban ---
    print_info "Enabling and restarting Fail2Ban to apply new rules..."
    systemctl enable fail2ban
    systemctl restart fail2ban
    sleep 2

    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2Ban is active with the new configuration."
        fail2ban-client status | tee -a "$LOG_FILE"

        # Show how to add IPs later
        if (( ${#INVALID_IPS[@]} > 0 )) || confirm "Show instructions for adding IPs later?" "n"; then
            printf "\n"
            if [[ $VERBOSE == false ]]; then
                printf '%s\n' "${PURPLE}ℹ Fail2Ban ignore list modification:${NC}"
            fi
            print_info "To add more IP addresses to Fail2Ban ignore list later:"
            printf "%s1. Edit the configuration file:%s\n" "$CYAN" "$NC"
            printf "   %ssudo nano /etc/fail2ban/jail.local%s\n" "$BOLD" "$NC"
            printf "%s2. Update the 'ignoreip' line under [DEFAULT]:%s\n" "$CYAN" "$NC"
            printf "   %signoreip = 127.0.0.1/8 ::1 YOUR_IP_HERE%s\n" "$BOLD" "$NC"
            printf "%s3. Restart Fail2Ban:%s\n" "$CYAN" "$NC"
            printf "   %ssudo systemctl restart fail2ban%s\n" "$BOLD" "$NC"
            printf "%s4. Verify the configuration:%s\n" "$CYAN" "$NC"
            printf "   %ssudo fail2ban-client status%s\n" "$BOLD" "$NC"
            printf "\n"
            log "Displayed post-installation Fail2Ban instructions."
        fi
    else
        print_error "Fail2Ban service failed to start. Check 'journalctl -u fail2ban' for errors."
        FAILED_SERVICES+=("fail2ban")
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

configure_kernel_hardening() {
    print_section "Kernel Parameter Hardening (sysctl)"
    if ! confirm "Apply recommended kernel security settings (sysctl)?"; then
        print_info "Skipping kernel hardening."
        log "Kernel hardening skipped by user."
        return 0
    fi

    local KERNEL_HARDENING_CONFIG
    KERNEL_HARDENING_CONFIG=$(mktemp)
    # create the config in a temporary file
    tee "$KERNEL_HARDENING_CONFIG" > /dev/null <<'EOF'
# Recommended Security Settings managed by du_setup.sh
# For details, see: https://www.kernel.org/doc/Documentation/sysctl/

# --- IPV4 Networking ---
# Protect against IP spoofing
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
# Block SYN-FLOOD attacks
net.ipv4.tcp_syncookies=1
# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=1
net.ipv4.conf.default.secure_redirects=1
# Ignore source-routed packets
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
# Log martian packets (packets with impossible source addresses)
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1

# --- IPV6 Networking (if enabled) ---
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0

# --- Kernel Security ---
# Enable ASLR (Address Space Layout Randomization) for better security
kernel.randomize_va_space=2
# Restrict access to kernel pointers in /proc to prevent leaks
kernel.kptr_restrict=2
# Restrict access to dmesg for unprivileged users
kernel.dmesg_restrict=1
# Restrict ptrace scope to prevent process injection attacks
kernel.yama.ptrace_scope=1

# --- Filesystem Security ---
# Protect against TOCTOU (Time-of-Check to Time-of-Use) race conditions
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF

    local SYSCTL_CONF_FILE="/etc/sysctl.d/99-du-hardening.conf"

    # Idempotency check: only update if the file doesn't exist or has changed
    if [[ -f "$SYSCTL_CONF_FILE" ]] && cmp -s "$KERNEL_HARDENING_CONFIG" "$SYSCTL_CONF_FILE"; then
        print_info "Kernel security settings are already configured correctly."
        rm -f "$KERNEL_HARDENING_CONFIG"
        log "Kernel hardening settings already in place."
        return 0
    fi

    print_info "Applying settings to $SYSCTL_CONF_FILE..."
    # Move the new config into place
    mv "$KERNEL_HARDENING_CONFIG" "$SYSCTL_CONF_FILE"
    chmod 644 "$SYSCTL_CONF_FILE"

    print_info "Loading new settings..."
    if sysctl -p "$SYSCTL_CONF_FILE" >/dev/null 2>&1; then
        print_success "Kernel security settings applied successfully."
        log "Applied kernel hardening settings."
    else
        print_error "Failed to apply kernel settings. Check for kernel compatibility."
        log "sysctl -p failed for kernel hardening config."
    fi
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
    curl -fsSL "https://download.docker.com/linux/${ID}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    # shellcheck source=/dev/null
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
    tee "$NEW_DOCKER_CONFIG" > /dev/null <<DAEMONFILE
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "5",
        "compress": "true"
    },
    "live-restore": true,
    "dns": [
        "9.9.9.9",
        "1.1.1.1",
        "208.67.222.222"
    ],
    "default-address-pools": [
        {
            "base": "172.80.0.0/16",
            "size": 24
        }
    ],
    "userland-proxy": false,
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 64000,
            "Soft": 64000
        }
    },
    "features": {
        "buildkit": true
    }
}
DAEMONFILE
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
    # Offer dtop installation
    install_dtop_optional
}

install_dtop_optional() {
    if sudo sh -c 'command -v dtop' >/dev/null 2>&1 || command -v dtop >/dev/null 2>&1; then
        print_info "dtop is already installed."
        return 0
    fi
    if ! confirm "Install 'dtop' (Docker container monitoring TUI)?"; then
        print_info "Skipping dtop installation."
        return 0
    fi
    print_info "Installing dtop for user '$USERNAME'..."
    local DTOP_INSTALLER="/tmp/dtop-installer.sh"
    if ! curl -fsSL "https://github.com/amir20/dtop/releases/latest/download/dtop-installer.sh" -o "$DTOP_INSTALLER"; then
        print_warning "Failed to download dtop installer. Continuing setup..."
        log "Failed to download dtop installer."
        return 0
    fi
    chmod +x "$DTOP_INSTALLER"
    # shellcheck disable=SC2064
    trap "rm -f '$DTOP_INSTALLER'" RETURN
    local USER_HOME
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
    local USER_LOCAL_BIN="$USER_HOME/.local/bin"
    if [[ ! -d "$USER_LOCAL_BIN" ]]; then
        print_info "Creating $USER_LOCAL_BIN..."
        if ! sudo -u "$USERNAME" mkdir -p "$USER_LOCAL_BIN"; then
            print_warning "Failed to create $USER_LOCAL_BIN. Skipping dtop."
            return 0
        fi
    fi
    # shellcheck disable=SC2024
    if sudo -u "$USERNAME" bash "$DTOP_INSTALLER" < /dev/null >> "$LOG_FILE" 2>&1; then
        # Verify installation
        if [[ -f "$USER_LOCAL_BIN/dtop" ]]; then
            sudo -u "$USERNAME" chmod +x "$USER_LOCAL_BIN/dtop"
            local BASHRC="$USER_HOME/.bashrc"
            if [[ -f "$BASHRC" ]] && ! grep -q "\.local/bin" "$BASHRC"; then
                print_info "Adding ~/.local/bin to PATH in $BASHRC..."
                {
                    echo ''
                    echo '# Add local bin to PATH'
                    # shellcheck disable=SC2016
                    echo 'if [ -d "$HOME/.local/bin" ]; then PATH="$HOME/.local/bin:$PATH"; fi'
                } >> "$BASHRC"
                chown "$USERNAME:$USERNAME" "$BASHRC"
                if grep -q "\.local/bin" "$BASHRC"; then
                    print_info "PATH configuration updated successfully."
                else
                    print_warning "Failed to update PATH, but dtop is still installed."
                fi
            fi
            print_success "dtop installed successfully to $USER_LOCAL_BIN."
            log "dtop installed to $USER_LOCAL_BIN for user $USERNAME"
        else
            print_warning "dtop installer finished, but binary not found at $USER_LOCAL_BIN/dtop"
            log "dtop binary missing after user installation attempt."
        fi
    else
        print_warning "dtop installation script failed. Continuing setup..."
        log "dtop installation script failed."
    fi
}

install_tailscale() {
    if ! confirm "Install and configure Tailscale VPN (Optional)?"; then
        print_info "Skipping Tailscale installation."
        log "Tailscale installation skipped by user."
        return 0
    fi
    print_section "Tailscale VPN Installation and Configuration"

    # Check if Tailscale is already installed and active
    if command -v tailscale >/dev/null 2>&1; then
        if systemctl is-active --quiet tailscaled && tailscale ip >/dev/null 2>&1; then
            local TS_IPS TS_IPV4
            TS_IPS=$(tailscale ip 2>/dev/null || echo "Unknown")
            TS_IPV4=$(echo "$TS_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo "Unknown")
            print_success "Service tailscaled is active and connected. Node IPv4 in tailnet: $TS_IPV4"
            echo "$TS_IPS" > /tmp/tailscale_ips.txt
        else
            print_warning "Service tailscaled is installed but not active or connected."
            FAILED_SERVICES+=("tailscaled")
            TS_COMMAND=$(grep "Tailscale connection failed: tailscale up" "$LOG_FILE" | tail -1 | sed 's/.*Tailscale connection failed: //')
            TS_COMMAND=${TS_COMMAND:-""}
        fi
    else
        print_info "Installing Tailscale..."
        # Gracefully handle download failures
        if ! curl -fsSL https://tailscale.com/install.sh -o /tmp/tailscale_install.sh; then
            print_error "Failed to download the Tailscale installation script."
            print_info "After setup completes, please try installing it manually: curl -fsSL https://tailscale.com/install.sh | sh"
            rm -f /tmp/tailscale_install.sh # Clean up partial download
            return 0 # Exit the function without exiting the main script
        fi

        # Execute the downloaded script with 'sh'
        if ! sh /tmp/tailscale_install.sh; then
            print_error "Tailscale installation script failed to execute."
            log "Tailscale installation failed."
            rm -f /tmp/tailscale_install.sh # Clean up
            return 0 # Exit the function gracefully
        fi

        rm -f /tmp/tailscale_install.sh # Clean up successful install
        print_success "Tailscale installation complete."
        log "Tailscale installation completed."
    fi

    if systemctl is-active --quiet tailscaled && tailscale ip >/dev/null 2>&1; then
        local TS_IPS TS_IPV4
        TS_IPS=$(tailscale ip 2>/dev/null || echo "Unknown")
        TS_IPV4=$(echo "$TS_IPS" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo "Unknown")
        print_info "Tailscale is already connected. Node IPv4 in tailnet: $TS_IPV4"
        echo "$TS_IPS" > /tmp/tailscale_ips.txt
        return 0
    fi

    if ! confirm "Configure Tailscale now?"; then
        print_info "You can configure Tailscale later by running: sudo tailscale up"
        print_info "If you are using a custom Tailscale server, use: sudo tailscale up --login-server=<your_server_url>"
        return 0
    fi

    print_info "Configuring Tailscale connection..."
    printf '%s\n' "${CYAN}Choose Tailscale connection method:${NC}"
    printf '  1) Standard Tailscale (requires pre-auth key from https://login.tailscale.com/admin)\n'
    printf '  2) Custom Tailscale server (requires server URL and pre-auth key)\n'
    read -rp "$(printf '%s' "${CYAN}Enter choice (1-2) [1]: ${NC}")" TS_CONNECTION
    TS_CONNECTION=${TS_CONNECTION:-1}
    local AUTH_KEY LOGIN_SERVER=""
    if [[ "$TS_CONNECTION" == "2" ]]; then
        while true; do
            read -rp "$(printf '%s' "${CYAN}Enter Tailscale server URL (e.g., https://ts.mydomain.cloud): ${NC}")" LOGIN_SERVER
            if [[ "$LOGIN_SERVER" =~ ^https://[a-zA-Z0-9.-]+(:[0-9]+)?$ ]]; then break; else print_error "Invalid URL. Must start with https://. Try again."; fi
        done
    fi
    while true; do
        read -rsp "$(printf '%s' "${CYAN}Enter Tailscale pre-auth key: ${NC}")" AUTH_KEY
        printf '\n'
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
    TS_COMMAND_SAFE=$(echo "$TS_COMMAND" | sed -E 's/--auth-key=[^[:space:]]+/--auth-key=REDACTED/g')
    print_info "Connecting to Tailscale with: $TS_COMMAND_SAFE"
    if ! $TS_COMMAND; then
        print_warning "Failed to connect to Tailscale. Possible issues: invalid pre-auth key, network restrictions, or server unavailability."
        print_info "Please run the following command manually after resolving the issue:"
        printf '%s\n' "${CYAN}  $TS_COMMAND_SAFE${NC}"
        log "Tailscale connection failed: $TS_COMMAND_SAFE"
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
            log "Tailscale connected: $TS_COMMAND_SAFE"
            # Store connection details for summary
            echo "${LOGIN_SERVER:-https://controlplane.tailscale.com}" > /tmp/tailscale_server
            echo "$TS_IPS" > /tmp/tailscale_ips.txt
            echo "None" > /tmp/tailscale_flags
        else
            print_warning "Tailscale connection attempt succeeded, but no IPs assigned."
            print_info "Please verify with 'tailscale ip' and run the following command manually if needed:"
            printf '%s\n' "${CYAN}  $TS_COMMAND_SAFE${NC}"
            log "Tailscale connection not verified: $TS_COMMAND_SAFE"
            tailscale status > /tmp/tailscale_status.txt 2>&1
            log "Tailscale status output saved to /tmp/tailscale_status.txt for debugging"
        fi
    fi

    # --- Configure Additional Flags ---
    print_info "Select additional Tailscale options to configure (comma-separated, e.g., 1,3):"
    printf '%s\n' "${CYAN}  1) SSH (--ssh) - WARNING: May restrict server access to Tailscale connections only${NC}"
    printf '%s\n' "${CYAN}  2) Advertise as Exit Node (--advertise-exit-node)${NC}"
    printf '%s\n' "${CYAN}  3) Accept DNS (--accept-dns)${NC}"
    printf '%s\n' "${CYAN}  4) Accept Routes (--accept-routes)${NC}"
    printf '%s\n' "${CYAN}  Enter numbers (1-4) or leave blank to skip:${NC}"
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
            TS_COMMAND_SAFE=$(echo "$TS_COMMAND" | sed -E 's/--auth-key=[^[:space:]]+/--auth-key=REDACTED/g')
            print_info "Reconfiguring Tailscale with additional options: $TS_COMMAND_SAFE"
            if ! $TS_COMMAND; then
                print_warning "Failed to reconfigure Tailscale with additional options."
                print_info "Please run the following command manually after resolving the issue:"
                printf '%s\n' "${CYAN}  $TS_COMMAND_SAFE${NC}"
                log "Tailscale reconfiguration failed: $TS_COMMAND_SAFE"
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
                    log "Tailscale reconfigured: $TS_COMMAND_SAFE"
		    # Store flags and IPs for summary
                    echo "$TS_FLAGS" | sed 's/ --/ /g' | sed 's/^ *//' > /tmp/tailscale_flags
                    echo "$TS_IPS" > /tmp/tailscale_ips.txt
                else
                    print_warning "Tailscale reconfiguration attempt succeeded, but no IPs assigned."
                    print_info "Please verify with 'tailscale ip' and run the following command manually if needed:"
                    printf '%s\n' "${CYAN}  $TS_COMMAND_SAFE${NC}"
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
    local CRON_MARKER="#-*- installed by du_setup script -*-"

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
        read -rp "$(printf '%s' "${CYAN}Enter backup destination (e.g., u12345@u12345.your-storagebox.de): ${NC}")" BACKUP_DEST
        if [[ "$BACKUP_DEST" =~ ^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$ ]]; then break; else print_error "Invalid format. Expected user@host. Please try again."; fi
    done

    while true; do
        read -rp "$(printf '%s' "${CYAN}Enter destination SSH port (Hetzner uses 23) [22]: ${NC}")" BACKUP_PORT
        BACKUP_PORT=${BACKUP_PORT:-22}
        if [[ "$BACKUP_PORT" =~ ^[0-9]+$ && "$BACKUP_PORT" -ge 1 && "$BACKUP_PORT" -le 65535 ]]; then break; else print_error "Invalid port. Must be between 1 and 65535. Please try again."; fi
    done

    while true; do
        read -rp "$(printf '%s' "${CYAN}Enter remote backup path (e.g., /home/my_backups/): ${NC}")" REMOTE_BACKUP_PATH
        if [[ "$REMOTE_BACKUP_PATH" =~ ^/[^[:space:]]*/$ ]]; then break; else print_error "Invalid path. Must start and end with '/' and contain no spaces. Please try again."; fi
    done

    print_info "Backup target set to: ${BACKUP_DEST}:${REMOTE_BACKUP_PATH} on port ${BACKUP_PORT}"

    # --- Hetzner Specific Handling ---
    if confirm "Is this backup destination a Hetzner Storage Box (requires special -s flag for key copy)?"; then
        SSH_COPY_ID_FLAGS="-s"
        print_info "Hetzner Storage Box mode enabled. Using '-s' for ssh-copy-id."
    fi

    # --- Handle SSH Key Copy ---
    printf '%s\n' "${CYAN}Choose how to copy the root SSH key:${NC}"
    printf '  1) Automate with password (requires sshpass, password stored briefly in memory)\n'
    printf '  2) Manual copy (recommended)\n'
    read -rp "$(printf '%s' "${CYAN}Enter choice (1-2) [2]: ${NC}")" KEY_COPY_CHOICE
    KEY_COPY_CHOICE=${KEY_COPY_CHOICE:-2}
    if [[ "$KEY_COPY_CHOICE" == "1" ]]; then
        if ! command -v sshpass >/dev/null 2>&1; then
            print_info "Installing sshpass for automated key copying..."
            if ! { apt-get update -qq && apt-get install -y -qq sshpass; }; then
                print_warning "Failed to install sshpass. Falling back to manual copy."
                KEY_COPY_CHOICE=2
            fi
        fi
        if [[ "$KEY_COPY_CHOICE" == "1" ]]; then
            read -rsp "$(printf '%s' "${CYAN}Enter password for $BACKUP_DEST: ${NC}")" BACKUP_PASSWORD; printf '\n'
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
        printf 'This will allow the root user to connect without a password for automated backups.\n'
        printf '%s' "${YELLOW}The root user's public key is:${NC}"; cat "${ROOT_SSH_KEY}.pub"; printf '\n'
        printf '%s\n' "${YELLOW}Run the following command from this server's terminal to copy the key:${NC}"
        printf '%s\n' "${CYAN}ssh-copy-id -p \"${BACKUP_PORT}\" -i \"${ROOT_SSH_KEY}.pub\" ${SSH_COPY_ID_FLAGS} \"${BACKUP_DEST}\"${NC}"; printf '\n'
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
            print_info "  - Check port: nc -zv $(echo "$BACKUP_DEST" | cut -d'@' -f2) \"$BACKUP_PORT\""
            print_info "  - Ensure key is in ~/.ssh/authorized_keys on the backup server."
            if [[ -n "$SSH_COPY_ID_FLAGS" ]]; then
                print_info "  - For Hetzner, ensure ~/.ssh/ exists: ssh -p \"$BACKUP_PORT\" \"$BACKUP_DEST\" \"mkdir -p ~/.ssh && chmod 700 ~/.ssh\""
            fi
        fi
    fi

    # --- Collect Backup Source Directories ---
    local BACKUP_DIRS_ARRAY=()
    while true; do
        print_info "Enter the full paths of directories to back up, separated by spaces."
        read -rp "$(printf '%s' "${CYAN}Default is '/home/${USERNAME}/'. Press Enter for default or provide your own: ${NC}")" -a user_input_dirs

        if [ ${#user_input_dirs[@]} -eq 0 ]; then
            BACKUP_DIRS_ARRAY=("/home/${USERNAME}/")
            break
        fi

        local all_valid=true
        for dir in "${user_input_dirs[@]}"; do
            if [[ ! "$dir" =~ ^/ ]]; then
                print_error "Invalid path: '$dir'. All paths must be absolute (start with '/'). Please try again."
                all_valid=false
                break
            fi
        done

        if [[ "$all_valid" == true ]]; then
            BACKUP_DIRS_ARRAY=("${user_input_dirs[@]}")
            break
        fi
    done
    # Convert array to a space-separated string for the backup script
    local BACKUP_DIRS_STRING="${BACKUP_DIRS_ARRAY[*]}"
    print_info "Directories to be backed up: $BACKUP_DIRS_STRING"

    # --- Create Exclude File ---
    print_info "Creating rsync exclude file at $EXCLUDE_FILE_PATH..."
    tee "$EXCLUDE_FILE_PATH" > /dev/null <<'EOF'
# Default Exclusions
.cache/
.docker/
.local/
.npm/
.ssh/
.vscode-server/
*.log
*.tmp
node_modules/
.bashrc
.bash_history
.bash_logout
.cloud-locale-test.skip
.profile
.wget-hsts
EOF
    if confirm "Add more directories/files to the exclude list?"; then
        read -rp "$(printf '%s' "${CYAN}Enter items separated by spaces (e.g., Videos/ 'My Documents/'): ${NC}")" -a extra_excludes
        for item in "${extra_excludes[@]}"; do echo "$item" >> "$EXCLUDE_FILE_PATH"; done
    fi
    chmod 600 "$EXCLUDE_FILE_PATH"
    print_success "Rsync exclude file created."

    # --- Collect Cron Schedule ---
    local CRON_SCHEDULE="5 3 * * *"
    print_info "Enter a cron schedule for the backup. Use https://crontab.guru for help."
    read -rp "$(printf '%s' "${CYAN}Enter schedule (default: daily at 3:05 AM) [${CRON_SCHEDULE}]: ${NC}")" input
    CRON_SCHEDULE="${input:-$CRON_SCHEDULE}"
    if ! echo "$CRON_SCHEDULE" | grep -qE '^((\*\/)?[0-9,-]+|\*)\s+(((\*\/)?[0-9,-]+|\*)\s+){3}((\*\/)?[0-9,-]+|\*|[0-6])$'; then
        print_error "Invalid cron expression. Using default: ${CRON_SCHEDULE}"
    fi

    # --- Collect Notification Details ---
    local NOTIFICATION_SETUP="none" NTFY_URL="" NTFY_TOKEN="" DISCORD_WEBHOOK=""
    if confirm "Enable backup status notifications?"; then
        printf '%s' "${CYAN}Select notification method: 1) ntfy.sh  2) Discord  [1]: ${NC}"; read -r n_choice
        if [[ "$n_choice" == "2" ]]; then
            NOTIFICATION_SETUP="discord"
            read -rp "$(printf '%s' "${CYAN}Enter Discord Webhook URL: ${NC}")" DISCORD_WEBHOOK
            if [[ ! "$DISCORD_WEBHOOK" =~ ^https://discord.com/api/webhooks/ ]]; then
                print_error "Invalid Discord webhook URL."
                log "Invalid Discord webhook URL provided."
                return 1
            fi
        else
            NOTIFICATION_SETUP="ntfy"
            read -rp "$(printf '%s' "${CYAN}Enter ntfy URL/topic (e.g., https://ntfy.sh/my-backups): ${NC}")" NTFY_URL
            read -rp "$(printf '%s' "${CYAN}Enter ntfy Access Token (optional): ${NC}")" NTFY_TOKEN
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
BACKUP_DIRS="${BACKUP_DIRS_STRING}"
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
rsync_output=$(rsync -avz --delete --stats --exclude-from="$EXCLUDE_FILE" -e "ssh -p $SSH_PORT" $BACKUP_DIRS "${REMOTE_DEST}:${REMOTE_PATH}" 2>&1)
rsync_exit_code=$?; echo "$rsync_output" >> "$LOG_FILE"
# --- NOTIFICATION ---
if [[ $rsync_exit_code -eq 0 ]]; then
    data_transferred=$(echo "$rsync_output" | grep 'Total transferred file size' | awk '{print $5}' | sed 's/,//g')
    human_readable=$(numfmt --to=iec-i --suffix=B --format="%.2f" "$data_transferred" 2>/dev/null || echo "0 B")
    printf -v message "Backup completed successfully.\nData Transferred: %s" "${human_readable}"
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
        return 0
    fi

    local BACKUP_SCRIPT_PATH="/root/run_backup.sh"
    if [[ ! -f "$BACKUP_SCRIPT_PATH" || ! -r "$BACKUP_SCRIPT_PATH" ]]; then
        print_error "Backup script not found or not readable at $BACKUP_SCRIPT_PATH."
        log "Backup test failed: Script not found or not readable."
        return 0
    fi

    if ! command -v timeout >/dev/null 2>&1; then
        print_error "The 'timeout' command is not available. Please install coreutils."
        log "Backup test failed: 'timeout' command not found."
        return 0
    fi

    if ! confirm "Run a test backup to verify configuration?"; then
        print_info "Skipping backup test."
        log "Backup test skipped by user."
        return 0
    fi

    # Extract backup configuration from the generated backup script
    local BACKUP_DEST REMOTE_BACKUP_PATH BACKUP_PORT
    BACKUP_DEST=$(grep "^REMOTE_DEST=" "$BACKUP_SCRIPT_PATH" | cut -d'"' -f2 2>/dev/null || echo "unknown")
    BACKUP_PORT=$(grep "^SSH_PORT=" "$BACKUP_SCRIPT_PATH" | cut -d'"' -f2 2>/dev/null || echo "22")
    REMOTE_BACKUP_PATH=$(grep "^REMOTE_PATH=" "$BACKUP_SCRIPT_PATH" | cut -d'"' -f2 2>/dev/null || echo "unknown")
    local BACKUP_LOG="/var/log/backup_rsync.log"

    if [[ "$BACKUP_DEST" == "unknown" || "$REMOTE_BACKUP_PATH" == "unknown" ]]; then
        print_error "Could not parse backup configuration from $BACKUP_SCRIPT_PATH."
        log "Backup test failed: Invalid configuration in $BACKUP_SCRIPT_PATH."
        return 0
    fi

    # Create a temporary directory and file for the test
    local TEST_DIR TEST_FILE
    TEST_DIR="/root/test_backup_$(date +%Y%m%d_%H%M%S)"
    TEST_FILE="$TEST_DIR/test_backup_verification_$(date +%s).txt"
    if ! mkdir -p "$TEST_DIR" || ! echo "Test file for backup verification - $(date)" > "$TEST_FILE"; then
        print_error "Failed to create test directory or file in /root/."
        log "Backup test failed: Cannot create test directory/file."
        rm -rf "$TEST_DIR" 2>/dev/null
        return 0
    fi

    print_info "Running test backup of single file to ${BACKUP_DEST}:${REMOTE_BACKUP_PATH}..."
    local RSYNC_OUTPUT RSYNC_EXIT_CODE TIMEOUT_DURATION=60
    local SSH_KEY="/root/.ssh/id_ed25519"
    local SSH_COMMAND="ssh -p $BACKUP_PORT -i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no"

    set +e
    RSYNC_OUTPUT=$(timeout "$TIMEOUT_DURATION" rsync -avz -e "$SSH_COMMAND" "$TEST_FILE" "${BACKUP_DEST}:${REMOTE_BACKUP_PATH}" 2>&1)
    RSYNC_EXIT_CODE=$?
    set -e

    {
        echo "--- Test Backup at $(date) ---"
        echo "Command: rsync -avz -e \"$SSH_COMMAND\" \"$TEST_FILE\" \"${BACKUP_DEST}:${REMOTE_BACKUP_PATH}\""
        echo "Output:"
        echo "$RSYNC_OUTPUT"
        echo "Exit Code: $RSYNC_EXIT_CODE"
    } >> "$BACKUP_LOG"

    if [[ $RSYNC_EXIT_CODE -eq 0 ]]; then
        print_success "Test backup (single file) successful! Check $BACKUP_LOG for details."
        log "Test backup successful (single file)."
        ssh -p "$BACKUP_PORT" -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=no "$BACKUP_DEST" "rm -f '${REMOTE_BACKUP_PATH}$(basename "$TEST_FILE")'" > /dev/null 2>&1 || true
        log "Attempted cleanup of remote test file: ${REMOTE_BACKUP_PATH}$(basename "$TEST_FILE")"

    else
        print_warning "The backup test (single file transfer) failed. This is not critical, and the script will continue."
        print_info "You can troubleshoot this after the server setup is complete."

        if [[ $RSYNC_EXIT_CODE -eq 124 ]]; then
            print_error "Test backup timed out after $TIMEOUT_DURATION seconds."
            log "Test backup failed: Timeout after $TIMEOUT_DURATION seconds."
        else
            print_error "Test backup failed (exit code: $RSYNC_EXIT_CODE). See $BACKUP_LOG for details."
            log "Test backup failed with exit code $RSYNC_EXIT_CODE."
            # Hints based on common rsync errors
            case "$RSYNC_OUTPUT" in
                *"Permission denied"*)
                    print_info "Hint: Check SSH key authentication and permissions on the remote path."
                    ;;
                *"Connection timed out"*|*"Connection refused"*|*"Network is unreachable"*)
                    print_info "Hint: Check network connectivity, firewall rules (local and remote), and the SSH port."
                    ;;
                *"No such file or directory"*)
                    print_info "Hint: Verify the remote path '${REMOTE_BACKUP_PATH}' is correct and accessible."
                    ;;
            esac
        fi

        print_info "Common troubleshooting steps:"
        print_info "  - Ensure the root SSH key is copied: ssh-copy-id -p \"$BACKUP_PORT\" -i \"$SSH_KEY.pub\" \"$BACKUP_DEST\""
        print_info "  - Manually test SSH connection: ssh -p \"$BACKUP_PORT\" -i \"$SSH_KEY\" \"$BACKUP_DEST\""
        print_info "  - Check permissions on the remote path: '${REMOTE_BACKUP_PATH}'"
    fi

    # Clean up the local temporary test directory and file
    rm -rf "$TEST_DIR" 2>/dev/null
    print_info "Local test directory cleaned up."
    print_success "Backup test completed."
    log "Backup test completed."
    return 0
}

configure_swap() {
    if [[ "$IS_CONTAINER" == true ]]; then
        print_info "Swap configuration skipped in container."
        return 0
    fi
    print_section "Swap Configuration"

    if lsblk -r | grep -q '\[SWAP\]'; then
        print_warning "Existing swap partition found on disk."
    fi

    # Detect active swap
    local existing_swap swap_type
    existing_swap=$(swapon --show=NAME,TYPE,SIZE --noheadings --bytes 2>/dev/null | head -n 1 | awk '{print $1}' || true)

    if [[ -n "$existing_swap" ]]; then
        swap_type=$(swapon --show=NAME,TYPE,SIZE --noheadings | head -n 1 | awk '{print $2}')
        local display_size
        display_size=$(du -h "$existing_swap" 2>/dev/null | awk '{print $1}' || echo "Unknown")

        print_info "Existing swap detected: $existing_swap (Type: $swap_type, Size: $display_size)"

        # --- Case 1: Partition detected ---
        if [[ "$swap_type" == "partition" ]] || [[ "$existing_swap" =~ ^/dev/ ]]; then
            print_warning "The detected swap is a disk partition, which cannot be resized by this script."

            if confirm "Disable this swap partition and create a standard /swapfile instead?" "n"; then
                print_info "Disabling swap partition $existing_swap..."
                if ! swapoff "$existing_swap"; then
                    print_error "Failed to disable swap partition. Keeping it active."
                    return 0
                fi

                sed -i "s|^${existing_swap}[[:space:]]|#&|" /etc/fstab

                local swap_uuid
                swap_uuid=$(blkid -s UUID -o value "$existing_swap" 2>/dev/null || true)
                if [[ -n "$swap_uuid" ]]; then
                    sed -i "s|^UUID=${swap_uuid}[[:space:]]|#&|" /etc/fstab
                fi

                print_success "Swap partition disabled and removed from fstab."

                existing_swap=""
            else
                print_info "Keeping existing swap partition."
                configure_swap_settings
                return 0
            fi
        else
            # --- Case 2: Swap File detected ---
            if confirm "Modify existing swap file size?"; then
                local SWAP_SIZE
                while true; do
                    read -rp "$(printf '%s' "${CYAN}Enter new swap size (e.g., 2G, 512M) [current: $display_size]: ${NC}")" SWAP_SIZE
                    SWAP_SIZE=${SWAP_SIZE:-$display_size}
                    if convert_to_mb "$SWAP_SIZE" >/dev/null; then
                        break
                    fi
                done

                local REQUIRED_MB AVAILABLE_KB
                if ! REQUIRED_MB=$(convert_to_mb "$SWAP_SIZE"); then return 1; fi

                AVAILABLE_KB=$(df -k / | tail -n 1 | awk '{print $4}')

                # Compare (Convert MB to KB for comparison)
                if (( (AVAILABLE_KB / 1024) < REQUIRED_MB )); then
                    print_error "Insufficient disk space. Required: ${REQUIRED_MB}MB, Available: $((AVAILABLE_KB / 1024))MB"
                    exit 1
                fi

                print_info "Disabling existing swap file..."
                swapoff "$existing_swap" || { print_error "Failed to disable swap file."; exit 1; }

                print_info "Resizing swap file to $SWAP_SIZE..."

                # Try fallocate first (fast), fallback to dd (compatible)
                if ! fallocate -l "$SWAP_SIZE" "$existing_swap" 2>/dev/null; then
                    print_warning "fallocate failed. Using dd (slower)..."
                    rm -f "$existing_swap"

                    # Check if dd supports progress
                    local dd_status=""
                    if dd --version 2>&1 | grep -q "progress"; then dd_status="status=progress"; fi

                    if ! dd if=/dev/zero of="$existing_swap" bs=1M count="$REQUIRED_MB" $dd_status; then
                        print_error "Failed to create swap file with dd."
                        exit 1
                    fi
                fi

                if ! chmod 600 "$existing_swap" || ! mkswap "$existing_swap" >/dev/null || ! swapon "$existing_swap"; then
                    print_error "Failed to configure swap file."
                    exit 1
                fi
                print_success "Swap file resized to $SWAP_SIZE."
            else
                print_info "Keeping existing swap file."
            fi
            configure_swap_settings
            return 0
        fi
    fi

    # --- Case 3: Create New Swap ---
    if [[ -z "$existing_swap" ]]; then
        if ! confirm "Configure a swap file (recommended for < 4GB RAM)?"; then
            print_info "Skipping swap configuration."
            return 0
        fi

        local SWAP_SIZE
        while true; do
            read -rp "$(printf '%s' "${CYAN}Enter swap file size (e.g., 2G, 512M) [2G]: ${NC}")" SWAP_SIZE
            SWAP_SIZE=${SWAP_SIZE:-2G}
            if convert_to_mb "$SWAP_SIZE" >/dev/null; then break; fi
        done

        local REQUIRED_MB AVAILABLE_KB
        if ! REQUIRED_MB=$(convert_to_mb "$SWAP_SIZE"); then return 1; fi
        AVAILABLE_KB=$(df -k / | tail -n 1 | awk '{print $4}')

        if (( (AVAILABLE_KB / 1024) < REQUIRED_MB )); then
            print_error "Insufficient disk space. Required: ${REQUIRED_MB}MB, Available: $((AVAILABLE_KB / 1024))MB"
            exit 1
        fi

        print_info "Creating $SWAP_SIZE swap file at /swapfile..."
        if ! fallocate -l "$SWAP_SIZE" /swapfile 2>/dev/null; then
            print_warning "fallocate failed. Using dd (slower)..."

            # Check dd status support
            local dd_status=""
            if dd --version 2>&1 | grep -q "progress"; then dd_status="status=progress"; fi

            if ! dd if=/dev/zero of=/swapfile bs=1M count="$REQUIRED_MB" $dd_status; then
                print_error "Failed to create swap file."
                rm -f /swapfile || true
                exit 1
            fi
        fi

        if ! chmod 600 /swapfile || ! mkswap /swapfile >/dev/null || ! swapon /swapfile; then
            print_error "Failed to enable swap file."
            rm -f /swapfile || true
            exit 1
        fi

        # Add to fstab if missing
        if ! grep -q '^/swapfile ' /etc/fstab; then
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
            print_success "Swap entry added to /etc/fstab."
        else
            print_info "Swap entry already exists in /etc/fstab."
        fi
        print_success "Swap file created: $SWAP_SIZE"
    fi

    configure_swap_settings
}

# Helper: Apply Sysctl Settings for Swap
configure_swap_settings() {
    print_info "Configuring swap settings..."
    local SWAPPINESS=10
    local CACHE_PRESSURE=50

    if confirm "Customize swap settings (vm.swappiness and vm.vfs_cache_pressure)?"; then
        while true; do
            read -rp "$(printf '%s' "${CYAN}Enter vm.swappiness (0-100) [default: $SWAPPINESS]: ${NC}")" INPUT
            INPUT=${INPUT:-$SWAPPINESS}
            if [[ "$INPUT" =~ ^[0-9]+$ && "$INPUT" -ge 0 && "$INPUT" -le 100 ]]; then SWAPPINESS=$INPUT; break; fi
            print_error "Invalid value (0-100)."
        done
        while true; do
            read -rp "$(printf '%s' "${CYAN}Enter vm.vfs_cache_pressure (1-1000) [default: $CACHE_PRESSURE]: ${NC}")" INPUT
            INPUT=${INPUT:-$CACHE_PRESSURE}
            if [[ "$INPUT" =~ ^[0-9]+$ && "$INPUT" -ge 1 && "$INPUT" -le 1000 ]]; then CACHE_PRESSURE=$INPUT; break; fi
            print_error "Invalid value (1-1000)."
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

    if [[ -f /etc/sysctl.d/99-swap.conf ]] && cmp -s "$NEW_SWAP_CONFIG" /etc/sysctl.d/99-swap.conf; then
        print_info "Swap settings already correct. Skipping."
        rm -f "$NEW_SWAP_CONFIG"
    else
        # Scan for conflicts
        for file in /etc/sysctl.conf /etc/sysctl.d/*.conf; do
            [[ -f "$file" && "$file" != "/etc/sysctl.d/99-swap.conf" ]] && \
            grep -E '^(vm\.swappiness|vm\.vfs_cache_pressure)=' "$file" >/dev/null && \
            print_warning "Note: Duplicate swap settings found in $file."
        done

        mv "$NEW_SWAP_CONFIG" /etc/sysctl.d/99-swap.conf
        chmod 644 /etc/sysctl.d/99-swap.conf
        sysctl -p /etc/sysctl.d/99-swap.conf >/dev/null
        print_success "Swap settings applied to /etc/sysctl.d/99-swap.conf."
    fi

    swapon --show | tee -a "$LOG_FILE"
    free -h | tee -a "$LOG_FILE"
    log "Swap configuration completed."
}

# Helper: Convert size (e.g., 2G) to MB for dd count
convert_to_mb() {
    local input="${1:-}"
    local size="${input^^}"
    size="${size// /}"
    local num="${size%[MG]}"
    local unit="${size: -1}"
    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
        print_error "Invalid swap size format: '$input'. Expected format: 2G, 512M." >&2
        return 1
    fi
    case "$unit" in
        G) echo "$((num * 1024))" ;;
        M) echo "$num" ;;
        *) print_error "Unknown or missing unit in swap size: '$input'. Use 'M' or 'G' (e.g., 2G)." >&2
            return 1 ;;
    esac
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
            #Extract top suggestions
            grep "Suggestion:" /var/log/lynis-report.dat | head -n 5 > /tmp/lynis_suggestions.txt 2>/dev/null || true
            # Append Lynis system log for persistence
            cat /var/log/lynis.log >> "$AUDIT_LOG" 2>/dev/null
        else
            print_error "Lynis audit failed. Check $AUDIT_LOG for details."
            log "Lynis audit failed."
        fi
    fi

    # Check if system is Debian before running debsecan
    # shellcheck source=/dev/null
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
    print_section "Final System Update & Cleanup"
    print_info "Performing final system upgrade (dist-upgrade) and cleanup..."
    print_info "This may take a moment. Please wait..."
    # Upgrade ALL packages (including kernels)
    if ! apt-get update -qq >/dev/null 2>&1; then
        print_warning "Failed to update package lists during final cleanup."
        log "Final apt-get update failed."
    fi
    if ! DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -qq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" >> "$LOG_FILE" 2>&1; then
        print_warning "Final system upgrade encountered issues. Check log for details."
        log "Final apt-get dist-upgrade failed."
    else
        print_success "System packages (including kernels) upgraded successfully."
        log "Final apt-get dist-upgrade completed."
    fi
    # Final cleanup
    print_info "Removing unused packages..."
    if ! apt-get --purge autoremove -y -qq >> "$LOG_FILE" 2>&1 || ! apt-get autoclean -y -qq >> "$LOG_FILE" 2>&1; then
        print_warning "Cleanup commands encountered minor issues."
    else
        print_success "Unused packages removed."
    fi
    systemctl daemon-reload
    print_success "Final cleanup complete."
    log "Final system cleanup completed."
}

generate_summary() {
    # Create the report file and set permissions first
    touch "$REPORT_FILE" && chmod 600 "$REPORT_FILE"

    # Using a subshell to group all output and tee it to the report file
    (
    print_section "Setup Complete!"

    printf '\n%s\n\n' "${GREEN}Server setup and hardening script has finished successfully.${NC}"
    printf '%s %s\n' "${CYAN}📋 A detailed report has been saved to:${NC}" "${BOLD}$REPORT_FILE${NC}"
    printf '%s    %s\n' "${CYAN}📜 The full execution log is available at:${NC}" "${BOLD}$LOG_FILE${NC}"
    printf '\n'

    print_separator "Final Service Status Check:"
    for service in "$SSH_SERVICE" fail2ban chrony; do
        if systemctl is-active --quiet "$service"; then
            printf "  %-20s ${GREEN}✓ Active${NC}\n" "$service"
        else
            printf "  %-20s ${RED}✗ INACTIVE${NC}\n" "$service"
            FAILED_SERVICES+=("$service")
        fi
    done
    if ufw status | grep -q "Status: active"; then
        printf "  %-20s ${GREEN}✓ Active${NC}\n" "ufw (firewall)"
    else
        printf "  %-20s ${RED}✗ INACTIVE${NC}\n" "ufw (firewall)"
        FAILED_SERVICES+=("ufw")
    fi
    if command -v docker >/dev/null 2>&1; then
        if systemctl is-active --quiet docker; then
            printf "  %-20s ${GREEN}✓ Active${NC}\n" "docker"
        else
            printf "  %-20s ${RED}✗ INACTIVE${NC}\n" "docker"
            FAILED_SERVICES+=("docker")
        fi
    fi
    if command -v tailscale >/dev/null 2>&1; then
        if systemctl is-active --quiet tailscaled && tailscale ip >/dev/null 2>&1; then
            printf "  %-20s ${GREEN}✓ Active & Connected${NC}\n" "tailscaled"
            tailscale ip 2>/dev/null > /tmp/tailscale_ips.txt || true
        else
            if grep -q "Tailscale connection failed: tailscale up" "$LOG_FILE"; then
                printf "  %-20s ${RED}✗ INACTIVE (Connection Failed)${NC}\n" "tailscaled"
                FAILED_SERVICES+=("tailscaled")
                TS_COMMAND=$(grep "Tailscale connection failed: tailscale up" "$LOG_FILE" | tail -1 | sed 's/.*Tailscale connection failed: //')
                TS_COMMAND=${TS_COMMAND:-""}
            else
                printf "  %-20s ${YELLOW}⚠ Installed but not configured${NC}\n" "tailscaled"
                TS_COMMAND=""
            fi
        fi
    fi
    if [[ "${AUDIT_RAN:-false}" == true ]]; then
        printf "  %-20s ${GREEN}✓ Performed${NC}\n" "Security Audit"
    else
        printf "  %-20s ${YELLOW}⚠ Not Performed${NC}\n" "Security Audit"
    fi
    printf '\n'

    # --- Main Configuration Summary ---
    print_separator "Configuration Summary:"
    printf "  %-15s %s\n" "Admin User:" "$USERNAME"
    printf "  %-15s %s\n" "Hostname:" "$SERVER_NAME"
    printf "  %-15s %s\n" "SSH Port:" "$SSH_PORT"
    if [[ "${SERVER_IP_V4:-}" != "unknown" && "${SERVER_IP_V4:-}" != "Unknown" ]]; then
        printf "  %-15s %s\n" "Server IPv4:" "$SERVER_IP_V4"
    fi
    if [[ "${SERVER_IP_V6:-}" != "not available" && "${SERVER_IP_V6:-}" != "Not available" ]]; then
        printf "  %-15s %s\n" "Server IPv6:" "$SERVER_IP_V6"
    fi

    # --- Kernel Hardening Status ---
    if [[ -f /etc/sysctl.d/99-du-hardening.conf ]]; then
        printf "  %-20s${GREEN}Applied${NC}\n" "Kernel Hardening:"
    else
        printf "  %-20s${YELLOW}Not Applied${NC}\n" "Kernel Hardening:"
    fi

    # --- Backup Configuration Summary ---
    if [[ -f /root/run_backup.sh ]]; then
        local CRON_SCHEDULE NOTIFICATION_STATUS BACKUP_DEST BACKUP_PORT REMOTE_BACKUP_PATH
        CRON_SCHEDULE=$(crontab -u root -l 2>/dev/null | grep -F "/root/run_backup.sh" | awk '{print $1, $2, $3, $4, $5}' || echo "Not configured")
        NOTIFICATION_STATUS="None"
        BACKUP_DEST=$(grep "^REMOTE_DEST=" /root/run_backup.sh | cut -d'"' -f2 || echo "Unknown")
        BACKUP_PORT=$(grep "^SSH_PORT=" /root/run_backup.sh | cut -d'"' -f2 || echo "Unknown")
        REMOTE_BACKUP_PATH=$(grep "^REMOTE_PATH=" /root/run_backup.sh | cut -d'"' -f2 || echo "Unknown")
        if grep -q "NTFY_URL=" /root/run_backup.sh && ! grep -q 'NTFY_URL=""' /root/run_backup.sh; then
            NOTIFICATION_STATUS="ntfy"
        elif grep -q "DISCORD_WEBHOOK=" /root/run_backup.sh && ! grep -q 'DISCORD_WEBHOOK=""' /root/run_backup.sh; then
            NOTIFICATION_STATUS="Discord"
        fi
        printf '%s\n' "  Remote Backup:      ${GREEN}Enabled${NC}"
        printf "    %-17s%s\n" "- Backup Script:" "/root/run_backup.sh"
        printf "    %-17s%s\n" "- Destination:" "$BACKUP_DEST"
        printf "    %-17s%s\n" "- SSH Port:" "$BACKUP_PORT"
        printf "    %-17s%s\n" "- Remote Path:" "$REMOTE_BACKUP_PATH"
        printf "    %-17s%s\n" "- Cron Schedule:" "$CRON_SCHEDULE"
        printf "    %-17s%s\n" "- Notifications:" "$NOTIFICATION_STATUS"
        if [[ -f "$BACKUP_LOG" ]] && grep -q "Test backup successful" "$BACKUP_LOG" 2>/dev/null; then
            printf "    %-17s%s\n" "- Test Status:" "${GREEN}Successful${NC}"
        elif [[ -f "$BACKUP_LOG" ]]; then
            printf "    %-17s%s\n" "- Test Status:" "Failed (check $BACKUP_LOG)"
        else
            printf "    %-17s%s\n" "- Test Status:" "Not run"
        fi
    else
        printf '%s\n' "  Remote Backup:      ${RED}Not configured${NC}"
    fi

    # --- Tailscale Summary ---
    if command -v tailscale >/dev/null 2>&1; then
        local TS_CONFIGURED=false
        if [[ -f /tmp/tailscale_ips.txt ]] && grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' /tmp/tailscale_ips.txt 2>/dev/null; then
            TS_CONFIGURED=true
        fi
        if $TS_CONFIGURED; then
            local TS_SERVER TS_IPS_RAW TS_IPS TS_FLAGS
            TS_SERVER=$(cat /tmp/tailscale_server 2>/dev/null || echo "https://controlplane.tailscale.com")
            TS_IPS_RAW=$(cat /tmp/tailscale_ips.txt 2>/dev/null || echo "Not connected")
            TS_IPS=$(echo "$TS_IPS_RAW" | paste -sd ", " -)
            TS_FLAGS=$(cat /tmp/tailscale_flags 2>/dev/null || echo "None")
            printf '%s\n' "  Tailscale:          ${GREEN}Configured and connected${NC}"
            printf "    %-17s%s\n" "- Server:" "${TS_SERVER:-Not set}"
            printf "    %-17s%s\n" "- Tailscale IPs:" "${TS_IPS:-Not connected}"
            printf "    %-17s%s\n" "- Flags:" "${TS_FLAGS:-None}"
        else
            printf '%s\n' "  Tailscale:          ${YELLOW}Installed but not configured${NC}"
        fi
    else
        printf '%s\n' "  Tailscale:          ${RED}Not installed${NC}"
    fi

    # --- Security Audit Summary ---
    if [[ "${AUDIT_RAN:-false}" == true ]]; then
        printf '%s\n' "  Security Audit:     ${GREEN}Performed${NC}"
        printf "    %-17s%s\n" "- Audit Log:" "${AUDIT_LOG:-N/A}"
        printf "    %-17s%s\n" "- Hardening Index:" "${HARDENING_INDEX:-Unknown}"
        printf "    %-17s%s\n" "- Vulnerabilities:" "${DEBSECAN_VULNS:-N/A}"
        if [[ -s /tmp/lynis_suggestions.txt ]]; then
            printf '%s\n' "    ${YELLOW}- Top Lynis Suggestions:${NC}"
            sed 's/^/      /' /tmp/lynis_suggestions.txt
        fi
    else
        printf '%s\n' "  Security Audit:     ${RED}Not run${NC}"
    fi
    printf '\n'

    # --- System & Environment Information ---
    print_separator "System & Environment Information"

    # OS and Kernel Info
    printf "%-20s %s\n" "OS:" "${PRETTY_NAME:-Unknown}"
    printf "%-20s %s\n" "Kernel:" "$(uname -r)"
    printf "%-20s %s\n" "Uptime:" "$(uptime -p 2>/dev/null || uptime | sed 's/.*up //;s/,.*//')"

    # Hardware/Virtualization Info
    printf "%-20s %s\n" "Virtualization:" "${DETECTED_VIRT_TYPE:-unknown}"
    if [[ "${DETECTED_MANUFACTURER:-unknown}" != "unknown" ]]; then
        printf "%-20s %s\n" "Manufacturer:" "$DETECTED_MANUFACTURER"
    fi
    if [[ "${DETECTED_PRODUCT:-unknown}" != "unknown" ]]; then
        printf "%-20s %s\n" "Product:" "$DETECTED_PRODUCT"
    fi
    if [[ "${DETECTED_BIOS_VENDOR:-unknown}" != "unknown" ]]; then
        printf "%-20s %s\n" "BIOS Vendor:" "$DETECTED_BIOS_VENDOR"
    fi

    # Environment Classification
    printf "%-20s " "Environment:"
    case "$ENVIRONMENT_TYPE" in
        commercial-cloud) printf "%sCloud VPS%s\n" "$YELLOW" "$NC" ;;
        bare-metal)       printf "%sBare Metal%s\n" "$GREEN" "$NC" ;;
        uncertain-kvm)    printf "%sGeneric KVM (Likely Cloud VPS)%s\n" "$YELLOW" "$NC" ;;
        personal-vm)      printf "%sPersonal VM%s\n" "$CYAN" "$NC" ;;
        *)                printf "Unknown\n" ;;
    esac

    if [[ -n "$DETECTED_PROVIDER_NAME" ]]; then
        printf "%-20s %s\n" "Detected Provider:" "$DETECTED_PROVIDER_NAME"
    fi
    printf '\n'

    # --- Post-Reboot Verification Steps ---
    print_separator "Post-Reboot Verification Steps:"
    printf '  - SSH access:\n'

    # 1. Public Access
    if [[ "${SERVER_IP_V4:-}" != "unknown" && "${SERVER_IP_V4:-}" != "Unknown" ]]; then
        printf "    %-26s ${CYAN}%s${NC}\n" "- Public (Internet):" "ssh -p $SSH_PORT $USERNAME@$SERVER_IP_V4"
    fi

    # 2. Local Access
    if [[ -n "${LOCAL_IP_V4:-}" ]]; then
        # Show local if public is unknown OR if they are different IPs
        if [[ "${SERVER_IP_V4:-}" == "Unknown" || "${SERVER_IP_V4:-}" == "unknown" || "${LOCAL_IP_V4:-}" != "${SERVER_IP_V4:-}" ]]; then
            printf "    %-26s ${CYAN}%s${NC}\n" "- Local (LAN):" "ssh -p $SSH_PORT $USERNAME@$LOCAL_IP_V4"
        fi
    fi

    # 3. Tailscale Access
    if [[ -f /tmp/tailscale_ips.txt ]]; then
        local TS_SUMMARY_IP
        TS_SUMMARY_IP=$(grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' /tmp/tailscale_ips.txt | head -n 1)
        if [[ -n "$TS_SUMMARY_IP" ]]; then
            printf "    %-26s ${CYAN}%s${NC}\n" "- Tailscale (VPN):" "ssh -p $SSH_PORT $USERNAME@$TS_SUMMARY_IP"
        fi
    fi

    # 4. IPv6 Access
    if [[ "${SERVER_IP_V6:-}" != "not available" && "${SERVER_IP_V6:-}" != "Not available" ]]; then
        printf "    %-26s ${CYAN}%s${NC}\n" "- IPv6:" "ssh -p $SSH_PORT $USERNAME@$SERVER_IP_V6"
    fi

    # Other verification commands
    printf "  %-28s ${CYAN}%s${NC}\n" "- Firewall rules:" "sudo ufw status verbose"
    printf "  %-28s ${CYAN}%s${NC}\n" "- Time sync:" "chronyc tracking"
    printf "  %-28s ${CYAN}%s${NC}\n" "- Fail2Ban sshd jail:" "sudo fail2ban-client status sshd"
    printf "  %-28s ${CYAN}%s${NC}\n" "- Fail2Ban ufw jail:" "sudo fail2ban-client status ufw-probes"
    printf "  %-28s ${CYAN}%s${NC}\n" "- Swap status:" "sudo swapon --show && free -h"
    printf "  %-28s ${CYAN}%s${NC}\n" "- Kernel settings:" "sudo sysctl fs.protected_hardlinks kernel.yama.ptrace_scope"
    if command -v docker >/dev/null 2>&1; then
        printf "  %-28s ${CYAN}%s${NC}\n" "- Docker status:" "docker ps"
    fi
    if command -v tailscale >/dev/null 2>&1; then
        printf "  %-28s ${CYAN}%s${NC}\n" "- Tailscale status:" "tailscale status"
    fi
    if [[ -f /root/run_backup.sh ]]; then
        printf '  Remote Backup:\n'
        printf "    %-23s ${CYAN}%s${NC}\n" "- Test backup:" "sudo /root/run_backup.sh"
        printf "    %-23s ${CYAN}%s${NC}\n" "- Check logs:" "sudo less $BACKUP_LOG"
    fi
    if [[ "${AUDIT_RAN:-false}" == true ]]; then
        printf '%s\n' "  ${YELLOW}Security Audit:${NC}"
        printf "    %-23s ${CYAN}%s${NC}\n" "- Check results:" "sudo less ${AUDIT_LOG:-/var/log/syslog}"
    fi
    printf '\n'

    # --- Final Warnings and Actions ---
    if [[ ${#FAILED_SERVICES[@]} -gt 0 ]]; then
        print_warning "ACTION REQUIRED: The following services failed: ${FAILED_SERVICES[*]}. Verify with 'systemctl status <service>'."
    fi
    if [[ -n "${TS_COMMAND:-}" ]]; then
        print_warning "ACTION REQUIRED: Tailscale connection failed. Run the following command to connect manually:"
        printf '%s\n' "${CYAN}  $TS_COMMAND${NC}"
    fi
    if [[ -f /root/run_backup.sh ]] && [[ "${KEY_COPY_CHOICE:-2}" != "1" ]]; then
        print_warning "ACTION REQUIRED: Ensure the root SSH key (/root/.ssh/id_ed25519.pub) is copied to the backup destination."
    fi

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

    ) | tee -a "$REPORT_FILE"

    log "Script finished successfully. Report generated at $REPORT_FILE"
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
    trap 'rm -f /tmp/lynis_suggestions.txt /tmp/tailscale_*.txt /tmp/sshd_config_test.log /tmp/ssh*.log /tmp/sshd_restart*.log' EXIT

    if [[ $(id -u) -ne 0 ]]; then
        printf '\n%s\n' "${RED}✗ Error: This script must be run with root privileges.${NC}"
        printf 'You are running as user '\''%s'\'', but root is required for system changes.\n' "$(whoami)"
        printf 'Please re-run the script using '\''sudo -E'\'':\n'
        printf '  %s\n\n' "${CYAN}sudo -E ./du_setup.sh${NC}"
        exit 1
    fi

    touch "$LOG_FILE" && chmod 600 "$LOG_FILE"
    log "Starting Debian/Ubuntu hardening script."

    # --- PRELIMINARY CHECKS ---
    print_header
    check_dependencies
    check_system
    run_update_check

    # --- HANDLE SPECIAL OPERATIONAL MODES ---
    if [[ "$CLEANUP_ONLY" == "true" ]]; then
        print_info "Running in cleanup-only mode..."
        detect_environment
        cleanup_provider_packages
        print_success "Cleanup-only mode completed."
        exit 0
    fi

    if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
        print_info "Running cleanup preview mode..."
        detect_environment
        cleanup_provider_packages
        print_success "Cleanup preview completed."
        exit 0
    fi

    # --- NORMAL EXECUTION FLOW ---
    # Detect environment used for the summary report at the end.
    detect_environment
    # --- CORE SETUP AND HARDENING ---
    collect_config
    install_packages
    setup_user
    configure_system
    configure_firewall
    configure_fail2ban
    configure_ssh
    configure_auto_updates
    configure_time_sync
    configure_kernel_hardening
    install_docker
    install_tailscale
    setup_backup
    configure_swap
    configure_security_audit

    # --- PROVIDER PACKAGE CLEANUP ---
    if [[ "$SKIP_CLEANUP" == "false" ]]; then
        cleanup_provider_packages
    else
        print_info "Skipping provider cleanup (--skip-cleanup flag set)."
        log "Provider cleanup skipped via --skip-cleanup flag."
    fi

    # --- FINAL STEPS ---
    final_cleanup
    generate_summary
}

# Run main function
main "$@"
