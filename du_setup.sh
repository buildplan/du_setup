#!/bin/bash

# Debian and Ubuntu Server Hardening Interactive Script
# Version: 0.70 | 2025-10-20
# Changelog:
# - v0.70: Option to remove cloud VPS provider packages (like cloud-init).
#          New operational modes: --cleanup-preview, --cleanup-only, --skip-cleanup.
#          Add help and usage instructions with --help flag.
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

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# --- Update Configuration ---
CURRENT_VERSION="0.70"
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
IS_CLOUD_PROVIDER=false
IS_CONTAINER=false

SSHD_BACKUP_FILE=""
LOCAL_KEY_ADDED=false
SSH_SERVICE=""
ID="" # This will be populated from /etc/os-release
FAILED_SERVICES=()

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
    printf "  %ssudo su -%s    # Switch to root\n" "$CYAN" "$NC"
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
    printf '%s\n' "${CYAN}║                      v0.70 | 2025-10-20                         ║${NC}"
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
    IS_CLOUD_PROVIDER="$IS_CLOUD_VPS"

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
        source /etc/os-release
        ID=$ID  # Populate global ID variable
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
    while true; do
        read -rp "$(printf '%s' "${CYAN}Enter custom SSH port (1024-65535) [2222]: ${NC}")" SSH_PORT
        SSH_PORT=${SSH_PORT:-2222}
        if validate_port "$SSH_PORT"; then break; else print_error "Invalid port number."; fi
    done
    SERVER_IP_V4=$(curl -4 -s https://ifconfig.me 2>/dev/null || echo "unknown")
    SERVER_IP_V6=$(curl -6 -s https://ifconfig.me 2>/dev/null || echo "not available")
    if [[ "$SERVER_IP_V4" != "unknown" ]]; then
        print_info "Detected server IPv4: $SERVER_IP_V4"
    fi
    if [[ "$SERVER_IP_V6" != "not available" ]]; then
        print_info "Detected server IPv6: $SERVER_IP_V6"
    fi
    printf '\n%s\n' "${YELLOW}Configuration Summary:${NC}"
    printf "  %-15s %s\n" "Username:" "$USERNAME"
    printf "  %-15s %s\n" "Hostname:" "$SERVER_NAME"
    printf "  %-15s %s\n" "SSH Port:" "$SSH_PORT"
    if [[ "$SERVER_IP_V4" != "unknown" ]]; then
        printf "  %-15s %s\n" "Server IPv4:" "$SERVER_IP_V4"
    fi
    if [[ "$SERVER_IP_V6" != "not available" ]]; then
        printf "  %-15s %s\n" "Server IPv6:" "$SERVER_IP_V6"
    fi
    if ! confirm "\nContinue with this configuration?" "y"; then print_info "Exiting."; exit 0; fi
    log "Configuration collected: USER=$USERNAME, HOST=$SERVER_NAME, PORT=$SSH_PORT, IPV4=$SERVER_IP_V4, IPV6=$SERVER_IP_V6"
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
            print_info "Temporary key file deleted."
            LOCAL_KEY_ADDED=true
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
    trap - ERR
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

    print_info "Backing up original SSH config..."
    SSHD_BACKUP_FILE="$BACKUP_DIR/sshd_config.backup_$(date +%Y%m%d_%H%M%S)"
    cp /etc/ssh/sshd_config "$SSHD_BACKUP_FILE"

    # Store the current active port as the previous port
    PREVIOUS_SSH_PORT=$(ss -tuln | grep -E ":(22|.*$SSH_SERVICE.*)" | awk '{print $5}' | cut -d':' -f2 | head -n1 || echo "22")
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
    printf '%s\n' "${CYAN}Test SSH access from a SEPARATE terminal now:${NC}"
    if [[ -n "$SERVER_IP_V4" && "$SERVER_IP_V4" != "unknown" ]]; then
        printf '%s\n' "${CYAN}  Using IPv4: ssh -p $CURRENT_SSH_PORT $USERNAME@$SERVER_IP_V4${NC}"
    fi
    if [[ -n "$SERVER_IP_V6" && "$SERVER_IP_V6" != "not available" ]]; then
        printf '%s\n' "${CYAN}  Using IPv6: ssh -p $CURRENT_SSH_PORT $USERNAME@$SERVER_IP_V6${NC}"
    fi

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
    if [[ -n "$SERVER_IP_V4" && "$SERVER_IP_V4" != "unknown" ]]; then
        print_info "Use IPv4: ssh -p $SSH_PORT $USERNAME@$SERVER_IP_V4"
    fi
    if [[ -n "$SERVER_IP_V6" && "$SERVER_IP_V6" != "not available" ]]; then
        print_info "Use IPv6: ssh -p $SSH_PORT $USERNAME@$SERVER_IP_V6"
    fi

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

    # --- Define Desired Configurations ---
    # Define content of config file.
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
ignoreip = 127.0.0.1/8 ::1
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
    # This checks if the on-disk files are already identical to our desired configuration.
    if [[ -f "$UFW_FILTER_PATH" && -f "$JAIL_LOCAL_PATH" ]] && \
       cmp -s "$UFW_FILTER_PATH" <<<"$UFW_PROBES_CONFIG" && \
       cmp -s "$JAIL_LOCAL_PATH" <<<"$JAIL_LOCAL_CONFIG"; then
        print_info "Fail2Ban is already configured correctly. Skipping."
        log "Fail2Ban configuration is already correct."
        return 0
    fi

    # --- Apply Configuration ---
    # If the check above fails, we write the correct configuration files.
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
    sleep 2 # Give the service a moment to initialize.

    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2Ban is active with the new configuration."
        # Show the status of the enabled jails for confirmation.
        fail2ban-client status | tee -a "$LOG_FILE"
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
            print_info "  - Check port: nc -zv $(echo \"$BACKUP_DEST\" | cut -d'@' -f2) \"$BACKUP_PORT\""
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
    local TEST_DIR
    TEST_DIR="/root/test_backup_$(date +%Y%m%d_%H%M%S)"
    if ! mkdir -p "$TEST_DIR" || ! echo "Test file for backup verification" > "$TEST_DIR/test.txt"; then
        print_error "Failed to create test directory or file in /root/."
        log "Backup test failed: Cannot create test directory/file."
        rm -rf "$TEST_DIR" 2>/dev/null
        return 0
    fi

    print_info "Running test backup to $BACKUP_DEST:$REMOTE_BACKUP_PATH..."
    local RSYNC_OUTPUT RSYNC_EXIT_CODE TIMEOUT_DURATION=120
    local SSH_KEY="/root/.ssh/id_ed25519"
    local SSH_COMMAND="ssh -p $BACKUP_PORT -i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=no"

    set +e
    RSYNC_OUTPUT=$(timeout "$TIMEOUT_DURATION" rsync -avz --delete -e "$SSH_COMMAND" "$TEST_DIR/" "${BACKUP_DEST}:${REMOTE_BACKUP_PATH}test_backup/" 2>&1)
    RSYNC_EXIT_CODE=$?
    set -e # Re-enable 'exit on error'

    echo "--- Test Backup at $(date) ---" >> "$BACKUP_LOG"
    echo "$RSYNC_OUTPUT" >> "$BACKUP_LOG"

    if [[ $RSYNC_EXIT_CODE -eq 0 ]]; then
        print_success "Test backup successful! Check $BACKUP_LOG for details."
        log "Test backup successful."
    else
        print_warning "The backup test failed. This is not critical, and the script will continue."
        print_info "You can troubleshoot this after the server setup is complete."

        if [[ $RSYNC_EXIT_CODE -eq 124 ]]; then
            print_error "Test backup timed out after $TIMEOUT_DURATION seconds."
            log "Test backup failed: Timeout after $TIMEOUT_DURATION seconds."
        else
            print_error "Test backup failed (exit code: $RSYNC_EXIT_CODE). See $BACKUP_LOG for details."
            log "Test backup failed with exit code $RSYNC_EXIT_CODE."
        fi

        print_info "Common troubleshooting steps:"
        print_info "  - Ensure the root SSH key is copied to the destination: ssh-copy-id -p \"$BACKUP_PORT\" -i \"$SSH_KEY.pub\" \"$BACKUP_DEST\""
        print_info "  - Check firewall rules on both this server and the destination."
    fi

    # Clean up the temporary test directory
    rm -rf "$TEST_DIR" 2>/dev/null
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
        current_size=$(du -h "$existing_swap" | awk '{print $1}')
        print_info "Existing swap file found: $existing_swap ($current_size)"
        if confirm "Modify existing swap file size?"; then
            local SWAP_SIZE
            while true; do
                read -rp "$(printf '%s' "${CYAN}Enter new swap size (e.g., 2G, 512M) [current: $current_size]: ${NC}")" SWAP_SIZE
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
            read -rp "$(printf '%s' "${CYAN}Enter swap file size (e.g., 2G, 512M) [2G]: ${NC}")" SWAP_SIZE
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
            read -rp "$(printf '%s' "${CYAN}Enter vm.swappiness (0-100) [default: $SWAPPINESS]: ${NC}")" INPUT_SWAPPINESS
            INPUT_SWAPPINESS=${INPUT_SWAPPINESS:-$SWAPPINESS}
            if [[ "$INPUT_SWAPPINESS" =~ ^[0-9]+$ && "$INPUT_SWAPPINESS" -ge 0 && "$INPUT_SWAPPINESS" -le 100 ]]; then
                SWAPPINESS=$INPUT_SWAPPINESS
                break
            else
                print_error "Invalid value for vm.swappiness. Must be between 0 and 100."
            fi
        done
        while true; do
            read -rp "$(printf '%s' "${CYAN}Enter vm.vfs_cache_pressure (1-1000) [default: $CACHE_PRESSURE]: ${NC}")" INPUT_CACHE_PRESSURE
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
    # Create the report file and set permissions first
    touch "$REPORT_FILE" && chmod 600 "$REPORT_FILE"

    # Using a subshell to group all output and tee it to the report file
    (
    print_section "Setup Complete!"

    printf '\n%s\n\n' "${GREEN}Server setup and hardening script has finished successfully.${NC}"
    printf '%s %s\n' "${CYAN}📋 A detailed report has been saved to:${NC}" "${BOLD}$REPORT_FILE${NC}"
    printf '%s    %s\n' "${CYAN}📜 The full execution log is available at:${NC}" "${BOLD}$LOG_FILE${NC}"
    printf '\n'

    printf '%s\n' "${YELLOW}Final Service Status Check:${NC}"
    printf '=====================================\n'
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
    printf '%s\n' "${YELLOW}Configuration Summary:${NC}"
    printf '==========================================\n'
    printf "  %-15s %s\n" "Admin User:" "$USERNAME"
    printf "  %-15s %s\n" "Hostname:" "$SERVER_NAME"
    printf "  %-15s %s\n" "SSH Port:" "$SSH_PORT"
    if [[ "$SERVER_IP_V4" != "unknown" ]]; then
        printf "  %-15s %s\n" "Server IPv4:" "$SERVER_IP_V4"
    fi
    if [[ "$SERVER_IP_V6" != "not available" ]]; then
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

    printf '%s\n' "${YELLOW}Environment Information${NC}"
    printf '==========================================\n'
    printf "%-20s %s\n" "Virtualization:" "${DETECTED_VIRT_TYPE:-unknown}"
    printf "%-20s %s\n" "Manufacturer:" "${DETECTED_MANUFACTURER:-unknown}"
    printf "%-20s %s\n" "Product:" "${DETECTED_PRODUCT:-unknown}"
    if [[ "$IS_CLOUD_PROVIDER" == "true" ]]; then
        printf "%-20s %s\n" "Environment:" "${YELLOW}Cloud VPS${NC}"
    elif [[ "$DETECTED_VIRT_TYPE" == "none" ]]; then
        printf "%-20s %s\n" "Environment:" "${GREEN}Bare Metal${NC}"
    else
        printf "%-20s %s\n" "Environment:" "${CYAN}Personal VM${NC}"
    fi
    printf '\n'

    # --- Post-Reboot Verification Steps ---
    printf '%s\n' "${YELLOW}Post-Reboot Verification Steps:${NC}"
    printf '==========================================\n'
    printf '  - SSH access:\n'
    if [[ "$SERVER_IP_V4" != "unknown" ]]; then
        printf "    %-26s ${CYAN}%s${NC}\n" "- Using IPv4:" "ssh -p $SSH_PORT $USERNAME@$SERVER_IP_V4"
    fi
    if [[ "$SERVER_IP_V6" != "not available" ]]; then
        printf "    %-26s ${CYAN}%s${NC}\n" "- Using IPv6:" "ssh -p $SSH_PORT $USERNAME@$SERVER_IP_V6"
    fi
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
    check_system
    run_update_check
    check_dependencies

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
