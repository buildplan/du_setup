#!/usr/bin/env python3
"""Port du_setup.sh (Debian/Ubuntu) to Arch Linux -> arch_setup.sh.

Every edit is either a whole-function replacement or an exact-string
substitution that must match exactly once (the script aborts otherwise),
so the result is auditable against the upstream file.
"""
import re
import sys
from pathlib import Path

SRC = Path(sys.argv[1])
DST = Path(sys.argv[2])
text = SRC.read_text()


def sub(old, new, count=1):
    global text
    n = text.count(old)
    if n != count:
        sys.exit(f"ABORT: expected {count} occurrence(s) of:\n{old!r}\nfound {n}")
    text = text.replace(old, new)


def func_span(name):
    m = re.search(rf"^{re.escape(name)}\(\) \{{\n", text, re.M)
    if not m:
        sys.exit(f"ABORT: function {name} not found")
    end = text.find("\n}\n", m.start())
    if end == -1:
        sys.exit(f"ABORT: end of function {name} not found")
    return m.start(), end + 3


def replace_func(name, new_body):
    global text
    s, e = func_span(name)
    text = text[:s] + new_body.rstrip("\n") + "\n" + text[e:]


def func_text(name):
    s, e = func_span(name)
    return text[s:e]


# ---------------------------------------------------------------- header
sub("# Debian and Ubuntu Server Hardening Interactive Script\n# Version: 0.81.4 | 2026-08-12\n# Changelog:\n",
    "# Arch Linux Server Hardening Interactive Script (port of buildplan/du_setup)\n"
    "# Version: 0.81.4-arch.1 | 2026-09-08\n"
    "# Changelog:\n"
    "# - v0.81.4-arch.1: Arch Linux port of du_setup v0.81.4.\n"
    "#            pacman instead of apt; wheel instead of sudo group; useradd instead of adduser;\n"
    "#            chronyd/cronie/sshd service names; fail2ban and CrowdSec read the journal (no rsyslog);\n"
    "#            unattended-upgrades replaced by a systemd timer (check-only by default);\n"
    "#            debsecan replaced by arch-audit; Docker/Tailscale from official repos;\n"
    "#            CrowdSec and NetBird built from the AUR (paru/yay or makepkg as the admin user);\n"
    "#            locale via locale.gen/locale-gen; 2FA drop-in sorted after 99-archlinux.conf;\n"
    "#            mandatory reboot if pacman -Syu replaced the running kernel (modules would be missing).\n")

sub("# This script provisions and hardens a fresh Debian 12 or Ubuntu server with essential security",
    "# This script provisions and hardens a fresh Arch Linux server with essential security")
sub("# README at GitHub: https://github.com/buildplan/du_setup/blob/main/README.md\n",
    "# Upstream README (Debian/Ubuntu original): https://github.com/buildplan/du_setup/blob/main/README.md\n"
    "# Arch notes: see README-arch.md next to this script.\n")
sub("# - Run as root on a fresh Debian 12 or Ubuntu server (e.g., sudo ./du_setup.sh or run as root -E ./du_setup.sh).",
    "# - Run as root on a fresh Arch Linux server (e.g., sudo -E ./arch_setup.sh).")
sub("#   Download: wget https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.sh\n"
    "#   Make it executable: chmod +x du_setup.sh\n"
    "#   Run it: sudo -E ./du_setup.sh [--quiet]\n",
    "#   Make it executable: chmod +x arch_setup.sh\n"
    "#   Run it: sudo -E ./arch_setup.sh [--quiet]\n")

# ---------------------------------------------------------------- globals
sub('CURRENT_VERSION="0.81.4"\n'
    'SCRIPT_URL="https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.sh"\n',
    'CURRENT_VERSION="0.81.4-arch.1"\n'
    '# Self-update is disabled for this port (no upstream URL for the Arch variant).\n'
    'SCRIPT_URL=""\n')
sub('DOCKER_INSTALL_WARN=false\n',
    'DOCKER_INSTALL_WARN=false\n'
    'AUR_HELPER=""\n'
    'AUTO_UPDATES="none"\n'
    'OS_PRETTY_NAME="Arch Linux"\n')

# ---------------------------------------------------------------- usage / header
sub('printf "%s%s%s\\n" "$CYAN" "Debian/Ubuntu Server Setup & Hardening Script" "$NC"',
    'printf "%s%s%s\\n" "$CYAN" "Arch Linux Server Setup & Hardening Script" "$NC"')
sub('printf "  This script provisions a fresh Debian or Ubuntu server with secure base configurations.\\n"',
    'printf "  This script provisions a fresh Arch Linux server with secure base configurations.\\n"')
sub('printf "  - For full documentation, see the project repository:\\n"\n'
    '    printf "    %s%s%s\\n" "$CYAN" "https://github.com/buildplan/du-setup" "$NC"',
    'printf "  - Arch port of du_setup. Upstream project (Debian/Ubuntu):\\n"\n'
    '    printf "    %s%s%s\\n" "$CYAN" "https://github.com/buildplan/du_setup" "$NC"')


def boxline(inner, width=65):
    pad = width - len(inner)
    return "║" + " " * (pad // 2) + inner + " " * (pad - pad // 2) + "║"


sub("║       DEBIAN/UBUNTU SERVER SETUP AND HARDENING SCRIPT           ║",
    boxline("ARCH LINUX SERVER SETUP AND HARDENING SCRIPT"))
sub("║                      v0.81.4 | 2026-08-12                       ║",
    boxline("v0.81.4-arch.1 | 2026-09-08"))
sub('log "Starting Debian/Ubuntu hardening script."', 'log "Starting Arch Linux hardening script."')

# ---------------------------------------------------------------- helpers + update check
HELPERS = r'''# --- ARCH PACKAGE HELPERS ---

pkg_installed() {
    pacman -Qq "$1" &>/dev/null
}

pkg_install() {
    # Install official-repo packages. The sync DB is refreshed by the
    # 'pacman -Syu' in install_packages, so plain -S is safe here (no partial upgrade).
    pacman -S --needed --noconfirm "$@"
}

detect_aur_helper() {
    local helper
    AUR_HELPER=""
    for helper in paru yay; do
        if command -v "$helper" >/dev/null 2>&1; then
            AUR_HELPER="$helper"
            log "Detected AUR helper: $AUR_HELPER"
            return 0
        fi
    done
    return 0
}

aur_install() {
    # Build and install AUR packages as the (non-root) admin user.
    # Uses paru/yay when present; otherwise git + makepkg with a temporary
    # passwordless sudo rule that only covers /usr/bin/pacman.
    local pkg
    if [[ -z "${USERNAME:-}" ]] || ! id "$USERNAME" >/dev/null 2>&1; then
        print_error "AUR builds must run as the admin user, but USERNAME is not set."
        return 1
    fi
    print_warning "AUR packages are user-submitted and not reviewed by Arch. Review PKGBUILDs if in doubt."
    detect_aur_helper
    if [[ -n "$AUR_HELPER" ]]; then
        print_info "Installing from AUR with $AUR_HELPER: $*"
        if sudo -u "$USERNAME" "$AUR_HELPER" -S --needed --noconfirm "$@" 2>&1 | tee -a "$LOG_FILE"; then
            return 0
        fi
        print_error "$AUR_HELPER failed to install: $*"
        return 1
    fi

    print_info "No AUR helper found. Building with makepkg as '$USERNAME'..."
    if ! pkg_install base-devel git; then
        print_error "Failed to install base-devel/git for AUR builds."
        return 1
    fi
    local USER_HOME BUILD_ROOT SUDO_RULE="/etc/sudoers.d/99-du-setup-aur"
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
    BUILD_ROOT="$USER_HOME/.cache/du_setup_aur"
    sudo -u "$USERNAME" mkdir -p "$BUILD_ROOT"
    printf '%s ALL=(root) NOPASSWD: /usr/bin/pacman\n' "$USERNAME" > "$SUDO_RULE"
    chmod 0440 "$SUDO_RULE"
    local rc=0
    for pkg in "$@"; do
        if pkg_installed "$pkg"; then
            print_info "$pkg is already installed."
            continue
        fi
        print_info "Building $pkg (this can take a while)..."
        rm -rf "${BUILD_ROOT:?}/$pkg"
        if ! sudo -u "$USERNAME" git clone -q "https://aur.archlinux.org/$pkg.git" "$BUILD_ROOT/$pkg" 2>&1 | tee -a "$LOG_FILE"; then
            print_error "Failed to clone AUR package $pkg."
            rc=1
            continue
        fi
        if ! (cd "$BUILD_ROOT/$pkg" && sudo -u "$USERNAME" makepkg -si --needed --noconfirm) >> "$LOG_FILE" 2>&1; then
            print_error "makepkg failed for $pkg. See $LOG_FILE."
            rc=1
            continue
        fi
        print_success "$pkg installed from AUR."
        log "Installed AUR package: $pkg"
    done
    rm -f "$SUDO_RULE"
    return $rc
}

# --- script update check ---
run_update_check() {
    if [[ -z "$SCRIPT_URL" ]]; then
        print_info "Self-update is disabled in this Arch port."
        log "Update check skipped: SCRIPT_URL is empty."
        return 0
    fi
    print_section "Checking for Script Updates"
'''
sub("# --- script update check ---\nrun_update_check() {\n    print_section \"Checking for Script Updates\"\n", HELPERS)

# ---------------------------------------------------------------- check_dependencies
sub('command -v gpg >/dev/null || missing_deps+=("gpg")', 'command -v gpg >/dev/null || missing_deps+=("gnupg")')
sub('if ! apt-get update -qq || ! apt-get install -y -qq "${missing_deps[@]}"; then',
    'if ! pacman -Syu --needed --noconfirm "${missing_deps[@]}"; then')

# ---------------------------------------------------------------- check_system
sub('''        ID=${ID:-unknown} # Populate global ID variable
	if [[ $ID == "debian" && $VERSION_ID =~ ^(12|13)$ ]] || \\
           [[ $ID == "ubuntu" && $VERSION_ID =~ ^(20.04|22.04|24.04|24.10|25.04|25.10|26.04)$ ]]; then
            print_success "Compatible OS detected: $PRETTY_NAME"
        else
            print_warning "Script not tested on $PRETTY_NAME. This is for Debian 12/13 or Ubuntu 20.04-26.04."
            if ! confirm "Continue anyway?"; then exit 1; fi
        fi
    else
        print_error "This does not appear to be a Debian or Ubuntu system."
        exit 1
    fi
''', '''        ID=${ID:-unknown} # Populate global ID variable
        OS_PRETTY_NAME="${PRETTY_NAME:-$ID}"
        if [[ $ID == "arch" ]] || [[ " ${ID_LIKE:-} " == *" arch "* ]]; then
            print_success "Compatible OS detected: $OS_PRETTY_NAME"
        else
            print_warning "Script not tested on $OS_PRETTY_NAME. This port is for Arch Linux (or Arch-based distros)."
            if ! confirm "Continue anyway?"; then exit 1; fi
        fi
    else
        print_error "This does not appear to be an Arch Linux system (no /etc/os-release)."
        exit 1
    fi
    if ! command -v pacman >/dev/null 2>&1; then
        print_error "pacman not found. This script requires Arch Linux."
        exit 1
    fi
''')
sub('''    if ! dpkg -l openssh-server | grep -q ^ii; then
        print_warning "openssh-server not installed. It will be installed in the next step."
    else''', '''    if ! pkg_installed openssh; then
        print_warning "openssh not installed. It will be installed in the next step."
    else''')
sub('''    if curl -s --head https://deb.debian.org >/dev/null || \\
       curl -s --head https://archive.ubuntu.com >/dev/null || \\
       wget -q --spider https://deb.debian.org || \\
       wget -q --spider https://archive.ubuntu.com; then''',
    '''    if curl -s --head https://archlinux.org >/dev/null || \\
       curl -s --head https://geo.mirror.pkgbuild.com >/dev/null || \\
       wget -q --spider https://archlinux.org || \\
       wget -q --spider https://geo.mirror.pkgbuild.com; then''')
sub('''    if [[ ! -w /etc/shadow ]]; then
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
''', '''    if [[ ! -w /etc/shadow ]]; then
        print_error "/etc/shadow is not writable. Check permissions (should be 600, root:root on Arch)."
        exit 1
    fi
    local SHADOW_PERMS
    SHADOW_PERMS=$(stat -c %a /etc/shadow)
    if [[ "$SHADOW_PERMS" != "600" && "$SHADOW_PERMS" != "640" ]]; then
        print_info "Fixing /etc/shadow permissions to 600 (Arch default)..."
        chmod 600 /etc/shadow
        chown root:root /etc/shadow
        log "Fixed /etc/shadow permissions to 600."
    fi
''')

# ---------------------------------------------------------------- install_packages
replace_func("install_packages", r'''install_packages() {
    print_section "Package Installation"
    print_info "Synchronizing package databases and upgrading the system (pacman -Syu)..."
    print_info "This may take a moment. Please wait..."
    if ! pacman -Syu --noconfirm; then
        print_error "Failed to synchronize or upgrade system packages."
        exit 1
    fi
    print_info "Installing essential packages..."
    if ! pacman -S --needed --noconfirm \
        ufw chrony rsync wget curl \
        vim htop iotop nethogs openbsd-netcat ncdu \
        tree cronie jq gawk coreutils perl skopeo git \
        ca-certificates gnupg logrotate make inetutils \
        pacman-contrib arch-audit dmidecode openssh; then
        print_error "Failed to install one or more essential packages."
        exit 1
    fi
    print_success "Essential packages installed."

    print_info "Enabling cron daemon (cronie) and SSH daemon (sshd)..."
    systemctl enable --now cronie.service >/dev/null 2>&1 || print_warning "Could not enable cronie.service."
    systemctl enable sshd.service >/dev/null 2>&1 || true
    if ! systemctl is-active --quiet sshd.service && ! pgrep -x sshd >/dev/null; then
        systemctl start sshd.service || print_warning "Could not start sshd.service."
    fi
    # sshd must read drop-in files: hardening and 2FA are applied via /etc/ssh/sshd_config.d/
    if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
        print_info "Adding 'Include /etc/ssh/sshd_config.d/*.conf' to sshd_config..."
        mkdir -p /etc/ssh/sshd_config.d
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
        log "Added sshd_config.d Include directive."
    fi

    # Arch gotcha: after a kernel upgrade the modules of the *running* kernel are gone,
    # so ufw/nftables/docker cannot load modules until the machine is rebooted.
    if [[ ! -d "/usr/lib/modules/$(uname -r)" ]]; then
        print_warning "The kernel was upgraded: modules for the running kernel ($(uname -r)) are no longer installed."
        print_warning "Firewall, IDS and Docker need to load kernel modules, so a reboot is required before continuing."
        print_info "This script is idempotent: after the reboot, simply run it again to continue."
        log "Kernel upgraded during install_packages; reboot required before continuing."
        if confirm "Reboot now?" "y"; then
            print_info "Rebooting, run the script again afterwards..."
            sleep 3
            reboot
            exit 0
        fi
        print_error "Cannot continue safely without rebooting. Exiting."
        exit 1
    fi
    log "Package installation completed."
}
''')

# ---------------------------------------------------------------- setup_user
sub('''        # Check if group exists but user doesn't (common with 'admin' on Ubuntu)
        local -a ADDUSER_OPTS=("--disabled-password" "--gecos" "")
        if getent group "$USERNAME" >/dev/null 2>&1; then
            print_warning "Group '$USERNAME' already exists. Attaching new user to this existing group."
            ADDUSER_OPTS+=("--ingroup" "$USERNAME")
        fi
        if ! adduser "${ADDUSER_OPTS[@]}" "$USERNAME"; then''',
    '''        # Check if group exists but user doesn't (attach to it instead of failing)
        local -a USERADD_OPTS=("-m" "-s" "/bin/bash")
        if getent group "$USERNAME" >/dev/null 2>&1; then
            print_warning "Group '$USERNAME' already exists. Attaching new user to this existing group."
            USERADD_OPTS+=("-g" "$USERNAME")
        else
            USERADD_OPTS+=("-U")
        fi
        if ! useradd "${USERADD_OPTS[@]}" "$USERNAME"; then''')
sub('''    print_info "Adding '$USERNAME' to sudo group..."
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
    fi''',
    '''    print_info "Adding '$USERNAME' to wheel (sudo) group..."
    if ! id -nG "$USERNAME" | grep -qw wheel; then
        if ! usermod -aG wheel "$USERNAME"; then
            print_error "Failed to add '$USERNAME' to wheel group."
            exit 1
        fi
        print_success "User added to wheel group."
    else
        print_info "User '$USERNAME' is already in the wheel group."
    fi

    # On Arch the wheel rule ships commented out in /etc/sudoers; grant it via a drop-in if missing.
    if ! grep -qsE '^[[:space:]]*%wheel[[:space:]]+ALL=\\(ALL(:ALL)?\\)[[:space:]]+(NOPASSWD:[[:space:]]*)?ALL' /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
        print_info "Granting sudo rights to the wheel group via /etc/sudoers.d/10-wheel..."
        echo '%wheel ALL=(ALL:ALL) ALL' > /etc/sudoers.d/10-wheel
        chmod 0440 /etc/sudoers.d/10-wheel
        if ! visudo -cf /etc/sudoers.d/10-wheel >/dev/null; then
            rm -f /etc/sudoers.d/10-wheel
            print_error "Generated sudoers rule failed validation and was removed."
            exit 1
        fi
        log "Created /etc/sudoers.d/10-wheel"
    fi

    if getent group wheel | grep -qw "$USERNAME"; then
        print_success "Wheel group membership confirmed for '$USERNAME'."
    else
        print_warning "Wheel group membership verification failed. Please check manually with 'sudo -l' as $USERNAME."
    fi''')

# ---------------------------------------------------------------- configure_system
sub('''    # Warn about /tmp being a RAM-backed filesystem on Debian 13+
    print_info "Note: Debian 13 uses tmpfs for /tmp by default (stored in RAM)"''',
    '''    # Warn about /tmp being a RAM-backed filesystem
    print_info "Note: Arch Linux mounts /tmp as tmpfs by default (stored in RAM)"''')
sub('cp "${SCRIPT_DIR}/$(basename "$0")" "$BACKUP_DIR/du_setup_v${CURRENT_VERSION}.sh"',
    'cp "${SCRIPT_DIR}/$(basename "$0")" "$BACKUP_DIR/arch_setup_v${CURRENT_VERSION}.sh"')
sub('''    if confirm "Configure system locales interactively?"; then
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
''', '''    if confirm "Configure system locale (/etc/locale.gen + /etc/locale.conf)?"; then
        local LOCALE_CHOICE CURRENT_LOCALE
        CURRENT_LOCALE=$(grep -E '^LANG=' /etc/locale.conf 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
        while true; do
            read -rp "$(printf '%s' "${CYAN}Enter locale to generate and set as LANG [${CURRENT_LOCALE:-en_US.UTF-8}]: ${NC}")" LOCALE_CHOICE
            LOCALE_CHOICE=${LOCALE_CHOICE:-${CURRENT_LOCALE:-en_US.UTF-8}}
            if grep -qE "^#?[[:space:]]*${LOCALE_CHOICE}([[:space:]]|$)" /etc/locale.gen; then
                break
            fi
            print_error "Locale '$LOCALE_CHOICE' not found in /etc/locale.gen (e.g. en_US.UTF-8, es_ES.UTF-8)."
        done
        cp /etc/locale.gen "$BACKUP_DIR/locale.gen.backup"
        sed -i -E "s/^#[[:space:]]*(${LOCALE_CHOICE}([[:space:]].*)?)$/\\1/" /etc/locale.gen
        if locale-gen >> "$LOG_FILE" 2>&1; then
            localectl set-locale LANG="$LOCALE_CHOICE" 2>/dev/null || echo "LANG=$LOCALE_CHOICE" > /etc/locale.conf
            export LANG="$LOCALE_CHOICE"
            print_success "Locale $LOCALE_CHOICE generated and set in /etc/locale.conf."
            log "Locale set to $LOCALE_CHOICE."
        else
            print_warning "locale-gen failed. Check $LOG_FILE."
            log "locale-gen failed."
        fi
    else
        print_info "Skipping locale configuration."
    fi
''')

# ---------------------------------------------------------------- configure_ssh / rollback
sub('''    if ! dpkg -l openssh-server | grep -q ^ii; then
        print_error "openssh-server package is not installed."
        return 1
    fi''', '''    if ! pkg_installed openssh; then
        print_error "openssh package is not installed."
        return 1
    fi''')
sub("/usr/sbin/sshd", "/usr/bin/sshd", count=5)
sub('SSH_SERVICE="ssh.service" # Fallback for Ubuntu', 'SSH_SERVICE="sshd.service" # Fallback for Arch')
sub('log "Rollback warning: Using fallback SSH service ssh.service."', 'log "Rollback warning: Using fallback SSH service sshd.service."')
sub('''        if ! systemctl list-units --full -all --no-pager | grep -E "[[:space:]]ssh.service[[:space:]]" >/dev/null 2>&1; then
            print_error "No valid SSH service (sshd.service or ssh.service) found."''',
    '''        if ! systemctl list-units --full -all --no-pager | grep -E "[[:space:]]sshd.service[[:space:]]" >/dev/null 2>&1; then
            print_error "No valid SSH service (sshd.service) found."''')
sub('local service_for_rollback="ssh.service"', 'local service_for_rollback="sshd.service"')

# ---------------------------------------------------------------- configure_2fa
sub('''    print_info "Installing libpam-google-authenticator and qrencode..."
    if ! apt-get update -qq || ! apt-get install -y -qq libpam-google-authenticator qrencode; then''',
    '''    print_info "Installing libpam-google-authenticator and qrencode..."
    if ! pkg_install libpam-google-authenticator qrencode; then''')
sub('''        # Prepend to ensure it runs
        sed -i '1i auth required pam_google_authenticator.so nullok' "$PAM_FILE"''',
    '''        # Prepend (after the #%PAM-1.0 header if present) to ensure it runs first
        if head -n1 "$PAM_FILE" | grep -q '^#%PAM'; then
            sed -i '1a auth required pam_google_authenticator.so nullok' "$PAM_FILE"
        else
            sed -i '1i auth required pam_google_authenticator.so nullok' "$PAM_FILE"
        fi''')
sub('''    local SSH_2FA_CONF="$SSH_DROPIN_DIR/95-2fa-${USERNAME}.conf"''',
    '''    # Must sort AFTER 99-archlinux.conf: sshd keeps the Match context across included files,
    # so a Match block in 95-* would swallow the global directives (UsePAM) in 99-archlinux.conf.
    local SSH_2FA_CONF="$SSH_DROPIN_DIR/zz-2fa-${USERNAME}.conf"''')
sub('''    # Check if drop-in directory exists and is included (standard on Ubuntu 20.04+/Debian 12)''',
    '''    # Check if drop-in directory exists and is included (standard on Arch)''')

# ---------------------------------------------------------------- configure_firewall
sub('''    if ufw status | grep -q "Status: active"; then
        print_success "Firewall is active."
    else
        print_error "UFW failed to activate. Check 'journalctl -u ufw' for details."
        exit 1
    fi''', '''    if ufw status | grep -q "Status: active"; then
        print_success "Firewall is active."
    else
        print_error "UFW failed to activate. Check 'journalctl -u ufw' for details."
        exit 1
    fi
    # On Arch the rules are only restored at boot if ufw.service is enabled
    if systemctl enable ufw.service >/dev/null 2>&1; then
        log "Enabled ufw.service for boot."
    else
        print_warning "Could not enable ufw.service; firewall rules may not be restored at boot."
    fi''')

# ---------------------------------------------------------------- configure_fail2ban
sub('''    if ! dpkg -l fail2ban | grep -q ^ii || ! dpkg -l nftables | grep -q ^ii; then
        print_info "Installing Fail2Ban and nftables..."
        if ! apt-get install -y -qq fail2ban nftables; then''',
    '''    if ! pkg_installed fail2ban || ! pkg_installed nftables; then
        print_info "Installing Fail2Ban and nftables..."
        if ! pkg_install fail2ban nftables; then''')
sub('''[Definition]
# This regex looks for the standard "[UFW BLOCK]" message in /var/log/ufw.log
failregex = \\[UFW BLOCK\\] IN=.* OUT=.* SRC=<HOST>
ignoreregex =
EOF''', '''[Definition]
# This regex looks for the standard "[UFW BLOCK]" kernel message.
# Arch has no rsyslog/ufw.log: read kernel messages straight from the journal.
failregex = \\[UFW BLOCK\\] IN=.* OUT=.* SRC=<HOST>
ignoreregex =
journalmatch = _TRANSPORT=kernel
EOF''')
sub('''[DEFAULT]
ignoreip = ${IGNORE_IPS[*]}
bantime = 1d
findtime = 10m
maxretry = 5
banaction = nftables-allports

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
EOF''', '''[DEFAULT]
ignoreip = ${IGNORE_IPS[*]}
bantime = 1d
findtime = 10m
maxretry = 5
banaction = nftables-allports
# Arch has no /var/log/auth.log; read everything from the systemd journal
backend = systemd

[sshd]
enabled = true
port = $SSH_PORT

# This jail monitors kernel [UFW BLOCK] messages for rejected packets (port scans, etc.).
[ufw-probes]
enabled = true
port = all
filter = ufw-probes
backend = systemd
maxretry = 3
EOF''')
sub('''    # --- Ensure the log file exists BEFORE restarting the service ---
    if [[ ! -f /var/log/ufw.log ]]; then
        touch /var/log/ufw.log
        print_info "Created empty /var/log/ufw.log to ensure Fail2Ban starts correctly."
    fi

''', '')

# ---------------------------------------------------------------- configure_crowdsec
cs = func_text("configure_crowdsec")
marker = "    # Optional Additional Collections\n"
if marker not in cs:
    sys.exit("ABORT: crowdsec marker not found")
cs_tail = cs[cs.index(marker):]
cs_head = r'''configure_crowdsec() {
    print_section "CrowdSec Configuration"
    print_info "On Arch Linux, CrowdSec and its firewall bouncer are built from the AUR."

    # Agent
    if command -v crowdsec >/dev/null 2>&1; then
        print_info "CrowdSec is already installed."
    else
        print_info "Installing CrowdSec agent from AUR (crowdsec)..."
        if ! aur_install crowdsec; then
            print_error "Failed to install CrowdSec."
            return 1
        fi
        print_success "CrowdSec agent installed."
    fi
    systemctl enable --now crowdsec.service >/dev/null 2>&1 || print_warning "Could not enable crowdsec.service."

    # Hub index + core collections
    print_info "Updating CrowdSec hub index..."
    cscli hub update >> "$LOG_FILE" 2>&1 || print_warning "cscli hub update failed. Check logs."
    print_info "Installing base collections (Linux & Iptables)..."
    if cscli collections install crowdsecurity/linux crowdsecurity/iptables 2>&1 | tee -a "$LOG_FILE"; then
        print_success "Base collections installed."
    else
        print_warning "Failed to install base collections. Check logs."
    fi

    # Log acquisition: Arch has no rsyslog, so read sshd and kernel (UFW) messages from the journal
    mkdir -p /etc/crowdsec/acquis.d
    print_info "Configuring journal acquisition (sshd + kernel/UFW messages)..."
    cat <<EOF > /etc/crowdsec/acquis.d/sshd-journal.yaml
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=sshd.service"
labels:
  type: syslog
EOF
    cat <<EOF > /etc/crowdsec/acquis.d/ufw-journal.yaml
source: journalctl
journalctl_filter:
  - "_TRANSPORT=kernel"
labels:
  type: syslog
EOF
    # The packaged acquis.yaml points at /var/log/auth.log & co, which do not exist on Arch
    if [[ -f /etc/crowdsec/acquis.yaml ]] && grep -qE '^\s*-?\s*/var/log/(auth|syslog|kern)' /etc/crowdsec/acquis.yaml; then
        cp /etc/crowdsec/acquis.yaml "$BACKUP_DIR/crowdsec_acquis.yaml.backup"
        print_info "Disabling default file-based acquisition (those log files do not exist on Arch)..."
        sed -i 's/^/#/' /etc/crowdsec/acquis.yaml
        log "Commented out default /etc/crowdsec/acquis.yaml"
    fi
    print_success "Journal acquisition configured."

    # Firewall bouncer (iptables flavour, compatible with UFW)
    local BOUNCER_PKG="crowdsec-firewall-bouncer-iptables"
    local BOUNCER_CFG="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
    if command -v crowdsec-firewall-bouncer >/dev/null 2>&1; then
        print_info "CrowdSec Firewall Bouncer already installed."
    else
        print_info "Installing CrowdSec Firewall Bouncer from AUR ($BOUNCER_PKG)..."
        if ! aur_install "$BOUNCER_PKG"; then
            print_warning "Failed to install firewall bouncer. CrowdSec will detect but NOT block attacks."
        else
            print_success "CrowdSec Firewall Bouncer installed."
        fi
    fi
    # Register the bouncer with the local API. The Debian package does this in postinst; the AUR one does not.
    if command -v crowdsec-firewall-bouncer >/dev/null 2>&1 && [[ -f "$BOUNCER_CFG" ]]; then
        local CURRENT_KEY
        CURRENT_KEY=$(awk -F': *' '/^api_key:/ {print $2; exit}' "$BOUNCER_CFG" | tr -d '"'"'"' \r')
        if [[ -z "$CURRENT_KEY" || "$CURRENT_KEY" == *API_KEY* ]]; then
            print_info "Registering firewall bouncer with the local CrowdSec API..."
            systemctl restart crowdsec.service
            sleep 3
            local BOUNCER_KEY
            cscli bouncers delete crowdsec-firewall-bouncer >/dev/null 2>&1 || true
            if BOUNCER_KEY=$(cscli bouncers add crowdsec-firewall-bouncer -o raw 2>>"$LOG_FILE") && [[ -n "$BOUNCER_KEY" ]]; then
                sed -i "s|^api_key:.*|api_key: ${BOUNCER_KEY}|" "$BOUNCER_CFG"
                print_success "Bouncer registered with the local API."
                log "Registered crowdsec-firewall-bouncer with LAPI."
            else
                print_warning "Could not register the bouncer automatically. Run: sudo cscli bouncers add crowdsec-firewall-bouncer"
            fi
        fi
        systemctl enable --now crowdsec-firewall-bouncer.service >/dev/null 2>&1 || print_warning "Could not enable crowdsec-firewall-bouncer.service."
    fi

'''
replace_func("configure_crowdsec", cs_head + cs_tail)
sub('''    systemctl restart crowdsec
    print_info "Restarted CrowdSec service to apply configurations."''',
    '''    systemctl restart crowdsec
    systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true
    print_info "Restarted CrowdSec service to apply configurations."''')

# ---------------------------------------------------------------- configure_auto_updates
replace_func("configure_auto_updates", r'''configure_auto_updates() {
    print_section "Automatic Updates (systemd timer)"
    print_info "Arch Linux has no 'security-only' update channel. Unattended full upgrades can break a"
    print_info "server (kernel/module mismatch, manual interventions announced on archlinux.org/news)."
    printf '%s\n' "${CYAN}Choose an update policy:${NC}"
    printf '  1) Daily check only: log pending updates and known vulnerabilities (checkupdates + arch-audit)\n'
    printf '  2) Daily unattended full upgrade (pacman -Syu --noconfirm) - NOT recommended for production\n'
    printf '  3) Skip\n'
    local UPD_CHOICE
    read -rp "$(printf '%s' "${CYAN}Enter choice [1]: ${NC}")" UPD_CHOICE
    UPD_CHOICE=${UPD_CHOICE:-1}

    case "$UPD_CHOICE" in
        1|2) ;;
        *)
            print_info "Skipping automatic updates."
            log "Automatic updates skipped by user."
            return 0
            ;;
    esac

    if [[ "$UPD_CHOICE" == "2" ]]; then
        print_warning "Unattended upgrades will run 'pacman -Syu --noconfirm' every day."
        print_warning "Read https://archlinux.org/news/ regularly if you rely on this."
        if ! confirm "Really enable unattended full upgrades?" "n"; then
            UPD_CHOICE=1
            print_info "Falling back to check-only mode."
        fi
    fi

    pkg_install pacman-contrib arch-audit >> "$LOG_FILE" 2>&1 || true

    local SCRIPT_PATH="/usr/local/sbin/du-arch-updates.sh"
    local UNIT_NAME="du-arch-updates"
    local MODE_TEXT="check"
    if [[ "$UPD_CHOICE" == "2" ]]; then
        MODE_TEXT="unattended upgrade"
        tee "$SCRIPT_PATH" > /dev/null <<'EOF'
#!/bin/bash
# Installed by arch_setup.sh - unattended full system upgrade
set -uo pipefail
LOG="/var/log/du-arch-updates.log"
{
    echo "=== $(date '+%F %T') pacman -Syu ==="
    pacman -Syu --noconfirm
    echo "--- orphans ---"
    orphans=$(pacman -Qdtq 2>/dev/null || true)
    # shellcheck disable=SC2086
    [ -n "$orphans" ] && pacman -Rns --noconfirm $orphans
    command -v paccache >/dev/null && paccache -rk2
    if [ ! -d "/usr/lib/modules/$(uname -r)" ]; then
        echo "REBOOT REQUIRED: the kernel was upgraded"
    fi
    command -v arch-audit >/dev/null && { echo "--- arch-audit ---"; arch-audit; }
} >> "$LOG" 2>&1
exit 0
EOF
    else
        tee "$SCRIPT_PATH" > /dev/null <<'EOF'
#!/bin/bash
# Installed by arch_setup.sh - report pending updates and vulnerabilities (makes no changes)
set -uo pipefail
LOG="/var/log/du-arch-updates.log"
{
    echo "=== $(date '+%F %T') update check ==="
    if command -v checkupdates >/dev/null; then
        updates=$(checkupdates 2>/dev/null || true)
    else
        updates=$(pacman -Qu 2>/dev/null || true)
    fi
    if [ -n "$updates" ]; then
        echo "$updates"
        echo "$(echo "$updates" | wc -l) package(s) can be upgraded. Run: sudo pacman -Syu"
    else
        echo "System is up to date."
    fi
    if [ ! -d "/usr/lib/modules/$(uname -r)" ]; then
        echo "REBOOT REQUIRED: modules for the running kernel are missing (kernel was upgraded)"
    fi
    command -v arch-audit >/dev/null && { echo "--- arch-audit ---"; arch-audit; }
} >> "$LOG" 2>&1
exit 0
EOF
    fi
    chmod 750 "$SCRIPT_PATH"

    tee "/etc/systemd/system/${UNIT_NAME}.service" > /dev/null <<EOF
[Unit]
Description=arch_setup: daily Arch Linux update ${MODE_TEXT}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCRIPT_PATH}
EOF
    tee "/etc/systemd/system/${UNIT_NAME}.timer" > /dev/null <<EOF
[Unit]
Description=arch_setup: daily Arch Linux update ${MODE_TEXT}

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    if systemctl enable --now "${UNIT_NAME}.timer" >> "$LOG_FILE" 2>&1; then
        if [[ "$UPD_CHOICE" == "2" ]]; then
            AUTO_UPDATES="unattended-upgrade"
            print_success "Unattended daily upgrades enabled (${UNIT_NAME}.timer). Log: /var/log/du-arch-updates.log"
        else
            AUTO_UPDATES="check-only"
            print_success "Daily update check enabled (${UNIT_NAME}.timer). Log: /var/log/du-arch-updates.log"
        fi
        log "Automatic updates configured: $AUTO_UPDATES"
    else
        print_error "Failed to enable ${UNIT_NAME}.timer."
        FAILED_SERVICES+=("${UNIT_NAME}.timer")
    fi
    log "Automatic updates configuration completed."
}
''')

# ---------------------------------------------------------------- configure_secure_dns
sub('''    # Ensure systemd-resolved is installed and active
    if ! command -v systemd-resolve >/dev/null 2>&1 && ! command -v resolvectl >/dev/null 2>&1; then
         print_warning "systemd-resolved is not installed on this system."
         if confirm "Install and enable systemd-resolved to handle encrypted DNS?"; then
             if ! apt-get update -qq || ! apt-get install -y -qq systemd-resolved; then
                 print_error "Failed to install systemd-resolved."
                 log "Failed to install systemd-resolved for secure DNS."
                 return 0
             fi
         else
             print_info "Skipping secure DNS setup."
             log "Secure DNS skipped (systemd-resolved not installed)."
             return 0
         fi
    fi
''', '''    # systemd-resolved ships with systemd on Arch; just make sure the tooling is there
    if ! command -v resolvectl >/dev/null 2>&1; then
         print_warning "resolvectl not found; systemd-resolved does not appear to be available."
         log "Secure DNS skipped (resolvectl missing)."
         return 0
    fi
''')

# ---------------------------------------------------------------- install_docker
sub('''    print_info "Removing old container runtimes..."
    apt-get remove -y -qq docker docker-engine docker.io containerd runc 2>/dev/null || true
    print_info "Adding Docker's official GPG key and repository..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${ID}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    # shellcheck source=/dev/null
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
    print_info "Installing Docker packages..."
    if ! apt-get update -qq || ! apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then''',
    '''    print_info "Installing Docker packages from the official Arch repositories (docker, docker-compose, docker-buildx)..."
    if ! pkg_install docker docker-compose docker-buildx; then''')

# ---------------------------------------------------------------- install_tailscale
sub('''        print_info "Installing Tailscale..."
        # Gracefully handle download failures
        if ! curl -fsSL https://tailscale.com/install.sh -o /tmp/tailscale_install.sh; then
            print_error "Failed to download the Tailscale installation script."
            print_info "After setup completes, please try installing it manually: curl -fsSL https://tailscale.com/install.sh | sh"
            rm -f /tmp/tailscale_install.sh # Clean up partial download
            TAILSCALE_INSTALL_WARN=true
            return 0 # Exit the function without exiting the main script
        fi

        # Execute the downloaded script with 'sh'
        if ! sh /tmp/tailscale_install.sh; then
            print_error "Tailscale installation script failed to execute."
            log "Tailscale installation failed."
            rm -f /tmp/tailscale_install.sh # Clean up
            TAILSCALE_INSTALL_WARN=true
            return 0 # Exit the function gracefully
        fi

        rm -f /tmp/tailscale_install.sh # Clean up successful install
        print_success "Tailscale installation complete."''',
    '''        print_info "Installing Tailscale from the official Arch repository..."
        if ! pkg_install tailscale; then
            print_error "Failed to install the tailscale package."
            print_info "After setup completes, please try installing it manually: sudo pacman -S tailscale"
            log "Tailscale installation failed."
            TAILSCALE_INSTALL_WARN=true
            return 0 # Exit the function gracefully
        fi
        print_success "Tailscale installation complete."''')
sub('''        else
            print_warning "Service tailscaled is installed but not active or connected."
        fi
    else
        print_info "Installing Tailscale from the official Arch repository..."''',
    '''        else
            print_warning "Service tailscaled is installed but not active or connected."
        fi
    else
        print_info "Installing Tailscale from the official Arch repository..."''')
# Make sure the daemon is enabled before we try to talk to it
sub('''    if systemctl is-active --quiet tailscaled && tailscale ip >/dev/null 2>&1; then
        local TS_IPS TS_IPV4
        TS_IPS=$(tailscale ip 2>/dev/null || echo "Unknown")
        TS_IPV4=$(echo "$TS_IPS" | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | head -1 || echo "Unknown")
        print_info "Tailscale is already connected. Node IPv4 in tailnet: $TS_IPV4"''',
    '''    systemctl enable --now tailscaled.service >/dev/null 2>&1 || print_warning "Could not enable tailscaled.service."
    if systemctl is-active --quiet tailscaled && tailscale ip >/dev/null 2>&1; then
        local TS_IPS TS_IPV4
        TS_IPS=$(tailscale ip 2>/dev/null || echo "Unknown")
        TS_IPV4=$(echo "$TS_IPS" | grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' | head -1 || echo "Unknown")
        print_info "Tailscale is already connected. Node IPv4 in tailnet: $TS_IPV4"''')

# ---------------------------------------------------------------- install_netbird
sub('''        print_info "Adding NetBird repository and installing package..."
        if ! apt-get update -qq || ! apt-get install -y -qq ca-certificates curl gnupg; then
            print_error "Failed to install dependencies for NetBird."
            NETBIRD_INSTALL_WARN=true
            return 0
        fi

        curl -sSL https://pkgs.netbird.io/debian/public.key | gpg --dearmor --output /usr/share/keyrings/netbird-archive-keyring.gpg 2>/dev/null
        echo 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main' | tee /etc/apt/sources.list.d/netbird.list >/dev/null

        if ! apt-get update -qq || ! apt-get install -y -qq netbird; then
            print_error "Failed to install NetBird package."
            log "NetBird installation failed."
            NETBIRD_INSTALL_WARN=true
            return 0
        fi
        print_success "NetBird installation complete."''',
    '''        print_info "Installing NetBird from the AUR (netbird)..."
        if ! aur_install netbird; then
            print_error "Failed to install NetBird package."
            log "NetBird installation failed."
            NETBIRD_INSTALL_WARN=true
            return 0
        fi
        if systemctl list-unit-files netbird.service 2>/dev/null | grep -q '^netbird.service'; then
            systemctl enable --now netbird.service >/dev/null 2>&1 || print_warning "Could not enable netbird.service."
        else
            netbird service install >> "$LOG_FILE" 2>&1 || true
            netbird service start >> "$LOG_FILE" 2>&1 || true
        fi
        print_success "NetBird installation complete."''')

# ---------------------------------------------------------------- setup_backup
sub('''            if ! { apt-get update -qq && apt-get install -y -qq sshpass; }; then''',
    '''            if ! pkg_install sshpass; then''')
sub('''HOSTNAME="\\$(hostname -f)"''', '''HOSTNAME="\\$(hostname -f 2>/dev/null || cat /etc/hostname)"''')
sub('''    # Ensure crontab is writable
    local CRON_DIR="/var/spool/cron/crontabs"
    mkdir -p "$CRON_DIR"
    chmod 1730 "$CRON_DIR"
    chown root:crontab "$CRON_DIR"
''', '''    # Arch uses cronie; make sure it is installed and running
    if ! command -v crontab >/dev/null 2>&1; then
        if ! pkg_install cronie; then
            print_error "Failed to install cronie. Cannot schedule the backup."
            return 1
        fi
    fi
    systemctl enable --now cronie.service >/dev/null 2>&1 || print_warning "Could not enable cronie.service; the backup job will not run."
''')

# ---------------------------------------------------------------- configure_time_sync
replace_func("configure_time_sync", r'''configure_time_sync() {
    print_section "Time Synchronization"
    print_info "Ensuring chrony is active (replacing systemd-timesyncd)..."
    if systemctl is-enabled --quiet systemd-timesyncd 2>/dev/null || systemctl is-active --quiet systemd-timesyncd; then
        systemctl disable --now systemd-timesyncd >/dev/null 2>&1 || true
        log "Disabled systemd-timesyncd in favour of chronyd."
    fi
    systemctl enable --now chronyd.service
    sleep 2
    if systemctl is-active --quiet chronyd; then
        print_success "Chrony (chronyd) is active for time synchronization."
        chronyc tracking | tee -a "$LOG_FILE"
    else
        print_error "chronyd service failed to start."
        exit 1
    fi
    log "Time synchronization completed."
}
''')
sub('for service in "$SSH_SERVICE" chrony; do', 'for service in "$SSH_SERVICE" chronyd; do')

# ---------------------------------------------------------------- configure_security_audit
sub('if ! confirm "Run a security audit with Lynis (and optionally debsecan on Debian)?"; then',
    'if ! confirm "Run a security audit with Lynis (and optionally arch-audit)?"; then')
audit = func_text("configure_security_audit")
start = audit.index('    # Install and run Lynis\n')
audit_head = audit[:start]
audit_new_tail = r'''    # Install and run Lynis
    print_info "Installing Lynis..."
    if ! pkg_install lynis; then
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

    # arch-audit: installed packages vs. the Arch security tracker (replaces debsecan)
    if confirm "Also run arch-audit to check installed packages against the Arch security tracker?"; then
        if ! pkg_install arch-audit; then
            print_warning "Failed to install arch-audit. Skipping."
            log "arch-audit installation failed."
        else
            print_info "Running arch-audit..."
            {
                printf '\n=== arch-audit (%s) ===\n' "$(date)"
                arch-audit
            } >> "$AUDIT_LOG" 2>&1 || true
            DEBSECAN_VULNS=$(arch-audit 2>/dev/null | grep -c 'CVE-' || true)
            DEBSECAN_VULNS=${DEBSECAN_VULNS:-0}
            print_success "arch-audit completed. Found $DEBSECAN_VULNS affected package(s)."
            log "arch-audit completed with $DEBSECAN_VULNS affected packages."
        fi
    else
        print_info "arch-audit skipped."
        log "arch-audit skipped by user."
    fi

    print_warning "Review audit results in $AUDIT_LOG for security recommendations."
    log "Security audit configuration completed."
}
'''
replace_func("configure_security_audit", audit_head + audit_new_tail)

# ---------------------------------------------------------------- final_cleanup
replace_func("final_cleanup", r'''final_cleanup() {
    print_section "Final System Update & Cleanup"
    print_info "Performing final full system upgrade (pacman -Syu) and cleanup..."
    print_info "This may take a moment. Please wait..."
    if ! pacman -Syu --noconfirm >> "$LOG_FILE" 2>&1; then
        print_warning "Final system upgrade encountered issues. Check log for details."
        log "Final pacman -Syu failed."
    else
        print_success "System packages (including kernels) upgraded successfully."
        log "Final pacman -Syu completed."
    fi
    print_info "Removing orphaned packages and trimming the package cache..."
    local ORPHANS
    ORPHANS=$(pacman -Qdtq 2>/dev/null || true)
    if [[ -n "$ORPHANS" ]]; then
        # shellcheck disable=SC2086
        if pacman -Rns --noconfirm $ORPHANS >> "$LOG_FILE" 2>&1; then
            print_success "Orphaned packages removed."
        else
            print_warning "Orphan removal encountered minor issues."
        fi
    else
        print_info "No orphaned packages to remove."
    fi
    if command -v paccache >/dev/null 2>&1; then
        paccache -rk2 >> "$LOG_FILE" 2>&1 || true
    else
        pacman -Sc --noconfirm >> "$LOG_FILE" 2>&1 || true
    fi
    systemctl daemon-reload
    if [[ ! -d "/usr/lib/modules/$(uname -r)" ]]; then
        print_warning "The kernel was upgraded: modules for the running kernel are gone. Reboot as soon as possible."
        log "Kernel upgraded during final cleanup; reboot required."
    fi
    print_success "Final cleanup complete."
    log "Final system cleanup completed."
}
''')

# ---------------------------------------------------------------- provider cleanup
sub('''        "openstack-guest-utils"
        "openstack-nova-agent"
    )''', '''        "openstack-guest-utils"
        "openstack-nova-agent"
        # Arch package names
        "virtualbox-guest-utils"
        "virtualbox-guest-utils-nox"
        "hyperv"
        "google-guest-agent"
        "google-compute-engine-oslogin"
    )''')
sub('''        "ec2-user"
        "linuxuser"
    )''', '''        "ec2-user"
        "linuxuser"
        "arch"
        "alarm"
    )''')
sub('''        if execute_check dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then''',
    '''        if execute_check pacman -Qq "$pkg" &>/dev/null; then''')
sub('''                    print_info "[PREVIEW] Would remove package: $pkg (with --purge flag)"''',
    '''                    print_info "[PREVIEW] Would remove package: $pkg (pacman -Rns)"''')
sub('''                    if execute_command apt-get remove --purge -y "$pkg" 2>&1 | tee -a "$LOG_FILE"; then''',
    '''                    if execute_command pacman -Rns --noconfirm "$pkg" 2>&1 | tee -a "$LOG_FILE"; then''')
sub('''            if id -nG "$user" 2>/dev/null | grep -qwE '(sudo|admin)'; then''',
    '''            if id -nG "$user" 2>/dev/null | grep -qwE '(wheel|sudo|admin)'; then''')
sub('''        if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
            print_info "[PREVIEW] Would run: apt-get autoremove --purge -y"
            print_info "[PREVIEW] Would run: apt-get autoclean -y"
        else
            print_info "Cleaning up..."
            execute_command apt-get autoremove --purge -y 2>&1 | tee -a "$LOG_FILE" || true
            execute_command apt-get autoclean -y 2>&1 | tee -a "$LOG_FILE" || true
            print_success "Cleanup complete."
            log "Ran apt autoremove and autoclean."
        fi''', '''        if [[ "$CLEANUP_PREVIEW" == "true" ]]; then
            print_info "[PREVIEW] Would run: pacman -Rns \\$(pacman -Qdtq)  (remove orphans)"
            print_info "[PREVIEW] Would run: paccache -rk2  (trim package cache)"
        else
            print_info "Cleaning up..."
            local ORPHANS
            ORPHANS=$(pacman -Qdtq 2>/dev/null || true)
            if [[ -n "$ORPHANS" ]]; then
                # shellcheck disable=SC2086
                execute_command pacman -Rns --noconfirm $ORPHANS 2>&1 | tee -a "$LOG_FILE" || true
            fi
            if command -v paccache >/dev/null 2>&1; then
                execute_command paccache -rk2 2>&1 | tee -a "$LOG_FILE" || true
            else
                execute_command pacman -Sc --noconfirm 2>&1 | tee -a "$LOG_FILE" || true
            fi
            print_success "Cleanup complete."
            log "Removed orphans and trimmed the package cache."
        fi''')

# ---------------------------------------------------------------- summary
sub('''    printf "%-20s %s\\n" "OS:" "${PRETTY_NAME:-Unknown}"''',
    '''    printf "%-20s %s\\n" "OS:" "${OS_PRETTY_NAME:-Unknown}"''')
sub('''    # --- Kernel Hardening Status ---
    if [[ -f /etc/sysctl.d/99-du-hardening.conf ]]; then''',
    '''    # --- Automatic Updates Status ---
    case "${AUTO_UPDATES:-none}" in
        unattended-upgrade) printf "  %-20s ${YELLOW}Unattended daily pacman -Syu (du-arch-updates.timer)${NC}\\n" "Auto Updates:" ;;
        check-only)         printf "  %-20s ${GREEN}Daily check + arch-audit (du-arch-updates.timer)${NC}\\n" "Auto Updates:" ;;
        *)                  printf "  %-20s ${YELLOW}Not configured${NC}\\n" "Auto Updates:" ;;
    esac

    # --- Kernel Hardening Status ---
    if [[ -f /etc/sysctl.d/99-du-hardening.conf ]]; then''')
sub('''    printf "  %-28s ${CYAN}%s${NC}\\n" "- Kernel settings:" "sudo sysctl fs.protected_hardlinks kernel.yama.ptrace_scope"''',
    '''    printf "  %-28s ${CYAN}%s${NC}\\n" "- Kernel settings:" "sudo sysctl fs.protected_hardlinks kernel.yama.ptrace_scope"
    if [[ "${AUTO_UPDATES:-none}" != "none" ]]; then
        printf "  %-28s ${CYAN}%s${NC}\\n" "- Update timer:" "systemctl list-timers du-arch-updates.timer && sudo less /var/log/du-arch-updates.log"
    fi''')

# ---------------------------------------------------------------- .bashrc (generated for the admin user)
sub('''    # --- Reboot Status ---
    if [ -f /var/run/reboot-required ]; then
        printf "${CYAN}%-15s${RESET} ${BOLD_RED}⚠ REBOOT REQUIRED${RESET}\\n" "System:"
        [ -s /var/run/reboot-required.pkgs ] && \\
            printf "               ${DIM}Reason:${RESET} %s\\n" "$(paste -sd ' ' /var/run/reboot-required.pkgs)"
    fi

    # --- Available Updates (APT) ---
    if command -v apt-get &>/dev/null; then''',
    '''    # --- Reboot Status ---
    # Debian/Ubuntu: /var/run/reboot-required. Arch: modules for the running kernel are gone after an upgrade.
    if [ -f /var/run/reboot-required ] || { command -v pacman &>/dev/null && [ ! -d "/usr/lib/modules/$(uname -r)" ]; }; then
        printf "${CYAN}%-15s${RESET} ${BOLD_RED}⚠ REBOOT REQUIRED${RESET}\\n" "System:"
        if [ -s /var/run/reboot-required.pkgs ]; then
            printf "               ${DIM}Reason:${RESET} %s\\n" "$(paste -sd ' ' /var/run/reboot-required.pkgs)"
        elif [ ! -d "/usr/lib/modules/$(uname -r)" ]; then
            printf "               ${DIM}Reason:${RESET} kernel upgraded (modules for %s missing)\\n" "$(uname -r)"
        fi
    fi

    # --- Available Updates (pacman, offline: as of the last database sync) ---
    if command -v pacman &>/dev/null; then
        local total security upgradable_list
        local -a upgradable_all=()
        mapfile -t upgradable_all < <(pacman -Qu 2>/dev/null)
        total=${#upgradable_all[@]}
        security=0
        if command -v arch-audit &>/dev/null; then
            security=$(arch-audit -uq 2>/dev/null | wc -l)
        fi
        if (( total > 0 )); then
            printf "${CYAN}%-15s${RESET} " "Updates:"
            if (( security > 0 )); then
                printf "${YELLOW}%s packages (%s with security fixes)${RESET}\\n" "$total" "$security"
            else
                printf "%s packages available\\n" "$total"
            fi
            upgradable_list=$(printf "%s\\n" "${upgradable_all[@]}" | head -n5 | awk '{print $1}')
            [ -n "$upgradable_list" ] && \\
                printf "               ${DIM}Upgradable:${RESET} %s" "$(echo "$upgradable_list" | paste -sd ', ')"
            [ "$total" -gt 5 ] && printf " ... (+%s more)\\n" $((total - 5)) || printf "\\n"
        fi

    # --- Available Updates (APT) ---
    elif command -v apt-get &>/dev/null; then''')
sub('''# Check for available updates
checkupdates() {
    if [ -x /usr/lib/update-notifier/apt-check ]; then''',
    '''# Check for available updates
checkupdates() {
    if command -v pacman &>/dev/null; then
        echo "Checking for updates..."
        if type -P checkupdates &>/dev/null; then
            command checkupdates || echo "System is up to date."
        else
            pacman -Qu 2>/dev/null || echo "No updates in the local database (run 'sudo pacman -Sy' to refresh)."
        fi
        if command -v arch-audit &>/dev/null; then
            echo "Security advisories (arch-audit):"
            arch-audit
        fi
    elif [ -x /usr/lib/update-notifier/apt-check ]; then''')
sub('''    alias aptlist='apt list --installed'
fi
''', '''    alias aptlist='apt list --installed'
fi

# Pacman aliases for Arch Linux (only if pacman is available).
if command -v pacman &>/dev/null; then
    alias pacup='sudo pacman -Syu'
    alias pacin='sudo pacman -S --needed'
    alias pacrm='sudo pacman -Rns'
    alias pacsearch='pacman -Ss'
    alias pacshow='pacman -Si'
    alias paclist='pacman -Qe'
    alias pacorphans='pacman -Qdt'
    alias pacfiles='pacman -Ql'
    alias pacown='pacman -Qo'
    pacclean() {
        local orphans
        orphans=$(pacman -Qdtq 2>/dev/null)
        # shellcheck disable=SC2086
        [ -n "$orphans" ] && sudo pacman -Rns $orphans
        if command -v paccache &>/dev/null; then sudo paccache -rk2; else sudo pacman -Sc; fi
    }
    if command -v paru &>/dev/null; then
        alias aurup='paru -Syu'; alias aurin='paru -S'; alias aursearch='paru -Ss'
    elif command -v yay &>/dev/null; then
        alias aurup='yay -Syu'; alias aurin='yay -S'; alias aursearch='yay -Ss'
    fi
fi
''')
sub('''APT (Debian/Ubuntu):
  aptup             Update and upgrade packages
  aptin <pkg>       Install package
  aptrm <pkg>       Remove package
  aptsearch <term>  Search for packages
  aptshow <pkg>     Show package information
  aptclean          Remove unused packages
  aptlist           List installed packages
''', '''Pacman (Arch Linux):
  pacup             Full system upgrade (pacman -Syu)
  pacin <pkg>       Install package
  pacrm <pkg>       Remove package with its unneeded deps
  pacsearch <term>  Search repositories
  pacshow <pkg>     Show package information
  paclist           List explicitly installed packages
  pacorphans        List orphaned packages
  pacfiles <pkg>    List files owned by a package
  pacown <file>     Which package owns a file
  pacclean          Remove orphans and trim the package cache
  aurup/aurin/aursearch  Same via paru/yay (if installed)

APT (Debian/Ubuntu):
  aptup             Update and upgrade packages
  aptin <pkg>       Install package
  aptrm <pkg>       Remove package
  aptsearch <term>  Search for packages
  aptshow <pkg>     Show package information
  aptclean          Remove unused packages
  aptlist           List installed packages
''')

# ---------------------------------------------------------------- sanity: no apt/dpkg left outside the bashrc
DST.write_text(text)
leftovers = [
    (i + 1, l) for i, l in enumerate(text.splitlines())
    if re.search(r"\b(apt-get|apt |dpkg|debconf|unattended-upgrades|deluser|adduser)\b", l)
    and not l.lstrip().startswith("#")
]
print(f"wrote {DST} ({len(text.splitlines())} lines)")
print("remaining apt/dpkg references (expected only inside the generated .bashrc):")
for n, l in leftovers:
    print(f"  {n}: {l.strip()[:110]}")
