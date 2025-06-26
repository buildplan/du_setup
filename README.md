# Debian/Ubuntu Server Setup and Hardening Script

**Version**: 4.0 | **Date**: 2025-06-26  
**Compatible with**: Debian 12 (Bookworm), Ubuntu 20.04 LTS, 22.04 LTS, 24.04 LTS, 24.10 (experimental)

## Overview

This Bash script automates the provisioning and hardening of a Debian 12 or Ubuntu server (20.04, 22.04, 24.04 LTS, or 24.10). It configures essential security settings, user management, SSH hardening, firewall rules, and optional features like Docker, Tailscale (with Headscale support), and system monitoring (SMTP and ntfy). The script is idempotent, supports configuration files for automation, and provides flexibility for missing or partial configurations.

## Features

- **System Checks**: Validates root privileges, internet connectivity, and OS compatibility.
- **User Management**: Creates a new admin user with sudo privileges and optional SSH key setup.
- **SSH Hardening**: Configures a custom SSH port, disables root login, and enforces key-based authentication.
- **Firewall (UFW)**: Sets up restrictive firewall rules with customizable ports.
- **Fail2Ban**: Protects against brute-force attacks on SSH and other ports.
- **Automatic Updates**: Enables unattended security updates (optional).
- **System Monitoring**: Configures disk space and backup alerts via SMTP and/or ntfy (optional).
- **Docker**: Installs Docker Engine and adds the user to the docker group (optional).
- **Tailscale**: Sets up Tailscale VPN with Headscale support (optional).
- **Swap**: Configures or resizes swap space (skipped in containers).
- **Time Sync**: Ensures chrony is active for time synchronization.
- **Logging & Backups**: Logs all actions to `/var/log/setup_harden_debian_ubuntu_*.log` and backs up critical files to `/root/setup_harden_backup_*`.

## Prerequisites

- Run as root (`sudo ./setup_harden_debian_ubuntu.sh`).
- Internet connectivity for package installation.
- At least 2GB free disk space for swap (if enabled).
- Compatible OS: Debian 12 or Ubuntu 20.04/22.04/24.04 LTS (24.10 experimental).

## Usage

1. **Download the Script**:
   ```bash
   wget https://raw.githubusercontent.com/buildplan/learning/refs/heads/main/setup_harden_debian_ubuntu.sh
   chmod +x setup_harden_debian_ubuntu.sh
   ```

2. **Run Interactively**:
   ```bash
   sudo ./setup_harden_debian_ubuntu.sh
   ```

3. **Run with Config File**:
   ```bash
   sudo ./setup_harden_debian_ubuntu.sh --config /etc/setup_harden.conf
   ```

4. **Run in Quiet Mode**:
   ```bash
   sudo ./setup_harden_debian_ubuntu.sh --quiet
   ```

## Configuration File

You can provide a configuration file (e.g., `/etc/setup_harden.conf`) to automate setup. If variables are missing or invalid, the script will prompt interactively (unless in `--quiet` mode, where it skips optional settings).

**Example Config**:
```bash
USERNAME=ali
HOSTNAME=doVPS
SSH_PORT=5595
TIMEZONE=Etc/UTC
SWAP_SIZE=2G
UFW_PORTS=80/tcp,443/tcp,51820/udp
AUTO_UPDATES=yes
INSTALL_DOCKER=yes
INSTALL_TAILSCALE=yes
TAILSCALE_LOGIN_SERVER=https://hs.mydomain.com
TAILSCALE_AUTH_KEY=tskey-xxxxxxxxxxxxxxxxxxxxxxxxxxxx
TAILSCALE_OPERATOR=ali
TAILSCALE_ACCEPT_DNS=yes
TAILSCALE_ACCEPT_ROUTES=yes
SMTP_SERVER=mail.smtp2go.com
SMTP_PORT=587
SMTP_FROM=alerts@mydomain.com
SMTP_TO=admin@mydomain.com
NTFY_SERVER=https://ntfy.mydomain.com/ovps
NTFY_TOKEN=tk_xxxxxxxxxxxxxxxxxxxxxxxx
```

**Configuration Notes**:
- **Required Variables**: `USERNAME`, `HOSTNAME`, `SSH_PORT`. If missing, the script will prompt (non-quiet mode) or fail (quiet mode).
- **Optional Variables**: All others (e.g., `UFW_PORTS`, `SMTP_*`, `NTFY_*`, `TAILSCALE_*`). If partially provided, the script prompts for missing values or skips the feature in quiet mode.
- **Validation**: The script validates all inputs (e.g., username format, port numbers, URLs). Invalid values trigger prompts or skipping.

## Flexible Configuration Handling

- **Missing Variables**: If a config file lacks variables, the script prompts interactively (non-quiet mode) or skips optional features (quiet mode).
- **Partial Configurations**: For features like Tailscale, SMTP, or ntfy, if some variables are missing, the script prompts for them or skips the feature in quiet mode.
- **No Config File**: Falls back to full interactive mode (non-quiet) or minimal setup with optional features skipped (quiet).
- **Summary**: The final summary lists applied, skipped, or prompted settings.

## Output

- **Log File**: `/var/log/setup_harden_debian_ubuntu_YYYYMMDD_HHMMSS.log`
- **Backups**: `/root/setup_harden_backup_YYYYMMDD_HHMMSS/`
- **Summary**: Displays configured settings, skipped features, and verification steps.

## Troubleshooting

- **SSH Lockout**: Restore SSH config from `/root/setup_harden_backup_*/sshd_config.backup_*`.
- **Errors**: Check the log file for details.
- **Firewall**: Ensure your VPS provider's edge firewall allows opened ports (e.g., SSH, HTTP).
- **Disk Space**: Verify >2GB free for swap (if enabled).
- **Testing**: Run in a VM before production use.

## Post-Setup Steps

1. **Verify SSH**: `ssh -p <SSH_PORT> <USERNAME>@<SERVER_IP>`
2. **Check Firewall**: `sudo ufw status verbose`
3. **Check Services**: `systemctl status ssh fail2ban chrony docker tailscaled postfix`
4. **Reboot**: Recommended to apply all changes (`sudo reboot`).

## Notes

- Tested on Debian 12, Ubuntu 20.04/22.04/24.04 LTS. Ubuntu 24.10 is experimental and may require manual adjustments.
- In quiet mode, missing optional settings are skipped, and required settings must be valid, or the script fails.
- A reboot is required to ensure all changes take effect.
- For DigitalOcean, configure the edge firewall in the Control Panel to allow custom SSH ports and other opened ports.
