# Debian & Ubuntu Server Setup & Hardening Script

[![Debian Compatibility](https://img.shields.io/badge/Compatibility–Debian%2012%7C13-%23A81D33?style=flat&labelColor=555&logo=debian&logoColor=white)](https://www.debian.org/releases/)
[![Ubuntu Compatibility](https://img.shields.io/badge/Compatibility–Ubuntu%2022.04%7C24.04-%23E95420?style=flat&labelColor=555&logo=ubuntu&logoColor=white)](https://ubuntu.com/download/server)
[![Shell Script Linter](https://github.com/buildplan/du_setup/actions/workflows/lint.yml/badge.svg)](https://github.com/buildplan/du_setup/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell](https://img.shields.io/badge/Shell-Bash%204.4%2B-green)](https://www.gnu.org/software/bash/)
[![Type](https://img.shields.io/badge/Type-Setup%20%26%20Hardening-blue)](https://github.com/buildplan/du_setup)

**Version:** v0.66

**Last Updated:** 2025-08-26

**Compatible With:**

  * Debian 12, 13
  * Ubuntu 20.04, 22.04, 24.04 (24.10 & 25.04 experimental)

## Overview

This script automates the initial setup and security hardening of a fresh Debian or Ubuntu server. It is **idempotent**, **safe**, and suitable for **production environments**, providing a secure baseline for further customization. The script runs interactively, guiding users through critical choices while automating essential security and setup tasks.

## Features

  * **Secure User Management**: Creates a new `sudo` user and disables root SSH access.
  * **SSH Hardening**: Configures a custom SSH port, enforces key-based authentication, and applies security best practices.
  * **Firewall Configuration**: Sets up UFW with secure defaults and customizable rules.
  * **Intrusion Prevention**: Installs and configures **Fail2Ban** to block malicious IPs.
  * **Kernel Hardening**: Optionally applies a set of recommended `sysctl` security settings to harden the kernel against common network and memory-related threats.
  * **Automated Security Updates**: Enables `unattended-upgrades` for automatic security patches.
  * **System Stability**: Configures NTP time synchronization with `chrony` and optional swap file setup for low-RAM systems.
  * **Remote rsync Backups**: Configures automated `rsync` backups over SSH to any compatible server (e.g., Hetzner Storage Box), with SSH key automation (`sshpass` or manual), cron scheduling, ntfy/Discord notifications, and a customizable exclude file.
  * **Backup Testing**: Includes an optional test backup to verify the rsync configuration before scheduling.
  * **Tailscale VPN**: Installs Tailscale and connects to the standard Tailscale network (pre-auth key required) or a custom server (URL and key required). Configures optional flags (`--ssh`, `--advertise-exit-node`, `--accept-dns`, `--accept-routes`).
  * **Security Auditing**: Optionally runs **Lynis** for system hardening audits and **debsecan** for package vulnerability checks, with results logged for review.
  * **Safety First**: Backs up critical configuration files before modification, stored in `/root/setup_harden_backup_*`.
  * **Optional Software**: Offers interactive installation of:
      * Docker & Docker Compose
      * Tailscale (Mesh VPN)
  * **Comprehensive Logging**: Logs all actions to `/var/log/du_setup_*.log`.
  * **Automation-Friendly**: Supports `--quiet` mode for automated provisioning.

## Installation & Usage

### Prerequisites

  * Fresh installation of a compatible OS.
  * Root or `sudo` privileges.
  * Internet access for package downloads.
  * Minimum 2GB disk space for swap file creation and temporary files.
  * For remote backups: An SSH-accessible server (e.g., Hetzner Storage Box) with credentials or SSH key access. For Hetzner, SSH (port 23) is used for rsync.
  * For Tailscale: A pre-auth key from [https://login.tailscale.com/admin](https://login.tailscale.com/admin) (standard, starts with `tskey-auth-`) or from a custom server (e.g., `https://ts.mydomain.cloud`).

### 1\. Download & Prepare Script

```
wget https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.sh
chmod +x du_setup.sh
```

### 2\. Verify Script Integrity (Recommended)

To ensure the script has not been altered, you can verify its SHA256 checksum.

**Option A: Automatic Check**

This command downloads the official checksum file and automatically compares it against your downloaded script.

```
# Download the official checksum file
wget https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.sh.sha256

# Run the check (it should output: du_setup.sh: OK)
sha256sum -c du_setup.sh.sha256
```

**Option B: Manual Check**

```
# Generate the hash of your downloaded script
sha256sum du_setup.sh
```

Compare the output hash to the one below. They must match exactly.

`0fd83600035b4d08ee574235bf95a03fea81e680db0caa5a6d77c6f7f5db203d`

Or echo the hash to check, it should output: `du_setup.sh: OK`

```
echo 0fd83600035b4d08ee574235bf95a03fea81e680db0caa5a6d77c6f7f5db203d du_setup.sh | sha256sum --check -
```

### 3\. Run the Script

**Interactively (Recommended)**

Ideally run as root, if you are a sudo user you can switch to root with `sudo su`

```
./du_setup
```
Alternatively run with sudo -E, -E flag preserve the environment variables.

```
sudo -E ./du_setup.sh
```

**Quiet Mode (For Automation)**

```
sudo -E ./du_setup.sh --quiet
```

> **Warning**: The script pauses to verify SSH access on the new port before disabling old access methods. **Test the new SSH connection from a separate terminal before proceeding\!**
>
> Ensure your VPS provider’s firewall allows the custom SSH port, backup server’s SSH port (e.g., 23 for Hetzner Storage Box), and Tailscale traffic (UDP 41641 for direct connections).

## What It Does

| Task | Description |
| :--- | :--- |
| **System Checks** | Verifies OS compatibility, root privileges, and internet connectivity. |
| **Package Management** | Updates packages and installs essential tools (`ufw`, `fail2ban`, `chrony`, `rsync`, etc.). |
| **Admin User Creation**| Creates a `sudo` user with a password and/or SSH public key. |
| **SSH Hardening** | Disables root login, enforces key-based auth, and sets a custom port with a robust rollback mechanism. |
| **Firewall Setup** | Configures UFW to deny incoming traffic by default, allowing specific user-defined ports. |
| **Fail2Ban Setup** | Configures Fail2Ban to monitor SSH and UFW logs, blocking suspicious IPs. |
| **Auto-Updates Setup** | Enables and configures `unattended-upgrades` for automatic security patches. |
| **Time Sync Setup** | Ensures `chrony` is active for accurate network time synchronization. |
| **Kernel Hardening** | Applies optional `sysctl` security settings to protect against IP spoofing and SYN floods. |
| **Docker Install** | Installs Docker Engine and Docker Compose, then adds the admin user to the `docker` group. |
| **Tailscale Setup** | Installs Tailscale and connects to a mesh network using a pre-auth key, with optional advanced flags. |
| **Remote Backup Setup**| Configures `rsync` backups to an SSH server, creating `/root/run_backup.sh` and a cron job. |
| **Backup Testing** | Performs an optional test backup to verify the `rsync` configuration. |
| **Swap File Setup** | Creates an optional swap file with tuned `swappiness` and `vfs_cache_pressure` settings. |
| **Security Auditing** | Runs optional **Lynis** and **debsecan** audits and logs the results. |
| **System Backups** | Saves timestamped backups of modified configuration files in `/root/setup_harden_backup_*`. |
| **Final Summary** | Generates a detailed report of all changes and saves it to `/var/log/du_setup_report_*.txt`. |
| **Final Cleanup** | Removes unused packages and reloads system daemons. |

## Logs & Backups

  * **Log Files**: `/var/log/du_setup_*.log`
  * **Backup Logs**: `/var/log/backup_rsync.log` (for remote backup operations)
  * **Audit Logs**: `/var/log/setup_harden_security_audit_*.log` (for Lynis and debsecan results)
  * **Configuration Backups**: `/root/setup_harden_backup_*`

## Post-Reboot Verification

After rebooting, verify the setup:

  * **SSH Access**: `ssh -p <custom_port> <username>@<server_ip>`
  * **Firewall Rules**: `sudo ufw status verbose`
  * **Time Synchronization**: `chronyc tracking`
  * **Fail2Ban Status**: `sudo fail2ban-client status sshd`
  * **Swap Status**: `sudo swapon --show && free -h`
  * **Hostname**: `hostnamectl`
  * **Kernal Hardening** (if configured):
      * Check the conf file: `sudo cat /etc/sysctl.d/99-du-hardening.conf`
      * Checks the live value of a few key parameters that script sets: `sudo sysctl fs.protected_hardlinks kernel.yama.ptrace_scope net.ipv4.tcp_syncookies`
  * **Docker Status** (if installed): `docker ps`
  * **Tailscale Status** (if installed): `tailscale status`
  * **Tailscale Verification** (if configured):
      * Check connection: `tailscale status`
      * Test Tailscale SSH (if enabled): `tailscale ssh <username>@<tailscale-ip>`
      * Verify exit node (if enabled): Check Tailscale admin console
      * If not connected, run the `tailscale up` command shown in the script output
  * **Remote Backup** (if configured):
      * Verify SSH key: `cat /root/.ssh/id_ed25519.pub`
      * Copy key (if not done): `ssh-copy-id -p <backup_port> -s <backup_user@backup_host>`
      * Test backup: `sudo /root/run_backup.sh`
      * Check logs: `sudo less /var/log/backup_rsync.log`
      * Verify cron job: `sudo crontab -l` (e.g., `5 3 * * * /root/run_backup.sh`)
  * **Security Audit** (if run):
      * Check results: `sudo less /var/log/setup_harden_security_audit_*.log`
      * Review Lynis hardening index and debsecan vulnerabilities in the script’s summary output

## Tested On

  * Debian 12, 13
  * Ubuntu 22.04, 24.04 - 24.10 & 25.04 (experimental)
  * Cloud providers: DigitalOcean, Oracle Cloud, OVH Cloud, Hetzner, Netcup
  * Backup destinations: Hetzner Storage Box (SSH, port 23), custom SSH servers
  * Tailscale: Standard network, custom self-hosted servers

## Important Notes

  * **Run on a fresh system**: Designed for initial provisioning with at least 2GB free disk space.
  * **Reboot required**: Ensures kernel and service changes apply cleanly.
  * Test in a non-production environment (e.g., staging VM) first.
  * Maintain out-of-band console access in case of SSH lockout.
  * For Hetzner Storage Box, ensure `~/.ssh/` exists on the remote server: `ssh -p 23 <backup_user@backup_host> "mkdir -p ~/.ssh && chmod 700 ~/.ssh"`. Backups use SSH (port 23) for rsync, not SFTP.
  * For Tailscale, generate a pre-auth key from [https://login.tailscale.com/admin](https://login.tailscale.com/admin) (standard, must start with `tskey-auth-`) or your custom server (any valid key). Ensure UDP 41641 is open for Tailscale traffic.
  * For security audits, review `/var/log/setup_harden_security_audit_*.log` for Lynis and debsecan recommendations.

## Troubleshooting

### SSH Lockout Recovery

If locked out, use your provider’s console:

1.  **Remove Hardened Configuration**:
    ```
    sudo rm /etc/ssh/sshd_config.d/99-hardening.conf
    ```
2.  **Restore Original `sshd_config`**:
    ```
    LATEST_BACKUP=$(ls -td /root/setup_harden_backup_* | head -1)
    sudo cp "$LATEST_BACKUP"/sshd_config.backup_* /etc/ssh/sshd_config
    ```
3.  **Restart SSH**:
    ```
    sudo systemctl restart ssh
    ```

### Backup Issues

If backups fail:

1.  **Verify SSH Key**:
      * Check: `sudo cat /root/.ssh/id_ed25519.pub`
      * Copy (if needed): `sudo ssh-copy-id -p <backup_port> -s <backup_user@backup_host>`
      * For Hetzner: `sudo ssh -p 23 <backup_user@backup_host> "mkdir -p ~/.ssh && chmod 700 ~/.ssh"`
      * Test SSH: `sudo ssh -p <backup_port> <backup_user@backup_host> exit`
2.  **Check Logs**:
      * Review: `sudo less /var/log/backup_rsync.log`
      * If automated key copy fails: `cat /tmp/ssh-copy-id.log`
3.  **Test Backup Manually**:
    ```
    sudo /root/run_backup.sh
    ```
4.  **Verify Cron Job**:
      * Check: `sudo crontab -l`
      * Ensure: `5 3 * * * /root/run_backup.sh #-*- managed by setup_harden script -*-`
      * Test cron permissions: `echo "5 3 * * * /root/run_backup.sh" | crontab -u root -`
      * Check permissions: `ls -l /var/spool/cron/crontabs/root` (expect `-rw------- root:crontab`)
5.  **Network Issues**:
      * Verify port: `nc -zv <backup_host> <backup_port>`
      * Check VPS firewall for outbound access to the backup port (e.g., 23 for Hetzner).
6.  **Summary Errors**:
      * If summary shows `Remote Backup: Not configured`, verify: `ls -l /root/run_backup.sh`

### Security Audit Issues

If audits fail:

1.  **Check Audit Log**:
      * Review: `sudo less /var/log/setup_harden_security_audit_*.log`
      * Look for Lynis errors or debsecan CVE reports
2.  **Verify Installation**:
      * Lynis: `command -v lynis`
      * Debsecan: `command -v debsecan`
      * Reinstall if needed: `sudo apt-get install lynis debsecan`
3.  **Run Manually**:
      * Lynis: `sudo lynis audit system --quick`
      * Debsecan: `sudo debsecan --suite $(source /etc/os-release && echo $VERSION_CODENAME)`

### Tailscale Issues

If Tailscale fails to connect:

1.  **Verify Installation**:
      * Check: `command -v tailscale`
      * Service status: `sudo systemctl status tailscaled`
2.  **Check Connection**:
      * Run: `tailscale status`
      * Verify server: `tailscale status --json | grep ControlURL`
      * Check logs: `sudo journalctl -u tailscaled`
3.  **Test Pre-Auth Key**:
      * Re-run the command shown in the script output (e.g., `sudo tailscale up --auth-key=<key> --operator=<username>` or with `--login-server=<url>`).
      * For custom servers, ensure the key is valid for the specified server (e.g., generated from `https://ts.mydomain.cloud`).
4.  **Additional Flags**:
      * Verify SSH: `tailscale ssh <username>@<tailscale-ip>`
      * Check exit node: Tailscale admin console
      * Verify DNS: `cat /etc/resolv.conf`
      * Check routes: `tailscale status`
5.  **Network Issues**:
      * Ensure UDP 41641 is open: `nc -zvu <tailscale-server> 41641`
      * Check VPS firewall for Tailscale traffic.

## [MIT](https://github.com/buildplan/du_setup/blob/main/LICENSE) License

This script is open-source and provided "as is" without warranty. Use at your own risk.
