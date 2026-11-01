# Debian & Ubuntu Server Setup & Hardening Script

[![Debian Compatibility](https://img.shields.io/badge/Compatibility–Debian%2012%7C13-%23A81D33?style=flat&labelColor=555&logo=debian&logoColor=white)](https://www.debian.org/releases/)
[![Ubuntu Compatibility](https://img.shields.io/badge/Compatibility–Ubuntu%2022.04%7C24.04%7C26.04-%23E95420?style=flat&labelColor=555&logo=ubuntu&logoColor=white)](https://ubuntu.com/download/server)  
[![Shell Script Linter](https://github.com/buildplan/du_setup/actions/workflows/lint.yml/badge.svg)](https://github.com/buildplan/du_setup/actions/workflows/lint.yml)
[![Codacy Security Scan](https://github.com/buildplan/du_setup/actions/workflows/codacy.yml/badge.svg?branch=main)](https://github.com/buildplan/du_setup/actions/workflows/codacy.yml)

-----

**Version:** v0.82.0

**Last Updated:** 2026-11-01

**Compatible With:**

* Debian 12, 13
* Ubuntu 20.04, 22.04, 24.04, 26.04 (24.10, 25.04 & 25.10 experimental)

## Overview

This script automates the initial setup and security hardening of a fresh Debian or Ubuntu server. It is **idempotent**, **safe**, and suitable for **production environments**, providing a secure baseline for further customization. The script runs interactively, guiding users through critical choices while automating essential security and setup tasks.

-----

## Features

* **Secure User Management**: Creates a new `sudo` user and disables root SSH access. Optionally installs a custom .bashrc for enhanced terminal experience.
* **SSH Hardening**: Configures a custom SSH port, enforces key-based authentication, and applies security best practices.
* **Firewall Configuration**: Sets up UFW with secure defaults, customizable rules, and optional Docker `DOCKER-USER` chain hardening so published container ports cannot bypass UFW.
* **2FA Configuration**: Optionally enhance server security with 2FA, Sets up 2FA and shows QR code to add to any TOTP authenticator.
* **Intrusion Prevention**: Installs and configures **Fail2Ban** (or **CrowdSec**) to block malicious IPs.
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
* **Automation-Friendly**: Supports `--config <file>` and `--quiet` mode with safe prompt defaults, pre-flight SSH key validation, and an example configuration file (`du_setup.env.example`).

-----

## Installation & Usage

### Prerequisites

* Fresh installation of a compatible OS.
* Root or `sudo` privileges.
* Internet access for package downloads.
* Minimum 2GB disk space for swap file creation and temporary files.
* For remote backups: An SSH-accessible server (e.g., Hetzner Storage Box) with credentials or SSH key access. For Hetzner, SSH (port 23) is used for rsync.
* For Tailscale: A pre-auth key from [https://login.tailscale.com/admin](https://login.tailscale.com/admin) (standard, starts with `tskey-auth-`) or from a custom server (e.g., `https://ts.mydomain.cloud`).

### 1. Download & Prepare Script

```bash
wget https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.sh
chmod +x du_setup.sh
```

### 2. Verify Script Integrity (Recommended)

To ensure the script has not been altered, you can verify its SHA256 checksum.

#### Option A: Automatic Check

This command downloads the official checksum file and automatically compares it against your downloaded script.

```bash
# Download the official checksum file
wget https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.sh.sha256

# Run the check (it should output: du_setup.sh: OK)
sha256sum -c du_setup.sh.sha256
```

#### Option B: Manual Check

```bash
# Generate the hash of your downloaded script
sha256sum du_setup.sh
```

Compare the output hash to the one below. They must match exactly.

`efc6de7602e528cffdb4a3c461d474db9064e7e575e685fbbe8dd38e75795652`

Or echo the hash to check, it should output: `du_setup.sh: OK`

```bash
echo efc6de7602e528cffdb4a3c461d474db9064e7e575e685fbbe8dd38e75795652 du_setup.sh | sha256sum --check
```

### 3. Run the Script

#### Interactively (Recommended)

Ideally run as root, if you are a sudo user you can switch to root with `sudo su`

```bash
./du_setup.sh
```

Alternatively run with sudo -E, -E flag preserve the environment variables.

```bash
sudo -E ./du_setup.sh
```

#### Quiet Mode / Unattended Automation (`--config` + `--quiet`)

For repeatable or automated server provisioning, copy the included `du_setup.env.example` template, fill in your `DU_USERNAME` and real `DU_SSH_PUBLIC_KEY`, and pass `--config` with `--quiet`:

```bash
# Download the example environment file (if not cloning the repo)
wget https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.env.example
cp du_setup.env.example du_setup.env
chmod 600 du_setup.env

# Edit DU_USERNAME, DU_SSH_PUBLIC_KEY, DU_SSH_PORT, and optional features
nano du_setup.env

# Run unattended provisioning
sudo -E ./du_setup.sh --config ./du_setup.env --quiet
```

* Only `DU_*` variables are accepted by `--config` (parsed safely line-by-line without `eval`/`source`).
* Pre-flight validation verifies `DU_USERNAME` and `DU_SSH_PUBLIC_KEY` before modifying packages or SSH settings to prevent accidental lockouts.
* If `DU_USER_PASSWORD` is left empty (and `DU_PASSWORDLESS_SUDO="false"`), a 24-character random sudo password is generated and saved with `0600` permissions (owned by `<username>:<username>`) at `/home/<username>/.du_initial_sudo_password`. On SSH login, a self-clearing reminder prompts `<username>` to save it (or change it with `passwd`) and delete it immediately via `shred -u ~/.du_initial_sudo_password`.

> **Warning**: The script pauses to verify SSH access on the new port before disabling old access methods. **Test the new SSH connection from a separate terminal before proceeding!**
>
> Ensure your VPS provider’s firewall allows the custom SSH port, backup server’s SSH port (e.g., 23 for Hetzner Storage Box), and Tailscale traffic (UDP 41641 for direct connections).

-----

## What It Does

| Task | Description |
| :--- | :--- |
| **Provider Package Cleanup** | Detects and optionally removes cloud provider packages, monitoring agents, and default provisioning users to reduce attack surface and unnecessary services. |
| **System Compatibility Checks** | Verifies OS compatibility, root privileges, and internet connectivity. |
| **Package Management** | Verifies root privileges, OS version compatibility, and internet connectivity. Prevents running on unsupported environments. |
| **Setup User Creation & Management** | Creates or uses an existing admin user with optional SSH key setup and strong password enforcement. Includes marker file for cleanup exclusion. |
| **SSH Hardening and Rollback** | Disables root login, configures key-based authentication, sets custom SSH port, and supports rollback of SSH configuration if connectivity fails. |
| **Firewall Setup** | Configures UFW to deny incoming traffic by default, allowing specific user-defined ports. |
| **Fail2Ban/CrowdSec Setup** | Configures Fail2Ban or CrowdSec to monitor SSH and UFW logs, blocking suspicious IPs. |
| **2FA Setup** | Configures TOTP, shows QR code in the terminal to be scanned with any OTP app and includes rollback in case it any issues with setup. |
| **Auto-Updates Setup** | Enables and configures `unattended-upgrades` for automatic security patches. |
| **Time Sync Setup** | Ensures `chrony` is active for accurate network time synchronization. |
| **Kernel and Sysctl Hardening** | Optional improvements to kernel parameters to mitigate common network attacks and improve system hardening. |
| **Docker Install** | Installs Docker Engine and Docker Compose, then adds the admin user to the `docker` group. |
| **Tailscale Setup** | Installs Tailscale and connects to a mesh network using a pre-auth key, with optional advanced flags. |
| **Automated Remote Backup** | Sets up cron-driven `rsync` backup script to remote SSH servers, integrates with notifications and performs backup verification. |
| **Swap File Setup** | Creates an optional swap file with tuned `swappiness` and `vfs_cache_pressure` settings. |
| **Security Auditing** | Runs optional **Lynis** and **debsecan** vulnerability audits and logs the results for review. |
| **Logging and Reporting** | Logs all actions and generates a detailed report of setup and cleanup in `/var/log` and backup directories. Saves timestamped backups of modified configuration files in `/root/setup_harden_backup_*`. |
| **Cleanup & Maintenance** | Performs `autoremove` and `autoclean` of unused packages and services after setup or cleanup phases. |
| **Final Summary** | Generates a detailed report of all changes and saves it to `/var/log/du_setup_report_*.txt`. |

-----

## Provider Package Cleanup

Detects and optionally removes provider-installed packages, monitoring agents, and default provisioning users to enhance server security.

Cleanup is optional but recommended for commercial VPS environments to reduce attack surface. Review preview outputs carefully before applying cleanup.  

### Usage

* **Preview cleanup actions:** `sudo ./du_setup.sh --cleanup-preview`  
  Shows what would be removed without making changes.
* **Run cleanup only:** `sudo ./du_setup.sh --cleanup-only`  
  Executes provider cleanup on existing servers without full setup.
* **Skip cleanup:** `sudo ./du_setup.sh --skip-cleanup`  
  Runs full setup but skips the cleanup phase.

### What it detects

* Common cloud provider monitoring agents (e.g., DigitalOcean, Hetzner, Vultr)
* Virtualization guest tools (qemu-guest-agent, cloud-init)
* Default provisioning users (ubuntu, debian, admin, cloud-user)
* Unexpected SSH keys in `/root/.ssh/authorized_keys`

-----

## Post-Reboot Verification

After rebooting, verify the setup:

* **SSH Access**: `ssh -p <custom_port> <username>@<server_ip>`
* **Firewall Rules**: `sudo ufw status verbose`
* **Time Synchronization**: `chronyc tracking`
* **Fail2Ban Status**: `sudo fail2ban-client status sshd`
* **Swap Status**: `sudo swapon --show && free -h`
* **Hostname**: `hostnamectl`
* **Kernel Hardening** (if configured):
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

-----

## Tested On

* Debian 12, 13
* Ubuntu 22.04, 24.04, 26.04 - 24.10, 25.04 & 25.10 (experimental)
* Cloud providers: DigitalOcean, Oracle Cloud, OVH Cloud, Hetzner, Netcup
* Backup destinations: Hetzner Storage Box (SSH, port 23), custom SSH servers
* Tailscale: Standard network, custom self-hosted servers

-----

## Important Notes

* **Run on a fresh system**: Designed for initial provisioning with at least 2GB free disk space.
* **Reboot required**: Ensures kernel and service changes apply cleanly.
* Test in a non-production environment (e.g., staging VM) first.
* Maintain out-of-band console access in case of SSH lockout.
* For Hetzner Storage Box, ensure `~/.ssh/` exists on the remote server: `ssh -p 23 <backup_user@backup_host> "mkdir -p ~/.ssh && chmod 700 ~/.ssh"`. Backups use SSH (port 23) for rsync, not SFTP.
* For Tailscale, generate a pre-auth key from [https://login.tailscale.com/admin](https://login.tailscale.com/admin) (standard, must start with `tskey-auth-`) or your custom server (any valid key). Ensure UDP 41641 is open for Tailscale traffic.
* For security audits, review `/var/log/setup_harden_security_audit_*.log` for Lynis and debsecan recommendations.
* **Docker + UFW Firewall Protection**:
  * By default on Linux, publishing Docker container ports with `-p 8080:8080` manipulates `iptables`/`ip6tables` directly and **bypasses UFW** incoming rules. Always bind internal services to localhost (`docker run -p 127.0.0.1:8080:8080 ...`) behind a reverse proxy whenever possible.
  * When installing Docker, `du_setup.sh` offers optional `DOCKER-USER` firewall hardening in `/etc/ufw/after.rules` and `/etc/ufw/after6.rules` (`DU_DOCKER_UFW_HARDEN="true"`). When enabled, external internet traffic to published container ports is blocked by default unless explicitly permitted via UFW route rules:

    ```bash
    sudo ufw route allow proto tcp from any to any port 8080
    ```

-----

## Troubleshooting

### SSH Lockout Recovery

If locked out, use your provider’s out-of-band console:

1. **Remove Hardened Drop-in & Systemd Port Overrides**:

    ```bash
    sudo rm -f /etc/ssh/sshd_config.d/10-hardening.conf /etc/ssh/sshd_config.d/95-2fa-*.conf
    sudo rm -rf /etc/systemd/system/ssh.socket.d /etc/systemd/system/ssh.service.d /etc/systemd/system/sshd.service.d
    sudo systemctl daemon-reload
    ```

2. **Restore Original `sshd_config` (and PAM if 2FA was enabled)**:

    ```bash
    LATEST_BACKUP=$(ls -td /root/setup_harden_backup_* | head -1)
    sudo cp "$(ls -t "$LATEST_BACKUP"/sshd_config.backup_* | head -1)" /etc/ssh/sshd_config
    # If 2FA was enabled, also restore PAM:
    ls "$LATEST_BACKUP"/pam_sshd.backup_* >/dev/null 2>&1 && sudo cp "$(ls -t "$LATEST_BACKUP"/pam_sshd.backup_* | head -1)" /etc/pam.d/sshd
    ```

3. **Restart SSH**:

    ```bash
    sudo systemctl restart ssh.socket 2>/dev/null || true
    sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd
    ```

### Backup Issues

If backups fail:

1. **Verify SSH Key**:
      * Check: `sudo cat /root/.ssh/id_ed25519.pub`
      * Copy (if needed): `sudo ssh-copy-id -p <backup_port> -s <backup_user@backup_host>`
      * For Hetzner: `sudo ssh -p 23 <backup_user@backup_host> "mkdir -p ~/.ssh && chmod 700 ~/.ssh"`
      * Test SSH: `sudo ssh -p <backup_port> <backup_user@backup_host> exit`
2. **Check Logs**:
      * Review: `sudo less /var/log/backup_rsync.log`
      * If automated key copy fails: `cat /tmp/ssh-copy-id.log`
3. **Test Backup Manually**:

    ```bash
    sudo /root/run_backup.sh
    ```

4. **Verify Cron Job**:
      * Check: `sudo crontab -l`
      * Ensure: `5 3 * * * /root/run_backup.sh #-*- managed by setup_harden script -*-`
      * Test cron permissions: `echo "5 3 * * * /root/run_backup.sh" | crontab -u root -`
      * Check permissions: `ls -l /var/spool/cron/crontabs/root` (expect `-rw------- root:crontab`)
5. **Network Issues**:
      * Verify port: `nc -zv <backup_host> <backup_port>`
      * Check VPS firewall for outbound access to the backup port (e.g., 23 for Hetzner).
6. **Summary Errors**:
      * If summary shows `Remote Backup: Not configured`, verify: `ls -l /root/run_backup.sh`

### Security Audit Issues

If audits fail:

1. **Check Audit Log**:
      * Review: `sudo less /var/log/setup_harden_security_audit_*.log`
      * Look for Lynis errors or debsecan CVE reports
2. **Verify Installation**:
      * Lynis: `command -v lynis`
      * Debsecan: `command -v debsecan`
      * Reinstall if needed: `sudo apt-get install lynis debsecan`
3. **Run Manually**:
      * Lynis: `sudo lynis audit system --quick`
      * Debsecan: `sudo debsecan --suite $(source /etc/os-release && echo $VERSION_CODENAME)`

### Tailscale Issues

If Tailscale fails to connect:

1. **Verify Installation**:
      * Check: `command -v tailscale`
      * Service status: `sudo systemctl status tailscaled`
2. **Check Connection**:
      * Run: `tailscale status`
      * Verify server: `tailscale status --json | grep ControlURL`
      * Check logs: `sudo journalctl -u tailscaled`
3. **Test Pre-Auth Key**:
      * Re-run the command shown in the script output (e.g., `sudo tailscale up --auth-key=<key> --operator=<username>` or with `--login-server=<url>`).
      * For custom servers, ensure the key is valid for the specified server (e.g., generated from `https://ts.mydomain.cloud`).
4. **Additional Flags**:
      * Verify SSH: `tailscale ssh <username>@<tailscale-ip>`
      * Check exit node: Tailscale admin console
      * Verify DNS: `cat /etc/resolv.conf`
      * Check routes: `tailscale status`
5. **Network Issues**:
      * Ensure UDP 41641 is open: `nc -zvu <tailscale-server> 41641`
      * Check VPS firewall for Tailscale traffic.

-----

## Acknowledgments & Credits

This setup script leverages the following excellent open-source projects and tools:

### Core System Tools

* **OpenSSH** - Secure Shell for remote access
* **Fail2Ban** - Intrusion prevention system for protecting SSH and services
* **UFW** - Uncomplicated Firewall for easy firewall management
* **Chrony** - Time synchronization and NTP service
* **Rsyslog** - System logging facility

### Monitoring & Administration

* **htop** - Interactive process viewer
* **iotop** - I/O monitoring tool
* **nethogs** - Real-time network traffic monitor
* **ncdu** - Disk usage analyzer with TUI
* **tree** - Directory structure visualization

### Networking & VPN

* **Tailscale** - Zero config VPN for secure networking (optional installation)

### Container & Orchestration

* **Docker Engine** - Container runtime and orchestration
* **Docker Compose** - Multi-container orchestration
* **dtop** - Terminal-based Docker container monitoring (by [amir20](https://github.com/amir20/dtop))
* **Skopeo** - Utility for working with container images and image repositories

### Security & Auditing

* **Lynis** - Comprehensive system security auditing
* **debsecan** - Debian package vulnerability checker (Debian only)
* **unattended-upgrades** - Automatic security update management
* **GPG** - GNU Privacy Guard for cryptographic operations

### Development & Utilities

* **Git** - Version control system
* **jq** - JSON query processor for data manipulation
* **make** - Utility for building and maintaining programmes from source code
* **rsync** - Efficient file synchronization
* **curl** - Data transfer tool
* **wget** - File download utility
* **Vim** - Text editor
* **netcat** - Network utility for diagnostics
* **coreutils, gawk, perl** - Core GNU utilities

### Security & System Hardening

This script implements hardening recommendations based on:

* **CIS Benchmarks** - Center for Internet Security standards
* **NIST guidelines** - National Institute of Standards and Technology
* **OWASP security practices** - Open Web Application Security Project

### Special Thanks

* Debian and Ubuntu maintainers
* Open-source community developers

**License & Attribution Note:** Most tools included are free, open-source software under various permissive licenses (GPL, MIT, Apache 2.0). Tailscale's client is open source, though its coordination server is proprietary. Hardening guidelines reference industry standards (NIST, CIS, OWASP).

-----

## MIT [License](https://github.com/buildplan/du_setup/blob/main/LICENSE)

This script is open-source and provided "as is" without warranty. Use at your own risk.
