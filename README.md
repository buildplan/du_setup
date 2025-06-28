# Debian & Ubuntu Server Setup & Hardening Script

**Version:** 4.1

**Last Updated:** 2025-06-29

**Compatible With:**

- Debian 12
- Ubuntu 22.04, 24.04, 24.10 (24.10 experimental)

## Overview

This script automates the initial setup and security hardening of a fresh Debian or Ubuntu server. It is **idempotent**, **safe**, and suitable for **production environments**, providing a secure baseline for further customization. The script runs interactively, guiding users through critical choices while automating essential security and setup tasks.

## Features

- **Secure User Management**: Creates a new `sudo` user and disables root SSH access.
- **SSH Hardening**: Configures a custom SSH port, enforces key-based authentication, and applies security best practices.
- **Firewall Configuration**: Sets up UFW with secure defaults and customizable rules.
- **Intrusion Prevention**: Installs and configures **Fail2Ban** to block malicious IPs.
- **Automated Security Updates**: Enables `unattended-upgrades` for automatic security patches.
- **System Stability**: Configures NTP time synchronization with `chrony` and optional swap file setup for low-RAM systems.
- **Remote rsync Backups**: Configures automated `rsync` backups over SSH to any compatible server (e.g., Hetzner Storage Box), with SSH key automation (`sshpass` or manual), cron scheduling, ntfy/Discord notifications, and a customizable exclude file.
- **Tailscale VPN**: Installs Tailscale and connects to the standard Tailscale network (pre-auth key required) or a custom server (URL and key required). Configures optional flags (`--ssh`, `--advertise-exit-node`, `--accept-dns`, `--accept-routes`).
- **Safety First**: Backs up critical configuration files before modification, stored in `/root/setup_harden_backup_*`.
- **Optional Software**: Offers interactive installation of:
  - Docker & Docker Compose
  - Tailscale (Mesh VPN)
- **Comprehensive Logging**: Logs all actions to `/var/log/setup_harden_debian_ubuntu_*.log`.
- **Automation-Friendly**: Supports `--quiet` mode for automated provisioning.

## Installation & Usage

### Prerequisites

- Fresh installation of a compatible OS.
- Root or `sudo` privileges.
- Internet access for package downloads.
- For remote backups: An SSH-accessible server (e.g., Hetzner Storage Box) with credentials or SSH key access.
- For Tailscale: A pre-auth key from https://login.tailscale.com/admin (standard, starts with `tskey-auth-`) or from a custom server (e.g., `https://ts.mydomain.cloud`).

### 1. Download the Script

```
wget https://raw.githubusercontent.com/buildplan/setup_harden_server/refs/heads/main/setup_harden_debian_ubuntu.sh
chmod +x setup_harden_debian_ubuntu.sh
```

### 2. Run Interactively (Recommended)

```
sudo ./setup_harden_debian_ubuntu.sh
```

### 3. Run in Quiet Mode (for Automation)

```
sudo ./setup_harden_debian_ubuntu.sh --quiet
```

> **Warning**: The script pauses to verify SSH access on the new port before disabling old access methods. **Test the new SSH connection from a separate terminal before proceeding!**
>
> Ensure your VPS provider’s firewall allows the custom SSH port, backup server’s SSH port (e.g., 23 for Hetzner Storage Box), and Tailscale traffic (UDP 41641 for direct connections).

## What It Does

| Task | Description |
| --- | --- |
| **System Checks** | Verifies OS compatibility, root privileges, and internet connectivity. |
| **Package Management** | Updates packages and installs tools (`ufw`, `fail2ban`, `chrony`, `rsync`, etc.). |
| **Admin User Creation** | Creates a `sudo` user with a password and/or SSH public key. |
| **SSH Hardening** | Disables root login, enforces key-based auth, and sets a custom port. |
| **Firewall Setup** | Configures UFW to deny incoming traffic by default, allowing specific ports. |
| **Remote Backup Setup** | Configures `rsync` backups to an SSH server (e.g., `u457300-sub4@u457300.your-storagebox.de:23`). Creates `/root/run_backup.sh`, `/root/rsync_exclude.txt`, and schedules a cron job. Supports ntfy/Discord notifications. |
| **Tailscale Setup** | Installs Tailscale and connects to the standard Tailscale network (pre-auth key starting with `tskey-auth-`) or a custom server (any valid key). Configures optional flags (`--ssh`, `--advertise-exit-node`, `--accept-dns`, `--accept-routes`). |
| **System Backups** | Saves timestamped configuration backups in `/root/setup_harden_backup_*`. |
| **Swap File Setup** | Creates an optional swap file (e.g., 2G) with tuned settings. |
| **Timezone & Locales** | Configures timezone and system locales interactively. |
| **Docker Install** | Installs Docker Engine and adds the user to the `docker` group. |
| **Final Cleanup** | Removes unused packages and reloads daemons. |

## Logs & Backups

- **Log Files**: `/var/log/setup_harden_debian_ubuntu_*.log`
- **Backup Logs**: `/var/log/backup_rsync.log` (for remote backup operations)
- **Configuration Backups**: `/root/setup_harden_backup_*`

## Post-Reboot Verification

After rebooting, verify the setup:

- **SSH Access**: `ssh -p <custom_port> <username>@<server_ip>`
- **Firewall Rules**: `sudo ufw status verbose`
- **Time Synchronization**: `chronyc tracking`
- **Fail2Ban Status**: `sudo fail2ban-client status sshd`
- **Swap Status**: `sudo swapon --show && free -h`
- **Hostname**: `hostnamectl`
- **Docker Status** (if installed): `docker ps`
- **Tailscale Status** (if installed): `tailscale status`
- **Tailscale Verification** (if configured):
  - Check connection: `tailscale status`
  - Test Tailscale SSH (if enabled): `tailscale ssh <username>@<tailscale-ip>`
  - Verify exit node (if enabled): Check Tailscale admin console
  - If not connected, run the `tailscale up` command shown in the script output
- **Remote Backup** (if configured):
  - Verify SSH key: `cat /root/.ssh/id_ed25519.pub`
  - Copy key (if not done): `ssh-copy-id -p <backup_port> -s <backup_user@backup_host>`
  - Test backup: `sudo /root/run_backup.sh`
  - Check logs: `sudo less /var/log/backup_rsync.log`
  - Verify cron job: `sudo crontab -l` (e.g., `3 3 * * * /root/run_backup.sh`)

## Tested On

- Debian 12
- Ubuntu 22.04, 24.04, 24.10 (experimental)
- Cloud providers: DigitalOcean, Oracle Cloud, Hetzner, Netcup
- Backup destinations: Hetzner Storage Box, custom SSH servers
- Tailscale: Standard network, custom self-hosted servers

## Important Notes

- **Run on a fresh system**: Designed for initial provisioning.
- **Reboot required**: Ensures kernel and service changes apply cleanly.
- Test in a non-production environment (e.g., staging VM) first.
- Maintain out-of-band console access in case of SSH lockout.
- For Hetzner Storage Box, ensure `~/.ssh/` exists on the remote server: `ssh -p 23 <backup_user@backup_host> "mkdir -p ~/.ssh && chmod 700 ~/.ssh"`.
- For Tailscale, generate a pre-auth key from https://login.tailscale.com/admin (standard, must start with `tskey-auth-`) or your custom server (any valid key). Ensure UDP 41641 is open for Tailscale traffic.

## Troubleshooting

### SSH Lockout Recovery

If locked out, use your provider’s console:

1. **Remove Hardened Configuration**:
   ```
   rm /etc/ssh/sshd_config.d/99-hardening.conf
   ```

2. **Restore Original `sshd_config`**:
   ```
   LATEST_BACKUP=$(ls -td /root/setup_harden_backup_* | head -1)
   cp "$LATEST_BACKUP"/sshd_config.backup_* /etc/ssh/sshd_config
   ```

3. **Restart SSH**:
   ```
   systemctl restart ssh
   ```

### Backup Issues

If backups fail:

1. **Verify SSH Key**:
   - Check: `cat /root/.ssh/id_ed25519.pub`
   - Copy (if needed): `ssh-copy-id -p <backup_port> -s <backup_user@backup_host>`
   - For Hetzner: `ssh -p 23 <backup_user@backup_host> "mkdir -p ~/.ssh && chmod 700 ~/.ssh"`
   - Test SSH: `ssh -p <backup_port> <backup_user@backup_host> exit`

2. **Check Logs**:
   - Review: `sudo less /var/log/backup_rsync.log`
   - If automated key copy fails: `cat /tmp/ssh-copy-id.log`

3. **Test Backup Manually**:
   ```
   sudo /root/run_backup.sh
   ```

4. **Verify Cron Job**:
   - Check: `sudo crontab -l`
   - Ensure: `3 3 * * * /root/run_backup.sh #-*- managed by setup_harden script -*-`
   - Test cron permissions: `echo "3 3 * * * /root/run_backup.sh" | crontab -u root -`
   - Check permissions: `ls -l /var/spool/cron/crontabs/root` (expect `-rw------- root:crontab`)

5. **Network Issues**:
   - Verify port: `nc -zv <backup_host> <backup_port>`
   - Check VPS firewall for outbound access to the backup port (e.g., 23 for Hetzner).

6. **Summary Errors**:
   - If summary shows `Remote Backup: Not configured`, verify: `ls -l /root/run_backup.sh`

### Tailscale Issues

If Tailscale fails to connect:

1. **Verify Installation**:
   - Check: `command -v tailscale`
   - Service status: `systemctl status tailscaled`

2. **Check Connection**:
   - Run: `tailscale status`
   - Verify server: `tailscale status --json | grep ControlURL`
   - Check logs: `sudo journalctl -u tailscaled`

3. **Test Pre-Auth Key**:
   - Re-run the command shown in the script output (e.g., `sudo tailscale up --auth-key=<key> --operator=<username>` or with `--login-server=<url>`).
   - For custom servers, ensure the key is valid for the specified server (e.g., generated from `https://ts.mydomain.cloud`).

4. **Additional Flags**:
   - Verify SSH: `tailscale ssh <username>@<tailscale-ip>`
   - Check exit node: Tailscale admin console
   - Verify DNS: `cat /etc/resolv.conf`
   - Check routes: `tailscale status`

5. **Network Issues**:
   - Ensure UDP 41641 is open: `nc -zvu <tailscale-server> 41641`
   - Check VPS firewall for Tailscale traffic.

## [MIT](https://github.com/buildplan/setup_harden_server/blob/main/LICENSE) License

This script is open-source and provided "as is" without warranty. Use at your own risk.
