# Debian & Ubuntu Server Setup & Hardening Script

**Version:** 3.13

**Last Updated:** 2025-06-27

**Compatible With:**

- Debian 12
- Ubuntu 22.04, 24.04, 24.10

* * *

## Overview

This script automates the initial setup and security hardening of a fresh Debian or Ubuntu server. It is designed to be **idempotent**, **safe**, and suitable for **production environments**, establishing a secure baseline from which to build upon.

It runs interactively, guiding the user through critical choices while automating the tedious but essential steps of securing a new server.

* * *

## Features

- **Secure User Management:** Creates a new administrator user with `sudo` privileges and disables the root account's SSH access.
- **SSH Hardening:** Configures the SSH server to use a custom port, disable password authentication (enforcing key-based login), and apply other security best practices.
- **Firewall Configuration:** Sets up UFW (Uncomplicated Firewall) with sensible defaults and allows for custom rules.
- **Intrusion Prevention:** Installs and configures **Fail2Ban** to automatically block IPs that show malicious signs, such as repeated password failures.
- **Automated Security Updates:** Configures `unattended-upgrades` to automatically install new security patches.
- **System Stability:** Sets up NTP time synchronization with `chrony` and can configure a swap file for systems with low RAM.
- **Safety First:** Automatically backs up all critical configuration files before modification, with simple restoration instructions.
- **Optional Software:** Provides optional, interactive installation for:
    - Docker & Docker Compose
    - Tailscale (Mesh VPN)
- **Comprehensive Logging:** All actions are logged to `/var/log/setup_harden_debian_ubuntu_*.log`.
- **Automation-Friendly:** Includes a `--quiet` mode to suppress non-essential output for use in automated provisioning workflows.

* * *

## Installation & Usage

### Prerequisites

- A fresh installation of a compatible OS.
- Root or `sudo` privileges.
- Internet access for downloading packages.

### 1\. Download the Script

```
wget https://raw.githubusercontent.com/buildplan/setup_harden_server/refs/heads/main/setup_harden_debian_ubuntu.sh
chmod +x setup_harden_debian_ubuntu.sh
```

### 2\. Run the Script Interactively

It is highly recommended to run the script interactively the first time.

```
sudo ./setup_harden_debian_ubuntu.sh
```

### 3\. Run in Quiet Mode (for automation - not recmmended)

```
sudo ./setup_harden_debian_ubuntu.sh --quiet
```

> :warning: **Critical Safety Check:** The script will pause and require you to test your new SSH connection from a separate terminal before it proceeds to disable old access methods. **Do not skip this step!**
> 
> *Make sure to check VPS providers firewall, you will have to open your selected custom SSH port there.*

* * *

## What It Does in Detail

| Task | Description |
| --- | --- |
| **System Checks** | Verifies OS compatibility, root privileges, and internet connectivity. |
| **Package Management** | Updates all packages and installs essential tools (`ufw`, `fail2ban`, `chrony`, etc.). |
| **Admin User Creation** | Creates a new `sudo` user with a password and/or a provided SSH public key. |
| **SSH Hardening** | Disables root login, enforces key-based auth, and sets a custom port. |
| **Firewall Setup** | Configures UFW to deny incoming traffic by default and allow specific ports. |
| **System Backups** | Creates timestamped backups of configs in `/root/` before modification. |
| **Swap File Setup** | (Optional) Creates a swap file with a user-selected size. |
| **Timezone & Locales** | (Optional) Interactive configuration for timezone and system locales. |
| **Docker Install** | (Optional) Installs and configures Docker Engine and adds the user to the `docker` group. |
| **Tailscale Install** | (Optional) Installs the Tailscale client. |
| **Final Cleanup** | Removes unused packages and reloads system daemons. |

* * *

## Logs & Backups

- **Log Files:** `/var/log/setup_harden_debian_ubuntu_*.log`
- **Configuration Backups:** `/root/setup_harden_backup_*`

* * *

## Tested On

- Debian 12
- Ubuntu 24.04 and 24.10
- Cloud providers (DigitalOcean, Oracle Cloud, Hetzner, Netcup) and local VMs.

* * *

## :exclamation: Important Notes

- **Run this on a fresh system.** While idempotent, the script is designed for initial provisioning.
- **A system reboot is required** after the script completes to ensure all changes, especially to the kernel and services, are applied cleanly.
- Always test the script in a non-production environment (like a staging VM) before deploying to a live server.
- Ensure you have out-of-band console access to your server in case you accidentally lock yourself out.

* * *

## Troubleshooting

### SSH Lockout Recovery

If you are locked out of SSH, use your provider's web console to perform the following steps:

1.  **Remove the hardened configuration:**
    
    ```
    # This file overrides the main config, so it must be removed.
    rm /etc/ssh/sshd_config.d/99-hardening.conf
    ```
    
2.  **Restore the original `sshd_config` file:**
    
    ```
    # Find the latest backup directory
    LATEST_BACKUP=$(ls -td /root/setup_harden_backup_* | head -1)
    
    # Copy the original config back into place
    cp "$LATEST_BACKUP"/sshd_config.backup_* /etc/ssh/sshd_config
    ```

3.  **Restart the SSH service:**
    ```
    systemctl restart ssh
    ```
    You should now be able to log in using the original port (usually 22) and credentials.

---

## [MIT](https://github.com/buildplan/setup_harden_server/blob/main/LICENSE "LICENCE") License

This script is open-source and provided "as is" without warranty. Use at your own risk.
