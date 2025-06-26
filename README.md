## Debian & Ubuntu Server Setup & Hardening Script

**Version:** 3.8  
**Last Updated:** 2025-06-26  
**Compatible With:**  
- Debian 12 (Bookworm)  
- Ubuntu 20.04 LTS, 22.04 LTS, 24.04 LTS  

---

## 📌 Overview

This script automates the secure provisioning and hardening of a fresh Debian or Ubuntu server. It covers essential system settings, user management, SSH hardening, firewall configuration, and optional installation of Docker and Tailscale.

It is designed to be **idempotent**, **safe**, and suitable for **production environments**.

---

## ⚙️ Features

- Root login disabled, new admin user creation  
- SSH key-based login support and key detection  
- UFW firewall configuration with custom port support  
- SSH and system configuration backup and rollback safety  
- Timezone and swap file setup  
- Optional installation of:
  - Docker & Docker Compose
  - Tailscale (Mesh VPN)
- Logging to `/var/log/`
- Optional quiet mode for automated scripts

---

## 📥 Installation & Usage

### 1. Download the script

```bash
wget https://raw.githubusercontent.com/buildplan/learning/refs/heads/main/setup_harden_debian_ubuntu.sh
chmod +x setup_harden_debian_ubuntu.sh
````

### 2. Run the script as root

```bash
sudo ./setup_harden_debian_ubuntu.sh
```

### 3. Optional: Run in quiet mode

```bash
sudo ./setup_harden_debian_ubuntu.sh --quiet
```

> 🔒 The script must be run as root (or with sudo privileges).

---

## 📂 What It Does

| Task                          | Description                                    |
| ----------------------------- | ---------------------------------------------- |
| Admin User Creation           | Creates new sudo user with password or SSH key |
| SSH Hardening                 | Disables root login, adjusts secure options    |
| Firewall                      | UFW setup with customisable ports              |
| Package Installation          | Essential tools (curl, fail2ban, etc.)         |
| System Config Backup          | Creates backups before making changes          |
| Swap File Setup               | Creates a swap file with size selection        |
| Timezone Selection            | Interactive timezone configuration             |
| Docker & Tailscale (optional) | Only installed when prompted                   |

---

## 🪵 Logs & Backups

* **Logs:** `/var/log/setup_harden_debian_ubuntu_*.log`
* **Config Backups:** `/root/setup_harden_backup_*`
* **SSHD Backup:** Restorable from the backup directory in case of issues

---

## 🧪 Tested On

* Debian 12 (Bookworm)
* Ubuntu 20.04, 22.04, and 24.04 (LTS only)
* VirtualBox, KVM, and common VPS providers (Hetzner, DigitalOcean, etc.)

---

## ❗ Important Notes

* Always test in a VM or staging VPS before using in production.
* Ensure you have console or out-of-band access in case SSH becomes inaccessible.
* A system **reboot is recommended** after running the script.

---

## 🛠 Troubleshooting

* **SSH Locked Out?** Use the server console and restore:

  ```bash
  cp /root/setup_harden_backup_*/sshd_config /etc/ssh/sshd_config
  systemctl restart ssh
  ```
* **No internet?** The script requires internet access to install packages.

---

## 📝 License

This script is open-source and provided "as is" without warranty.
Use at your own risk.
