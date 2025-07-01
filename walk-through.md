### **Setup**
- **Environment**: A fresh VM running **Ubuntu 22.04 LTS** (a supported OS) with:
  - Root privileges (`sudo` or direct root access).
  - Internet connectivity (for package downloads and Tailscale).
  - At least 2GB free disk space (for swap and temporary files).
  - Minimal installation (no prior SSH hardening, UFW, or Fail2Ban configured).
- **Script Version**: v0.52
- **Execution Mode**: Interactive (not `--quiet`), to capture user prompts and verify decision points.

---

### **Walkthrough**

#### **1. Preparation**
- **Download and Permissions**:
  - The README instructs downloading with `wget https://raw.githubusercontent.com/buildplan/du_setup/refs/heads/main/du_setup.sh` and setting `chmod +x du_setup.sh`.
  - Assumed command: `sudo ./du_setup.sh`.
  - The script starts with `#!/bin/bash` and `set -euo pipefail`, ensuring strict error handling.

- **Log File Creation**:
  - The script creates `/var/log/du_setup_$(date +%Y%m%d_%H%M%S).log` (e.g., `/var/log/du_setup_20250630_222800.log`) with `chmod 600`.
  - Backup directory `/root/setup_harden_backup_20250630_222800` is created with `chmod 700`.\c

#### **2. Main Function Execution**

##### **check_dependencies**
- **Logic**: Checks for `curl`, `sudo`, and `gpg`. Installs missing dependencies via `apt-get`.
- **Simulation**:
  - On a fresh Ubuntu 22.04 VM, `sudo` and `curl` are typically present, but `gpg` might be missing in minimal installs.
  - The script runs `apt-get install -y -qq gpg` if needed, which should succeed given internet access.
- **Expected Output**: `✓ All essential dependencies are installed.` (or installs `gpg` if missing).
- **Potential Issues**: None likely, as `apt-get update` and `install` are robust, and internet is assumed available.

##### **check_system**
- **Logic**: Verifies root privileges, OS compatibility (Ubuntu 22.04), internet connectivity, SSH service, and `/var/log` writability.
- **Simulation**:
  - Root check: `id -u` returns 0 (root), passes.
  - OS check: `/etc/os-release` confirms `ID=ubuntu`, `VERSION_ID=22.04`, passes.
  - Container check: No container detected (`/proc/1/cgroup` lacks docker/lxc/kubepod), so `IS_CONTAINER=false`.
  - SSH check: Assumes `openssh-server` is installed (common in Ubuntu server). Detects `ssh.service` or `sshd.service`.
  - Internet check: `curl -s --head https://archive.ubuntu.com` succeeds.
  - `/var/log` and `/etc/shadow` checks: Permissions are correct (640 for `/etc/shadow`, writable `/var/log`).
- **Expected Output**:
  ```
  ✓ Running with root privileges.
  ✓ Compatible OS detected: Ubuntu 22.04 LTS
  ✓ Internet connectivity confirmed.
  ```
- **Potential Issues**: If `openssh-server` is missing, the script installs it later in `install_packages`. No issues expected.

##### **collect_config**
- **Logic**: Prompts for username, hostname, pretty hostname, and SSH port. Validates inputs.
- **Simulation Inputs**:
  - Username: `adminuser` (valid, passes `validate_username`).
  - Hostname: `myserver` (valid, passes `validate_hostname`).
  - Pretty hostname: `My Server` (optional, accepted).
  - SSH port: `2222` (default, passes `validate_port`).
  - Server IP: Detected via `curl -s https://ifconfig.me` (e.g., `192.0.2.1`).
  - Confirmation: User confirms the configuration.
- **Expected Output**:
  ```
  Configuration Summary:
    Username:   adminuser
    Hostname:   myserver
    SSH Port:   2222
    Server IP:  192.0.2.1
  Continue with this configuration? [Y/n]: y
  ```
- **Log Entry**: `Configuration collected: USER=adminuser, HOST=myserver, PORT=2222`
- **Potential Issues**: Invalid inputs (e.g., username with spaces) prompt re-entry, which is robust. No issues expected.

##### **install_packages**
- **Logic**: Updates and upgrades packages, installs essentials (`ufw`, `fail2ban`, `chrony`, `rsync`, etc.).
- **Simulation**:
  - `apt-get update` and `apt-get upgrade -y` run silently.
  - Installs packages like `ufw`, `fail2ban`, `chrony`, `rsync`, `openssh-server`, etc.
  - Assumes sufficient disk space and internet access.
- **Expected Output**: `✓ Essential packages installed.`
- **Potential Issues**: Rare chance of `apt-get` failures due to repository issues, but `set -e` ensures the script exits on error. No issues expected in a fresh VM.

##### **setup_user**
- **Logic**: Creates `adminuser` if it doesn’t exist, sets a password (or skips for key-only), adds to `sudo` group, and configures SSH keys.
- **Simulation**:
  - User `adminuser` doesn’t exist, so `adduser --disabled-password --gecos "" adminuser` runs.
  - Password prompt: User enters `securepassword123` twice, set via `chpasswd`.
  - SSH key prompt: User pastes a valid key (`ssh-ed25519 AAAAC3Nza... user@local`).
  - Key is added to `/home/adminuser/.ssh/authorized_keys` with `chmod 600` and `chown adminuser:adminuser`.
  - Adds `adminuser` to `sudo` group with `usermod -aG sudo adminuser`.
- **Expected Output**:
  ```
  ✓ User 'adminuser' created.
  ✓ SSH public key added.
  ✓ User added to sudo group.
  ✓ Sudo group membership confirmed for 'adminuser'.
  ```
- **Potential Issues**: Password mismatch prompts re-entry. If key is invalid, user is prompted again. Robust validation prevents issues.

##### **configure_system**
- **Logic**: Sets timezone, hostname, and optionally configures locales. Backs up `/etc/hosts`, `/etc/fstab`, `/etc/sysctl.conf`.
- **Simulation**:
  - Timezone: User enters `America/New_York`, validated via `/usr/share/zoneinfo`.
  - Locale configuration: User skips (`dpkg-reconfigure locales` not run).
  - Hostname: Sets `myserver` and pretty name `My Server` via `hostnamectl`.
  - Updates `/etc/hosts` with `127.0.1.1 myserver`.
- **Expected Output**:
  ```
  ✓ Timezone set to America/New_York.
  ✓ Hostname configured: myserver
  ```
- **Potential Issues**: Invalid timezone prompts re-entry. No issues expected.

##### **configure_ssh**
- **Logic**: Hardens SSH by setting a custom port (2222), disabling root login, enforcing key-based auth, and creating `/etc/issue.net`. Includes rollback on failure.
- **Simulation**:
  - Detects `ssh.service` (Ubuntu 22.04).
  - Current port: 22 (default).
  - Backs up `/etc/ssh/sshd_config` to `/root/setup_harden_backup_20250630_222800/sshd_config.backup_*`.
  - Sets port 2222 in `/etc/ssh/sshd_config` (Ubuntu 22.04 uses direct config).
  - Creates `/etc/ssh/sshd_config.d/99-hardening.conf` with:
    ```
    PermitRootLogin no
    PasswordAuthentication no
    PubkeyAuthentication yes
    MaxAuthTries 3
    ClientAliveInterval 300
    X11Forwarding no
    PrintMotd no
    Banner /etc/issue.net
    ```
  - Creates `/etc/issue.net` with a warning banner.
  - Restarts `ssh.service` and verifies port 2222 with `ss -tuln`.
  - User tests SSH: `ssh -p 2222 adminuser@192.0.2.1` (assumed successful).
  - Verifies root login is disabled with `ssh -p 2222 root@localhost` (fails, as expected).
- **Expected Output**:
  ```
  ✓ SSH service restarted on port 2222.
  ✓ Confirmed: Root SSH login is disabled.
  ✓ SSH hardening confirmed and finalized.
  ```
- **Potential Issues**: If the user fails to test SSH on port 2222, the script rolls back to port 22. The `trap` ensures rollback on errors. No issues expected with correct user input.

##### **configure_firewall**
- **Logic**: Configures UFW with deny incoming, allow outgoing, and specific ports (2222/tcp, optional 80/tcp, 443/tcp, 41641/udp).
- **Simulation**:
  - UFW is inactive initially.
  - Sets `ufw default deny incoming`, `ufw default allow outgoing`.
  - Allows `2222/tcp` (SSH).
  - User allows HTTP (80/tcp) and HTTPS (443/tcp), skips Tailscale (41641/udp) and custom ports.
  - Enables UFW with `ufw --force enable`.
- **Expected Output**:
  ```
  ✓ HTTP traffic allowed.
  ✓ HTTPS traffic allowed.
  ✓ Firewall is active.
  Status: active
  To                         Action      From
  --                         ------      ----
  2222/tcp (Custom SSH)     ALLOW       Anywhere
  80/tcp (HTTP)             ALLOW       Anywhere
  443/tcp (HTTPS)           ALLOW       Anywhere
  ```
- **Potential Issues**: If the VPS provider’s firewall blocks port 2222, the user is warned to check. UFW enable failure is caught by `set -e`. No issues expected.

##### **configure_fail2ban**
- **Logic**: Configures Fail2Ban to monitor SSH on port 2222 with `bantime=1h`, `findtime=10m`, `maxretry=3`.
- **Simulation**:
  - Creates `/etc/fail2ban/jail.local` with:
    ```
    [DEFAULT]
    bantime = 1h
    findtime = 10m
    maxretry = 3
    backend = auto
    [sshd]
    enabled = true
    port = 2222
    logpath = %(sshd_log)s
    backend = %(sshd_backend)s
    ```
  - Enables and restarts `fail2ban`.
- **Expected Output**:
  ```
  ✓ Fail2Ban is active and monitoring port(s) 2222.
  Status: sshd
  ```
- **Potential Issues**: Fail2Ban service failure is caught and exits the script. No issues expected.

##### **configure_auto_updates**
- **Logic**: Configures `unattended-upgrades` for automatic security updates.
- **Simulation**:
  - User confirms enabling auto-updates.
  - Sets `unattended-upgrades/enable_auto_updates` to `true` and runs `dpkg-reconfigure`.
- **Expected Output**: `✓ Automatic security updates enabled.`
- **Potential Issues**: Package is already installed via `install_packages`. No issues expected.

##### **configure_time_sync**
- **Logic**: Enables and verifies `chrony` for time synchronization.
- **Simulation**:
  - `systemctl enable --now chrony` runs.
  - `chronyc tracking` confirms synchronization.
- **Expected Output**:
  ```
  ✓ Chrony is active for time synchronization.
  Reference ID    : 192.168.1.1 (time.example.com)
  Stratum         : 2
  ...
  ```
- **Potential Issues**: Chrony failure is caught and exits. No issues expected.

##### **install_docker**
- **Logic**: Installs Docker if user confirms, adds `adminuser` to `docker` group, and runs a `hello-world` test.
- **Simulation**:
  - User confirms Docker installation.
  - Removes old runtimes, adds Docker GPG key and repository, installs `docker-ce`, `docker-ce-cli`, etc.
  - Configures `/etc/docker/daemon.json` with log settings.
  - Adds `adminuser` to `docker` group.
  - Runs `docker run --rm hello-world` as `adminuser`.
- **Expected Output**:
  ```
  ✓ Docker sanity check passed.
  NOTE: 'adminuser' must log out and back in to use Docker without sudo.
  ```
- **Potential Issues**: Docker repository issues are caught by `set -e`. No issues expected with internet access.

##### **install_tailscale**
- **Logic**: Installs Tailscale if confirmed, connects using a pre-auth key, and applies optional flags.
- **Simulation**:
  - User confirms Tailscale installation.
  - Chooses standard Tailscale (option 1).
  - Enters key: `tskey-auth-xyz123`.
  - Skips additional flags ( `--ssh`, `--advertise-exit-node`, etc.).
  - Runs `tailscale up --auth-key=tskey-auth-xyz123 --operator=adminuser`.
  - Verifies connection with `tailscale ip` (e.g., `100.64.0.1`).
- **Expected Output**:
  ```
  ✓ Tailscale connected successfully. Node IPv4 in tailnet: 100.64.0.1
  ```
- **Potential Issues**: Invalid key or network issues are logged to `/tmp/tailscale_status.txt`. Retries (3x) mitigate transient failures.

##### **setup_backup**
- **Logic**: Configures rsync backups over SSH with optional notifications and a test backup.
- **Simulation**:
  - User confirms backup setup.
  - Backup destination: `u12345@u12345.your-storagebox.de`.
  - Port: `23` (Hetzner).
  - Remote path: `/home/backups/`.
  - Hetzner mode: Enabled (uses `-s` for `ssh-copy-id`).
  - Key copy: Manual (user runs `ssh-copy-id -p 23 -i /root/.ssh/id_ed25519.pub -s u12345@u12345.your-storagebox.de`).
  - Creates `/root/.ssh/id_ed25519` if missing.
  - Creates `/root/rsync_exclude.txt` with defaults.
  - Cron schedule: `5 3 * * *` (daily at 3:05 AM).
  - Notifications: Skipped.
  - Test backup: User confirms, creates `/root/test_backup_*`, runs `rsync` to `u12345@u12345.your-storagebox.de:/home/backups/test_backup/`.
- **Expected Output**:
  ```
  ✓ Root SSH key generated at /root/.ssh/id_ed25519
  ACTION REQUIRED: Copy the root SSH key to the backup destination.
  The root user's public key is: ssh-ed25519 AAAAC3Nza... root@myserver
  Run the following command: ssh-copy-id -p "23" -i "/root/.ssh/id_ed25519.pub" -s "u12345@u12345.your-storagebox.de"
  ✓ Rsync exclude file created.
  ✓ Test backup successful! Check /var/log/backup_rsync.log for details.
  ✓ Backup cron job scheduled: 5 3 * * *
  ```
- **Potential Issues**: If the SSH key isn’t copied, the test backup fails, logged to `/var/log/backup_rsync.log`. Manual copy instructions are clear. No issues expected with correct setup.

##### **configure_swap**
- **Logic**: Configures a swap file if confirmed, with default size 2G.
- **Simulation**:
  - User confirms swap creation.
  - Size: `2G`.
  - Disk space check: Assumes >2GB available.
  - Creates `/swapfile` with `fallocate`, `chmod 600`, `mkswap`, `swapon`.
  - Adds `/swapfile none swap sw 0 0` to `/etc/fstab`.
  - Sets `vm.swappiness=10`, `vm.vfs_cache_pressure=50` in `/etc/sysctl.d/99-swap.conf`.
- **Expected Output**:
  ```
  ✓ Swap file created: 2G
  ✓ Swap entry added to /etc/fstab.
  ✓ Swap settings applied to /etc/sysctl.d/99-swap.conf.
  NAME      TYPE  SIZE  USED PRIO
  /swapfile file   2G    0B   -2
  ```
- **Potential Issues**: Insufficient disk space exits the script. No issues expected.

##### **configure_security_audit**
- **Logic**: Runs Lynis and (on Debian) debsecan if confirmed.
- **Simulation**:
  - User confirms audit.
  - Installs `lynis`, runs `lynis audit system --quick`.
  - Skips debsecan (Ubuntu 22.04, not supported).
  - Logs to `/var/log/setup_harden_security_audit_20250630_222800.log`.
  - Extracts hardening index (e.g., `75`).
- **Expected Output**:
  ```
  ✓ Lynis audit completed. Check /var/log/setup_harden_security_audit_20250630_222800.log for details.
  ℹ debsecan is not supported on Ubuntu. Skipping debsecan audit.
  ```
- **Potential Issues**: Lynis failure is logged and doesn’t exit the script. No issues expected.

##### **final_cleanup**
- **Logic**: Runs `apt-get update`, `upgrade`, `autoremove`, `autoclean`, and reloads daemons.
- **Simulation**: All commands succeed.
- **Expected Output**: `✓ Final system update and cleanup complete.`
- **Potential Issues**: Repository issues are logged as warnings, not fatal. No issues expected.

##### **generate_summary**
- **Logic**: Summarizes configuration, checks service status, and provides verification steps.
- **Simulation**:
  - Services (`ssh.service`, `fail2ban`, `chrony`, `ufw`, `docker`, `tailscaled`) are active.
  - Backup is configured, test successful.
  - Tailscale is connected (IP: `100.64.0.1`).
  - Audit ran, hardening index: `75`, debsecan: `Not supported on Ubuntu`.
- **Expected Output**:
  ```
  Setup Complete!
  ✓ Service ssh.service is active.
  ✓ Service fail2ban is active.
  ✓ Service chrony is active.
  ✓ Service ufw is active.
  ✓ Service docker is active.
  ✓ Service tailscaled is active and connected.
  ✓ Security audit performed.
  Configuration Summary:
    Admin User:      adminuser
    Hostname:        myserver
    SSH Port:        2222
    Server IP:       192.0.2.1
    Remote Backup:   Enabled
      - Backup Script: /root/run_backup.sh
      - Destination:   u12345@u12345.your-storagebox.de
      - SSH Port:      23
      - Remote Path:   /home/backups/
      - Cron Schedule: 5 3 * * *
      - Notifications: None
      - Test Status:   Successful
    Tailscale:       Enabled
      - Server:        https://controlplane.tailscale.com
      - Tailscale IPs: 100.64.0.1
      - Flags:         None
    Security Audit:  Performed
      - Audit Log:     /var/log/setup_harden_security_audit_20250630_222800.log
      - Hardening Index: 75
      - Vulnerabilities: Not supported on Ubuntu
    Log File:        /var/log/du_setup_20250630_222800.log
    Backups:         /root/setup_harden_backup_20250630_222800
  Post-Reboot Verification Steps:
    - SSH access:       ssh -p 2222 adminuser@192.0.2.1
    - Firewall rules:   sudo ufw status verbose
    - Time sync:        chronyc tracking
    - Fail2Ban status:  sudo fail2ban-client status sshd
    - Swap status:      sudo swapon --show && free -h
    - Hostname:         hostnamectl
    - Docker status:    docker ps
    - Tailscale status: tailscale status
    - Remote Backup:
        - Verify SSH key: sudo cat /root/.ssh/id_ed25519.pub
        - Copy key if needed: ssh-copy-id -p 23 -s u12345@u12345.your-storagebox.de
        - Test backup:     sudo /root/run_backup.sh
        - Check logs:      sudo less /var/log/backup_rsync.log
    - Security Audit:
        - Check results:   sudo less /var/log/setup_harden_security_audit_20250630_222800.log
  ⚠ ACTION REQUIRED: Ensure the root SSH key (/root/.ssh/id_ed25519.pub) is copied to u12345@u12345.your-storagebox.de.
  ⚠ A reboot is required to apply all changes cleanly.
  Reboot now? [Y/n]: n
  ⚠ Please reboot manually with 'sudo reboot'.
  ```
- **Potential Issues**: If services fail, they’re listed in `FAILED_SERVICES`. Backup key copy warning for manual mode. No issues expected.

---

### **Potential Runtime Issues**
- **SSH Lockout**: If the user fails to test SSH on port 2222, the script rolls back to port 22, preventing lockout. The warning to test in a separate terminal is clear.
- **Backup Failure**: If the root SSH key isn’t copied to the backup server, the test backup fails, and logs provide clear troubleshooting steps (e.g., `ssh-copy-id`, `nc -zv`).
- **Tailscale**: Invalid keys or network issues (e.g., UDP 41641 blocked) are caught with retries and logged to `/tmp/tailscale_status.txt`.
- **Disk Space**: Swap creation checks available space, exiting if insufficient. Assumed 2GB available in the VM.
- **Package Installation**: Repository failures are caught by `set -e`, and the script exits cleanly.
