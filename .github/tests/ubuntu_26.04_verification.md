# Ubuntu 26.04 LTS Verification Report

**Date:** 2026-06-18
**Target OS:** Ubuntu 26.04 LTS (Resolute Raccoon) - Linux 7.0.0-22-generic x86_64
**Script Version:** v0.80.7
**Environment:** Vultr Commercial Cloud VPS

## Executive Summary

Comprehensive testing of `du_setup.sh` on a fresh installation of Ubuntu 26.04 LTS was performed successfully. All base services, package management functions, security hardening measures, and optional software installations operated without errors, proving full compatibility with the latest LTS release.

## Execution Logs Overview

- **Script Validation:** SHA256 checksum verified (`du_setup.sh: OK`).
- **OS Detection:** Script correctly recognized Ubuntu 26.04 LTS and proceeded via the updated validations.
- **Package Management:** `apt` and `dpkg` successfully installed all essential tools (vim, chrony, fail2ban, tailscale, docker, etc.) with no dependency issues.
- **System Service Overrides:** Properly removed `systemd-timesyncd` in favor of `chrony` without disrupting the provisioning process.

## Feature Verification Checklist

### 1. User Management

- [x] Sudo user (`admin`) successfully created.
- [x] SSH public key injection succeeded.
- [x] Custom `.bashrc` deployed for the user.

### 2. Networking & Firewall (UFW)

- [x] UFW activated and persisted through reboot.
- [x] Custom SSH port (`5555/tcp`) allowed, and default `22/tcp` safely closed.
- [x] IPv4 & IPv6 firewall rules accurately loaded.
- [x] Tailscale UDP 41641 allowed.

### 3. Intrusion Prevention (Fail2Ban)

- [x] Fail2Ban successfully compiled and deployed active jails.
- [x] `sshd` and `ufw-probes` jails verified active.
- [x] **Live Defense Verified:** 4 malicious IPs actively banned by the `ufw-probes` jail during the immediate post-boot testing phase.

### 4. Hardening (Sysctl & SSH)

- [x] Root SSH login successfully disabled.
- [x] Key-based authentication successfully enforced.
- [x] SSH listener correctly moved to port `5555`.
- [x] Kernel parameters validated post-reboot (`fs.protected_hardlinks = 1`, `kernel.yama.ptrace_scope = 1`).

### 5. Services & Addons

- [x] **Time Sync (Chrony):** Successfully synchronized with canonical NTP servers (`ntp-nts-2.ps5.canonical.com`).
- [x] **Docker:** Engine cleanly installed via official repositories, and execution via the `admin` user group succeeded without `sudo` (`docker ps`).
- [x] **Tailscale:** Package loaded successfully from the stable repository (daemon active and ready for auth).
- [x] **Swap Memory:** Swap correctly disabled, resized, and dynamically mounted as a 2.3Gi file.
- [x] **Provider Cleanup:** Vultr commercial VPS successfully audited; default provisioning user `linuxuser` safely removed.

## Conclusion

The `du_setup.sh` script is 100% stable on Ubuntu 26.04 LTS. The underlying shifts in the new LTS release do not negatively impact any of the standard POSIX shell tools or package managers (`apt`/`dpkg`) that the script orchestrates. All configurations persist flawlessly across system reboots. No further logic updates are required beyond the OS version-check modifications already committed.
