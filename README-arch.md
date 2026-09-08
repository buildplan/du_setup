# Arch Linux port: `arch_setup.sh`

`arch_setup.sh` is a port of `du_setup.sh` (v0.81.4, Debian/Ubuntu) to **Arch Linux**
and Arch-based distributions (anything with `ID=arch` or `ID_LIKE=arch` in `/etc/os-release`).

The interactive flow, prompts, safety checks (SSH rollback, lockout prevention, config
backups in `/root/setup_harden_backup_*`, logs in `/var/log/du_setup_*.log`) and the
optional features are the same as upstream. Only the distribution-specific plumbing changed.
The original `du_setup.sh` is left untouched.

## Usage

```bash
chmod +x arch_setup.sh
sudo -E ./arch_setup.sh            # full interactive setup
sudo -E ./arch_setup.sh --help     # options are identical to du_setup.sh
sha256sum -c arch_setup.sh.sha256  # integrity check
```

Run it on a fresh Arch install (cloud image, VPS, VM or bare metal) as root.
The script is idempotent: it can be re-run to continue after a reboot.

## What changed versus `du_setup.sh`

| Area | Debian/Ubuntu (`du_setup.sh`) | Arch (`arch_setup.sh`) |
|---|---|---|
| Package manager | `apt-get` / `dpkg` | `pacman` (`-Syu` once, then `-S --needed`), helpers `pkg_install` / `pkg_installed` |
| Admin user | `adduser`, group `sudo` | `useradd -m -U -s /bin/bash`, group `wheel`; `/etc/sudoers.d/10-wheel` is created if wheel has no sudo rule |
| `/etc/shadow` perms | forced to `640 root:shadow` | accepts `600 root:root` (Arch default) or `640` |
| Locale | `dpkg-reconfigure locales` | uncomment in `/etc/locale.gen`, `locale-gen`, `localectl set-locale` |
| SSH service | `ssh.service` / `ssh.socket` | `sshd.service`, binary `/usr/bin/sshd`; the `Include sshd_config.d/*.conf` line is added if missing |
| 2FA drop-in | `sshd_config.d/95-2fa-<user>.conf` | `sshd_config.d/zz-2fa-<user>.conf` so its `Match` block sorts **after** `99-archlinux.conf` (see note below) |
| PAM | prepend to `/etc/pam.d/sshd` | same, inserted after the `#%PAM-1.0` header |
| Firewall | UFW | UFW, plus `systemctl enable ufw.service` so rules survive reboots |
| Fail2Ban | reads `/var/log/ufw.log` (rsyslog) | `backend = systemd`; the `ufw-probes` filter uses `journalmatch = _TRANSPORT=kernel` |
| CrowdSec | apt repo + `crowdsec-firewall-bouncer-iptables` | AUR `crowdsec` + `crowdsec-firewall-bouncer-iptables`; journal acquisition for `sshd.service` and kernel messages; the bouncer is registered with `cscli bouncers add` (the AUR package does not do it) |
| Automatic updates | `unattended-upgrades` | `du-arch-updates.timer` (systemd). Default: **check only** (`checkupdates` + `arch-audit` logged to `/var/log/du-arch-updates.log`). Optional: unattended `pacman -Syu --noconfirm` (not recommended) |
| Time sync | `chrony` | `chronyd`; `systemd-timesyncd` is disabled |
| Cron | `cron` | `cronie` (installed and enabled; backup job still uses root's crontab) |
| Docker | Docker apt repo | `docker docker-compose docker-buildx` from `extra` |
| Tailscale | `install.sh` | `tailscale` from `extra`, `tailscaled.service` enabled |
| NetBird | NetBird apt repo | AUR `netbird` |
| Security audit | Lynis + `debsecan` | Lynis + `arch-audit` |
| Final cleanup | `dist-upgrade`, `autoremove`, `autoclean` | `pacman -Syu`, orphan removal (`pacman -Qdtq`), `paccache -rk2` |
| Provider cleanup | `dpkg -l`, `apt-get remove --purge` | `pacman -Qq`, `pacman -Rns`; also looks for `virtualbox-guest-utils`, `hyperv`, `google-guest-agent`, users `arch`/`alarm` |
| Generated `.bashrc` | apt aliases, apt update counts | pacman aliases (`pacup`, `pacin`, `pacclean`, …), `pacman -Qu` + `arch-audit` counts, kernel-upgrade reboot detection |
| Self-update | downloads from upstream | disabled (`SCRIPT_URL=""`) |

## Arch-specific behaviour worth knowing

**Reboot after a kernel upgrade.** `pacman -Syu` in the package step may replace the kernel.
Arch then removes the modules of the *running* kernel, so UFW, nftables, Fail2Ban and Docker
cannot load modules until you reboot. The script detects this (`/usr/lib/modules/$(uname -r)`
missing), asks to reboot, and tells you to run it again. Everything before that point is
idempotent.

**AUR packages (CrowdSec, NetBird).** They are built as the admin user. If `paru` or `yay`
is installed, it is used; otherwise the script installs `base-devel` + `git`, clones from
`aur.archlinux.org`, runs `makepkg -si` as the user, and grants a temporary
`NOPASSWD` sudo rule limited to `/usr/bin/pacman` (removed afterwards). Review the PKGBUILDs
if you do not trust the AUR.

**2FA drop-in ordering.** `sshd` keeps a `Match` context across included files. A `Match User`
block in `95-2fa-*.conf` would swallow the global directives in Arch's `99-archlinux.conf`
(`UsePAM yes`) and `sshd -t` would fail. The port therefore names the file `zz-2fa-<user>.conf`.

**Automatic updates.** Arch has no security-only channel and expects you to read
<https://archlinux.org/news/> before upgrading. The default timer only reports pending updates
and known vulnerabilities. Enable full unattended upgrades only on disposable machines.

**Logs.** There is no rsyslog and no `/var/log/auth.log`. Fail2Ban and CrowdSec read the
systemd journal directly, so nothing needs to be written to `/var/log/ufw.log`.

## Package availability

Everything except CrowdSec and NetBird comes from the official repositories (`core`/`extra`):
`ufw fail2ban nftables chrony cronie rsync docker docker-compose docker-buildx tailscale lynis
arch-audit pacman-contrib qrencode libpam-google-authenticator sshpass skopeo openssh …`.
AUR: `crowdsec`, `crowdsec-firewall-bouncer-iptables`, `netbird`.

## Testing status

The port was produced by an auditable transformation script (function replacements and
exact-string substitutions on `du_setup.sh`), passes `bash -n` and ShellCheck 0.11 with zero
warnings, and its new regexes and helpers were unit-tested in isolation. It has **not yet
been run end-to-end on a fresh Arch server**; test it in a VM before using it in production,
exactly as upstream recommends. The transformation script is kept in `tools/port_to_arch.py`
(`python3 tools/port_to_arch.py du_setup.sh arch_setup.sh`).
