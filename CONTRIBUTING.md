# Contributing to du_setup

Thank you for your interest in contributing to the `du_setup` project! This Bash script automates the setup and hardening of Debian 12 and Ubuntu (20.04/22.04/24.04) servers, focusing on security, automation, and ease of use. Any contributions are welcome to improve the script, fix bugs, or add features while maintaining its reliability and safety.

This document outlines how to contribute effectively. Please read it carefully before submitting issues or pull requests.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Submitting Pull Requests](#submitting-pull-requests)
- [Development Guidelines](#development-guidelines)
  - [Setting Up a Development Environment](#setting-up-a-development-environment)
  - [Coding Standards](#coding-standards)
  - [Testing Changes](#testing-changes)
- [Community and Support](#community-and-support)

## Code of Conduct
We are committed to fostering a welcoming and inclusive community. By participating, you agree to:
- Be respectful and considerate in all interactions.
- Avoid offensive or harmful language.
- Provide constructive feedback and support others’ contributions.

Any violations (e.g., harassment, discrimination) may result in removal from the project. Report issues to the maintainers at [insert contact, e.g., email or GitHub Discussions].

## How to Contribute

### Reporting Bugs
If you encounter a bug, please open an issue on the [GitHub Issues page](https://github.com/buildplan/du_setup/issues) with the following details:
- **Title**: A clear, concise description of the bug (e.g., "SSH rollback fails on Ubuntu 24.04 with ssh.socket").
- **Description**:
  - Steps to reproduce the issue.
  - Expected behavior vs. actual behavior.
  - Environment details (e.g., OS version, script version, hardware/cloud provider).
  - Relevant logs (e.g., from `/var/log/du_setup_*.log` or `/tmp/sshd_*.log`).
- **Screenshots or Logs**: Attach relevant output (sanitize sensitive data like IPs or keys).
- **Labels**: Add the `bug` label to help us triage.

Example:
```
Title: Backup test fails with invalid cron schedule
Description:
- Ran `./du_setup.sh` on Debian 12.
- Entered cron schedule `60 * * * *` for backups.
- Expected: Script validates and rejects invalid schedule.
- Actual: Cron job added but fails silently.
- Logs: /var/log/backup_rsync.log shows "invalid cron expression".
Environment: Debian 12, du_setup v0.60, Hetzner Cloud.
```

### Suggesting Features
We welcome ideas for new features or improvements! To suggest a feature:
- Open an issue on the [GitHub Issues page](https://github.com/buildplan/du_setup/issues).
- Use the `enhancement` label.
- Describe the feature, its use case, and how it aligns with the script’s goals (e.g., security, automation).
- Example:
  ```
  Title: Add support for encrypted rsync backups
  Description:
  - Feature: Integrate GPG encryption for rsync backups in `setup_backup`.
  - Use Case: Protect sensitive data during transfer to remote servers.
  - Implementation: Add option to encrypt files before rsync and decrypt on restore.
  ```

### Submitting Pull Requests
To contribute code or documentation changes:
1. **Fork the Repository**: Create a fork of [buildplan/du_setup](https://github.com/buildplan/du_setup).
2. **Create a Branch**: Use a descriptive branch name (e.g., `fix/ssh-port-detection`, `feature/encrypted-backups`).
3. **Make Changes**: Follow the [Coding Standards](#coding-standards) and [Testing Changes](#testing-changes).
4. **Commit Messages**:
   - Use clear, concise messages (e.g., `Fix SSH port detection in configure_ssh`).
   - Reference related issues (e.g., `Fixes #123`).
5. **Update Documentation**:
   - Update `README.md` if you add features or change usage instructions.
   - Update the script’s changelog (in the header) with your changes.
6. **Run ShellCheck**: Ensure your code passes `shellcheck du_setup.sh` with no errors or warnings.
7. **Submit a Pull Request**:
   - Target the `main` branch.
   - Include a description of changes, referencing any related issues.
   - Confirm you’ve tested the changes on Debian 12 and/or Ubuntu (20.04/22.04/24.04).
8. **Review Process**: Maintainers will review your PR, provide feedback, and merge if it meets standards.

## Development Guidelines

### Setting Up a Development Environment
To work on `du_setup.sh`, set up a test environment:
1. **Use a Virtual Machine**:
   - Create a fresh Debian 12 or Ubuntu (20.04/22.04/24.04) VM using tools like VirtualBox, Vagrant, or a cloud provider (e.g., Hetzner, Oracle Cloud).
   - Example with Vagrant:
     ```bash
     vagrant init ubuntu/jammy64
     vagrant up
     vagrant ssh
     ```
2. **Install Dependencies**:
   - Install `git`, `shellcheck`, and `bash`:
     ```bash
     sudo apt-get update
     sudo apt-get install -y git shellcheck
     ```
3. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/du_setup.git
   cd du_setup
   ```
4. **Test in a Safe Environment**:
   - Use a snapshot or disposable VM to avoid breaking your system.
   - Run the script with `sudo -E ./du_setup.sh` to test changes.

### Coding Standards
- **Bash Style**:
  - Use `set -euo pipefail` for strict error handling.
  - Follow ShellCheck guidelines (`shellcheck du_setup.sh`).
  - Use consistent indentation (2 spaces) and avoid tabs.
  - Add comments for complex logic (e.g., `rollback_ssh_changes`, `setup_backup`).
- **Idempotency**:
  - Ensure changes are idempotent (safe to run multiple times without side effects).
  - Check for existing configurations before modifying (e.g., using `cmp`, `grep`).
- **Safety**:
  - Back up critical files (e.g., `/etc/ssh/sshd_config`) before modification.
  - Validate all user inputs with regex or functions like `validate_username`, `validate_port`.
  - Avoid hardcoding sensitive data (e.g., store backup credentials securely).
- **Logging**:
  - Use the script’s `log`, `print_success`, `print_error`, etc., functions for consistent output.
  - Log all significant actions to `/var/log/du_setup_*.log`.

### Testing Changes
- Test on **Debian 12** and **Ubuntu 20.04/22.04/24.04** to ensure compatibility.
- Verify key features:
  - SSH hardening: Test new port, key-based auth, and root login disablement.
  - Firewall: Check `ufw status` for correct rules.
  - Backups: Run `test_backup` and verify remote SSH connectivity.
  - Tailscale/Docker: Confirm services are active and configured.
  - Security audit: Run Lynis and check output in `/var/log/setup_harden_security_audit_*.log`.
- Use a clean VM for each test to avoid conflicts with prior runs.
- Check logs (`/var/log/du_setup_*.log`) for errors or warnings.
- Run `shellcheck du_setup.sh` to catch Bash errors before submitting.

## Community and Support
- **Questions**: Use [GitHub Discussions](https://github.com/buildplan/du_setup/discussions) for questions or ideas.
- **Issues**: Report bugs or suggest features via [GitHub Issues](https://github.com/buildplan/du_setup/issues).
- **Contact**: Reach out to maintainers at [insert contact, e.g., email or GitHub handle].

Thank you for contributing to `du_setup`! Your efforts help make server hardening easier and more secure for everyone.
