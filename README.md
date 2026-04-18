## TUBSS: The Ubuntu/Debian Basic Setup Script

**TUBSS** is a comprehensive Bash script that automates the initial setup and hardening of a new Ubuntu or Debian server. With a single command, TUBSS saves time, ensures consistency, and establishes a secure, production-ready foundation.

The script auto-detects OS/version via `/etc/os-release` — a single `tubss_setup.sh` at the repository root covers Ubuntu 20.04/22.04/24.04 and Debian 12/13/14. The `versions/` tree is retained as a historical safety net.

### Features

- **Automated Security:** Installs and configures essential tools like UFW and Fail2ban.
- **Optional SSH hardening (opt-in):** Disable key-less auth, root login, X11 forwarding, and empty credentials with safety checks that refuse to lock you out.
- **Networking:** Sets up network configuration, supporting both DHCP and static IP addresses.
- **Essential Tools:** Installs key utilities (Git, NFS, SMB) by default.
- **System Health:** Configures automatic security updates.
- **Privacy:** Disables optional telemetry and analytics.
- **Configuration Review:** Presents a detailed summary of proposed changes before execution.
- **Final Report:** Saves a complete log of original and final configurations to your desktop.

### How to Use

Download and run the script with `sudo` on a fresh Ubuntu installation:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/OrangeZef/tubss/main/tubss_setup.sh)"
```

### Why TUBSS?

Setting up a new server is often repetitive and time-consuming. TUBSS standardizes the process, reduces human error, and ensures every server starts with a secure and well-documented base. It’s ideal for developers, system administrators, and anyone deploying Ubuntu servers efficiently.

**Feel free to fork, customize, and contribute!**

### Development

SHA256 checksums are automatically regenerated via GitHub Actions on every push to `main` that modifies a `tubss_setup.sh` file — no manual step required.
