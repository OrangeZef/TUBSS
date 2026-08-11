## TUBSS: The Ubuntu/Debian Basic Setup Script

**TUBSS** is a comprehensive Bash script that automates the initial setup and hardening of a new Ubuntu or Debian server. With a single command, TUBSS saves time, ensures consistency, and establishes a secure, production-ready foundation.

The script auto-detects OS/version via `/etc/os-release` — a single `tubss_setup.sh` at the repository root covers Ubuntu 20.04/22.04/24.04/26.04 (LTS) and Debian 11/12/13/14. CI (lint, container tests, integration tests) runs against every one of those targets on every push — including Debian 14 (Forky), which is still Debian's testing suite rather than a stable release, so support there is best-effort and flagged as such at runtime.

### Features

- **Automated Security:** Installs and configures essential tools like UFW and Fail2ban.
- **Optional SSH hardening (opt-in):** Disable key-less auth, root login, X11 forwarding, and empty credentials with safety checks that refuse to lock you out.
- **Networking:** Sets up network configuration, supporting both DHCP and static IP addresses.
- **Essential Tools:** Installs key utilities (Git, NFS, SMB) by default.
- **System Health:** Configures automatic security updates, with an opt-in (default off) auto-reboot at 04:00 local time when a security update requires one — off by default because some servers must stay up until a human approves a reboot. Also installs and syncs `chrony` unconditionally, since accurate time matters for TLS validation and log/audit timestamps on any hardened server, not just for AD joins.
- **Privacy:** Disables optional telemetry and analytics.
- **Login Banner:** Optional (default off) standard authorized-access-only notice at login, aimed at hardened/compliance-flavored deployments rather than personal homelab servers.
- **Configuration Review:** Presents a detailed summary of proposed changes before execution, and shows what a prior TUBSS run on this host did (version, status, last step) before you start a new one.
- **End-of-Run Issue Summary:** Any warn-and-continue problem (a failed package upgrade, AD join/permit/sudo/identity check) is collected into one summary at the end and requires acknowledgment in interactive mode, rather than relying on you to catch a warning buried in the log. TUBSS is safe to run again afterward — it checks current state before making changes and won't redo work already applied.
- **Final Report:** Saves a before/after configuration summary as a `.txt` file to the invoking user's Desktop folder if one exists, or their home directory otherwise (most headless servers have no Desktop folder, so home directory is the common case). The full run log — every command and its output — is separately written to `/var/log/tubss.log` (root-only, falls back to `/tmp/tubss.log` if that path isn't writable).
- **Optional Active Directory domain join:** Joins the box to an AD domain via `realmd`/`sssd`. Handles clock sync (Kerberos requires it), lets you choose who can log in once joined (everyone in the domain by default, or a specific group/users), grants sudo to the `Domain Admins` group by default (with an option to add one more specific user), and — if you also enable key-only SSH hardening in the same run — keeps password-based SSH working for exactly the accounts permitted to log in, since domain accounts authenticate with their AD password, not an SSH key.

### How to Use

Download and run the script with `sudo` on a fresh Ubuntu or Debian installation:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/OrangeZef/tubss/main/tubss_setup.sh)"
```

### Why TUBSS?

Setting up a new server is often repetitive and time-consuming. TUBSS standardizes the process, reduces human error, and ensures every server starts with a secure and well-documented base. It’s ideal for developers, system administrators, and anyone deploying Ubuntu servers efficiently.

**Feel free to fork, customize, and contribute!**

### Active Directory Domain Join

When you opt in, TUBSS will:

1. Prompt for the domain name, a domain account with permission to join computers, and its password (never echoed, never passed on the command line, never stored). TUBSS installs and syncs `chrony` unconditionally on every run (not just when joining a domain), so by the time the join happens the clock has already had the run's full duration to converge — Kerberos, which the domain join depends on, fails if the clock is off by more than a few minutes.
2. Ask who should be allowed to log in once joined: everyone in the domain (the default — matches how most homelab/office AD setups already work), a specific group, or specific users.
3. Grant `sudo` to the `Domain Admins` group by default (togglable), plus an optional prompt to grant it to one more specific user.
4. If you also enable SSH key-only hardening in the same run, automatically keep password-based SSH login working for whichever accounts you just permitted — otherwise they'd have no way to SSH in at all, since domain accounts don't have SSH keys.
5. After a successful join, verify with `id` that the join account — and, if you granted sudo to a specific named user, that account too — actually resolves via NSS. `realm join` succeeding only proves the realmd handshake worked; this confirms sssd is actually resolving identities, which is what determines whether anyone can really log in. A failed check here is surfaced as its own status in the summary, distinct from (and more informative than) "Joined."

Any step that fails (bad credentials, unreachable domain controller, a permit/sudo grant that doesn't apply, or a failed identity check) is reported clearly and does not abort the rest of the hardening run — but it is collected into the end-of-run issue summary (see Features above) so it can't be missed.

**Testing status:** this feature has been through multiple rounds of code review and passes the full local test suite, but has not yet been exercised against a live production Active Directory domain controller in CI (that's not something a container can do). If you're trying this for the first time, test against a non-critical box first and confirm domain login actually works end to end before relying on it.

### Development

SHA256 checksums are automatically regenerated via GitHub Actions on every push to `main` that modifies a `tubss_setup.sh` file — no manual step required.
