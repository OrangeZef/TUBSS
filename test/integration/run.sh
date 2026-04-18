#!/usr/bin/env bash
# Integration test harness. Runs inside a systemd-enabled container.
# Usage: run.sh [default|ssh-hardened]
set -euo pipefail

MODE=${1:-default}
source /root/assertions.sh

# openssh-server needs /run/sshd for `sshd -t` validation. The tmpfs /run
# inside test containers is empty at boot, so create it before TUBSS runs.
mkdir -p /run/sshd && chmod 755 /run/sshd

echo "=========================================="
echo "TUBSS Integration Test — mode: $MODE"
echo "=========================================="

# Run the script with unattended + skip-reboot
export TUBSS_UNATTENDED=1
export TUBSS_SKIP_REBOOT=1

if [[ "$MODE" == "ssh-hardened" ]]; then
    # Flip SSH hardening on via env — script respects SSH_HARDENING=yes
    # when pre-seeded in the environment (documented opt-in for tests/automation).
    export SSH_HARDENING=yes
    export SSH_DISABLE_PW_AUTH=no   # test default-OFF for this toggle so we can verify partial config works
    export SSH_DISABLE_ROOT=yes
    export SSH_DISABLE_X11=yes
    export SSH_DISABLE_EMPTY_PW=yes
fi

# Execute
if ! bash /root/tubss_setup.sh --unattended; then
    echo "[FATAL] Script exited non-zero"
    exit 1
fi

# The script pipes stdout/stderr through a background tee — give it
# a moment to flush the final "TUBSS run ended rc=0" line before
# assertions read the log.
sync || true
sleep 1

echo ""
echo "=========================================="
echo "Running assertions (mode: $MODE)"
echo "=========================================="

# Common assertions (both modes)
assert_pkg_installed ufw
assert_pkg_installed fail2ban
assert_pkg_installed unattended-upgrades
assert_service_enabled fail2ban
assert_file_exists /var/log/tubss.log
assert_file_contains /var/log/tubss.log 'run ended rc=0'
assert_file_exists /var/lib/tubss/last_run
assert_file_contains /var/lib/tubss/last_run 'STATUS=completed'
# cloud-init drop-in is only written when /etc/cloud/cloud.cfg.d/ exists
# (cloud-init installed). Minimal test containers typically lack it, so
# only assert when the parent dir is present.
if [[ -d /etc/cloud/cloud.cfg.d ]]; then
    assert_file_exists /etc/cloud/cloud.cfg.d/99-tubss-disable-network.cfg
fi

if [[ "$MODE" == "default" ]]; then
    # SSH hardening default is OFF — drop-in must NOT exist
    assert_file_absent /etc/ssh/sshd_config.d/99-tubss-hardening.conf
elif [[ "$MODE" == "ssh-hardened" ]]; then
    # SSH hardening drop-in should exist
    assert_file_exists /etc/ssh/sshd_config.d/99-tubss-hardening.conf
    assert_file_contains /etc/ssh/sshd_config.d/99-tubss-hardening.conf 'PermitRootLogin no'
    assert_file_contains /etc/ssh/sshd_config.d/99-tubss-hardening.conf 'X11Forwarding no'
    assert_file_contains /etc/ssh/sshd_config.d/99-tubss-hardening.conf 'PermitEmptyPasswords no'
fi

summary
