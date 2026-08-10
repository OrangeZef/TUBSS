#!/usr/bin/env bash
# Integration test harness. Runs inside a systemd-enabled container.
# Usage: run.sh [default|ssh-hardened|ssh-hardening-broken]
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

if [[ "$MODE" == "ssh-hardened" || "$MODE" == "ssh-hardening-broken" ]]; then
    # Flip SSH hardening on via env — script respects SSH_HARDENING=yes
    # when pre-seeded in the environment (documented opt-in for tests/automation).
    export SSH_HARDENING=yes
    export SSH_DISABLE_PW_AUTH=no   # test default-OFF for this toggle so we can verify partial config works
    export SSH_DISABLE_ROOT=yes
    export SSH_DISABLE_X11=yes
    export SSH_DISABLE_EMPTY_PW=yes
fi

if [[ "$MODE" == "ssh-hardening-broken" ]]; then
    # CC-181 regression: force `sshd -t` to fail regardless of what TUBSS
    # itself writes, by pre-seeding an unrecognized directive into the main
    # sshd_config that TUBSS's own hardening settings can never satisfy.
    # `sshd -t -f sshd_config` validates the merged config (main file plus
    # any Include'd drop-ins), so this fails validation no matter what the
    # drop-in contains. Before this fix, a validation failure here used
    # `return 1` from a bare, unguarded call site — under `set -e` that
    # aborted the entire run before auto-updates/MOTD/telemetry/AD ever ran.
    echo "TubssBogusDirectiveForCI981 yes" >> /etc/ssh/sshd_config
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
# CC-131: apt upgrade step must have executed (not just update)
assert_file_contains /var/log/tubss.log 'Applying pending package updates'
assert_file_contains /var/log/tubss.log 'Package updates applied'
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
    assert_file_absent /etc/ssh/sshd_config.d/00-tubss-hardening.conf
elif [[ "$MODE" == "ssh-hardened" ]]; then
    # SSH hardening drop-in should exist
    assert_file_exists /etc/ssh/sshd_config.d/00-tubss-hardening.conf
    assert_file_contains /etc/ssh/sshd_config.d/00-tubss-hardening.conf 'PermitRootLogin no'
    assert_file_contains /etc/ssh/sshd_config.d/00-tubss-hardening.conf 'X11Forwarding no'
    assert_file_contains /etc/ssh/sshd_config.d/00-tubss-hardening.conf 'PermitEmptyPasswords no'
elif [[ "$MODE" == "ssh-hardening-broken" ]]; then
    # CC-181: the whole point of this mode is that the run reaches this line
    # at all. If the old `return 1`-from-a-bare-call-site bug ever comes
    # back, `bash /root/tubss_setup.sh --unattended` above exits non-zero
    # under `set -e` and the harness already exited 1 before reaching here.
    assert_file_contains /var/log/tubss.log 'sshd -t validation failed'
    assert_file_contains /var/log/tubss.log 'SSH Hardening: Failed \(sshd -t validation'
    # This run uses the SAME settings as the preceding "ssh-hardened" run,
    # so the drop-in already matches desired state and TUBSS takes the
    # [SKIP] branch — it never rewrites the drop-in this run. The bogus
    # directive is unrelated to TUBSS's own content, so the fix under
    # review (this run didn't write it -> don't delete it) means the
    # already-valid, previously-applied drop-in from the prior run MUST
    # survive. Deleting a known-good drop-in over an unrelated sshd_config
    # problem would silently un-harden SSH on the next reload/reboot for
    # no reason connected to what TUBSS actually did.
    assert_file_exists /etc/ssh/sshd_config.d/00-tubss-hardening.conf
    assert_file_contains /etc/ssh/sshd_config.d/00-tubss-hardening.conf 'PermitRootLogin no'
    # Steps AFTER ssh_hardening in the pipeline must still have executed —
    # this is the actual regression: proof the run didn't abort mid-pipeline.
    assert_file_contains /var/log/tubss.log 'Enabling Automatic Security Updates'
fi

summary
