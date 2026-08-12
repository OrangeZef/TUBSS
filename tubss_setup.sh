#!/bin/bash

#==============================================================================
# TUBSS — The Ubuntu/Debian Basic Setup Script
# Version: 2.9.0
# Author: OrangeZef
#
# Automates the initial setup and hardening of a new Ubuntu or Debian
# server. OS and version are auto-detected via /etc/os-release.
#
# Full changelog: git log --oneline -- tubss_setup.sh
#
# Provided by Joka.ca
#==============================================================================

set -euo pipefail
# Never leave AD_PASSWORD (resident in this process's memory between the
# prompt and its scrub) recoverable from a core dump.
ulimit -c 0

# --- Global Variables & Colors ---
YELLOW='\033[1;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Must be defined before BANNER_ART, which interpolates it.
TUBSS_SCRIPT_VERSION="2.9.0"

BANNER_ART="
+---------------------------------------------+
|    T U B S S                                |
+---------------------------------------------+
|    The Ubuntu/Debian Basic Setup Script     |
|    Version ${TUBSS_SCRIPT_VERSION}$(printf '%*s' $((33 - ${#TUBSS_SCRIPT_VERSION})) '')|
+---------------------------------------------+
|    Provided by Joka.ca                      |
+---------------------------------------------+
"
INFO_ART="
============================================================
              ${YELLOW}System Information & Status${NC}
============================================================
"
SUMMARY_ART="
============================================================
           ${YELLOW}Configuration Review (Intended Changes)${NC}
============================================================
"
EXECUTION_ART="
============================================================
            ${YELLOW}Applying Configuration (Execution)${NC}
============================================================
"
CLOSING_ART="
 ___________________________________________________________________
< Thank you for using TUBSS - The Ubuntu/Debian Basic Setup Script! >
 -------------------------------------------------------------------
"

# --- Global Summary Variables (for DRY principle) ---
NEW_WEBMIN_SUMMARY=""
NEW_UFW_SUMMARY=""
NEW_AUTO_UPDATES_SUMMARY=""
NEW_AUTO_REBOOT_SUMMARY=""
NEW_MOTD_SUMMARY=""
NEW_FAIL2BAN_SUMMARY=""
NEW_TELEMETRY_SUMMARY=""
NEW_DOMAIN_SUMMARY=""
NEW_NFS_SUMMARY=""
NEW_SMB_SUMMARY=""
NEW_GIT_SUMMARY=""
NEW_IP_ADDRESS_SUMMARY=""
NEW_GATEWAY_SUMMARY=""
NEW_DNS_SUMMARY=""
NEW_SSH_HARDENING_SUMMARY=""
NEW_AD_PERMIT_SUMMARY=""
NEW_AD_SUDO_SUMMARY=""
NEW_AD_IDENTITY_SUMMARY=""
# "pending" until install_packages() runs, then "Applied" or
# "Partial (upgrade failed, continuing)".
PACKAGE_UPDATES_STATUS="pending"
# "pending" until join_ad_domain() runs, then "Skipped", "Joined (<domain>)",
# "Joined (dry-run)" or "Failed (<reason>)".
AD_JOIN_STATUS="pending"
# Who is allowed onto the box after the join, and who gets sudo.
# AD_PERMIT_MODE is "a" (all domain users), "g" (one group) or "u" (named
# users); it drives BOTH the `realm permit` call and the sshd Match block
# that re-allows password auth for those accounts under key-only hardening.
# ${VAR:-} rather than VAR="" so pre-seeded unattended-mode environment
# values survive this initialization instead of being clobbered.
AD_PERMIT_MODE="${AD_PERMIT_MODE:-}"
AD_PERMIT_GROUP="${AD_PERMIT_GROUP:-}"
AD_PERMIT_USERS="${AD_PERMIT_USERS:-}"
AD_GRANT_ADMINS_SUDO="${AD_GRANT_ADMINS_SUDO:-}"
AD_SUDO_EXTRA_USER="${AD_SUDO_EXTRA_USER:-}"
# Configure sssd for bare-username logins (no @domain suffix) after a
# successful join. Opt-out rather than opt-in — it's what operators expect,
# but it's still a real change to a live auth path, so it stays a choice.
AD_BARE_USERNAMES="${AD_BARE_USERNAMES:-}"
AD_PERMIT_STATUS="pending"
AD_SUDO_STATUS="pending"
# Post-join `id` check on the join account. Stronger signal than
# AD_JOIN_STATUS: `realm join` only proves the realmd handshake worked, not
# that NSS/sssd actually resolves identities, so "Joined" plus a failed
# identity check means the box likely can't do real logins.
AD_IDENTITY_STATUS="pending"

# --- SSH hardening toggles ---
# OFF by default to avoid silent SSH lockout, including under --unattended,
# unless the caller pre-seeds SSH_HARDENING=yes in the environment.
SSH_HARDENING="${SSH_HARDENING:-no}"
SSH_DISABLE_PW_AUTH="${SSH_DISABLE_PW_AUTH:-yes}"
SSH_DISABLE_ROOT="${SSH_DISABLE_ROOT:-yes}"
SSH_DISABLE_X11="${SSH_DISABLE_X11:-yes}"
SSH_DISABLE_EMPTY_PW="${SSH_DISABLE_EMPTY_PW:-yes}"
SSH_HARDENING_STATUS="pending"
SNAPSHOT_STATUS="pending"

# Auto-reboot after a required unattended security update (e.g. a new
# kernel). OFF by default for the same reason as SSH_HARDENING: never
# reboot a server the operator didn't ask to have rebooted.
AUTO_REBOOT_UPDATES="${AUTO_REBOOT_UPDATES:-no}"

# Elements: "port|protocol|direction|description". Ranges use a hyphen:
# "5000-5010|tcp|allow|Dev range"
CUSTOM_UFW_RULES=()

PREFLIGHT_FAILED=0

# Used by the cleanup guard.
PACKAGES_INSTALLED=0

# --- OS / version detection globals (set by detect_os, read elsewhere) ---
DETECTED_OS=""                 # "ubuntu" or "debian"
DETECTED_VERSION=""
# Fallback for resolving DETECTED_VERSION when VERSION_ID is absent from
# /etc/os-release (see detect_os()).
DETECTED_CODENAME=""
SUPPORTED_VERSIONS=()          # Populated in detect_os based on DETECTED_OS
PACKAGE_SERVER=""              # archive.ubuntu.com or deb.debian.org
DEBIAN_TESTING_TIER=0          # 1 for Debian 14 (Forky / testing) warning

# Safe default to avoid an unbound variable under set -u.
ORIGINAL_IP=""

NETPLAN_APPLY_PENDING=0        # forces reboot if netplan try/apply failed

# --- Run-state persistence ---
TUBSS_STATE_DIR="/var/lib/tubss"
TUBSS_STATE_FILE="/var/lib/tubss/last_run"
CURRENT_STEP=""
DHCP_RESTORE_FILE=""

# --- CLI / runtime flags ---
# Declared with defaults so `set -u` does not trip before parse_args.
TUBSS_UNATTENDED=${TUBSS_UNATTENDED:-0}
TUBSS_DRY_RUN=${TUBSS_DRY_RUN:-0}
TUBSS_VERBOSE=${TUBSS_VERBOSE:-0}
TUBSS_NO_LOG=${TUBSS_NO_LOG:-0}
TUBSS_TTY=${TUBSS_TTY:-1}
TUBSS_FORCE_REBOOT=${TUBSS_FORCE_REBOOT:-0}
TUBSS_SKIP_REBOOT=${TUBSS_SKIP_REBOOT:-0}
TUBSS_ROLLBACK=0


# --- Utility Functions ---

handle_error() {
    local exit_code=$?
    mark_run_state_failed "${CURRENT_STEP:-unknown}"
    local line_number=${BASH_LINENO[0]}
    local command=${BASH_COMMAND}
    echo ""
    echo -e "${RED}--------------------------------------------------------${NC}"
    echo -e "${RED}An error occurred at line ${line_number} with command: ${command}${NC}"
    echo -e "${RED}Exiting script with status code: ${exit_code}${NC}"
    echo -e "${RED}--------------------------------------------------------${NC}"
    echo ""
    exit "$exit_code"
}

# Progress spinner with task name; falls back to periodic elapsed-time
# lines when not on a TTY so captured logs stay readable.
#
# Writes to /dev/tty when available to bypass setup_logging()'s
# line-buffered tee pipe: spinner frames are not newline-terminated, so
# that pipe holds them until the step finishes and every long step looks
# frozen. Animation frames are never worth capturing in the log anyway.
spinner() {
    local pid=$1
    local task_name=$2
    local delay=0.1
    local spinstr='|/-\'
    # Open the output fd ONCE and reuse it for every frame. A per-write
    # `> "$path"` redirect re-opens with O_TRUNC each time, which against a
    # regular file (systemd StandardOutput=file:, cron redirect) wipes all
    # prior output on every frame. One `exec {fd}>` shares a single open
    # file description, so frames append.
    local sp_fd
    if { : > /dev/tty; } 2>/dev/null; then
        exec {sp_fd}> /dev/tty
    else
        exec {sp_fd}>&1
    fi
    echo -ne "${YELLOW}[TUBSS] ${task_name} ... ${NC}" >&"$sp_fd"
    if [[ ${TUBSS_TTY:-1} -ne 1 ]]; then
        # Report elapsed time every 2s rather than a per-frame dot, which
        # produced hundreds of meaningless dots for a long apt-get run.
        # Short operations finish before the first report prints.
        local start_s=$SECONDS
        local last_report=0
        local elapsed=0
        while kill -0 "$pid" 2>/dev/null; do
            sleep $delay
            elapsed=$(( SECONDS - start_s ))
            if (( elapsed - last_report >= 2 )); then
                printf "\n  ... still working (%ds elapsed)" "$elapsed" >&"$sp_fd"
                last_report=$elapsed
            fi
        done
        printf " done (%ds)\n" "$elapsed" >&"$sp_fd"
        exec {sp_fd}>&-
        return
    fi
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf "\b${spinstr:0:1}" >&"$sp_fd"
        spinstr=$temp${spinstr:0:1}
        sleep $delay
    done
    printf "\b \n" >&"$sp_fd"
    exec {sp_fd}>&-
}

# Runs a command behind the spinner (output hidden) or, under --verbose, in
# the foreground with output visible. Returns the command's real exit status
# either way so callers' `run_step ... || ...` handling is unaffected.
run_step() {
    local label="$1"; shift
    if (( TUBSS_VERBOSE == 1 )); then
        echo -e "${YELLOW}[TUBSS] ${label} (verbose) ...${NC}"
        "$@"
        return $?
    fi
    "$@" > /dev/null 2>&1 &
    local pid=$!
    spinner "$pid" "$label"
    wait "$pid"
}

# Convert a CIDR prefix to a dotted-decimal subnet mask.
cidr2mask() {
    local cidr=$1
    local i
    local mask=""
    if ! [[ "$cidr" =~ ^[0-9]+$ ]]; then
        echo "255.255.255.0"
        return
    fi
    for i in {1..4}; do
        local val=$(( ( (cidr > 8) ? 255 : (256 - 2**(8-cidr)) ) ))
        mask+="$val."
        cidr=$(( cidr-8 ))
        if (( cidr < 0 )); then cidr=0; fi
    done
    echo "${mask%.}"
}

# Returns 0 only when the package is in `install ok installed`. `dpkg -l`
# is not usable here: it also matches rc-state (removed, config-files left).
pkg_installed() {
    local pkg="$1"
    dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null \
        | grep -q '^install ok installed$'
}

# True when apt has a real install candidate for $1 ("Candidate: (none)"
# means no). Debian testing periodically drops packages, and asking
# apt-get for a missing one aborts the whole run.
#
# Output is captured before grepping: under pipefail, `grep -q` exits early
# and apt-cache takes SIGPIPE, turning a match into exit 141.
#
# LC_ALL=C is required: "Candidate:" is gettext-translated and sudo
# preserves the operator's locale, so on a non-English locale this would
# silently match nothing and skip every package install.
pkg_available() {
    local pkg="$1" policy
    policy=$(LC_ALL=C apt-cache policy "$pkg" 2>/dev/null) || return 1
    grep -q '^  Candidate: [^(]' <<< "$policy"
}

# SECURITY: gate for any value that reaches a sudoers line or a
# `realm permit` argument. AD_SUDO_EXTRA_USER is concatenated straight into
# a sudoers rule, so a value containing '#' comments out the rest of the
# line and injects an attacker-controlled rule that visudo accepts as valid.
# A leading '-' would also be read as a flag by `realm permit`.
#
# Allowlist, not denylist: must start alphanumeric/dot/underscore, then only
# alphanumerics, dots, underscores, spaces, hyphens, '@' or "'". That blocks
# '#', '=', '(', ')', ':', quotes, backslashes and newlines. '@' and "'" are
# allowed on purpose — UPN usernames and names like O'Brien are legitimate.
_is_safe_ad_identifier() {
    [[ "$1" =~ ^[A-Za-z0-9._][A-Za-z0-9._\ @\'-]*$ ]]
}

# _is_safe_ad_identifier only anchors the FIRST character of the whole
# string, so a value like "alice -w" passes it (the leading '-' check does
# not apply to later whitespace-separated tokens) and then splits into a
# flag argument when word-split unquoted into `realm permit $AD_PERMIT_USERS`.
# Used alongside _is_safe_ad_identifier wherever that value is a
# space-separated list, not a single field.
_has_flaglike_token() {
    local tok
    for tok in $1; do
        [[ "$tok" == -* ]] && return 0
    done
    return 1
}

# SECURITY: a single sudo-username field must additionally not be "ALL" or
# contain a space. "ALL" passes the character allowlist but is a sudoers
# keyword meaning every user, so "ALL ALL=(ALL:ALL) ALL" would grant the
# whole box root. Group names and space-separated user lists are exempt and
# only need _is_safe_ad_identifier.
_is_safe_sudo_username() {
    local val="$1"
    _is_safe_ad_identifier "$val" || return 1
    [[ "$val" == "ALL" ]] && return 1
    [[ "$val" == *" "* ]] && return 1
    return 0
}

# Only called when AD_BARE_USERNAMES is enabled. The allowlist above accepts
# '@', so a qualified "user@domain" would land in sudoers verbatim and never
# match a bare-username login — a silent, non-functional sudo grant. Strip
# the suffix and warn so sudoers matches what the operator actually types.
_strip_ad_domain_suffix() {
    local val="$1"
    if [[ "$val" == *@* ]]; then
        echo -e "  ${YELLOW}[WARN]${NC} AD_SUDO_EXTRA_USER '${val}' includes an '@domain' suffix — sssd is being configured for bare-username logins this run, so using '${val%%@*}' instead. If that sssd change failed (check the log above), you may need to grant sudo to the qualified form by hand instead." >&2
        val="${val%%@*}"
    fi
    printf '%s' "$val"
}

# Convert a dotted IPv4 to a 32-bit integer (stdout).
ip_to_int() {
    local ip="$1" a b c d
    IFS=. read -r a b c d <<< "$ip"
    local octet
    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || { echo ""; return 1; }
        (( octet >= 0 && octet <= 255 )) || { echo ""; return 1; }
    done
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# Validate that the chosen GATEWAY lives inside STATIC_IP/NETMASK_CIDR.
# Uses pure bash arithmetic — no ipcalc / ipset dependency. Exits non-zero
# with a clear error if the gateway is outside the subnet.
validate_gateway_in_subnet() {
    local ip="$1" cidr="$2" gw="$3"
    local ip_i gw_i mask host_bits
    ip_i=$(ip_to_int "$ip") || {
        echo -e "${RED}[NET-VALIDATE]${NC} Malformed IP: ${ip}" >&2
        return 1
    }
    gw_i=$(ip_to_int "$gw") || {
        echo -e "${RED}[NET-VALIDATE]${NC} Malformed gateway: ${gw}" >&2
        return 1
    }
    if ! [[ "$cidr" =~ ^[0-9]+$ ]] || (( cidr < 1 || cidr > 32 )); then
        echo -e "${RED}[NET-VALIDATE]${NC} Invalid CIDR: ${cidr}" >&2
        return 1
    fi
    host_bits=$(( 32 - cidr ))
    if (( host_bits == 32 )); then
        mask=0
    else
        mask=$(( (0xFFFFFFFF << host_bits) & 0xFFFFFFFF ))
    fi
    if (( (ip_i & mask) != (gw_i & mask) )); then
        echo -e "${RED}[NET-VALIDATE]${NC} Gateway ${gw} is not in subnet ${ip}/${cidr}." >&2
        echo -e "${RED}[NET-VALIDATE]${NC} Refusing to write a static config that would break networking." >&2
        return 1
    fi
    return 0
}

cleanup() {
    local rc=$?
    echo ""
    echo -e "${YELLOW}============================================================${NC}"
    echo -e "${YELLOW}                  Final Cleanup and Exit${NC}"
    echo -e "${YELLOW}============================================================${NC}"
    if (( PACKAGES_INSTALLED == 1 )); then
        if [[ ${TUBSS_DRY_RUN:-0} -ne 1 && ${EUID:-$(id -u)} -eq 0 ]]; then
            # Don't abort the rest of cleanup if autoremove itself fails during a trap
            run_step "Removing unused packages" apt-get autoremove -y || echo -e "\n${YELLOW}[WARN]${NC} Removing unused packages failed (non-fatal during cleanup)"
        else
            echo "[DRY-RUN] Would run apt-get autoremove"
        fi
    fi
    # Scrub AD credentials unconditionally — they may have been partially
    # collected before an interrupt.
    unset -v AD_PASSWORD AD_DOMAIN AD_USER 2>/dev/null || true
    echo -e "${GREEN}[OK]${NC} Cleanup complete."
    echo -e "${NC}\033[0m"
    echo "===== TUBSS run ended rc=${rc} ====="
    # Flush the log pipeline: close stdout/stderr and wait for the tee subshell
    # to drain before returning. Without this, the final markers may be lost to
    # tee teardown in non-TTY contexts (containers, CI).
    if [[ -n "${TUBSS_TEE_PID:-}" ]]; then
        exec 1>&- 2>&- || true
        wait "$TUBSS_TEE_PID" 2>/dev/null || true
    fi
}

trap 'handle_error' ERR
trap 'cleanup' EXIT

print_usage() {
    cat << 'USAGE'
TUBSS — The Ubuntu/Debian Basic Setup Script

Usage:
  sudo tubss_setup.sh [OPTIONS]

Options:
  -h, --help          Show this help and exit.
  -V, --version       Print script version and exit.
  -y, --unattended,
      --defaults      Skip the default-vs-manual prompt and use defaults.
  -n, --dry-run       Print state-changing commands instead of executing them.
                      Best-effort; wraps apt install, ufw mutations, netplan
                      apply/try, fail2ban restart, systemctl enable/start, and
                      writes to /etc/ config files.
  -v, --verbose       Show real command output (apt, ufw, systemctl, etc.)
                      instead of a progress spinner. Off by default because
                      most runs don't need the extra noise; turn it on when
                      you want to see exactly what a step is doing.
      --rollback      Launch the snapshot-based rollback UI and exit.
      --              Stop parsing options.

Environment:
  TUBSS_UNATTENDED=1    Equivalent to --unattended.
  TUBSS_DRY_RUN=1       Equivalent to --dry-run.
  TUBSS_VERBOSE=1       Equivalent to --verbose.
  TUBSS_NO_LOG=1        Skip log redirection to /var/log/tubss.log.
  TUBSS_FORCE_REBOOT=1  Acknowledge remote-lockout risk and allow
                        --unattended with static IP configuration.
                        Required only when NET_TYPE=static is combined
                        with --unattended (auto-reboot path).
  TUBSS_SKIP_REBOOT=1   Skip the final reboot in --unattended mode.
                        Intended for integration tests / CI; the script
                        otherwise reboots unconditionally in unattended
                        mode when not in dry-run.
  SSH_HARDENING=yes     Opt into SSH hardening in --unattended mode.
                        Without this, --unattended forces hardening OFF
                        to avoid silent SSH lockout. Safety checks still
                        apply (key-only refusal when no authorized_keys).
  JOIN_DOMAIN=yes       Opt into AD domain join in --unattended mode
                        (forced OFF by default, same reasoning as SSH
                        hardening above). Requires AD_DOMAIN, AD_USER,
                        and AD_PASSWORD to also be pre-set — none of the
                        AD prompts are shown in unattended mode.
  AD_PERMIT_MODE=all|group|user
                        Who may log in once joined. Defaults to "all"
                        if unset. "group" requires AD_PERMIT_GROUP;
                        "user" requires AD_PERMIT_USERS (space-separated).
  AD_GRANT_ADMINS_SUDO=yes
                        Grant sudo to the domain's "Domain Admins" group.
                        Defaults to "yes" if unset. Set to "no" to skip.
  AD_SUDO_EXTRA_USER=<username>
                        Additionally grant sudo to one specific domain
                        username. Unset/empty skips this.
  AD_BARE_USERNAMES=yes
                        Configure sssd so domain users sign in with just
                        their username instead of username@domain.
                        Defaults to "yes" if unset. Set to "no" to leave
                        sssd at its own default (qualified names).
  AUTO_REBOOT_UPDATES=yes
                        Opt into automatic reboot when a security update
                        requires it (e.g. a new kernel), at 04:00 local
                        time. Off by default even when auto-updates are
                        on — a server that must stay up until a human
                        approves a reboot should never get one it didn't
                        ask for. Only meaningful if ENABLE_AUTO_UPDATES
                        is also on (the default in --unattended).
  ENABLE_MOTD_BANNER=yes
                        Opt into a standard authorized-access-only login
                        banner (/etc/motd). Off by default — aimed at
                        hardened/compliance-flavored deployments, not
                        personal homelab servers.

Examples:
  sudo tubss_setup.sh
  sudo tubss_setup.sh --unattended
  TUBSS_DRY_RUN=1 sudo -E tubss_setup.sh --unattended

Features:
  - UFW firewall (with optional custom rules), Fail2ban, automatic
    security updates, NTP time sync, optional AD domain join,
    NFS/SMB/Git clients, telemetry disable, static or DHCP networking.
  - Optional SSH hardening (opt-in, default OFF): disable password
    auth (only if authorized_keys exists), disable root login,
    disable X11 forwarding, disable empty passwords. Prompted for in
    manual mode; --unattended keeps it OFF unless explicitly opted
    into via SSH_HARDENING=yes (see Environment above) to avoid
    silent lockout by default.
  - Optional AD domain join is the same shape: prompted for in manual
    mode; --unattended keeps it OFF unless explicitly opted into via
    JOIN_DOMAIN=yes plus AD_DOMAIN/AD_USER/AD_PASSWORD (see
    Environment above). After a successful join, TUBSS verifies with
    `id` that the join account actually resolves via NSS — a stronger
    signal than realm's own exit code that domain logins will work.
  - Optional auto-reboot after a required security update (opt-in,
    default OFF — see AUTO_REBOOT_UPDATES above), and an optional
    standard login banner (opt-in, default OFF — see
    ENABLE_MOTD_BANNER above).
  - Any warn-and-continue issue (a failed package upgrade, AD join,
    permit, sudo grant, or identity check) is collected into a single
    summary at the end of the run and requires acknowledgment in
    interactive mode, instead of relying on you to spot a warning
    buried in the log. TUBSS is safe to run again afterward — it
    checks current state before making changes and won't redo work
    that's already been applied.

Provided by Joka.ca
USAGE
}

print_version() {
    echo "TUBSS ${TUBSS_SCRIPT_VERSION}"
}

# Parse CLI flags. Runs BEFORE the root check so --help / --version work for
# non-root users.
parse_args() {
    while (( $# > 0 )); do
        case "$1" in
            -h|--help)
                trap - EXIT ERR
                print_usage
                exit 0
                ;;
            -V|--version)
                trap - EXIT ERR
                print_version
                exit 0
                ;;
            -y|--unattended|--defaults)
                TUBSS_UNATTENDED=1
                ;;
            -n|--dry-run)
                TUBSS_DRY_RUN=1
                ;;
            -v|--verbose)
                TUBSS_VERBOSE=1
                ;;
            --rollback)
                TUBSS_ROLLBACK=1
                ;;
            --)
                shift
                break
                ;;
            -*)
                trap - EXIT ERR
                echo "Unknown option: $1" >&2
                echo "Run with --help for usage." >&2
                exit 2
                ;;
            *)
                trap - EXIT ERR
                echo "Unexpected positional argument: $1" >&2
                echo "Run with --help for usage." >&2
                exit 2
                ;;
        esac
        shift
    done
}

# Route stdout+stderr through a tee to /var/log/tubss.log with timestamps.
# Falls back to /tmp/tubss.log if the primary path isn't writable. Skipped
# when TUBSS_NO_LOG=1 to keep dry-run / help fast and side-effect-free.
setup_logging() {
    [[ ${TUBSS_NO_LOG:-0} -eq 1 ]] && { TUBSS_TTY=$([[ -t 1 ]] && echo 1 || echo 0); export TUBSS_TTY; return 0; }
    local log=/var/log/tubss.log
    if ! ( : >> "$log" ) 2>/dev/null; then log="/tmp/tubss.log"; fi
    # The log records the AD domain and admin username (never the password),
    # so keep it root-only.
    chmod 600 "$log" 2>/dev/null || true
    TUBSS_TTY=$([[ -t 1 ]] && echo 1 || echo 0)
    export TUBSS_TTY
    exec > >(while IFS= read -r line; do printf '%s %s\n' "$(date -Is)" "$line"; done | tee -a "$log") 2>&1
    TUBSS_TEE_PID=$!
    export TUBSS_TEE_PID
    echo "===== TUBSS run started $(date -Is) pid=$$ version=${TUBSS_SCRIPT_VERSION} argv=$* ====="
}

# Shows an interactive prompt on /dev/tty, bypassing setup_logging()'s
# line-buffered pipe (which would otherwise swallow read -p's no-newline
# prompt text until the script looked hung). _flush_log() gives the async
# log subshell a moment to drain first so output doesn't land after the
# prompt (best-effort, not guaranteed). Prompt text itself is intentionally
# not captured in the log — the end-of-run summary table is the audit
# record of what the operator chose.
#
# Usage: prompt VARNAME "Prompt text: "

_flush_log() {
    sleep 0.05 2>/dev/null || true
}

# A `__`-prefixed varname from a caller would collide with the helper's own
# locals (`__varname`, `__text`).
_prompt_validate_varname() {
    local name="$1"
    if [[ "$name" =~ ^__ ]]; then
        echo "[BUG] prompt(): reserved varname '$name' (double-underscore prefix)." >&2
        return 2
    fi
    return 0
}

prompt() {
    local __varname="$1"
    local __text="$2"
    _prompt_validate_varname "$__varname" || return 2
    _flush_log
    if { : > /dev/tty; } 2>/dev/null; then
        printf '%s' "$__text" > /dev/tty
        # shellcheck disable=SC2229
        read -r "$__varname" < /dev/tty
    else
        # No /dev/tty: a stdout fallback would sit in the tee buffer
        # forever, so refuse rather than silently hang.
        echo "[FATAL] prompt(): /dev/tty is not writable — cannot prompt interactively." >&2
        echo "[FATAL] Run with --unattended (skips prompts) or from a real terminal." >&2
        exit 3
    fi
}

# No-echo variant for passwords. Same /dev/tty rationale as prompt(); the
# trailing newline is manual because `-s` swallows the user's Enter.
#
# Usage: prompt_secret VARNAME "Password: "
prompt_secret() {
    local __varname="$1"
    local __text="$2"
    _prompt_validate_varname "$__varname" || return 2
    _flush_log
    if { : > /dev/tty; } 2>/dev/null; then
        printf '%s' "$__text" > /dev/tty
        # shellcheck disable=SC2229
        read -r -s "$__varname" < /dev/tty
        printf '\n' > /dev/tty
    else
        echo "[FATAL] prompt_secret(): /dev/tty is not writable — cannot prompt interactively." >&2
        echo "[FATAL] Run with --unattended or from a real terminal." >&2
        exit 3
    fi
}

# Detect OS from /etc/os-release and populate distro-specific globals.
detect_os() {
    # shellcheck disable=SC1091
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        DETECTED_OS="${ID:-unknown}"
        DETECTED_VERSION="${VERSION_ID:-unknown}"
        DETECTED_CODENAME="${VERSION_CODENAME:-unknown}"
    else
        DETECTED_OS="unknown"
        DETECTED_VERSION="unknown"
        DETECTED_CODENAME="unknown"
    fi

    # Debian testing/unstable omits VERSION_ID until the release freezes, so
    # without this fallback DETECTED_VERSION stays "unknown" and silently
    # defeats both the SUPPORTED_VERSIONS check and DEBIAN_TESTING_TIER.
    # Extend as later testing codenames replace "forky".
    if [[ "$DETECTED_OS" == "debian" && "$DETECTED_VERSION" == "unknown" ]]; then
        case "$DETECTED_CODENAME" in
            forky) DETECTED_VERSION="14" ;;
        esac
    fi

    case "$DETECTED_OS" in
        ubuntu)
            SUPPORTED_VERSIONS=("20.04" "22.04" "24.04" "26.04")
            PACKAGE_SERVER="archive.ubuntu.com"
            ;;
        debian)
            SUPPORTED_VERSIONS=("11" "12" "13" "14")
            PACKAGE_SERVER="deb.debian.org"
            if [[ "$DETECTED_VERSION" == "14" ]]; then
                DEBIAN_TESTING_TIER=1
            fi
            ;;
        *)
            SUPPORTED_VERSIONS=()
            PACKAGE_SERVER="archive.ubuntu.com"
            ;;
    esac
}

main() {
    parse_args "$@"

    # --rollback needs root too, but not the full setup flow.
    if (( TUBSS_ROLLBACK == 1 )); then
        if [[ $EUID -ne 0 ]]; then
            echo -e "${RED}This script must be run with root privileges. Please use sudo.${NC}"
            exit 1
        fi
        setup_logging "$@"
        run_rollback_ui
        exit 0
    fi

    # Dry-run mode is safe for non-root (no state changes) — skip the root
    # gate so CI smoke tests can run without sudo. All other paths require
    # root.
    if [[ $EUID -ne 0 && ${TUBSS_DRY_RUN:-0} -ne 1 ]]; then
        echo -e "${RED}This script must be run with root privileges. Please use sudo.${NC}"
        exit 1
    fi

    # When running unprivileged in dry-run mode, /var/log/tubss.log is not
    # writable — force TUBSS_NO_LOG to keep the smoke test side-effect-free.
    if [[ $EUID -ne 0 ]]; then
        TUBSS_NO_LOG=1
    fi

    # Guard against curl|bash / no-TTY invocations in interactive mode:
    # without a TTY, prompts silently take defaults or loop forever, so
    # refuse loudly rather than ship a half-configured box.
    if [[ ${TUBSS_UNATTENDED:-0} -ne 1 ]] && [[ ! -t 0 ]]; then
        echo -e "${RED}[ERROR]${NC} TUBSS requires an interactive TTY for configuration prompts." >&2
        echo -e "${RED}[ERROR]${NC} Don't run via 'curl | bash'. Download first, then execute:" >&2
        echo -e "  curl -fsSL <url> -o tubss_setup.sh && sudo bash tubss_setup.sh" >&2
        echo -e "${RED}[ERROR]${NC} Or use --unattended to skip prompts (defaults: DHCP, all services enabled)." >&2
        trap - EXIT ERR
        exit 3
    fi

    setup_logging "$@"
    detect_os

    echo -e "${NC}" # Reset first
    [[ ${TUBSS_TTY:-1} -eq 1 ]] && clear

    echo -e "$BANNER_ART"
    echo -e "--------------------------------------------------------"

    if (( TUBSS_UNATTENDED == 1 )); then
        echo -e "${YELLOW}[INFO]${NC} Running in unattended mode (defaults)."
    fi
    if (( TUBSS_DRY_RUN == 1 )); then
        echo -e "${YELLOW}[INFO]${NC} Dry-run mode enabled — best-effort (state changes logged, not executed)."
    fi

    # Run the setup steps
    run_preflight
    run_prereqs
    get_user_configuration
    show_summary_and_confirm
    apply_configuration
    reboot_prompt
}

# --- Step 0: Pre-flight Validation ---
run_preflight() {
    display_prior_run_state
    echo ""
    echo -e "${YELLOW}============================================================${NC}"
    echo -e "${YELLOW}              [PREFLIGHT] System Checks${NC}"
    echo -e "${YELLOW}============================================================${NC}"
    echo ""

    # Check 1: Root filesystem >= 2GB free
    local avail_gb
    avail_gb=$(df --output=avail -BG / | tail -1 | tr -d 'G ')
    if (( avail_gb < 2 )); then
        echo -e "${RED}[PREFLIGHT] [FAIL]${NC} Root filesystem has only ${avail_gb}GB free. At least 2GB is required."
        PREFLIGHT_FAILED=1
    else
        echo -e "${GREEN}[PREFLIGHT] [OK]${NC} Root filesystem has ${avail_gb}GB free (>= 2GB required)."
    fi

    # Check 2: OS version supported — warn only (duplicate check removed from run_prereqs)
    # DETECTED_OS / DETECTED_VERSION were set in detect_os() at startup.
    local _pretty_os
    case "$DETECTED_OS" in
        ubuntu) _pretty_os="Ubuntu" ;;
        debian) _pretty_os="Debian" ;;
        *)      _pretty_os="${DETECTED_OS:-unknown}" ;;
    esac
    if [[ "$DETECTED_OS" != "ubuntu" && "$DETECTED_OS" != "debian" ]]; then
        echo -e "${RED}[PREFLIGHT] [FAIL]${NC} Unsupported OS: ${DETECTED_OS}. TUBSS supports Ubuntu and Debian only."
        PREFLIGHT_FAILED=1
    elif [[ ! " ${SUPPORTED_VERSIONS[*]} " == *" ${DETECTED_VERSION} "* ]]; then
        echo -e "${YELLOW}[PREFLIGHT] [WARN]${NC} ${_pretty_os} ${DETECTED_VERSION} is not officially supported. Tested versions: ${SUPPORTED_VERSIONS[*]}"
        echo -e "${YELLOW}[PREFLIGHT] [WARN]${NC} Proceeding anyway — some features may not work correctly."
    else
        echo -e "${GREEN}[PREFLIGHT] [OK]${NC} ${_pretty_os} ${DETECTED_VERSION} detected — fully supported."
    fi

    if (( DEBIAN_TESTING_TIER == 1 )); then
        echo -e "${YELLOW}[PREFLIGHT] [WARN]${NC} Debian 14 (Forky) is a testing-tier release — TUBSS support is best-effort."
    fi

    # Check 3: Package server reachable — warn only
    if curl --silent --max-time 5 --head "http://${PACKAGE_SERVER}" > /dev/null 2>&1; then
        echo -e "${GREEN}[PREFLIGHT] [OK]${NC} Package server ${PACKAGE_SERVER} is reachable."
    else
        echo -e "${YELLOW}[PREFLIGHT] [WARN]${NC} Package server ${PACKAGE_SERVER} is not reachable. Package installation may fail."
    fi

    # Check 4: apt state valid — warn only
    if apt-get check > /dev/null 2>&1; then
        echo -e "${GREEN}[PREFLIGHT] [OK]${NC} apt state is valid."
    else
        echo -e "${YELLOW}[PREFLIGHT] [WARN]${NC} apt state check failed. There may be broken packages or a lock conflict."
    fi

    echo ""

    if (( PREFLIGHT_FAILED == 1 )); then
        echo -e "${RED}[PREFLIGHT] One or more critical checks failed. Exiting.${NC}"
        exit 1
    fi

    if (( TUBSS_UNATTENDED == 1 )); then
        echo "[PREFLIGHT] All checks passed. Continuing (unattended)."
    else
        prompt REPLY "[PREFLIGHT] All checks passed. Press Enter to continue..."
    fi
    echo ""
}

# --- Step 1: System Prereqs and Info ---
run_prereqs() {
    local disk_usage_output original_user original_user_home

    # OS version already detected and checked in run_preflight
    # Display the result here for the info screen
    local _pretty_os
    case "$DETECTED_OS" in
        ubuntu) _pretty_os="Ubuntu" ;;
        debian) _pretty_os="Debian" ;;
        *)      _pretty_os="${DETECTED_OS:-unknown}" ;;
    esac
    if [[ ! " ${SUPPORTED_VERSIONS[*]} " == *" ${DETECTED_VERSION} "* ]]; then
        echo -e "${YELLOW}[WARN]${NC} ${_pretty_os} ${DETECTED_VERSION} is not officially supported. Tested versions: ${SUPPORTED_VERSIONS[*]}"
        echo -e "${YELLOW}[WARN]${NC} Proceeding anyway — some features may not work correctly."
    else
        echo -e "${GREEN}[OK]${NC} ${_pretty_os} ${DETECTED_VERSION} detected — fully supported."
    fi

    # Get the original user's desktop path for the summary file
    # Prefer $SUDO_USER, then $USER, then fall back to root to avoid logname failure in non-TTY contexts
    original_user=${SUDO_USER:-${USER:-root}}
    original_user_home=$(getent passwd "$original_user" | cut -d: -f6)
    DESKTOP_DIR="$original_user_home/Desktop"
    if [ ! -d "$DESKTOP_DIR" ]; then
        DESKTOP_DIR="$original_user_home"
    fi
    SUMMARY_FILE="$DESKTOP_DIR/tubss_configuration_summary_$(date +%Y%m%d_%H%M%S).txt"

    # Capture Before Values
    # Headless/no-IP hosts produce empty pipes — guard with `|| true` and
    # fall back to "0.0.0.0" so set -u downstream stays safe.
    # Exclude the interface by name (field 2) before reducing to the address
    # (field 4) — filtering the address string itself for "lo" never matches
    # (an address like 127.0.0.1/8 doesn't contain "lo"), so loopback was
    # never actually excluded and would win via `head -n 1` on most hosts.
    ORIGINAL_IP_CIDR=$(ip -o -4 a 2>/dev/null | awk '$2 != "lo" {print $4}' | head -n 1 || true)
    ORIGINAL_NETMASK_DETECTED=1
    if [[ -z "${ORIGINAL_IP_CIDR:-}" ]]; then
        ORIGINAL_IP="0.0.0.0"
        ORIGINAL_NETMASK_CIDR="24"
        ORIGINAL_NETMASK_DETECTED=0
        # shellcheck disable=SC2034
        ORIGINAL_NETMASK="255.255.255.0"
    elif [[ "$ORIGINAL_IP_CIDR" =~ "/" ]]; then
        ORIGINAL_IP=$(echo "$ORIGINAL_IP_CIDR" | cut -d/ -f1)
        ORIGINAL_NETMASK_CIDR=$(echo "$ORIGINAL_IP_CIDR" | cut -d/ -f2)
        ORIGINAL_NETMASK=$(cidr2mask "$ORIGINAL_NETMASK_CIDR")
    else
        ORIGINAL_IP="$ORIGINAL_IP_CIDR"
        ORIGINAL_NETMASK_CIDR="24"
        ORIGINAL_NETMASK_DETECTED=0
        # shellcheck disable=SC2034
        # Stored for potential future use in a restore/summary display; not read elsewhere currently
        ORIGINAL_NETMASK="255.255.255.0"
    fi
    # shellcheck disable=SC2034
    # Stored for potential future use in restore/display logic; interface selection uses INTERFACE_NAME instead
    ORIGINAL_INTERFACE=$(ip -o -4 a 2>/dev/null | awk '{print $2}' | grep -v 'lo' | head -n 1 || true)
    ORIGINAL_GATEWAY=$(ip r 2>/dev/null | grep default | awk '{print $3}' | head -n 1 || true)
    # Detect network management layer. On Ubuntu, netplan rules. On Debian,
    # /etc/network/interfaces may be the canonical config — prefer netplan
    # if present, otherwise look at ifupdown.
    if compgen -G "/etc/netplan/*.yaml" > /dev/null 2>&1 || compgen -G "/etc/netplan/*.yml" > /dev/null 2>&1; then
        if grep -q "dhcp4: true" /etc/netplan/* 2>/dev/null; then
            ORIGINAL_NET_TYPE="dhcp"
        elif grep -q "dhcp4: false" /etc/netplan/* 2>/dev/null; then
            ORIGINAL_NET_TYPE="static"
        else
            ORIGINAL_NET_TYPE="unknown"
        fi
    elif [[ -f /etc/network/interfaces ]]; then
        if grep -q "dhcp" /etc/network/interfaces 2>/dev/null; then
            ORIGINAL_NET_TYPE="dhcp"
        else
            ORIGINAL_NET_TYPE="static-ifupdown"
        fi
    else
        ORIGINAL_NET_TYPE="unknown"
    fi

    ORIGINAL_HOSTNAME=$(hostname)
    ORIGINAL_DNS=$(resolvectl status 2>/dev/null | grep 'DNS Servers' | awk '{print $3}' | head -n 1 || echo "N/A")
    ORIGINAL_WEBMIN_STATUS=$(pkg_installed webmin && echo "Installed" || echo "Not Installed")
    ORIGINAL_UFW_STATUS=$(ufw status 2>/dev/null | grep 'Status:' | awk '{print $2}' || echo "inactive")
    ORIGINAL_AUTO_UPDATES_STATUS=$(grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades &>/dev/null && echo "Enabled" || echo "Disabled")
    ORIGINAL_AUTO_REBOOT_STATUS=$([[ -f /etc/apt/apt.conf.d/51-tubss-auto-reboot ]] && echo "Enabled" || echo "Disabled")
    # Detection string matches configure_motd_banner()'s own _motd_unique_line
    # — must stay in sync (see that function for why there's no marker comment).
    ORIGINAL_MOTD_STATUS=$(grep -qF 'This system is for authorized use only. All activity on this system may be' /etc/motd 2>/dev/null && echo "Enabled" || echo "Disabled")
    ORIGINAL_FAIL2BAN_STATUS=$(pkg_installed fail2ban && echo "Installed" || echo "Not Installed")
    ORIGINAL_DOMAIN_STATUS=$(realm list 2>/dev/null | grep 'realm-name:' | awk '{print $2}' | head -n1 || echo "Not Joined")
    if [[ "$DETECTED_OS" == "debian" ]]; then
        ORIGINAL_TELEMETRY_STATUS="N/A (Debian)"
    else
        ORIGINAL_TELEMETRY_STATUS=$(pkg_installed ubuntu-report && grep -q 'enable = true' /etc/ubuntu-report/ubuntu-report.conf &>/dev/null && echo "Enabled" || echo "Disabled")
    fi
    ORIGINAL_NFS_STATUS=$(pkg_installed nfs-common && echo "Installed" || echo "Not Installed")
    ORIGINAL_SMB_STATUS=$(pkg_installed cifs-utils && echo "Installed" || echo "Not Installed")
    ORIGINAL_GIT_STATUS=$(pkg_installed git && echo "Installed" || echo "Not Installed")

    # System Information Screen
    echo ""
    echo -e "$INFO_ART"
    echo -e "${YELLOW}Operating System:   ${NC}$(lsb_release -ds)"
    echo -e "${YELLOW}Kernel Version:     ${NC}$(uname -r)"
    echo -e "${YELLOW}Current Hostname:   ${NC}$(hostname)"
    echo -e "${YELLOW}IP Address(es):     ${NC}$(ip -o -4 a | awk '{print $2, $4}' | grep -v 'lo' | sed 's/ /\t/g')"
    echo -e "${YELLOW}CPU:                ${NC}$(lscpu | grep 'Model name:' | sed 's/Model name://' | awk '{$1=$1}1')"
    echo -e "${YELLOW}Memory:             ${NC}$(free -h | grep 'Mem:' | awk '{print $2}')"

    # Store disk usage in a variable and check for success
    # This version is robust against 'set -e' by wrapping the command in a subshell
    disk_usage_output=$( (df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 " used)"}') 2>/dev/null || echo "" )
    if [[ -z "$disk_usage_output" ]]; then
        echo -e "${YELLOW}Disk Usage (/):     ${NC}Failed to retrieve disk usage.${NC}"
    else
        echo -e "${YELLOW}Disk Usage (/):     ${NC}${disk_usage_output}"
    fi

    echo -e "--------------------------------------------------------"
    if (( TUBSS_UNATTENDED == 1 )); then
        echo "[UNATTENDED] Beginning configuration."
    else
        prompt REPLY "Press Enter to begin the configuration..."
    fi
}

# --- Step 2: Get User Configuration ---
get_user_configuration() {
    local first_interface
    # Initial Prompt for Defaults
    echo ""
    if (( TUBSS_UNATTENDED == 1 )); then
        CONFIG_CHOICE="default"
        echo "[UNATTENDED] Using default configuration (skipping default-vs-manual prompt)."
    else
        prompt CONFIG_CHOICE "Would you like to use the default configuration or manually configure each option? (default/manual) [default]: "
        CONFIG_CHOICE=${CONFIG_CHOICE:-default}
        CONFIG_CHOICE=$(echo "$CONFIG_CHOICE" | tr '[:upper:]' '[:lower:]')
    fi

    # Asked up front so the operator doesn't have to know --verbose/TUBSS_VERBOSE
    # beforehand. Skipped in "default" mode, which is meant to be question-free.
    if [[ "$CONFIG_CHOICE" == "manual" ]] && (( TUBSS_VERBOSE != 1 )); then
        local _verbose_choice
        prompt _verbose_choice "Show real command output instead of a progress spinner? (yes/no) [no]: "
        if [[ "$_verbose_choice" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            TUBSS_VERBOSE=1
        fi
    fi

    # User Configuration Prompts
    echo -e "${YELLOW}--------------------------------------------------------${NC}"
    echo -e "${YELLOW}     Please provide your configuration choices.${NC}"
    echo -e "${YELLOW}--------------------------------------------------------${NC}"
    echo ""

    # Filesystem Snapshot
    # Must be "pending", not "Not Applicable": this runs before
    # show_summary_and_confirm(), and snapshot_summary_value() only shows the
    # operator's CREATE_SNAPSHOT intent while the status is "pending".
    SNAPSHOT_STATUS="pending"
    CREATE_SNAPSHOT="no" # Default to no
    if command -v timeshift &> /dev/null; then
        echo -e "${YELLOW}Timeshift snapshot utility detected.${NC}"
        if [[ "$CONFIG_CHOICE" == "default" ]]; then
            CREATE_SNAPSHOT="yes"
        else
            prompt CREATE_SNAPSHOT "Do you want to create a Timeshift snapshot? (yes/no) [yes]: "
            CREATE_SNAPSHOT=${CREATE_SNAPSHOT:-yes}
        fi
    elif command -v zfs &> /dev/null; then
        if zfs list -o name,mountpoint -t filesystem | grep -q " /$"; then
            echo -e "${YELLOW}ZFS root filesystem detected.${NC}"
            if [[ "$CONFIG_CHOICE" == "default" ]]; then
                CREATE_SNAPSHOT="yes"
            else
                prompt CREATE_SNAPSHOT "Do you want to create a ZFS snapshot for rollback? (yes/no) [yes]: "
                CREATE_SNAPSHOT=${CREATE_SNAPSHOT:-yes}
            fi
        fi
    elif command -v btrfs &> /dev/null; then
        # The `df` command can fail and cause the script to exit in strict mode.
        # We redirect stderr to /dev/null to prevent this.
        if df -t btrfs / 2>/dev/null | grep -q ' /$'; then
            echo -e "${YELLOW}Btrfs root filesystem detected.${NC}"
            if [[ "$CONFIG_CHOICE" == "default" ]]; then
                CREATE_SNAPSHOT="yes"
            else
                prompt CREATE_SNAPSHOT "Do you want to create a Btrfs snapshot for rollback? (yes/no) [yes]: "
                CREATE_SNAPSHOT=${CREATE_SNAPSHOT:-yes}
            fi
        fi
    else
        echo -e "${YELLOW}No supported snapshot utilities (Timeshift, ZFS, or Btrfs) detected. Skipping snapshot.${NC}"
    fi

    # Hostname
    if [[ "$CONFIG_CHOICE" == "default" ]]; then
        HOSTNAME="$ORIGINAL_HOSTNAME"
    else
        while true; do
            prompt HOSTNAME "Enter the desired hostname for this machine [$ORIGINAL_HOSTNAME]: "
            HOSTNAME=${HOSTNAME:-$ORIGINAL_HOSTNAME}
            if [[ "$HOSTNAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,61}[a-zA-Z0-9]$ && ! "$HOSTNAME" =~ ^[0-9.]+$ ]]; then
                break
            else
                echo -e "${RED}Invalid hostname. Please use a valid name (e.g., my-server).${NC}"
            fi
        done
    fi

    # Network Configuration
    if [[ "$CONFIG_CHOICE" == "default" ]]; then
        NET_TYPE="dhcp"
    else
        while true; do
            prompt NET_TYPE "Do you want to use DHCP or a static IP? (dhcp/static) [dhcp]: "
            NET_TYPE=${NET_TYPE:-dhcp}
            NET_TYPE=$(echo "$NET_TYPE" | tr '[:upper:]' '[:lower:]')
            if [[ "$NET_TYPE" == "dhcp" || "$NET_TYPE" == "static" ]]; then
                break
            else
                echo -e "${RED}Invalid choice. Please enter 'dhcp' or 'static'.${NC}"
            fi
        done
    fi

    # Static IP specific prompts
    if [[ "$NET_TYPE" == "static" ]]; then
        if [[ "$CONFIG_CHOICE" == "default" ]]; then
            STATIC_IP="192.168.1.100"
            NETMASK_CIDR="24"
            GATEWAY="192.168.1.1"
            DNS_SERVER="8.8.8.8"
        else
            echo ""
            echo "Please provide the network interface name for the static IP configuration."
            echo "Available network interfaces are:"
            for _iface in /sys/class/net/*; do
                [[ "${_iface##*/}" == "lo" ]] && continue
                echo "${_iface##*/}"
            done
            first_interface=""
            for _iface in /sys/class/net/*; do
                [[ "${_iface##*/}" == "lo" ]] && continue
                first_interface="${_iface##*/}"
                break
            done
            while true; do
                prompt INTERFACE_NAME "Enter the network interface name (e.g., enp0s3) [$first_interface]: "
                INTERFACE_NAME=${INTERFACE_NAME:-$first_interface}
                if [[ -d "/sys/class/net/$INTERFACE_NAME" ]]; then
                    break
                else
                    echo "Error: Interface '$INTERFACE_NAME' not found. Please enter a valid interface name."
                fi
            done
            while true; do
                prompt STATIC_IP "Enter the static IP address (e.g., ${ORIGINAL_IP}): "
                STATIC_IP=${STATIC_IP:-$ORIGINAL_IP}
                if [[ "$STATIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                else
                    echo -e "${RED}Invalid IP address format. Please try again.${NC}"
                fi
            done
            while true; do
                local _netmask_label="${ORIGINAL_NETMASK_CIDR}"
                if (( ${ORIGINAL_NETMASK_DETECTED:-1} == 0 )); then
                    _netmask_label="${ORIGINAL_NETMASK_CIDR} (default)"
                fi
                prompt NETMASK_CIDR "Enter the network mask (CIDR notation, e.g., 24) [${_netmask_label}]: "
                NETMASK_CIDR=${NETMASK_CIDR:-$ORIGINAL_NETMASK_CIDR}
                if [[ "$NETMASK_CIDR" =~ ^(8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32)$ ]]; then
                    break
                else
                    echo -e "${RED}Invalid CIDR mask. Please enter a number between 8 and 32.${NC}"
                fi
            done
            while true; do
                prompt GATEWAY "Enter the gateway IP address (e.g., $ORIGINAL_GATEWAY) [$ORIGINAL_GATEWAY]: "
                GATEWAY=${GATEWAY:-$ORIGINAL_GATEWAY}
                if [[ "$GATEWAY" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                else
                    echo -e "${RED}Invalid IP address format. Please try again.${NC}"
                fi
            done
            while true; do
                prompt DNS_SERVER "Enter the DNS server IP address (e.g., $ORIGINAL_DNS) [$ORIGINAL_DNS]: "
                DNS_SERVER=${DNS_SERVER:-$ORIGINAL_DNS}
                if [[ "$DNS_SERVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                else
                    echo -e "${RED}Invalid IP address format. Please try again.${NC}"
                fi
            done
        fi
        echo -e "${RED}!! WARNING !!${NC} ${YELLOW}Incorrect static IP settings can cut off network access, requiring console access to fix — double-check your entries in the summary screen.${NC}"
        prompt REPLY "Press Enter to acknowledge and continue..."
    fi

    # Service and Security Prompts
    if [[ "$CONFIG_CHOICE" == "default" ]]; then
        INSTALL_WEBMIN="no"
        ENABLE_UFW="yes"
        ENABLE_AUTO_UPDATES="yes"
        INSTALL_FAIL2BAN="yes"
        DISABLE_TELEMETRY="yes"
        INSTALL_NFS="yes"
        INSTALL_SMB="yes"
        INSTALL_GIT="yes"
        # SSH hardening stays OFF in default/unattended mode to avoid silent
        # SSH lockout. Opt in via manual mode or by pre-seeding SSH_HARDENING=yes.
        if [[ "${SSH_HARDENING:-}" == "yes" ]]; then
            SSH_HARDENING="yes"
            SSH_DISABLE_PW_AUTH="${SSH_DISABLE_PW_AUTH:-yes}"
            SSH_DISABLE_ROOT="${SSH_DISABLE_ROOT:-yes}"
            SSH_DISABLE_X11="${SSH_DISABLE_X11:-yes}"
            SSH_DISABLE_EMPTY_PW="${SSH_DISABLE_EMPTY_PW:-yes}"
        else
            SSH_HARDENING="no"
        fi
        # Auto-reboot stays OFF in default/unattended mode for the same
        # reason as SSH hardening — opt in via manual mode or by
        # pre-seeding AUTO_REBOOT_UPDATES=yes in the environment.
        if [[ "${AUTO_REBOOT_UPDATES:-}" == "yes" ]]; then
            AUTO_REBOOT_UPDATES="yes"
        else
            AUTO_REBOOT_UPDATES="no"
        fi
        # MOTD banner is opt-in, not a "basic setup" default — a personal
        # homelab box has no real use for authorized-access legal text;
        # it's aimed at more hardened/compliance-flavored deployments.
        if [[ "${ENABLE_MOTD_BANNER:-}" == "yes" ]]; then
            ENABLE_MOTD_BANNER="yes"
        else
            ENABLE_MOTD_BANNER="no"
        fi
        # AD domain join stays OFF in default/unattended mode, same opt-in
        # pattern as SSH_HARDENING. All AD_* settings must also be pre-seeded:
        # this branch never prompts, because unattended runs may have no
        # /dev/tty and prompt()/prompt_secret() fatal-exit rather than hang.
        if [[ "${JOIN_DOMAIN:-}" == "yes" ]]; then
            JOIN_DOMAIN="yes"
        else
            JOIN_DOMAIN="no"
        fi
    else
        prompt INSTALL_WEBMIN "Do you want to install Webmin? (yes/no) [no]: "
        INSTALL_WEBMIN=${INSTALL_WEBMIN:-no}
        prompt ENABLE_UFW "Do you want to enable the UFW firewall? (yes/no) [yes]: "
        ENABLE_UFW=${ENABLE_UFW:-yes}
        prompt ENABLE_AUTO_UPDATES "Do you want to enable automatic security updates? (yes/no) [yes]: "
        ENABLE_AUTO_UPDATES=${ENABLE_AUTO_UPDATES:-yes}
        if [[ "$ENABLE_AUTO_UPDATES" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            echo -e "${YELLOW}Some servers need to stay up until a human approves a reboot — leave this off if that's you.${NC}"
            prompt AUTO_REBOOT_UPDATES "Do you want to automatically reboot when a security update requires it (e.g., a new kernel)? (yes/no) [no]: "
            AUTO_REBOOT_UPDATES=${AUTO_REBOOT_UPDATES:-no}
        else
            AUTO_REBOOT_UPDATES="no"
        fi
        prompt ENABLE_MOTD_BANNER "Do you want to show a standard authorized-access-only warning banner at login? (yes/no) [no]: "
        ENABLE_MOTD_BANNER=${ENABLE_MOTD_BANNER:-no}
        prompt INSTALL_FAIL2BAN "Do you want to install Fail2ban? (yes/no) [yes]: "
        INSTALL_FAIL2BAN=${INSTALL_FAIL2BAN:-yes}
        prompt DISABLE_TELEMETRY "Do you want to disable optional telemetry and analytics? (yes/no) [yes]: "
        DISABLE_TELEMETRY=${DISABLE_TELEMETRY:-yes}

        # SSH hardening — opt-in, default no. Manual mode only.
        prompt SSH_HARDENING "Do you want to enable SSH hardening (sshd_config tightening)? (yes/no) [no]: "
        SSH_HARDENING=${SSH_HARDENING:-no}
        SSH_HARDENING=$(echo "$SSH_HARDENING" | tr '[:upper:]' '[:lower:]')
        if [[ "$SSH_HARDENING" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            SSH_HARDENING="yes"
            echo -e "${YELLOW}Answering yes disables SSH password login entirely — only SSH keys will work. You'll be locked out if you don't have a key set up (TUBSS checks for one first and refuses if it can't find it).${NC}"
            prompt SSH_DISABLE_PW_AUTH "  Disable SSH password login and require SSH keys only? (yes/no) [yes]: "
            SSH_DISABLE_PW_AUTH=${SSH_DISABLE_PW_AUTH:-yes}
            prompt SSH_DISABLE_ROOT "  Disable root login over SSH? (yes/no) [yes]: "
            SSH_DISABLE_ROOT=${SSH_DISABLE_ROOT:-yes}
            prompt SSH_DISABLE_X11 "  Disable X11 forwarding? (yes/no) [yes]: "
            SSH_DISABLE_X11=${SSH_DISABLE_X11:-yes}
            prompt SSH_DISABLE_EMPTY_PW "  Disable empty credentials? (yes/no) [yes]: "
            SSH_DISABLE_EMPTY_PW=${SSH_DISABLE_EMPTY_PW:-yes}
            SSH_DISABLE_PW_AUTH=$(echo "$SSH_DISABLE_PW_AUTH" | tr '[:upper:]' '[:lower:]')
            SSH_DISABLE_ROOT=$(echo "$SSH_DISABLE_ROOT" | tr '[:upper:]' '[:lower:]')
            SSH_DISABLE_X11=$(echo "$SSH_DISABLE_X11" | tr '[:upper:]' '[:lower:]')
            SSH_DISABLE_EMPTY_PW=$(echo "$SSH_DISABLE_EMPTY_PW" | tr '[:upper:]' '[:lower:]')
        else
            SSH_HARDENING="no"
        fi

        if [ "$ORIGINAL_DOMAIN_STATUS" != "Not Joined" ]; then
            echo -e "${YELLOW}Your system is currently joined to the domain: ${ORIGINAL_DOMAIN_STATUS}${NC}"
            prompt JOIN_DOMAIN "Do you want to leave this domain and join another? (yes/no) [no]: "
            JOIN_DOMAIN=${JOIN_DOMAIN:-no}
        else
            prompt JOIN_DOMAIN "Do you want to join an Active Directory domain? (yes/no) [no]: "
            JOIN_DOMAIN=${JOIN_DOMAIN:-no}
        fi

        # Wording says "packages" deliberately: this installs
        # nfs-common/cifs-utils only, no mounts or /etc/fstab entries.
        prompt INSTALL_NFS "Do you want to install the NFS Client packages? (yes/no) [yes]: "
        INSTALL_NFS=${INSTALL_NFS:-yes}
        prompt INSTALL_SMB "Do you want to install the SMB Client packages? (yes/no) [yes]: "
        INSTALL_SMB=${INSTALL_SMB:-yes}
        prompt INSTALL_GIT "Do you want to install Git? (yes/no) [yes]: "
        INSTALL_GIT=${INSTALL_GIT:-yes}
    fi
    # Use tr for flexible input handling
    CREATE_SNAPSHOT=$(echo "$CREATE_SNAPSHOT" | tr '[:upper:]' '[:lower:]')
    INSTALL_WEBMIN=$(echo "$INSTALL_WEBMIN" | tr '[:upper:]' '[:lower:]')
    ENABLE_UFW=$(echo "$ENABLE_UFW" | tr '[:upper:]' '[:lower:]')
    ENABLE_AUTO_UPDATES=$(echo "$ENABLE_AUTO_UPDATES" | tr '[:upper:]' '[:lower:]')
    AUTO_REBOOT_UPDATES=$(echo "$AUTO_REBOOT_UPDATES" | tr '[:upper:]' '[:lower:]')
    ENABLE_MOTD_BANNER=$(echo "$ENABLE_MOTD_BANNER" | tr '[:upper:]' '[:lower:]')
    INSTALL_FAIL2BAN=$(echo "$INSTALL_FAIL2BAN" | tr '[:upper:]' '[:lower:]')
    DISABLE_TELEMETRY=$(echo "$DISABLE_TELEMETRY" | tr '[:upper:]' '[:lower:]')
    JOIN_DOMAIN=$(echo "$JOIN_DOMAIN" | tr '[:upper:]' '[:lower:]')
    INSTALL_NFS=$(echo "$INSTALL_NFS" | tr '[:upper:]' '[:lower:]')
    INSTALL_SMB=$(echo "$INSTALL_SMB" | tr '[:upper:]' '[:lower:]')
    INSTALL_GIT=$(echo "$INSTALL_GIT" | tr '[:upper:]' '[:lower:]')


    # AD details if requested. AD_DOMAIN / AD_USER / AD_PASSWORD are consumed
    # by join_ad_domain(), which scrubs all three once the join has been
    # attempted; cleanup() scrubs them again on any early exit.
    if [[ "$JOIN_DOMAIN" =~ ^([yY][eE][sS]|[yY])$ ]] && [[ "$CONFIG_CHOICE" == "default" ]]; then
        # Unattended/default mode: never prompt here — no /dev/tty is guaranteed
        # and the prompt helpers fatal-exit rather than hang. Credentials must be
        # pre-seeded; if they aren't, perform_realm_join()'s guard reports
        # "Failed (incomplete credentials)" and the run continues.
        AD_PERMIT_MODE=$(echo "${AD_PERMIT_MODE:-all}" | tr '[:upper:]' '[:lower:]')
        case "$AD_PERMIT_MODE" in
            a|all) AD_PERMIT_MODE="a" ;;
            g|group) AD_PERMIT_MODE="g" ;;
            u|user|users) AD_PERMIT_MODE="u" ;;
            *) AD_PERMIT_MODE="a" ;;
        esac
        AD_GRANT_ADMINS_SUDO=$(echo "${AD_GRANT_ADMINS_SUDO:-yes}" | tr '[:upper:]' '[:lower:]')
        AD_BARE_USERNAMES=$(echo "${AD_BARE_USERNAMES:-yes}" | tr '[:upper:]' '[:lower:]')
        # Pre-seeded env values skip the interactive validation loops, so
        # re-check them here — surfacing a bad value at config-review time
        # rather than mid-run. See _is_safe_ad_identifier for the rules.
        if [[ "$AD_PERMIT_MODE" == "g" ]] && ! _is_safe_ad_identifier "${AD_PERMIT_GROUP:-}"; then
            echo -e "  ${YELLOW}[WARN]${NC} AD_PERMIT_GROUP is empty or contains unsafe characters — falling back to 'all domain users'."
            AD_PERMIT_MODE="a"
        fi
        if [[ "$AD_PERMIT_MODE" == "u" ]] && { ! _is_safe_ad_identifier "${AD_PERMIT_USERS:-}" || _has_flaglike_token "${AD_PERMIT_USERS:-}"; }; then
            echo -e "  ${YELLOW}[WARN]${NC} AD_PERMIT_USERS is empty, contains unsafe characters, or has a username starting with '-' — falling back to 'all domain users'."
            AD_PERMIT_MODE="a"
        fi
        if [[ -n "${AD_SUDO_EXTRA_USER:-}" ]] && [[ "$AD_BARE_USERNAMES" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            AD_SUDO_EXTRA_USER=$(_strip_ad_domain_suffix "$AD_SUDO_EXTRA_USER")
        fi
        if [[ -n "${AD_SUDO_EXTRA_USER:-}" ]] && ! _is_safe_sudo_username "$AD_SUDO_EXTRA_USER"; then
            echo -e "  ${YELLOW}[WARN]${NC} AD_SUDO_EXTRA_USER is unsafe (contains unsafe characters, a space, or is the reserved word 'ALL') — the extra sudo grant will be skipped."
            AD_SUDO_EXTRA_USER=""
        fi
    elif [[ "$JOIN_DOMAIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        # Validate AD_DOMAIN/AD_USER: a value like "--help" would otherwise pass
        # straight through to `realm` as a flag (argument injection).
        while true; do
            prompt AD_DOMAIN "Enter the Active Directory domain name (e.g., corp.example.com): "
            if [[ -n "$AD_DOMAIN" ]] && _is_safe_ad_identifier "$AD_DOMAIN"; then
                break
            else
                echo -e "${RED}Enter a domain name using letters, digits, dots, and hyphens.${NC}"
            fi
        done
        while true; do
            prompt AD_USER "Enter a domain account with permission to join computers to the domain (e.g., a service account like svc-join, or your own admin account): "
            if [[ -n "$AD_USER" ]] && _is_safe_ad_identifier "$AD_USER"; then
                break
            else
                echo -e "${RED}Enter a username using letters, digits, dots, underscores, hyphens, '@', or apostrophes.${NC}"
            fi
        done
        echo -e "${YELLOW}Not displayed as you type.${NC}"
        prompt_secret AD_PASSWORD "Enter the password for that account: "

        # Who may log in once joined. A bare `realm join` leaves realmd at its
        # PERMIT-ALL default; TUBSS keeps that default but makes it an explicit,
        # recorded choice rather than an accident.
        echo -e "${YELLOW}Default is everyone in the domain, matching how most homelab/office AD setups already work — restrict below only if you want it narrower (separate from sudo, asked next).${NC}"
        while true; do
            # Full words to match the other multi-choice prompts; single
            # letters also work since the value is normalized to 'a'/'g'/'u'.
            prompt AD_PERMIT_MODE "Allow login for all domain users, a specific group, or specific user(s)? (all/group/user) [all]: "
            AD_PERMIT_MODE=${AD_PERMIT_MODE:-all}
            AD_PERMIT_MODE=$(echo "$AD_PERMIT_MODE" | tr '[:upper:]' '[:lower:]')
            case "$AD_PERMIT_MODE" in
                a|all) AD_PERMIT_MODE="a"; break ;;
                g|group) AD_PERMIT_MODE="g"; break ;;
                u|user|users) AD_PERMIT_MODE="u"; break ;;
                *) echo -e "${RED}Invalid choice. Please enter 'all', 'group', or 'user' (or just 'a', 'g', 'u').${NC}" ;;
            esac
        done
        if [[ "$AD_PERMIT_MODE" == "g" ]]; then
            while true; do
                prompt AD_PERMIT_GROUP "Enter the domain group to permit (e.g., 'Domain Admins'): "
                if [[ -z "$AD_PERMIT_GROUP" ]]; then
                    echo -e "${RED}A group name is required. Enter one, or re-run and choose 'all' for all domain users.${NC}"
                elif ! _is_safe_ad_identifier "$AD_PERMIT_GROUP"; then
                    echo -e "${RED}Only letters, digits, spaces, dots, underscores, and hyphens are allowed. Please re-enter.${NC}"
                else
                    break
                fi
            done
        elif [[ "$AD_PERMIT_MODE" == "u" ]]; then
            while true; do
                prompt AD_PERMIT_USERS "Enter domain username(s) to permit, space-separated: "
                if [[ -z "$AD_PERMIT_USERS" ]]; then
                    echo -e "${RED}At least one username is required. Enter one, or re-run and choose 'all' for all domain users.${NC}"
                elif ! _is_safe_ad_identifier "$AD_PERMIT_USERS"; then
                    echo -e "${RED}Only letters, digits, spaces, dots, underscores, and hyphens are allowed. Please re-enter.${NC}"
                elif _has_flaglike_token "$AD_PERMIT_USERS"; then
                    echo -e "${RED}No username may start with '-'. Please re-enter.${NC}"
                else
                    break
                fi
            done
        fi

        # Bare-username logins (no @domain suffix at login/id/sudo). Defaults
        # to yes but is asked, since it edits sssd.conf on a live auth path.
        # See _configure_sssd_login_format's header for detail.
        prompt AD_BARE_USERNAMES "Do you want to configure sssd so domain users sign in with just their username (no '@${AD_DOMAIN:-domain}' suffix needed)? (yes/no) [yes]: "
        AD_BARE_USERNAMES=${AD_BARE_USERNAMES:-yes}
        AD_BARE_USERNAMES=$(echo "$AD_BARE_USERNAMES" | tr '[:upper:]' '[:lower:]')

        # Sudo for domain accounts. "Domain Admins" already implies full
        # administrative authority, so granting it sudo is the expected default.
        prompt AD_GRANT_ADMINS_SUDO "Do you want to grant sudo to the 'Domain Admins' group by default? (yes/no) [yes]: "
        AD_GRANT_ADMINS_SUDO=${AD_GRANT_ADMINS_SUDO:-yes}
        AD_GRANT_ADMINS_SUDO=$(echo "$AD_GRANT_ADMINS_SUDO" | tr '[:upper:]' '[:lower:]')
        local _sudo_extra_prompt
        if [[ "$AD_BARE_USERNAMES" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            _sudo_extra_prompt="Additionally grant sudo to one specific domain username — bare username, e.g., 'jsmith' (optional, leave blank to skip): "
        else
            _sudo_extra_prompt="Additionally grant sudo to one specific domain username — enter it in whatever format sssd will resolve at login (optional, leave blank to skip): "
        fi
        while true; do
            prompt AD_SUDO_EXTRA_USER "$_sudo_extra_prompt"
            if [[ -n "$AD_SUDO_EXTRA_USER" ]] && [[ "$AD_BARE_USERNAMES" =~ ^([yY][eE][sS]|[yY])$ ]]; then
                AD_SUDO_EXTRA_USER=$(_strip_ad_domain_suffix "$AD_SUDO_EXTRA_USER")
            fi
            if [[ -z "$AD_SUDO_EXTRA_USER" ]] || _is_safe_sudo_username "$AD_SUDO_EXTRA_USER"; then
                break
            else
                echo -e "${RED}Enter a single username (no spaces) using letters, digits, dots, underscores, hyphens, '@', or apostrophes — 'ALL' is reserved and not allowed. Leave blank to skip.${NC}"
            fi
        done
    fi

    # Custom UFW rules — only in manual mode with UFW enabled
    if [[ "$ENABLE_UFW" =~ ^([yY][eE][sS]|[yY])$ ]] && [[ "$CONFIG_CHOICE" == "manual" ]]; then
        collect_custom_ufw_rules
    fi
}

# --- Feature 2: Collect Custom UFW Rules ---
collect_custom_ufw_rules() {
    local add_rule port proto dir desc rule_count=0
    echo -e "${YELLOW}You may add up to 20 custom UFW rules. Port ranges use a hyphen (e.g., 5000-5010).${NC}"

    while true; do
        if (( rule_count >= 20 )); then
            echo -e "${YELLOW}[WARN]${NC} Maximum of 20 custom rules reached."
            break
        fi

        prompt add_rule "Do you want to add a custom firewall rule? (yes/no) [no]: "
        add_rule=${add_rule:-no}
        add_rule=$(echo "$add_rule" | tr '[:upper:]' '[:lower:]')

        if [[ ! "$add_rule" =~ ^([yY][eE][sS]|[yY]|yes)$ ]]; then
            break
        fi

        # Prompt for port (single or range)
        while true; do
            prompt port "  Port or range (e.g., 8080 or 5000-5010): "
            if [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" =~ ^[0-9]+-[0-9]+$ ]]; then
                break
            else
                echo -e "  ${RED}Invalid port. Enter a number (e.g., 8080) or range (e.g., 5000-5010).${NC}"
            fi
        done

        # Prompt for protocol
        while true; do
            prompt proto "  Protocol (tcp/udp/both) [tcp]: "
            proto=${proto:-tcp}
            proto=$(echo "$proto" | tr '[:upper:]' '[:lower:]')
            if [[ "$proto" == "tcp" || "$proto" == "udp" || "$proto" == "both" ]]; then
                break
            else
                echo -e "  ${RED}Invalid protocol. Enter tcp, udp, or both.${NC}"
            fi
        done

        # Prompt for direction
        while true; do
            prompt dir "  Direction (allow/deny) [allow]: "
            dir=${dir:-allow}
            dir=$(echo "$dir" | tr '[:upper:]' '[:lower:]')
            if [[ "$dir" == "allow" || "$dir" == "deny" ]]; then
                break
            else
                echo -e "  ${RED}Invalid direction. Enter allow or deny.${NC}"
            fi
        done

        # Prompt for description (optional)
        prompt desc "  Description (optional, free text): "
        desc=${desc:-""}

        # Store as "port|protocol|direction|description"
        CUSTOM_UFW_RULES+=("${port}|${proto}|${dir}|${desc}")
        rule_count=$(( rule_count + 1 ))
        echo -e "  ${GREEN}[OK]${NC} Rule added: ${dir} ${port}/${proto}${desc:+ — ${desc}}"
    done

    if (( ${#CUSTOM_UFW_RULES[@]} > 0 )); then
        echo -e "${GREEN}[OK]${NC} ${#CUSTOM_UFW_RULES[@]} custom UFW rule(s) queued."
    else
        echo -e "${YELLOW}[INFO]${NC} No custom UFW rules added."
    fi
}

# --- Shared Summary Display ---
# The summary table is rendered twice (configuration review before execution,
# final summary after). While a *_STATUS is still "pending" the row shows the
# operator's intent (NEW_*_SUMMARY); afterwards it shows the real outcome. For
# SSH hardening that distinction matters: an `sshd -t` validation failure rolls
# the config back, and a static row would keep claiming hardening was applied.
snapshot_summary_value() {
    if [[ "${SNAPSHOT_STATUS:-pending}" == "pending" ]]; then
        echo "${CREATE_SNAPSHOT}"
    else
        echo "${SNAPSHOT_STATUS}"
    fi
}

ssh_hardening_summary_value() {
    if [[ "${SSH_HARDENING_STATUS:-pending}" == "pending" ]]; then
        echo "${NEW_SSH_HARDENING_SUMMARY}"
    else
        echo "${SSH_HARDENING_STATUS}"
    fi
}

ad_join_summary_value() {
    if [[ "${AD_JOIN_STATUS:-pending}" == "pending" ]]; then
        echo "${NEW_DOMAIN_SUMMARY}"
    else
        echo "${AD_JOIN_STATUS}"
    fi
}

# "Who may log in" and "who gets sudo" get their own rows: a successful join
# that permitted nobody is a box no one can use.
ad_permit_summary_value() {
    if [[ "${AD_PERMIT_STATUS:-pending}" == "pending" ]]; then
        echo "${NEW_AD_PERMIT_SUMMARY}"
    else
        echo "${AD_PERMIT_STATUS}"
    fi
}

ad_sudo_summary_value() {
    if [[ "${AD_SUDO_STATUS:-pending}" == "pending" ]]; then
        echo "${NEW_AD_SUDO_SUMMARY}"
    else
        echo "${AD_SUDO_STATUS}"
    fi
}

# Whether NSS/sssd actually resolves a real identity post-join — a stronger
# signal than AD_JOIN_STATUS alone, since a "Joined" box nobody can log into
# is not a working box.
ad_identity_summary_value() {
    if [[ "${AD_IDENTITY_STATUS:-pending}" == "pending" ]]; then
        echo "${NEW_AD_IDENTITY_SUMMARY}"
    else
        echo "${AD_IDENTITY_STATUS}"
    fi
}

# Extracted to eliminate DRY violation between show_summary_and_confirm() and reboot_prompt()
display_config_summary() {
    printf "%-30b | %-20s | %-20s\n" "Setting" "Original Value" "New Value"
    printf "%-30s | %-20s | %-20s\n" "------------------------------" "--------------------" "--------------------"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Hostname:" "${NC}" "${ORIGINAL_HOSTNAME}" "${HOSTNAME}"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Network Type:" "${NC}" "${ORIGINAL_NET_TYPE}" "${NET_TYPE}"
    if [[ "$NET_TYPE" == "static" ]]; then
        printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "IP Address:" "${NC}" "${ORIGINAL_IP:-N/A}" "${NEW_IP_ADDRESS_SUMMARY}"
        printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Gateway:" "${NC}" "${ORIGINAL_GATEWAY:-N/A}" "${NEW_GATEWAY_SUMMARY}"
        printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "DNS Server:" "${NC}" "${ORIGINAL_DNS:-N/A}" "${NEW_DNS_SUMMARY}"
    fi
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Filesystem Snapshot:" "${NC}" "N/A" "$(snapshot_summary_value)"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Webmin Status:" "${NC}" "${ORIGINAL_WEBMIN_STATUS}" "${NEW_WEBMIN_SUMMARY}"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "UFW Firewall Status:" "${NC}" "${ORIGINAL_UFW_STATUS}" "${NEW_UFW_SUMMARY}"
    local custom_rule_count="${#CUSTOM_UFW_RULES[@]}"
    if (( custom_rule_count > 0 )); then
        printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Custom UFW Rules:" "${NC}" "N/A" "${custom_rule_count} custom rules"
    else
        printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Custom UFW Rules:" "${NC}" "N/A" "none"
    fi
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Auto Updates Status:" "${NC}" "${ORIGINAL_AUTO_UPDATES_STATUS}" "${NEW_AUTO_UPDATES_SUMMARY}"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Auto Reboot on Update:" "${NC}" "${ORIGINAL_AUTO_REBOOT_STATUS}" "${NEW_AUTO_REBOOT_SUMMARY}"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Login Banner (MOTD):" "${NC}" "${ORIGINAL_MOTD_STATUS}" "${NEW_MOTD_SUMMARY}"
    # "Package Updates" row — "pending" pre-execution, then "Applied" or
    # "Partial (upgrade failed, continuing)" once the upgrade has run.
    local _pkg_after
    if [[ "$PACKAGE_UPDATES_STATUS" == "pending" ]]; then
        _pkg_after="To be Applied"
    else
        _pkg_after="$PACKAGE_UPDATES_STATUS"
    fi
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Package Updates:" "${NC}" "N/A" "${_pkg_after}"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Fail2ban Status:" "${NC}" "${ORIGINAL_FAIL2BAN_STATUS}" "${NEW_FAIL2BAN_SUMMARY}"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "SSH Hardening:" "${NC}" "N/A" "$(ssh_hardening_summary_value)"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Telemetry/Analytics:" "${NC}" "${ORIGINAL_TELEMETRY_STATUS}" "${NEW_TELEMETRY_SUMMARY}"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "AD Domain Join:" "${NC}" "${ORIGINAL_DOMAIN_STATUS:-Not Joined}" "$(ad_join_summary_value)"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "AD Login Permitted:" "${NC}" "N/A" "$(ad_permit_summary_value)"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "AD Sudo Granted:" "${NC}" "N/A" "$(ad_sudo_summary_value)"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "AD Identity Check:" "${NC}" "N/A" "$(ad_identity_summary_value)"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "NFS Client Status:" "${NC}" "${ORIGINAL_NFS_STATUS}" "${NEW_NFS_SUMMARY}"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "SMB Client Status:" "${NC}" "${ORIGINAL_SMB_STATUS}" "${NEW_SMB_SUMMARY}"
    printf "%b%-30s%b | %-20s | %-20s\n" "${YELLOW}" "Git Status:" "${NC}" "${ORIGINAL_GIT_STATUS}" "${NEW_GIT_SUMMARY}"
    echo -e "--------------------------------------------------------"
}

# --- Step 3: Show Summary and Confirm ---
show_summary_and_confirm() {
    # Calculate and assign to global summary variables
    NEW_WEBMIN_SUMMARY=$(if [[ "$INSTALL_WEBMIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Installed"; else echo "Skipped"; fi)
    NEW_UFW_SUMMARY=$(if [[ "$ENABLE_UFW" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Enabled"; else echo "Skipped"; fi)
    NEW_AUTO_UPDATES_SUMMARY=$(if [[ "$ENABLE_AUTO_UPDATES" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Enabled"; else echo "Skipped"; fi)
    # Own row, not a suffix on Auto Updates Status — a server rebooting itself
    # unattended is consequential enough to be its own visible line.
    NEW_AUTO_REBOOT_SUMMARY=$(if [[ "$AUTO_REBOOT_UPDATES" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Enabled (04:00 local)"; else echo "Skipped"; fi)
    NEW_MOTD_SUMMARY=$(if [[ "$ENABLE_MOTD_BANNER" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Enabled"; else echo "Skipped"; fi)
    NEW_FAIL2BAN_SUMMARY=$(if [[ "$INSTALL_FAIL2BAN" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Installed"; else echo "Skipped"; fi)
    NEW_TELEMETRY_SUMMARY=$(if [[ "$DISABLE_TELEMETRY" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Disabled"; else echo "Skipped"; fi)
    NEW_DOMAIN_SUMMARY=$(if [[ "$JOIN_DOMAIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Joined"; else echo "Skipped"; fi)
    NEW_NFS_SUMMARY=$(if [[ "$INSTALL_NFS" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Installed"; else echo "Skipped"; fi)
    NEW_SMB_SUMMARY=$(if [[ "$INSTALL_SMB" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Installed"; else echo "Skipped"; fi)
    NEW_GIT_SUMMARY=$(if [[ "$INSTALL_GIT" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Installed"; else echo "Skipped"; fi)

    # SSH hardening summary: list enabled toggles, or "Disabled"
    if [[ "$SSH_HARDENING" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        local _ssh_parts=()
        [[ "$SSH_DISABLE_PW_AUTH"   =~ ^([yY][eE][sS]|[yY])$ ]] && _ssh_parts+=("key-only")
        [[ "$SSH_DISABLE_ROOT"      =~ ^([yY][eE][sS]|[yY])$ ]] && _ssh_parts+=("no-root")
        [[ "$SSH_DISABLE_X11"       =~ ^([yY][eE][sS]|[yY])$ ]] && _ssh_parts+=("no-x11")
        [[ "$SSH_DISABLE_EMPTY_PW"  =~ ^([yY][eE][sS]|[yY])$ ]] && _ssh_parts+=("no-empty")
        if (( ${#_ssh_parts[@]} > 0 )); then
            NEW_SSH_HARDENING_SUMMARY=$(IFS=,; echo "${_ssh_parts[*]}")
        else
            NEW_SSH_HARDENING_SUMMARY="Enabled (no opts)"
        fi
    else
        NEW_SSH_HARDENING_SUMMARY="Disabled"
    fi

    # AD access summary: intent shown pre-execution, real outcome after.
    if [[ "$JOIN_DOMAIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        case "${AD_PERMIT_MODE:-a}" in
            g) NEW_AD_PERMIT_SUMMARY="group '${AD_PERMIT_GROUP}'" ;;
            u) NEW_AD_PERMIT_SUMMARY="user(s) '${AD_PERMIT_USERS}'" ;;
            *) NEW_AD_PERMIT_SUMMARY="all domain users" ;;
        esac
        local _sudo_parts=()
        [[ "${AD_GRANT_ADMINS_SUDO:-no}" =~ ^([yY][eE][sS]|[yY])$ ]] && _sudo_parts+=("Domain Admins")
        [[ -n "${AD_SUDO_EXTRA_USER:-}" ]] && _sudo_parts+=("${AD_SUDO_EXTRA_USER}")
        if (( ${#_sudo_parts[@]} > 0 )); then
            NEW_AD_SUDO_SUMMARY=$(IFS=,; echo "${_sudo_parts[*]}")
        else
            NEW_AD_SUDO_SUMMARY="none"
        fi
        NEW_AD_IDENTITY_SUMMARY="to be checked"
    else
        NEW_AD_PERMIT_SUMMARY="N/A"
        NEW_AD_SUDO_SUMMARY="N/A"
        NEW_AD_IDENTITY_SUMMARY="N/A"
    fi

    NEW_IP_ADDRESS_SUMMARY=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$STATIC_IP/$NETMASK_CIDR"; else echo "N/A"; fi)
    NEW_GATEWAY_SUMMARY=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$GATEWAY"; else echo "N/A"; fi)
    NEW_DNS_SUMMARY=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$DNS_SERVER"; else echo "N/A"; fi)

    echo ""
    echo -e "$SUMMARY_ART"
    display_config_summary

    if (( TUBSS_UNATTENDED == 1 )); then
        CONFIRM_EXECUTION="yes"
        echo "[UNATTENDED] Auto-confirming configuration."
    else
        prompt CONFIRM_EXECUTION "Does the above configuration look correct? (yes/no) [yes]: "
        CONFIRM_EXECUTION=${CONFIRM_EXECUTION:-yes}
    fi

    if [[ ! "$CONFIRM_EXECUTION" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${RED}Execution aborted by user.${NC}"
        exit 1
    fi

    echo ""
    echo -e "$EXECUTION_ART"
    echo -e "--------------------------------------------------------"
}

# --- Run State Persistence ---

display_prior_run_state() {
    [[ ! -f "$TUBSS_STATE_FILE" ]] && return 0

    # `|| true` on each: a state file from an older/different TUBSS version
    # missing one of these keys would otherwise make grep exit non-zero and,
    # under pipefail, abort the whole run right here at startup.
    local ver start end status last_step failed_step host
    ver=$(grep "^TUBSS_VERSION=" "$TUBSS_STATE_FILE" | cut -d= -f2) || true
    start=$(grep "^RUN_START=" "$TUBSS_STATE_FILE" | cut -d= -f2) || true
    end=$(grep "^RUN_END=" "$TUBSS_STATE_FILE" | cut -d= -f2) || true
    status=$(grep "^STATUS=" "$TUBSS_STATE_FILE" | cut -d= -f2) || true
    last_step=$(grep "^LAST_STEP=" "$TUBSS_STATE_FILE" | cut -d= -f2) || true
    failed_step=$(grep "^FAILED_STEP=" "$TUBSS_STATE_FILE" | cut -d= -f2) || true
    host=$(grep "^HOSTNAME=" "$TUBSS_STATE_FILE" | cut -d= -f2) || true

    echo ""
    echo -e "============================================================"
    echo -e "                   Prior Run State"
    echo -e "============================================================"
    echo -e "  Last run:    ${start:-unknown}"
    if [[ "$status" == "completed" ]]; then
        echo -e "  Status:      ${GREEN}completed${NC}"
        echo -e "  Finished:    ${end:-unknown}"
    elif [[ "$status" == "pending_reboot" ]]; then
        # Loud warning — the live config is not yet the declared config.
        echo -e "  Status:      ${YELLOW}pending_reboot${NC}"
        echo -e "  Finished:    ${end:-unknown}"
        echo -e "  ${YELLOW}>>> Previous run completed but a reboot is still required.${NC}"
        echo -e "  ${YELLOW}>>> The live network config does NOT match the written config.${NC}"
        echo -e "  ${YELLOW}>>> Reboot this host (sudo reboot) before relying on it.${NC}"
    elif [[ "$status" == "failed" ]]; then
        if [[ -n "$failed_step" ]]; then
            echo -e "  Status:      ${RED}failed${NC}"
            echo -e "  Failed step: ${failed_step}"
        else
            echo -e "  Status:      ${YELLOW}interrupted or failed${NC}"
            echo -e "  Last step:   ${last_step:-none completed}"
        fi
    elif [[ "$status" == "running" ]]; then
        echo -e "  Status:      ${YELLOW}running${NC} (interrupted — did not finish)"
        echo -e "  Last step:   ${last_step:-none}"
    else
        echo -e "  Status:      ${status:-unknown}"
    fi
    echo -e "  Script ver:  ${ver:-unknown}"
    echo -e "  Hostname:    ${host:-unknown}"
    echo -e "============================================================"
    if [[ "$status" != "pending_reboot" ]]; then
        echo "It's safe to run TUBSS again — it checks current state before making"
        echo "changes and won't redo work that's already been applied."
    fi
    echo ""
}

init_run_state() {
    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] write run state to $TUBSS_STATE_FILE"
        return 0
    fi
    mkdir -p "$TUBSS_STATE_DIR"
    cat > "$TUBSS_STATE_FILE" << EOF
TUBSS_VERSION=${TUBSS_SCRIPT_VERSION}
RUN_START=$(date -Iseconds)
RUN_END=
STATUS=failed
LAST_STEP=
FAILED_STEP=
HOSTNAME=${HOSTNAME:-$(hostname)}
NET_TYPE=${NET_TYPE:-unknown}
EOF
}

update_run_state_step() {
    [[ ! -f "$TUBSS_STATE_FILE" ]] && return 0
    sed -i "s|^LAST_STEP=.*|LAST_STEP=${1}|" "$TUBSS_STATE_FILE"
}

mark_run_state_failed() {
    [[ ! -f "$TUBSS_STATE_FILE" ]] && return 0
    sed -i "s|^STATUS=.*|STATUS=failed|" "$TUBSS_STATE_FILE"
    sed -i "s|^FAILED_STEP=.*|FAILED_STEP=${1}|" "$TUBSS_STATE_FILE"
}

finalize_run_state() {
    # Optional status override: callers pass "pending_reboot" when the user
    # declines a reboot while NETPLAN_APPLY_PENDING=1, so the next run's
    # "config already exists — skipping" shortcut can't make that permanent.
    local state=${1:-completed}
    [[ ! -f "$TUBSS_STATE_FILE" ]] && return 0
    sed -i "s|^STATUS=.*|STATUS=${state}|" "$TUBSS_STATE_FILE"
    sed -i "s|^RUN_END=.*|RUN_END=$(date -Iseconds)|" "$TUBSS_STATE_FILE"
}

# --- Step 4: Apply Configuration ---
apply_configuration() {
    # Unattended + static IP risks remote lockout on auto-reboot, so require an
    # explicit TUBSS_FORCE_REBOOT=1 opt-in. Dry-run mutates nothing, so it's exempt.
    if (( TUBSS_UNATTENDED == 1 )) \
        && [[ "${NET_TYPE:-}" == "static" ]] \
        && [[ "${TUBSS_FORCE_REBOOT:-0}" != "1" ]] \
        && (( TUBSS_DRY_RUN != 1 )); then
        echo -e "${RED}[ERROR]${NC} Refusing to run unattended with static IP configuration." >&2
        echo -e "${RED}[ERROR]${NC} This combination risks remote lockout on bad config." >&2
        echo -e "${RED}[ERROR]${NC} Set TUBSS_FORCE_REBOOT=1 env var to acknowledge and proceed." >&2
        trap - EXIT ERR
        exit 4
    fi

    init_run_state

    CURRENT_STEP="configure_snapshot"
    configure_snapshot
    update_run_state_step "configure_snapshot"

    CURRENT_STEP="configure_hostname"
    configure_hostname
    update_run_state_step "configure_hostname"

    CURRENT_STEP="install_packages"
    install_packages
    update_run_state_step "install_packages"

    # Unconditional, not just an AD-join prerequisite: accurate time matters for
    # TLS validation, log timestamps, and cron. Early, so chrony can converge
    # in the background during the remaining steps.
    CURRENT_STEP="configure_time_sync"
    ensure_time_sync
    update_run_state_step "configure_time_sync"

    CURRENT_STEP="configure_ufw"
    configure_ufw
    update_run_state_step "configure_ufw"

    CURRENT_STEP="configure_fail2ban"
    configure_fail2ban
    update_run_state_step "configure_fail2ban"

    # Runs after fail2ban so fail2ban still protects SSH if hardening fails.
    CURRENT_STEP="ssh_hardening"
    configure_ssh_hardening
    update_run_state_step "ssh_hardening"

    CURRENT_STEP="configure_auto_updates"
    configure_auto_updates
    update_run_state_step "configure_auto_updates"

    CURRENT_STEP="configure_motd_banner"
    configure_motd_banner
    update_run_state_step "configure_motd_banner"

    CURRENT_STEP="disable_telemetry"
    disable_telemetry
    update_run_state_step "disable_telemetry"

    CURRENT_STEP="join_ad_domain"
    join_ad_domain
    update_run_state_step "join_ad_domain"

    # Debian requires an extra AppArmor GRUB nudge (Ubuntu has it on by default)
    if [[ "$DETECTED_OS" == "debian" ]]; then
        CURRENT_STEP="configure_apparmor_debian"
        configure_apparmor_debian
        update_run_state_step "configure_apparmor_debian"
    fi

    # Network Configuration — done last so all other steps complete before
    # the network changes on reboot
    CURRENT_STEP="configure_network"
    configure_network
    update_run_state_step "configure_network"
}

# --- Debian-only: AppArmor GRUB boot parameter setup ---
configure_apparmor_debian() {
    echo -e "${YELLOW}[TUBSS] Checking AppArmor boot parameters (Debian)... ${NC}"
    local grub_file="/etc/default/grub"
    if [[ ! -f "$grub_file" ]]; then
        echo -e "${YELLOW}[WARN]${NC} GRUB config not found — skipping AppArmor boot parameter setup."
        return 0
    fi
    if grep -q "apparmor=1" "$grub_file" 2>/dev/null; then
        echo -e "${GREEN}[SKIP]${NC} AppArmor boot parameters already present."
        return 0
    fi
    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo ""
        echo "[DRY-RUN] patch ${grub_file} with apparmor=1 security=apparmor and run update-grub"
        return 0
    fi
    # shellcheck disable=SC2016
    sed -i 's/\(GRUB_CMDLINE_LINUX_DEFAULT="[^"]*\)"/\1 apparmor=1 security=apparmor"/' "$grub_file"
    if command -v update-grub > /dev/null 2>&1; then
        update-grub > /dev/null 2>&1
    else
        echo -e "  ${YELLOW}[WARN]${NC} update-grub not found — run it manually before rebooting."
    fi
    # sed exits 0 whether or not the pattern matched, so verify the edit
    # actually landed before claiming success (a non-stock grub file may not
    # have this exact GRUB_CMDLINE_LINUX_DEFAULT="..." form).
    if grep -q 'apparmor=1' "$grub_file" 2>/dev/null; then
        echo -e "${GREEN}[OK]${NC} AppArmor kernel parameters added — takes effect on next boot."
    else
        echo -e "  ${YELLOW}[WARN]${NC} Could not find a matching GRUB_CMDLINE_LINUX_DEFAULT line in ${grub_file} — apparmor=1 was NOT added. Edit it by hand."
    fi
}

configure_snapshot() {
    local snapshot_name zfs_root_dataset
    if [[ "$CREATE_SNAPSHOT" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if command -v timeshift &> /dev/null; then
            snapshot_name="tubss-pre-config-$(date +%Y%m%d-%H%M)"
            run_step "Creating Timeshift snapshot" timeshift --create --comments "TUBSS Pre-Setup Snapshot" || { echo -e "\n${RED}[ERROR]${NC} Creating Timeshift snapshot failed (exit $?)"; exit 1; }
            SNAPSHOT_STATUS="Created: Timeshift"
            echo -e "${GREEN}[OK]${NC} Timeshift snapshot created successfully."
        elif command -v zfs &> /dev/null && zfs list -o name,mountpoint -t filesystem | grep -q " /$"; then
            zfs_root_dataset=$(zfs list -o name,mountpoint -t filesystem | grep " /$" | awk '{print $1}')
            snapshot_name="tubss-pre-config-$(date +%Y%m%d-%H%M)"
            run_step "Creating ZFS snapshot" zfs snapshot "${zfs_root_dataset}@${snapshot_name}" || { echo -e "\n${RED}[ERROR]${NC} Creating ZFS snapshot failed (exit $?)"; exit 1; }
            SNAPSHOT_STATUS="Created: $snapshot_name (ZFS)"
            echo -e "${GREEN}[OK]${NC} ZFS snapshot created successfully."
        elif command -v btrfs &> /dev/null && df -t btrfs / 2>/dev/null | grep -q ' /$'; then
            snapshot_name="tubss-pre-config-$(date +%Y%m%d-%H%M)"
            if [[ ! -d /@snapshots ]]; then
                local _btrfs_create_err
                if ! _btrfs_create_err=$(btrfs subvolume create /@snapshots 2>&1); then
                    echo -e "  ${YELLOW}[WARN]${NC} Could not create /@snapshots: ${_btrfs_create_err}"
                fi
            fi
            run_step "Creating Btrfs snapshot" btrfs subvolume snapshot -r "/@" "/@snapshots/$snapshot_name" || { echo -e "\n${RED}[ERROR]${NC} Creating Btrfs snapshot failed (exit $?)"; exit 1; }
            SNAPSHOT_STATUS="Created: $snapshot_name (Btrfs)"
            echo -e "${GREEN}[OK]${NC} Btrfs snapshot created successfully."
        else
            # Must set a status here: left "pending", snapshot_summary_value()
            # would render the operator's "yes" intent post-execution and
            # falsely imply a snapshot was created.
            SNAPSHOT_STATUS="Skipped (no snapshot tool detected)"
            echo -e "  ${YELLOW}[WARN]${NC} No supported snapshot utility (Timeshift, ZFS, or Btrfs) found — skipping snapshot."
        fi
    else
        SNAPSHOT_STATUS="Skipped"
        echo -e "${YELLOW}[SKIPPED]${NC} Snapshot creation."
    fi
}

configure_hostname() {
    local NEW_HOSTNAME="$HOSTNAME"
    if [[ "$(hostname)" == "$NEW_HOSTNAME" ]]; then
        echo -e "  ${GREEN}[SKIP]${NC} Hostname already set to $NEW_HOSTNAME"
    elif [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] hostnamectl set-hostname $NEW_HOSTNAME"
    else
        hostnamectl set-hostname "$NEW_HOSTNAME"
        echo -e "${GREEN}[OK]${NC} Hostname set to '$NEW_HOSTNAME'."
    fi
}

install_packages() {
    local packages_to_install=()
    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo -e "${YELLOW}[TUBSS] Updating package lists...${NC}"
        echo "[DRY-RUN] apt-get update -y"
    else
        # No announce here -- run_step()'s spinner prints its own header and
        # bypasses setup_logging()'s tee pipe. A second announce would sit
        # buffered in that pipe and re-render later, out of order.
        run_step "Updating package lists" apt-get update -y || { echo -e "\n${RED}[ERROR]${NC} Updating package lists failed (exit $?)"; exit 1; }
    fi
    echo -e "${GREEN}[OK]${NC} Package lists updated."

    # `apt-get upgrade`, not dist-upgrade, to avoid silent metapackage removals.
    # Guards: needrestart's 24.04 hang, maintainer prompts, and clobbering
    # hand-edited conffiles. Warn-and-continue so the rest of the run still lands.
    PACKAGE_UPDATES_STATUS="Applied"
    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo -e "${YELLOW}[TUBSS] Applying pending package updates...${NC}"
        echo "[DRY-RUN] apt-get upgrade -y (--force-confdef --force-confold)"
        echo -e "${GREEN}[OK]${NC} Package updates applied."
    else
        # No announce here -- see the matching comment in the previous
        # step (Updating package lists) for why.
        if run_step "Applying pending package updates" \
            env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive \
            apt-get -y \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            upgrade; then
            # A 0 exit doesn't mean every update landed. Held-back packages are
            # normal (`apt-get upgrade` skips anything needing add/remove, e.g. a
            # new kernel), so the status stays "Applied" with a suffix rather than
            # "Partial", which would trip the end-of-run acknowledgment gate.
            local _still_upgradable
            _still_upgradable=$(apt list --upgradable 2>/dev/null | grep -c '^[a-z0-9]' || true)
            if (( _still_upgradable > 0 )); then
                PACKAGE_UPDATES_STATUS="Applied (${_still_upgradable} kept back)"
                echo -e "\n${YELLOW}[NOTE]${NC} ${_still_upgradable} package(s) still show as upgradable — usually normal (a pending kernel update or similar that 'apt-get upgrade' deliberately keeps back; run 'sudo apt-get full-upgrade' if you want it now). Less commonly: Ubuntu phased rollout or a held/pinned package. Check with: apt list --upgradable"
            else
                echo -e "${GREEN}[OK]${NC} Package updates applied."
            fi
        else
            local _rc=$?
            PACKAGE_UPDATES_STATUS="Partial (upgrade failed, continuing)"
            echo -e "\n${YELLOW}[WARN]${NC} Package updates failed (exit ${_rc}) — continuing with TUBSS hardening."
            echo -e "${YELLOW}[WARN]${NC} Investigate with: sudo apt-get upgrade (rerun interactively)."
        fi
    fi

    # Distro-aware base package set; Debian ships apparmor-utils separately.
    # Every entry is candidate-checked so one package missing on a release can't
    # abort the run, and the fetch tool is resolved dynamically rather than from
    # a per-release table (neofetch has no candidate on Ubuntu 26.04).
    local _base_pkgs=("curl" "ufw" "unattended-upgrades" "apparmor" "net-tools" "htop" "vim" "build-essential" "rsync" "chrony")
    if [[ "$DETECTED_OS" == "debian" ]]; then
        _base_pkgs+=("apparmor-utils")
    fi
    # Under --dry-run no `apt-get update` actually ran, so pkg_available can
    # false-negative against a stale cache. The caveat below stays worded as
    # one possible explanation, not a diagnosis — a locale mismatch produces
    # the identical symptom.
    local _cand_caveat=""
    (( ${TUBSS_DRY_RUN:-0} == 1 )) && _cand_caveat=" (under --dry-run this checks apt's existing cache rather than a freshly updated one — verify independently with: apt-cache policy <package>)"
    if pkg_available "neofetch"; then
        _base_pkgs+=("neofetch")
    elif pkg_available "fastfetch"; then
        _base_pkgs+=("fastfetch")
    else
        echo -e "  ${YELLOW}[WARN]${NC} Neither neofetch nor fastfetch has an installation candidate on this release${_cand_caveat} — skipping the system-info tool."
    fi

    local PACKAGES=()
    local _base_pkg
    for _base_pkg in "${_base_pkgs[@]}"; do
        if pkg_available "$_base_pkg"; then
            PACKAGES+=("$_base_pkg")
        else
            echo -e "  ${YELLOW}[WARN]${NC} Base package '${_base_pkg}' has no installation candidate on this release${_cand_caveat} — skipping it."
        fi
    done

    if [[ "$INSTALL_FAIL2BAN" =~ ^([yY][eE][sS]|[yY])$ ]]; then PACKAGES+=("fail2ban"); fi
    if [[ "$INSTALL_GIT" =~ ^([yY][eE][sS]|[yY])$ ]]; then PACKAGES+=("git"); fi
    if [[ "$INSTALL_WEBMIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then PACKAGES+=("webmin"); fi
    if [[ "$INSTALL_NFS" =~ ^([yY][eE][sS]|[yY])$ ]]; then PACKAGES+=("nfs-common"); fi
    if [[ "$INSTALL_SMB" =~ ^([yY][eE][sS]|[yY])$ ]]; then PACKAGES+=("cifs-utils"); fi
    # AD domain-join stack, only pulled in when a join was requested. `realm
    # join` (without --install) installs nothing itself, so every dependency
    # must be listed explicitly. Candidate-checked because e.g. Debian 14
    # ships realmd/adcli but not sssd, and an uninstallable package would
    # abort the whole run; join_ad_domain() reports a failed join instead.
    if [[ "$JOIN_DOMAIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        local ad_pkg
        for ad_pkg in realmd sssd sssd-tools libnss-sss libpam-sss adcli; do
            if pkg_available "$ad_pkg"; then
                PACKAGES+=("$ad_pkg")
            else
                echo -e "  ${YELLOW}[WARN]${NC} AD package '${ad_pkg}' has no installation candidate on this release — skipping it."
            fi
        done
    fi

    # Add Webmin APT repository if Webmin installation is requested
    if [[ "$INSTALL_WEBMIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if ! pkg_installed webmin; then
            echo -e "${YELLOW}[TUBSS] Adding Webmin repository...${NC}"
            if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
                echo ""
                echo "[DRY-RUN] add Webmin APT repo + key + apt-get update"
            else
                curl -fsSL https://download.webmin.com/jcameron-key.asc \
                    | gpg --dearmor -o /usr/share/keyrings/webmin-archive-keyring.gpg 2>/dev/null
                echo "deb [signed-by=/usr/share/keyrings/webmin-archive-keyring.gpg] https://download.webmin.com/download/repository sarge contrib" \
                    > /etc/apt/sources.list.d/webmin.list
                apt-get update -y > /dev/null 2>&1
            fi
            echo -e "${GREEN}[OK]${NC} Webmin repository added."
        fi
    fi

    for pkg in "${PACKAGES[@]}"; do
        if pkg_installed "$pkg"; then
            echo -e "  ${GREEN}[SKIP]${NC} $pkg already installed"
        else
            packages_to_install+=("$pkg")
        fi
    done

    # Flip the autoremove guard BEFORE mutating the package database so an
    # interrupted install still triggers cleanup on exit.
    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        PACKAGES_INSTALLED=1
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo -e "${YELLOW}[TUBSS] Installing packages...${NC}"
            echo "[DRY-RUN] apt-get install -y ${packages_to_install[*]}"
        else
            # No announce here -- see the matching comment on the
            # "Updating package lists" step for why.
            run_step "Installing packages" env NEEDRESTART_MODE=a DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages_to_install[@]}" || { echo -e "\n${RED}[ERROR]${NC} Installing packages failed (exit $?)"; exit 1; }
        fi
        echo -e "${GREEN}[OK]${NC} All selected packages installed successfully."
    else
        echo -e "  ${GREEN}[SKIP]${NC} All packages already installed"
    fi

    # Start chrony converging now. `systemctl enable --now` returns as soon as
    # chronyd launches and doesn't block on NTP convergence, so starting here
    # lets it converge during the remaining steps and makes ensure_time_sync()'s
    # poll-wait a near-instant confirmation. Purely an optimization —
    # ensure_time_sync() still does its own idempotent enable --now.
    if [[ ${TUBSS_DRY_RUN:-0} -ne 1 ]]; then
        local _early_chrony_svc="" _early_candidate
        for _early_candidate in chrony chronyd; do
            if timeout 5 systemctl cat "${_early_candidate}.service" > /dev/null 2>&1; then
                _early_chrony_svc="$_early_candidate"
                break
            fi
        done
        if [[ -n "$_early_chrony_svc" ]]; then
            timeout 15 systemctl enable --now "${_early_chrony_svc}.service" > /dev/null 2>&1 || true
        fi
    fi
}

disable_cloud_init_network() {
    local cloud_cfg_dir="/etc/cloud/cloud.cfg.d"
    local tubss_override="${cloud_cfg_dir}/99-tubss-disable-network.cfg"

    if [[ ! -d "$cloud_cfg_dir" ]]; then
        return 0
    fi

    if grep -qs "config: disabled" "${cloud_cfg_dir}"/*.cfg 2>/dev/null; then
        echo -e "  ${GREEN}[SKIP]${NC} Cloud-init network management already disabled."
        return 0
    fi

    cat > "$tubss_override" << EOF
# Written by TUBSS v${TUBSS_SCRIPT_VERSION} to prevent cloud-init from
# overwriting TUBSS-managed netplan configuration on reboot.
network:
  config: disabled
EOF
    echo -e "  ${YELLOW}[CLOUD-INIT]${NC} Disabled cloud-init network management: ${tubss_override}"
}

restore_dhcp_config() {
    local target_config_file="$1"
    local most_recent active_iface iface_to_use

    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] restore DHCP config (netplan) — target=${target_config_file}"
        return 0
    fi

    # Try to restore a previously backed-up DHCP config.
    # `find` may exit non-zero under pipefail when the backup dir doesn't
    # exist — `|| true` keeps us out of the ERR trap in that case.
    most_recent=$( (find /etc/netplan/tubss-backup/ -maxdepth 2 \
        \( -name "*.yaml" -o -name "*.yml" \) \
        -printf "%T@ %p\n" 2>/dev/null \
        | sort -rn | head -1 | awk '{print $2}') || true)

    if [[ -n "$most_recent" ]]; then
        cp "$most_recent" /etc/netplan/
        DHCP_RESTORE_FILE="/etc/netplan/$(basename "$most_recent")"
        echo -e "  ${YELLOW}[NETPLAN]${NC} Restored backup config: $(basename "$most_recent")"
        return 0
    fi

    # No backup found — check if any other netplan config exists
    local other_config
    other_config=$(find /etc/netplan/ -maxdepth 1 \( -name "*.yaml" -o -name "*.yml" \) \
        ! -name "$(basename "$target_config_file")" 2>/dev/null | head -1)
    if [[ -n "$other_config" ]]; then
        # Other configs exist that will handle DHCP — nothing to write
        return 0
    fi

    # Last resort: write a minimal DHCP fallback
    active_iface=$(ip -o -4 a | awk '{print $2}' | grep -v lo | head -1)
    iface_to_use="${INTERFACE_NAME:-${active_iface:-eth0}}"
    cat > /etc/netplan/99-tubss-dhcp.yaml << EOF
network:
  version: 2
  ethernets:
    ${iface_to_use}:
      dhcp4: true
EOF
    DHCP_RESTORE_FILE="/etc/netplan/99-tubss-dhcp.yaml"
    echo -e "  ${YELLOW}[NETPLAN]${NC} No backup found — wrote minimal DHCP config for '${iface_to_use}'."
}

# Decide whether this host should use netplan or ifupdown. Debian may have
# both; netplan wins when present.
_network_renderer() {
    if command -v netplan > /dev/null 2>&1 \
        && ( compgen -G "/etc/netplan/*.yaml" > /dev/null 2>&1 \
          || compgen -G "/etc/netplan/*.yml" > /dev/null 2>&1 \
          || [[ "$DETECTED_OS" == "ubuntu" ]] ); then
        echo "netplan"
    elif [[ -f /etc/network/interfaces ]]; then
        echo "ifupdown"
    elif command -v netplan > /dev/null 2>&1; then
        echo "netplan"
    else
        echo "unknown"
    fi
}

# Apply the freshly-generated netplan config. Prefer `netplan try` — it
# auto-reverts if SSH dies, preventing remote lockout. Falls back to `netplan
# apply`; on failure sets NETPLAN_APPLY_PENDING so the reboot prompt is forced.
_netplan_apply_or_try() {
    local gen_err
    gen_err=$(mktemp)
    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] netplan generate"
    elif ! netplan generate 2>"$gen_err"; then
        echo -e "${RED}[ERROR]${NC} Netplan configuration validation failed — not applying to avoid network lockout"
        echo -e "${RED}[ERROR]${NC} netplan generate stderr:"
        sed 's/^/    /' "$gen_err" >&2 || true
        rm -f "$gen_err"
        exit 1
    fi
    rm -f "$gen_err"

    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] netplan try --timeout 60  (fallback: netplan apply)"
        echo -e "  ${YELLOW}[NETPLAN]${NC} Dry-run — skipping live apply."
        return 0
    fi

    # `netplan try` needs an interactive TTY to confirm. Without one, some
    # netplan builds silently revert yet still exit 0, falsely reporting
    # "applied live". Skip `try` and defer the apply to reboot instead.
    if [[ ! -t 0 ]]; then
        echo -e "  ${YELLOW}[NETPLAN]${NC} No TTY available — skipping 'netplan try' (requires interactive confirm)."
        echo -e "  ${YELLOW}[NETPLAN]${NC} Will defer apply to reboot (safer for remote sessions)."
        NETPLAN_APPLY_PENDING=1
        return 0
    fi

    # Detect whether `netplan try` is supported on this distro version.
    # Merge stderr into stdout: some netplan builds print --help to stderr, and
    # the flag may appear as `--timeout=SECS` — match on the literal `--timeout`.
    local try_timeout=60
    if (( TUBSS_UNATTENDED == 1 )); then
        try_timeout=30
    fi
    if netplan try --help 2>&1 | grep -q -- '--timeout'; then
        echo -e "  ${YELLOW}[NETPLAN]${NC} Running 'netplan try --timeout ${try_timeout}' (auto-reverts if SSH dies)..."
        if netplan try --timeout "$try_timeout" < /dev/null; then
            echo -e "  ${GREEN}[NETPLAN]${NC} 'netplan try' accepted — config applied live."
            return 0
        else
            echo -e "  ${YELLOW}[NETPLAN]${NC} 'netplan try' failed or was reverted — falling back."
        fi
    else
        echo -e "  ${YELLOW}[NETPLAN]${NC} 'netplan try' unavailable — falling back to 'netplan apply'."
    fi

    # Fallback: netplan apply. If it fails (e.g. noninteractive shell, SSH
    # disruption risk) mark the reboot as mandatory so user can't skip it.
    if netplan apply > /dev/null 2>&1; then
        echo -e "  ${GREEN}[NETPLAN]${NC} 'netplan apply' succeeded."
        return 0
    fi

    NETPLAN_APPLY_PENDING=1
    echo -e "  ${YELLOW}[NETPLAN]${NC} 'netplan apply' deferred — a reboot is required to activate the new config."
    return 0
}

configure_network() {
    local renderer
    renderer=$(_network_renderer)
    echo -e "${YELLOW}[TUBSS] Configuring Network (renderer=${renderer})... ${NC}"

    if [[ "$renderer" == "ifupdown" ]]; then
        _configure_network_ifupdown
        return
    fi

    # --- netplan path ---
    local network_config_file="/etc/netplan/01-static-network.yaml"
    if [[ "$NET_TYPE" == "dhcp" ]]; then
        if [ -f "$network_config_file" ]; then
            DHCP_RESTORE_FILE=""
            restore_dhcp_config "$network_config_file"
            if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
                echo "[DRY-RUN] mv $network_config_file /tmp/tubss-static-rollback.yaml; netplan generate; netplan apply"
                echo -e "${GREEN}[OK]${NC} DHCP config restored — will apply on reboot. (dry-run)"
            else
                local static_temp="/tmp/tubss-static-rollback.yaml"
                mv "$network_config_file" "$static_temp"
                local gen_err
                gen_err=$(mktemp)
                if ! netplan generate 2>"$gen_err"; then
                    mv "$static_temp" "$network_config_file"
                    [[ -n "$DHCP_RESTORE_FILE" ]] && rm -f "$DHCP_RESTORE_FILE"
                    echo -e "${RED}[ERROR]${NC} Netplan configuration validation failed — rolled back to static config"
                    echo -e "${RED}[ERROR]${NC} netplan generate stderr:"
                    sed 's/^/    /' "$gen_err" >&2 || true
                    rm -f "$gen_err"
                    exit 1
                fi
                rm -f "$static_temp" "$gen_err"
                echo -e "${GREEN}[OK]${NC} DHCP config restored — will apply on reboot."
            fi
        else
            echo -e "${YELLOW}[SKIPPED]${NC} Already using DHCP."
        fi
    else
        # After a pending_reboot run, don't short-circuit on "config already
        # exists": it was never applied to the running kernel, and this session
        # may carry corrected IP/gateway values. Remove the stale file and fall
        # through to the normal write path.
        local prior_status=""
        if [[ -r "$TUBSS_STATE_FILE" ]]; then
            prior_status=$(grep '^STATUS=' "$TUBSS_STATE_FILE" 2>/dev/null | cut -d= -f2)
        fi
        if [[ "$prior_status" == "pending_reboot" ]]; then
            if [[ -f "$network_config_file" ]]; then
                echo -e "  ${YELLOW}[NETPLAN]${NC} Prior run left reboot pending — regenerating config from current session values."
                if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
                    echo "  [DRY-RUN] Would remove stale $network_config_file"
                else
                    rm -f "$network_config_file"
                fi
            fi
            # Fall through to the normal write path below.
        elif [[ -f "$network_config_file" ]]; then
            echo -e "  ${GREEN}[SKIP]${NC} Static network config already exists — skipping."
            echo -e "  ${YELLOW}[WARN]${NC} If you added netplan files since the last run, delete /etc/netplan/01-static-network.yaml and re-run to trigger cleanup."
            return 0
        fi

        warn_if_gateway_unreachable
        # Validate the gateway is inside the chosen subnet before writing anything.
        if ! validate_gateway_in_subnet "$STATIC_IP" "$NETMASK_CIDR" "$GATEWAY"; then
            exit 1
        fi
        # Disable cloud-init network management first so it can't race this
        # write or overwrite it on next boot. Dry-run guarded — the override
        # write, backup mkdir, and netplan mv are all real mutations.
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo "[DRY-RUN] disable_cloud_init_network (write /etc/cloud/cloud.cfg.d/99-tubss-disable-network.cfg)"
        else
            disable_cloud_init_network
        fi

        # Backup and remove conflicting netplan configs to prevent IP merging
        local backup_timestamp
        backup_timestamp=$(date +%Y%m%d-%H%M%S)
        local backup_dir="/etc/netplan/tubss-backup/${backup_timestamp}"
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo "[DRY-RUN] mkdir -p ${backup_dir}"
        else
            mkdir -p "$backup_dir"
        fi
        for f in /etc/netplan/*.yaml /etc/netplan/*.yml; do
            [[ -f "$f" ]] || continue
            [[ "$f" == "$network_config_file" ]] && continue
            if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
                echo "[DRY-RUN] mv $f ${backup_dir}/"
                echo -e "  ${YELLOW}[NETPLAN]${NC} Would back up conflicting config: $(basename "$f") (dry-run)"
            else
                mv "$f" "$backup_dir/"
                echo -e "  ${YELLOW}[NETPLAN]${NC} Backed up conflicting config: $(basename "$f")"
            fi
        done
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo "[DRY-RUN] write netplan static config to $network_config_file"
        else
            # umask in a subshell so the file is created root-only from the
            # first byte, rather than at default permissions and narrowed a
            # moment later by the chmod below.
            (
                umask 077
                cat << EOF > "$network_config_file"
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE_NAME:
      dhcp4: false
      addresses: [$STATIC_IP/$NETMASK_CIDR]
      routes:
        - to: default
          via: $GATEWAY
      nameservers:
        addresses: [$DNS_SERVER]
EOF
            )
            # Belt-and-suspenders: keep it root-only even if the umask above
            # didn't apply for some reason.
            chmod 600 "$network_config_file" 2>/dev/null || true
        fi
        # Apply immediately via `netplan try` (auto-reverts on SSH loss).
        _netplan_apply_or_try
        if (( NETPLAN_APPLY_PENDING == 1 )); then
            echo -e "${YELLOW}[OK]${NC} Static IP config written for '$INTERFACE_NAME' — reboot required to activate."
        else
            echo -e "${GREEN}[OK]${NC} Static IP config applied for '$INTERFACE_NAME'."
        fi
    fi
}

# Debian ifupdown (/etc/network/interfaces) path — used when netplan is absent.
_configure_network_ifupdown() {
    local ifaces_file="/etc/network/interfaces"
    local backup_file="/etc/network/interfaces.tubss-backup"

    if [[ "$NET_TYPE" == "dhcp" ]]; then
        if grep -q "inet static" "$ifaces_file" 2>/dev/null; then
            restore_dhcp_config "$ifaces_file"
            echo -e "${GREEN}[OK]${NC} DHCP config restored — will apply on reboot."
        else
            echo -e "${YELLOW}[SKIPPED]${NC} Already using DHCP."
        fi
        return
    fi

    if grep -q "address ${STATIC_IP:-__nonexistent__}" "$ifaces_file" 2>/dev/null; then
        echo -e "  ${GREEN}[SKIP]${NC} Static network config already exists — skipping."
        echo -e "  ${YELLOW}[WARN]${NC} If you changed the IP, remove ${ifaces_file} and re-run to apply."
        return
    fi

    warn_if_gateway_unreachable
    if ! validate_gateway_in_subnet "$STATIC_IP" "$NETMASK_CIDR" "$GATEWAY"; then
        exit 1
    fi
    disable_cloud_init_network
    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] backup + write ${ifaces_file} with static config"
    else
        [[ -f "$ifaces_file" ]] && cp "$ifaces_file" "$backup_file"
        cat > "$ifaces_file" << EOF
# Managed by TUBSS v${TUBSS_SCRIPT_VERSION} — do not edit manually
auto lo
iface lo inet loopback

auto ${INTERFACE_NAME}
iface ${INTERFACE_NAME} inet static
    address ${STATIC_IP}/${NETMASK_CIDR}
    gateway ${GATEWAY}
    dns-nameservers ${DNS_SERVER}
EOF
    fi
    # ifupdown doesn't have a no-risk "try" mode — defer to reboot.
    NETPLAN_APPLY_PENDING=1
    echo -e "${YELLOW}[OK]${NC} Static IP config written for '${INTERFACE_NAME}' — reboot required to activate."
}

# --- Feature 3: Pre-write Gateway Reachability Check ---
warn_if_gateway_unreachable() {
    [[ "$NET_TYPE" != "static" ]] && return 0
    [[ -z "${GATEWAY:-}" ]] && return 0

    echo -e "${YELLOW}[TUBSS] Checking gateway reachability before writing config... ${NC}"
    if ping -c 2 -W 2 "$GATEWAY" > /dev/null 2>&1; then
        echo -e "${GREEN}[OK]${NC} Gateway ${GATEWAY} is reachable."
    else
        echo ""
        echo -e "${YELLOW}[WARN]${NC} Gateway ${GATEWAY} did not respond to ping."
        echo -e "${YELLOW}       This may indicate the gateway IP is incorrect.${NC}"
        echo -e "${YELLOW}       Proceeding anyway — double-check your network settings.${NC}"
    fi
    return 0
}

configure_ufw() {
    if [[ "$ENABLE_UFW" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}[TUBSS] Configuring UFW... ${NC}"
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            echo -e "  ${GREEN}[SKIP]${NC} UFW already active"
        elif [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo ""
            echo "[DRY-RUN] ufw default deny incoming / allow outgoing"
            echo "[DRY-RUN] ufw allow ssh"
            echo "[DRY-RUN] ufw --force enable"
        else
            # Some kernels (minimal cloud/container images, nftables-only
            # builds) ship the ip6tables binary with an unreachable filter
            # table, so every ufw call touching the v6 ruleset exits non-zero
            # and kills the run under `set -e`. Probe first and restrict ufw
            # to IPv4 instead.
            if [[ -f /etc/default/ufw ]] && ! ip6tables -L >/dev/null 2>&1; then
                sed -i 's/^IPV6=yes/IPV6=no/' /etc/default/ufw
                # sed exits 0 whether or not the pattern matched — verify
                # IPV6 actually ended up disabled before claiming it's safe
                # to proceed; the commands below still touch v6 otherwise.
                if grep -q '^IPV6=no' /etc/default/ufw 2>/dev/null; then
                    echo -e "  ${YELLOW}[WARN]${NC} ip6tables unusable on this kernel — UFW will manage IPv4 only."
                else
                    echo -e "  ${YELLOW}[WARN]${NC} ip6tables unusable on this kernel, and IPV6 could not be confirmed disabled in /etc/default/ufw — UFW commands below may still fail. Edit /etc/default/ufw by hand (set IPV6=no) if so."
                fi
            fi
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow ssh
            run_step "Enabling UFW" ufw --force enable || { echo -e "\n${RED}[ERROR]${NC} Enabling UFW failed (exit $?)"; exit 1; }
            echo -e "${GREEN}[OK]${NC} UFW configured and enabled."
        fi
        # Apply custom rules (always, even if UFW was already active)
        apply_custom_ufw_rules
    else
        echo -e "${YELLOW}[SKIPPED]${NC} UFW configuration."
    fi
}

# --- Feature 2: Apply Custom UFW Rules ---
apply_custom_ufw_rules() {
    if (( ${#CUSTOM_UFW_RULES[@]} == 0 )); then
        return 0
    fi

    echo ""
    echo -e "${YELLOW}[TUBSS] Applying custom UFW rules...${NC}"

    local rule port proto dir desc
    for rule in "${CUSTOM_UFW_RULES[@]}"; do
        # Parse "port|protocol|direction|description"
        IFS='|' read -r port proto dir desc <<< "$rule"

        # Validate parsed values before applying
        if [[ -z "$port" || -z "$proto" || -z "$dir" ]]; then
            echo -e "  ${YELLOW}[SKIP]${NC} Malformed rule entry: ${rule}"
            continue
        fi

        # Handle port ranges: stored with hyphen (e.g., 5000-5010)
        # UFW range syntax: ufw allow 5000:5010/tcp
        local ufw_port
        if [[ "$port" =~ ^[0-9]+-[0-9]+$ ]]; then
            ufw_port="${port/-/:}"
        else
            ufw_port="$port"
        fi

        if [[ "$proto" == "both" ]]; then
            if ufw status | grep -qE "^${ufw_port}/tcp"; then
                echo -e "  ${YELLOW}[UFW]${NC} Rule for ${ufw_port}/tcp already exists — skipping."
            elif ufw "$dir" "${ufw_port}/tcp" > /dev/null 2>&1; then
                echo -e "  ${GREEN}[OK]${NC} ${dir} ${ufw_port}/tcp${desc:+ — ${desc}}"
            else
                echo -e "  ${YELLOW}[SKIP]${NC} Failed to apply: ${dir} ${ufw_port}/tcp"
            fi
            if ufw status | grep -qE "^${ufw_port}/udp"; then
                echo -e "  ${YELLOW}[UFW]${NC} Rule for ${ufw_port}/udp already exists — skipping."
            elif ufw "$dir" "${ufw_port}/udp" > /dev/null 2>&1; then
                echo -e "  ${GREEN}[OK]${NC} ${dir} ${ufw_port}/udp${desc:+ — ${desc}}"
            else
                echo -e "  ${YELLOW}[SKIP]${NC} Failed to apply: ${dir} ${ufw_port}/udp"
            fi
        else
            if ufw status | grep -qE "^${ufw_port}/${proto}"; then
                echo -e "  ${YELLOW}[UFW]${NC} Rule for ${ufw_port}/${proto} already exists — skipping."
            elif ufw "$dir" "${ufw_port}/${proto}" > /dev/null 2>&1; then
                echo -e "  ${GREEN}[OK]${NC} ${dir} ${ufw_port}/${proto}${desc:+ — ${desc}}"
            else
                echo -e "  ${YELLOW}[SKIP]${NC} Failed to apply: ${dir} ${ufw_port}/${proto}"
            fi
        fi
    done

    echo -e "${GREEN}[OK]${NC} Custom UFW rules applied."
}

configure_fail2ban() {
    local jail_file
    if [[ "$INSTALL_FAIL2BAN" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}[TUBSS] Configuring Fail2ban... ${NC}"
        jail_file="/etc/fail2ban/jail.local"

        if [[ -f "$jail_file" ]]; then
            echo -e "  ${GREEN}[SKIP]${NC} Fail2ban already configured — skipping (delete /etc/fail2ban/jail.local to reconfigure)"
        elif [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo ""
            echo "[DRY-RUN] write ${jail_file}, systemctl daemon-reload, systemctl enable --now fail2ban"
        else
            # Write the jail.local file
            cat << EOF > "$jail_file"
[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 5
banaction = ufw

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
backend = systemd

EOF

            # Reload daemon and enable/start fail2ban
            run_step "Reloading systemd daemon" systemctl daemon-reload || { echo -e "\n${RED}[ERROR]${NC} Reloading systemd daemon failed (exit $?)"; exit 1; }

            run_step "Starting and enabling Fail2ban" systemctl enable --now fail2ban || { echo -e "\n${RED}[ERROR]${NC} Starting and enabling Fail2ban failed (exit $?)"; exit 1; }

            echo -e "${GREEN}[OK]${NC} Fail2ban configured and running."
        fi
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Fail2ban configuration."
    fi
}

# --- Opt-in SSH hardening ---
# Applies a drop-in /etc/ssh/sshd_config.d/00-tubss-hardening.conf when
# the distro supports sshd_config.d, otherwise edits /etc/ssh/sshd_config
# in place via sed. Always backs up /etc/ssh/sshd_config before editing,
# validates with `sshd -t`, and reloads (not restarts) the ssh daemon.
#
# Safety rails:
#   * Refuses to disable key-less auth if no authorized_keys exists for
#     the invoking user (or root when root login is disabled).
#   * Restores the backup if `sshd -t` fails.
configure_ssh_hardening() {
    update_run_state_step "ssh_hardening"

    if [[ ! "$SSH_HARDENING" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}[SKIP] SSH hardening disabled${NC}"
        SSH_HARDENING_STATUS="Skipped"
        return 0
    fi

    echo -e "${YELLOW}[TUBSS] Applying SSH hardening...${NC}"

    local sshd_config="/etc/ssh/sshd_config"
    local sshd_d_dir="/etc/ssh/sshd_config.d"
    # Named 00-, not 99-, so it sorts before cloud-init's 50-cloud-init.conf,
    # which ships `PasswordAuthentication yes`. sshd honors the first value it
    # sees per keyword, so a later file would lose to cloud-init.
    local dropin="${sshd_d_dir}/00-tubss-hardening.conf"
    local backup_ts
    backup_ts=$(date +%Y%m%d%H%M)
    local backup="${sshd_config}.tubss.bak.${backup_ts}"

    # --- Safety: verify authorized_keys exists before disabling key-less auth ---
    local disable_pw_auth="no"
    if [[ "$SSH_DISABLE_PW_AUTH" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        local invoking_user invoking_home auth_keys_found=0
        invoking_user="${SUDO_USER:-${USER:-root}}"
        if [[ "$invoking_user" == "root" ]]; then
            invoking_home="/root"
        else
            invoking_home=$(getent passwd "$invoking_user" 2>/dev/null | cut -d: -f6)
        fi
        if [[ -n "$invoking_home" && -s "${invoking_home}/.ssh/authorized_keys" ]]; then
            auth_keys_found=1
        fi
        # If root login will remain enabled, also accept /root/.ssh/authorized_keys
        if (( auth_keys_found == 0 )) && [[ ! "$SSH_DISABLE_ROOT" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            if [[ -s /root/.ssh/authorized_keys ]]; then
                auth_keys_found=1
            fi
        fi
        if (( auth_keys_found == 1 )); then
            disable_pw_auth="yes"
        else
            echo -e "  ${YELLOW}[SAFETY]${NC} No authorized_keys found for '${invoking_user}' — refusing to disable key-less auth (would lock you out)."
        fi
    fi

    # Only prefer the drop-in if sshd_config actually Includes sshd_config.d/*;
    # without that directive the drop-in is silently ignored, so fall back to
    # editing sshd_config directly.
    local use_dropin=0
    if [[ -d "$sshd_d_dir" ]]; then
        if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$sshd_config" 2>/dev/null; then
            use_dropin=1
        else
            echo -e "  ${YELLOW}[SSH]${NC} sshd_config does not Include sshd_config.d — falling back to in-place edit."
        fi
    fi

    # A domain account has no SSH key and no local password, so disabling
    # password auth on a joined box locks out exactly the people the join was
    # for. Re-allow it via a trailing Match block scoped to no more than what
    # `realm permit` let in. Safe to write pre-join: `sshd -t` doesn't require
    # the group to exist. Drop-in path only — in the sed fallback a later run's
    # append would land inside the Match block and be silently rescoped.
    local ad_match_line=""
    if [[ "$disable_pw_auth" == "yes" ]] && [[ "${JOIN_DOMAIN:-no}" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        case "${AD_PERMIT_MODE:-a}" in
            g) ad_match_line="Match Group \"${AD_PERMIT_GROUP}\"" ;;
            # sshd's Match User takes a comma-separated list with no spaces.
            u) ad_match_line="Match User \"$(tr -s '[:blank:]' ',' <<< "$AD_PERMIT_USERS")\"" ;;
            # Every AD account's default primary group.
            *) ad_match_line='Match Group "domain users"' ;;
        esac
    fi
    if [[ -n "$ad_match_line" ]] && (( use_dropin == 0 )); then
        echo -e "  ${YELLOW}[WARN]${NC} Password auth is being disabled on a domain-joined host, but this box uses the legacy in-place sshd_config edit path — TUBSS will not inject an sshd Match block there (a later run's key append could land inside it and be silently rescoped)."
        echo -e "  ${YELLOW}[WARN]${NC} Domain users will be locked out of SSH until you add this by hand at the END of ${sshd_config}:"
        echo -e "  ${YELLOW}[WARN]${NC}     ${ad_match_line}"
        echo -e "  ${YELLOW}[WARN]${NC}         PasswordAuthentication yes"
        ad_match_line=""
    fi

    # --- Dry-run: announce intent and return ---
    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] cp ${sshd_config} ${backup}"
        if (( use_dropin == 1 )); then
            echo "[DRY-RUN] write drop-in ${dropin}"
        else
            echo "[DRY-RUN] sed -i edits on ${sshd_config}"
        fi
        [[ "$disable_pw_auth" == "yes" ]]                              && echo "[DRY-RUN]   set PasswordAuthentication no"
        [[ "$SSH_DISABLE_ROOT"     =~ ^([yY][eE][sS]|[yY])$ ]]         && echo "[DRY-RUN]   set PermitRootLogin no"
        [[ "$SSH_DISABLE_X11"      =~ ^([yY][eE][sS]|[yY])$ ]]         && echo "[DRY-RUN]   set X11Forwarding no"
        [[ "$SSH_DISABLE_EMPTY_PW" =~ ^([yY][eE][sS]|[yY])$ ]]         && echo "[DRY-RUN]   set PermitEmptyPasswords no"
        if [[ -n "$ad_match_line" ]]; then
            echo "[DRY-RUN]   append domain-login exception: ${ad_match_line}"
            echo "[DRY-RUN]       PasswordAuthentication yes"
        fi
        echo "[DRY-RUN] sshd -t -f ${sshd_config}"
        echo "[DRY-RUN] systemctl reload ssh (or sshd)"
        SSH_HARDENING_STATUS="Not applied (dry-run)"
        return 0
    fi

    # --- Backup sshd_config ---
    if [[ -f "$sshd_config" ]]; then
        cp -a "$sshd_config" "$backup"
        echo -e "  ${GREEN}[OK]${NC} Backed up ${sshd_config} -> ${backup}"
    else
        echo -e "  ${YELLOW}[WARN]${NC} ${sshd_config} not found — aborting SSH hardening."
        SSH_HARDENING_STATUS="Failed (sshd_config not found)"
        return 0
    fi

    # --- Build desired setting list ---
    local -a settings=()
    # Tracks whether THIS run actually wrote the drop-in (vs. found it
    # already matching and skipped) — see rollback logic below.
    local dropin_written=0
    [[ "$disable_pw_auth" == "yes" ]]                      && settings+=("PasswordAuthentication no")
    [[ "$SSH_DISABLE_ROOT"     =~ ^([yY][eE][sS]|[yY])$ ]] && settings+=("PermitRootLogin no")
    [[ "$SSH_DISABLE_X11"      =~ ^([yY][eE][sS]|[yY])$ ]] && settings+=("X11Forwarding no")
    [[ "$SSH_DISABLE_EMPTY_PW" =~ ^([yY][eE][sS]|[yY])$ ]] && settings+=("PermitEmptyPasswords no")

    if (( ${#settings[@]} == 0 )); then
        echo -e "  ${YELLOW}[SKIP]${NC} No SSH hardening options selected (or all blocked by safety checks)."
        SSH_HARDENING_STATUS="Skipped (no options selected)"
        return 0
    fi

    # --- Apply: prefer drop-in (only if sshd_config Includes it), fall back to sed-in-place ---
    if (( use_dropin == 1 )); then
        # Idempotency: skip the write if the drop-in already matches.
        # Built by concatenation, NOT `want=$(printf ...)`: command substitution
        # strips the trailing newline and glues the first setting onto the
        # comment line, commenting out `PasswordAuthentication no`.
        local want
        want='# TUBSS SSH hardening'$'\n''# Managed file — regenerate via tubss_setup.sh'$'\n'
        local s
        for s in "${settings[@]}"; do
            want+="${s}"$'\n'
        done
        # Match blocks must come after every global directive — anything
        # below one is scoped to it until EOF.
        if [[ -n "$ad_match_line" ]]; then
            want+=$'\n''# Domain accounts have no SSH key and no local password — allow'$'\n'
            want+='# password auth for exactly the accounts the realm permit scope let in.'$'\n'
            want+="${ad_match_line}"$'\n'
            want+='    PasswordAuthentication yes'$'\n'
        fi
        # Comparison only: $(cat) strips the trailing newline that $want always
        # has, so a raw compare never matches and rewrites the file every run.
        # Wrapping $want in its own substitution makes the compare symmetric;
        # the printf below still writes the intact string.
        if [[ -f "$dropin" ]] && [[ "$(cat "$dropin")" == "$(printf '%s' "$want")" ]]; then
            echo -e "  ${GREEN}[SKIP]${NC} ${dropin} already matches desired state."
        else
            printf '%s' "$want" > "$dropin"
            chmod 0644 "$dropin"
            dropin_written=1
            echo -e "  ${GREEN}[OK]${NC} Wrote drop-in ${dropin}"
        fi
        if [[ -n "$ad_match_line" ]]; then
            echo -e "  ${GREEN}[OK]${NC} Domain-login exception: ${ad_match_line} -> PasswordAuthentication yes"
        fi
    else
        # In-place sed edit of sshd_config. Only modify lines that need changing.
        local key value
        for s in "${settings[@]}"; do
            key="${s%% *}"
            value="${s#* }"
            if grep -Eq "^[[:space:]]*${key}[[:space:]]+${value}([[:space:]]|$)" "$sshd_config"; then
                echo -e "  ${GREEN}[SKIP]${NC} ${key} already set to ${value}"
                continue
            fi
            if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]" "$sshd_config"; then
                sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*$|${key} ${value}|" "$sshd_config"
            else
                printf '\n# TUBSS SSH hardening\n%s\n' "$s" >> "$sshd_config"
            fi
            echo -e "  ${GREEN}[OK]${NC} Set ${key} ${value}"
        done
    fi

    # --- Validate ---
    # Returns 0 even on validation failure, reporting the outcome via
    # SSH_HARDENING_STATUS — matching every other warn-and-continue function
    # here. A non-zero return from this unguarded call would fire the ERR trap
    # under `set -e` and abort the whole run, even though the backup is
    # restored and sshd was never left broken.
    local _sshd_t_output
    if ! _sshd_t_output=$(sshd -t -f "$sshd_config" 2>&1); then
        echo -e "  ${RED}[ERROR]${NC} sshd -t validation failed — restoring backup."
        # Show sshd's actual complaint — "validation failed" alone is
        # undiagnosable from the log.
        if [[ -n "$_sshd_t_output" ]]; then
            echo -e "  ${RED}[ERROR]${NC} sshd -t said:"
            # printf, not echo -e: sshd's output may contain backslash
            # sequences that echo -e would interpret as escapes.
            local _line
            while IFS= read -r _line; do printf '    %s%s%s\n' "$RED" "$_line" "$NC"; done <<< "$_sshd_t_output"
        fi
        cp -a "$backup" "$sshd_config"
        # Only remove the drop-in if THIS run wrote it. If it already matched,
        # the breakage is elsewhere in sshd_config, and deleting a known-good
        # drop-in would just silently un-harden SSH on the next reload.
        if (( dropin_written == 1 )) && [[ -f "$dropin" ]]; then
            rm -f "$dropin"
        fi
        SSH_HARDENING_STATUS="Failed (sshd -t validation — backup restored, no changes applied)"
        return 0
    fi
    echo -e "  ${GREEN}[OK]${NC} sshd configuration validated."

    # --- Reload (NOT restart — preserves existing sessions) ---
    local ssh_unit=""
    if systemctl list-unit-files ssh.service >/dev/null 2>&1 && \
       systemctl list-unit-files ssh.service 2>/dev/null | grep -q '^ssh\.service'; then
        ssh_unit="ssh"
    elif systemctl list-unit-files sshd.service >/dev/null 2>&1 && \
         systemctl list-unit-files sshd.service 2>/dev/null | grep -q '^sshd\.service'; then
        ssh_unit="sshd"
    fi

    if [[ -n "$ssh_unit" ]]; then
        if systemctl reload "$ssh_unit" >/dev/null 2>&1; then
            echo -e "  ${GREEN}[OK]${NC} Reloaded ${ssh_unit}.service (existing sessions preserved)."
        else
            echo -e "  ${YELLOW}[WARN]${NC} systemctl reload ${ssh_unit} failed — run it manually."
        fi
    else
        echo -e "  ${YELLOW}[WARN]${NC} Could not locate ssh/sshd systemd unit — reload skipped."
    fi

    echo -e "${GREEN}[OK]${NC} SSH hardening applied."
    SSH_HARDENING_STATUS="Applied"
}

configure_auto_updates() {
    if [[ "$ENABLE_AUTO_UPDATES" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}[TUBSS] Enabling Automatic Security Updates... ${NC}"
        if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
            echo -e "  ${GREEN}[SKIP]${NC} Auto-updates already configured"
        elif [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo ""
            echo "[DRY-RUN] write /etc/apt/apt.conf.d/20auto-upgrades"
        else
            echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
            echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
            echo -e "${GREEN}[OK]${NC} Automatic security updates enabled."
        fi
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Automatic security updates."
    fi

    # Auto-reboot is a separate, more disruptive opt-in than auto-updates, and
    # gets its own drop-in rather than patching the distro's
    # 50unattended-upgrades, which places these directives differently across
    # releases. apt.conf.d applies lexically, so 51- layers on top of 50-.
    # Idempotent both ways: the drop-in is removed when auto-reboot is no
    # longer requested, so a re-run actually revokes the prior setting.
    local _reboot_dropin="/etc/apt/apt.conf.d/51-tubss-auto-reboot"
    if [[ "$AUTO_REBOOT_UPDATES" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo "[DRY-RUN] write ${_reboot_dropin} (Automatic-Reboot true, Automatic-Reboot-Time 04:00)"
        else
            printf 'Unattended-Upgrade::Automatic-Reboot "true";\nUnattended-Upgrade::Automatic-Reboot-Time "04:00";\n' > "$_reboot_dropin"
            echo -e "  ${GREEN}[OK]${NC} Auto-reboot after required security updates enabled (04:00 local time)."
        fi
    elif [[ -e "$_reboot_dropin" ]]; then
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo "[DRY-RUN] rm -f ${_reboot_dropin}"
        else
            rm -f "$_reboot_dropin"
            echo -e "  ${YELLOW}[OK]${NC} Removed stale auto-reboot config (not requested this run)."
        fi
    fi
}

# Opt-in authorized-access-only login banner, mirroring the DISA STIG/CIS
# short-form consent text. "may be monitored" (not "is monitored") is
# deliberate: TUBSS configures no monitoring, so the banner must not claim any.
# Boilerplate, not legal advice — have counsel review it if it must hold up.
# Appends a delimited block rather than overwriting /etc/motd, and removal
# strips only that block, so distro branding or a prior message survives.
# Idempotent both ways: turning this off actually removes the block.
configure_motd_banner() {
    # /etc/motd has no comment syntax: BEGIN/END marker lines would print to
    # every user at login. The banner text is fixed, so its border line plus
    # one distinctive sentence are enough to detect and remove the block.
    local _motd_border='***************************************************************************'
    local _motd_unique_line='This system is for authorized use only. All activity on this system may be'
    if [[ "$ENABLE_MOTD_BANNER" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}[TUBSS] Configuring login banner... ${NC}"
        if grep -qF "$_motd_unique_line" /etc/motd 2>/dev/null; then
            echo -e "  ${GREEN}[SKIP]${NC} Login banner already configured"
        elif [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo ""
            echo "[DRY-RUN] append authorized-access notice block to /etc/motd"
        else
            # Without a trailing newline the border would be glued onto the
            # previous line, breaking the whole-line removal logic below.
            if [[ -s /etc/motd ]] && [[ -n "$(tail -c1 /etc/motd)" ]]; then
                echo "" >> /etc/motd
            fi
            # Quoted 'EOF' (no expansion), dynamic line printed separately —
            # an unquoted heredoc here would be an injection surface.
            printf '%s\n' "$_motd_border" >> /etc/motd
            cat << 'EOF' >> /etc/motd
                              NOTICE TO USERS

This system is for authorized use only. All activity on this system may be
monitored and recorded. By using this system, you consent to such
monitoring and recording. Unauthorized access, use, or modification is
prohibited and may be subject to criminal and/or civil penalties. Users
have no expectation of privacy on this system.
EOF
            printf '%s\n' "$_motd_border" >> /etc/motd
            echo -e "${GREEN}[OK]${NC} Login banner configured."
        fi
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Login banner."
        if grep -qF "$_motd_unique_line" /etc/motd 2>/dev/null; then
            if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
                echo "[DRY-RUN] remove TUBSS-managed block from /etc/motd"
            else
                # Walk outward from the unique line to the nearest border
                # above and below and drop that inclusive range plus any blank
                # separator. Only delete when BOTH borders matched — otherwise
                # the walk runs to the start/end of file and takes unrelated
                # content with it; exit 1 instead so the caller can warn.
                local _staged
                if ! _staged=$(mktemp); then
                    echo -e "  ${YELLOW}[WARN]${NC} Could not create a temp file — leaving /etc/motd unchanged."
                elif ! awk -v uniq="$_motd_unique_line" -v border="$_motd_border" '
                    BEGIN { n = 0; uniq_line = 0 }
                    { lines[++n] = $0 }
                    $0 == uniq { uniq_line = NR }
                    END {
                        # exit 1, not 0: the caller got here via a substring
                        # grep, so an exact-line miss (trailing whitespace,
                        # say) is a mismatch worth reporting rather than a
                        # silent no-op reported as "[OK] Removed".
                        if (uniq_line == 0) { for (i = 1; i <= n; i++) print lines[i]; exit 1 }
                        start = uniq_line
                        while (start > 1 && lines[start] != border) start--
                        endl = uniq_line
                        while (endl < n && lines[endl] != border) endl++
                        if (lines[start] != border || lines[endl] != border) {
                            for (i = 1; i <= n; i++) print lines[i]
                            exit 1
                        }
                        del_start = start
                        if (del_start > 1 && lines[del_start-1] == "") del_start--
                        for (i = 1; i <= n; i++) {
                            if (i >= del_start && i <= endl) continue
                            print lines[i]
                        }
                        exit 0
                    }
                ' /etc/motd > "$_staged"; then
                    echo -e "  ${YELLOW}[WARN]${NC} /etc/motd looked like it had TUBSS's banner but the exact text/border lines couldn't be pinned down — leaving /etc/motd unchanged rather than risk deleting unrelated content. Remove the block by hand if needed."
                    rm -f "$_staged"
                else
                    # install -m, because mv preserves mktemp's 0600 and would
                    # leave /etc/motd unreadable at login. Staged in /etc/ (same
                    # filesystem) for an atomic rename, as _install_sudoers_file does.
                    if install -m 0644 "$_staged" /etc/motd.tubss-new 2>/dev/null && mv -f /etc/motd.tubss-new /etc/motd 2>/dev/null; then
                        echo -e "  ${YELLOW}[OK]${NC} Removed login banner (not requested this run)."
                        rm -f "$_staged"
                    else
                        echo -e "  ${YELLOW}[WARN]${NC} Could not update /etc/motd — remove the block by hand if needed."
                        rm -f "$_staged" /etc/motd.tubss-new 2>/dev/null
                    fi
                fi
            fi
        fi
    fi
}

disable_telemetry() {
    if [[ "$DISABLE_TELEMETRY" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if [[ "$DETECTED_OS" == "debian" ]]; then
            echo -e "${GREEN}[OK]${NC} Telemetry N/A on Debian — no ubuntu-report installed."
            return 0
        fi
        echo -e "${YELLOW}[TUBSS] Disabling Ubuntu Telemetry... ${NC}"
        if grep -q "^enable = false" /etc/ubuntu-report/ubuntu-report.conf 2>/dev/null; then
            echo -e "  ${GREEN}[SKIP]${NC} Telemetry already disabled"
        elif [ -f /etc/ubuntu-report/ubuntu-report.conf ]; then
            if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
                echo ""
                echo "[DRY-RUN] sed -i 's/^enable = true/enable = false/' /etc/ubuntu-report/ubuntu-report.conf"
                echo -e "${GREEN}[OK]${NC} Ubuntu telemetry disabled."
            else
                sed -i 's/^enable = true/enable = false/' /etc/ubuntu-report/ubuntu-report.conf
                # sed exits 0 whether or not the pattern matched — verify before
                # claiming success.
                if grep -q '^enable = false' /etc/ubuntu-report/ubuntu-report.conf 2>/dev/null; then
                    echo -e "${GREEN}[OK]${NC} Ubuntu telemetry disabled."
                else
                    echo -e "  ${YELLOW}[WARN]${NC} Could not find 'enable = true' in ubuntu-report.conf — telemetry was NOT confirmed disabled. Check the file by hand."
                fi
            fi
        else
            echo -e "${YELLOW}Warning: Ubuntu telemetry configuration file not found. Skipping.${NC}"
        fi
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Telemetry disablement."
    fi
}

# --- Clock/NTP preflight (unconditional) ---
#
# Accurate time matters for TLS validation, log timestamps, and cron; Kerberos
# additionally rejects tickets from a client more than 5 minutes off
# (KRB5KRB_AP_ERR_SKEW). chrony is installed and started early in
# install_packages(); this just confirms it, or starts it if that was skipped.
# Diagnostic, not a gate — every failure path warns and returns 0.
ensure_time_sync() {
    # max_wait is a wall-clock deadline (via $SECONDS), not an iteration count,
    # and every probe is individually `timeout`-bounded — a hung
    # systemd-timedated or wedged chronyd socket must not stall the run.
    local max_wait=30 svc="" candidate tracking deadline
    deadline=$(( SECONDS + max_wait ))
    # Only the AD join specifically needs Kerberos-accurate time; mention it
    # in the warnings below only when it's actually relevant to this run.
    local _ad_hint=""
    [[ "${JOIN_DOMAIN:-no}" =~ ^([yY][eE][sS]|[yY])$ ]] && _ad_hint=" and the domain join below will likely fail (AD login is time-sensitive)"

    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] systemctl enable --now chrony"
        echo "[DRY-RUN] poll timedatectl/chronyc for NTP sync (up to ${max_wait}s)"
        return 0
    fi

    if ! command -v systemctl > /dev/null 2>&1; then
        echo -e "  ${YELLOW}[WARN]${NC} systemctl not available — cannot verify clock sync."
        echo -e "  ${YELLOW}[WARN]${NC} If this machine's date/time is more than a few minutes off, TLS"
        echo -e "  ${YELLOW}[WARN]${NC} validation and log timestamps may be affected${_ad_hint}. Check with: date"
        return 0
    fi

    # Debian and Ubuntu both ship the unit as chrony.service; some upstream
    # builds register it as chronyd.service. Use whichever actually exists.
    for candidate in chrony chronyd; do
        if timeout 5 systemctl cat "${candidate}.service" > /dev/null 2>&1; then
            svc="$candidate"
            break
        fi
    done

    if [[ -z "$svc" ]]; then
        echo -e "  ${YELLOW}[WARN]${NC} chrony is not installed — the system clock is not being kept in sync."
        echo -e "  ${YELLOW}[WARN]${NC} If it's more than a few minutes off, TLS validation and log timestamps"
        echo -e "  ${YELLOW}[WARN]${NC} may be affected${_ad_hint}. Check with: timedatectl status"
        return 0
    fi

    timeout 15 systemctl enable --now "${svc}.service" > /dev/null 2>&1 || true

    while (( SECONDS < deadline )); do
        # Output is captured before matching rather than piped into grep -q:
        # under `set -o pipefail` grep exits on first match and the writer
        # takes SIGPIPE, turning a successful match into a 141 exit.
        if [[ "$(timeout 5 timedatectl show -p NTPSynchronized --value 2>/dev/null)" == "yes" ]]; then
            echo -e "  ${GREEN}[OK]${NC} System clock is NTP-synchronised."
            return 0
        fi
        tracking=$(timeout 5 chronyc tracking 2>/dev/null || true)
        if grep -q 'Leap status.*Normal' <<< "$tracking"; then
            echo -e "  ${GREEN}[OK]${NC} System clock is NTP-synchronised (chrony)."
            return 0
        fi
        sleep 2
    done

    echo -e "  ${YELLOW}[WARN]${NC} Could not confirm the clock is synced after waiting ${max_wait}s."
    echo -e "  ${YELLOW}[WARN]${NC} If it's more than a few minutes off, TLS validation and log timestamps"
    echo -e "  ${YELLOW}[WARN]${NC} may be affected${_ad_hint}. Check with: timedatectl status && chronyc tracking"
    return 0
}

# --- Post-join access control ---
#
# `realm join` on its own leaves realmd at PERMIT-ALL: every domain account
# can already log in. TUBSS re-states that scope explicitly from the operator's
# answer, so "everyone in the domain can sign in here" is a recorded decision
# rather than a default nobody looked at.
#
# Warn-and-continue, like every other step in the AD path: a joined box whose
# permit call failed is still joined, so AD_JOIN_STATUS is left alone and the
# outcome is tracked separately in AD_PERMIT_STATUS. Always returns 0.
apply_realm_permit() {
    local mode="${AD_PERMIT_MODE:-a}"
    local -a permit_cmd=()
    local desc="" display=""

    # Validated here — the actual trust boundary — since these values may have
    # arrived pre-seeded from the environment rather than a validated prompt.
    if [[ "$mode" == "g" ]] && ! _is_safe_ad_identifier "${AD_PERMIT_GROUP:-}"; then
        AD_PERMIT_STATUS="Failed (invalid group name)"
        echo -e "  ${RED}[ERROR]${NC} AD_PERMIT_GROUP contains characters that are not safe to use here — refusing to run 'realm permit'."
        return 0
    fi
    if [[ "$mode" == "u" ]] && { ! _is_safe_ad_identifier "${AD_PERMIT_USERS:-}" || _has_flaglike_token "${AD_PERMIT_USERS:-}"; }; then
        AD_PERMIT_STATUS="Failed (invalid username)"
        echo -e "  ${RED}[ERROR]${NC} AD_PERMIT_USERS contains characters, or a username starting with '-', that are not safe to use here — refusing to run 'realm permit'."
        return 0
    fi

    case "$mode" in
        g)
            permit_cmd=(realm permit -g "$AD_PERMIT_GROUP")
            desc="group '${AD_PERMIT_GROUP}'"
            display="realm permit -g \"${AD_PERMIT_GROUP}\""
            ;;
        u)
            # Deliberately unquoted: AD_PERMIT_USERS holds a space-separated
            # list and `realm permit` takes one argument per username. `--`
            # is a second line of defense so a token starting with '-' is
            # read as a username, not a flag, even if the checks above
            # somehow let one through.
            # shellcheck disable=SC2206
            permit_cmd=(realm permit -- $AD_PERMIT_USERS)
            desc="user(s) '${AD_PERMIT_USERS}'"
            display="realm permit ${AD_PERMIT_USERS}"
            ;;
        *)
            permit_cmd=(realm permit --all)
            desc="all domain users"
            display="realm permit --all"
            ;;
    esac

    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] ${display}"
        AD_PERMIT_STATUS="${desc} (dry-run)"
        return 0
    fi

    if "${permit_cmd[@]}" > /dev/null 2>&1; then
        AD_PERMIT_STATUS="$desc"
        echo -e "  ${GREEN}[OK]${NC} Login permitted for ${desc}."
    else
        AD_PERMIT_STATUS="Failed (permit)"
        echo -e "  ${YELLOW}[WARN]${NC} 'realm permit' failed — login for ${desc} was NOT configured."
        echo -e "  ${YELLOW}[WARN]${NC} The host is still joined. Retry manually with: sudo ${display}"
    fi
    return 0
}

# Validate a sudoers snippet on a TEMP copy, and install it at 0440 only once
# it parses. A malformed file under /etc/sudoers.d/ makes sudo refuse to run
# at all, with no easy recovery on a headless box — so nothing is ever written
# to that directory unvalidated. sudo also ignores any file there that is not
# mode 0440, hence the explicit install mode.
#
# SECURITY: `visudo -cf` validates syntax, not intent. A '#' or newline in
# $content lets an attacker-controlled rule ride past validation and get
# installed at 0440 as root, because everything after '#' is a comment. Callers
# validate their own input, but the check is repeated here unconditionally —
# this is the one path all content takes before /etc/sudoers.d/.
#
# Returns 0 only when the snippet is installed (or announced under dry-run).
_install_sudoers_file() {
    local dest="$1" content="$2" tmp

    if [[ "$content" == *$'\n'* || "$content" == *"#"* ]]; then
        echo -e "  ${RED}[ERROR]${NC} Refusing to write ${dest} — its content contains a newline or '#', either of which could let unvalidated input smuggle an extra rule past 'visudo -cf'."
        return 1
    fi

    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] validate with visudo -cf <tempfile>: ${content}"
        echo "[DRY-RUN] install -m 0440 <tempfile> ${dest}"
        return 0
    fi

    if ! command -v visudo > /dev/null 2>&1; then
        echo -e "  ${YELLOW}[WARN]${NC} visudo not found — refusing to write ${dest} without validating it."
        return 1
    fi

    if ! tmp=$(mktemp); then
        echo -e "  ${YELLOW}[WARN]${NC} Could not create a temp file — skipping ${dest}."
        return 1
    fi
    printf '# TUBSS AD sudo grant — managed file, regenerate via tubss_setup.sh\n%s\n' \
        "$content" > "$tmp"

    if ! visudo -cf "$tmp" > /dev/null 2>&1; then
        echo -e "  ${RED}[ERROR]${NC} sudoers validation failed — ${dest} was NOT installed."
        echo -e "  ${RED}[ERROR]${NC} Rejected line: ${content}"
        rm -f "$tmp"
        return 1
    fi

    # Stage in the destination directory (same filesystem, so `mv` is a single
    # atomic rename) instead of installing over the live file: install's
    # overwrite isn't atomic, and a crash mid-copy leaves a truncated sudoers
    # file that breaks sudo entirely.
    local staged="${dest}.tubss-new"
    if install -m 0440 "$tmp" "$staged" 2>/dev/null && mv -f "$staged" "$dest" 2>/dev/null; then
        rm -f "$tmp"
        echo -e "  ${GREEN}[OK]${NC} Installed ${dest} (0440)."
        return 0
    fi
    rm -f "$tmp" "$staged" 2>/dev/null
    echo -e "  ${YELLOW}[WARN]${NC} Could not install ${dest} — sudo grant skipped."
    return 1
}

# Post-join identity verification. A successful `realm join` only means
# realmd's handshake worked, not that NSS/sssd can resolve an identity — so run
# the `id` check automatically instead of waiting for a failed login. Tries the
# bare username then user@domain, since use_fully_qualified_names varies.
# Warn-only: sssd can take a moment to warm up right after a join.
_verify_ad_identity() {
    local user="$1" label="$2" domain="$3" out
    if out=$(id "$user" 2>&1); then
        echo -e "  ${GREEN}[OK]${NC} Identity resolves for ${label} '${user}': ${out}"
        return 0
    fi
    if out=$(id "${user}@${domain}" 2>&1); then
        echo -e "  ${GREEN}[OK]${NC} Identity resolves for ${label} '${user}@${domain}': ${out}"
        return 0
    fi
    echo -e "  ${YELLOW}[WARN]${NC} Could not resolve identity for ${label} '${user}' via NSS yet."
    echo -e "  ${YELLOW}[WARN]${NC} This can be normal right after a join (sssd may still be warming up)."
    echo -e "  ${YELLOW}[WARN]${NC} Verify manually with: id ${user}  (or: id ${user}@${domain})"
    return 1
}

# sssd's AD provider defaults to use_fully_qualified_names=True, so only
# `id user@domain` resolves. That's collision-avoidance for multi-domain trust
# setups; for a single-domain join it just forces the qualified form into every
# login, `id` check, and sudoers entry. Flip it by editing sssd.conf directly
# (realmd/adcli expose no join-time flag) and restart sssd so it applies within
# this run. fallback_homedir is aligned so bare logins don't get a
# domain-suffixed home.
#
# TRADEOFF: if this box later joins a second, trusted domain, same-named
# accounts become ambiguous. Single-domain joins (TUBSS's target) don't hit it.
#
# Everything else is left at realmd's defaults on purpose — notably
# ldap_id_mapping (a wrong guess silently reassigns every UID/GID) and
# ad_gpo_access_control/ad_access_filter (GPO-dependent, untestable from here).
_configure_sssd_login_format() {
    local domain="$1"
    local sssd_conf="/etc/sssd/sssd.conf"

    # Warn-and-continue (always returns 0), like every other AD sub-step: the
    # caller is unguarded under set -e, so a non-zero return would abort the
    # run right after a successful join, skipping permit, sudoers, identity
    # verification, and the AD_PASSWORD scrub.
    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] set use_fully_qualified_names = False, fallback_homedir = /home/%u in ${sssd_conf}"
        echo "[DRY-RUN] systemctl restart sssd"
        return 0
    fi

    if [[ ! -f "$sssd_conf" ]]; then
        echo -e "  ${YELLOW}[WARN]${NC} ${sssd_conf} not found — leaving login-name format at sssd's default (qualified)."
        return 0
    fi

    # Read the section name from the live file rather than constructing
    # "[domain/${domain}]": realmd's casing may not match what the operator
    # typed. Trailing whitespace is trimmed so the literal `$0 == section`
    # comparison in the awk below still matches. `|| true` because under
    # pipefail a no-match grep would propagate non-zero straight to set -e and
    # kill the run before the `[[ -z "$section" ]]` handler below can report it.
    local section
    section=$(grep -oE '^\[domain/[^]]+\]' "$sssd_conf" | head -1 | sed 's/[[:space:]]*$//') || true
    if [[ -z "$section" ]]; then
        echo -e "  ${YELLOW}[WARN]${NC} No [domain/...] section found in ${sssd_conf} — leaving login-name format at sssd's default (qualified)."
        return 0
    fi

    local backup
    backup="${sssd_conf}.tubss.bak.$(date +%Y%m%d%H%M)"
    if ! cp -a "$sssd_conf" "$backup" 2>/dev/null; then
        echo -e "  ${YELLOW}[WARN]${NC} Could not back up ${sssd_conf} — leaving login-name format at sssd's default (qualified) rather than edit without a backup."
        return 0
    fi

    local tmp
    if ! tmp=$(mktemp); then
        echo -e "  ${YELLOW}[WARN]${NC} Could not create a temp file — leaving login-name format at sssd's default (qualified)."
        return 0
    fi

    # `if ! awk ...` rather than a bare statement, so a genuine awk failure is
    # handled here instead of firing the ERR trap under set -e.
    if ! awk -v section="$section" '
        BEGIN { in_section = 0; done_uqn = 0; done_home = 0 }
        function flush_missing() {
            if (!done_uqn)  print "use_fully_qualified_names = False"
            if (!done_home) print "fallback_homedir = /home/%u"
        }
        {
            line = $0
            sub(/[ \t]+$/, "", line)
            if (line == section) { in_section = 1; print; next }
            if (in_section && /^\[/ && line != section) { flush_missing(); in_section = 0 }
            if (in_section && $0 ~ /^[ \t]*use_fully_qualified_names[ \t]*=/) { print "use_fully_qualified_names = False"; done_uqn = 1; next }
            if (in_section && $0 ~ /^[ \t]*fallback_homedir[ \t]*=/)          { print "fallback_homedir = /home/%u"; done_home = 1; next }
            print
        }
        END { if (in_section) flush_missing() }
    ' "$sssd_conf" > "$tmp"; then
        echo -e "  ${YELLOW}[WARN]${NC} sssd.conf rewrite failed — leaving login-name format at sssd's default (qualified)."
        rm -f "$tmp" "$backup"
        return 0
    fi

    if [[ ! -s "$tmp" ]]; then
        echo -e "  ${YELLOW}[WARN]${NC} sssd.conf rewrite produced an empty file — refusing to install it. Login-name format left at sssd's default (qualified)."
        rm -f "$tmp" "$backup"
        return 0
    fi

    chmod 600 "$tmp"
    chown root:root "$tmp" 2>/dev/null || true
    local staged="${sssd_conf}.tubss-new"
    if ! (cp -a "$tmp" "$staged" 2>/dev/null && mv -f "$staged" "$sssd_conf" 2>/dev/null); then
        echo -e "  ${YELLOW}[WARN]${NC} Could not install updated ${sssd_conf} — login-name format left at sssd's default (qualified)."
        rm -f "$tmp" "$staged" "$backup" 2>/dev/null
        return 0
    fi
    rm -f "$tmp"

    # Verify the key actually landed before claiming success — a section
    # match that silently failed (e.g. due to a formatting quirk this awk
    # doesn't handle) would otherwise rewrite the file unchanged, restart
    # sssd for no reason, and still print [OK].
    if ! grep -qE '^[ \t]*use_fully_qualified_names[ \t]*=[ \t]*False' "$sssd_conf"; then
        echo -e "  ${YELLOW}[WARN]${NC} sssd.conf was rewritten but use_fully_qualified_names = False is not present afterward — restoring backup. Login-name format left at sssd's default (qualified)."
        cp -a "$backup" "$sssd_conf" || echo -e "  ${RED}[ERROR]${NC} Could not restore ${backup} to ${sssd_conf} — check it by hand: sudo cp -a ${backup} ${sssd_conf}"
        rm -f "$backup"
        return 0
    fi

    if systemctl restart sssd > /dev/null 2>&1; then
        echo -e "  ${GREEN}[OK]${NC} sssd configured for bare-username logins (no @${domain} suffix needed) and restarted."
        rm -f "$backup"
        return 0
    fi
    echo -e "  ${YELLOW}[WARN]${NC} Updated ${sssd_conf} but 'systemctl restart sssd' failed — restoring backup and retrying restart so sssd isn't left down."
    cp -a "$backup" "$sssd_conf" || echo -e "  ${RED}[ERROR]${NC} Could not restore ${backup} to ${sssd_conf} — check it by hand: sudo cp -a ${backup} ${sssd_conf}"
    if systemctl restart sssd > /dev/null 2>&1; then
        echo -e "  ${YELLOW}[WARN]${NC} sssd restarted on the restored (pre-change) config — login-name format left at sssd's default (qualified)."
    else
        echo -e "  ${RED}[ERROR]${NC} sssd would not restart even on the restored config — check: systemctl status sssd ; journalctl -u sssd -n 50"
    fi
    rm -f "$backup"
    return 0
}

# Grant sudo to the domain accounts the operator asked for. Warn-and-continue:
# a joined box with no domain sudo is still a joined box, and the local admin
# account is untouched either way.
#
# Group names containing a space must be BACKSLASH-escaped in sudoers
# ("%domain\ admins"). The double-quoted form ('%"domain admins"') is rejected
# by visudo as an empty group. sssd's AD provider is case-insensitive by
# default for a single-domain join, so the lowercase spelling matches AD's
# "Domain Admins". Always returns 0.
install_ad_sudoers() {
    local -a granted=()

    # Idempotency: a re-run answering "no" must actually revoke an earlier
    # grant, not just skip reinstalling it. These two files are the only state
    # this feature owns, so remove whichever no longer applies first.
    if [[ ! "${AD_GRANT_ADMINS_SUDO:-no}" =~ ^([yY][eE][sS]|[yY])$ ]] && [[ -e /etc/sudoers.d/tubss-ad-admins ]]; then
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo "[DRY-RUN] rm -f /etc/sudoers.d/tubss-ad-admins"
        else
            rm -f /etc/sudoers.d/tubss-ad-admins
            echo -e "  ${YELLOW}[OK]${NC} Removed stale /etc/sudoers.d/tubss-ad-admins (Domain Admins sudo not requested this run)."
        fi
    fi
    if [[ -z "${AD_SUDO_EXTRA_USER:-}" ]] && [[ -e /etc/sudoers.d/tubss-ad-extra-sudo ]]; then
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo "[DRY-RUN] rm -f /etc/sudoers.d/tubss-ad-extra-sudo"
        else
            rm -f /etc/sudoers.d/tubss-ad-extra-sudo
            echo -e "  ${YELLOW}[OK]${NC} Removed stale /etc/sudoers.d/tubss-ad-extra-sudo (no extra user requested this run)."
        fi
    fi

    if [[ "${AD_GRANT_ADMINS_SUDO:-no}" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if _install_sudoers_file "/etc/sudoers.d/tubss-ad-admins" '%domain\ admins ALL=(ALL:ALL) ALL'; then
            granted+=("Domain Admins")
        fi
    fi

    if [[ -n "${AD_SUDO_EXTRA_USER:-}" ]]; then
        # Validated here too, for a specific message instead of the generic
        # refusal. Uses _is_safe_sudo_username, not the more permissive
        # _is_safe_ad_identifier: this becomes a sudoers User_List, where the
        # bare word "ALL" would mean every account.
        if ! _is_safe_sudo_username "$AD_SUDO_EXTRA_USER"; then
            echo -e "  ${RED}[ERROR]${NC} AD_SUDO_EXTRA_USER ('${AD_SUDO_EXTRA_USER}') is not a safe single username (unsafe characters, a space, or the reserved word 'ALL') — sudo grant skipped."
        elif _install_sudoers_file "/etc/sudoers.d/tubss-ad-extra-sudo" "${AD_SUDO_EXTRA_USER} ALL=(ALL:ALL) ALL"; then
            granted+=("${AD_SUDO_EXTRA_USER}")
        fi
    fi

    if (( ${#granted[@]} > 0 )); then
        AD_SUDO_STATUS=$(IFS=,; echo "${granted[*]}")
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            AD_SUDO_STATUS="${AD_SUDO_STATUS} (dry-run)"
        else
            # _install_sudoers_file logs the file path and mode; this is the
            # plain-language answer to "can I sudo now".
            local who
            for who in "${granted[@]}"; do
                echo -e "  ${GREEN}[OK]${NC} '${who}' can now use sudo on this machine."
            done
        fi
    elif [[ "${AD_GRANT_ADMINS_SUDO:-no}" =~ ^([yY][eE][sS]|[yY])$ ]] || [[ -n "${AD_SUDO_EXTRA_USER:-}" ]]; then
        AD_SUDO_STATUS="Failed (none installed)"
    else
        AD_SUDO_STATUS="none"
    fi
    return 0
}

# --- AD Domain Join ---
#
# Credential handling rules — do not relax:
#   * AD_PASSWORD reaches `realm` on stdin ONLY. Never in argv (world-readable
#     via `ps`), never exported (world-readable via /proc/<pid>/environ).
#   * No `set -x` in or anywhere near this function.
#   * realm's own output is captured, never streamed, and is redacted before
#     printing — everything printed here goes through the tee'd log.
#
# Failure policy matches the apt-upgrade step: warn and continue, never abort.
# A hardened box that failed its domain join beats an aborted run that
# configured nothing. The outcome lands in AD_JOIN_STATUS.
#
# Always returns 0 so the ERR trap never fires on a join failure.
perform_realm_join() {
    local domain="${AD_DOMAIN:-}"
    local user="${AD_USER:-}"
    local realm_output=""

    if [[ -z "$domain" || -z "$user" || -z "${AD_PASSWORD:-}" ]]; then
        AD_JOIN_STATUS="Failed (incomplete credentials)"
        echo -e "${RED}[ERROR]${NC} Domain, username or password is empty — skipping AD join."
        return 0
    fi

    # Validated here too — the actual trust boundary, since these may have been
    # pre-seeded rather than prompted. A value starting with '-' would
    # otherwise reach `realm discover`/`realm join` as a flag.
    if ! _is_safe_ad_identifier "$domain" || ! _is_safe_ad_identifier "$user"; then
        AD_JOIN_STATUS="Failed (invalid domain or username)"
        echo -e "${RED}[ERROR]${NC} AD_DOMAIN or AD_USER contains characters that are not safe to pass to 'realm' — skipping AD join."
        return 0
    fi

    if [[ ${TUBSS_DRY_RUN:-0} -ne 1 ]] && ! command -v realm > /dev/null 2>&1; then
        AD_JOIN_STATUS="Failed (realmd missing)"
        echo -e "${RED}[ERROR]${NC} 'realm' command not found — the realmd install did not succeed."
        echo -e "${RED}[ERROR]${NC} Skipping AD join. Install with: sudo apt-get install realmd sssd adcli"
        return 0
    fi

    # Clock preflight — must run before discovery/join so chrony has as much
    # of the run as possible to converge. Never blocks the join.
    ensure_time_sync

    # Discovery proves DNS SRV records resolve and the DCs are reachable before
    # touching the existing join. Must run before the leave below: leaving first
    # and then finding the new domain unreachable strands the box joined to neither.
    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] realm discover ${domain}"
    elif realm discover "$domain" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[OK]${NC} Domain '${domain}' discovered."
    else
        AD_JOIN_STATUS="Failed (discovery)"
        echo -e "${YELLOW}[WARN]${NC} Could not discover domain '${domain}' — DNS or network unreachable."
        echo -e "${YELLOW}[WARN]${NC} Skipping the join. Investigate with: sudo realm discover ${domain}"
        # The join deliberately runs before configure_network, so a new DNS
        # server chosen in this same run isn't live yet and discovery can fail
        # for a reason that resolves itself on reboot. Say so rather than let
        # the operator debug a non-problem. Static-DNS runs only.
        if [[ "${NET_TYPE:-}" == "static" && -n "${DNS_SERVER:-}" ]]; then
            echo -e "${YELLOW}[NOTE]${NC} This run is also changing this host's network/DNS configuration (new DNS server: ${DNS_SERVER})."
            echo -e "${YELLOW}[NOTE]${NC} That change is applied AFTER this join attempt and is not live until 'netplan try' succeeds or the box reboots."
            echo -e "${YELLOW}[NOTE]${NC} If ${DNS_SERVER} is the resolver for '${domain}', this discovery failure is expected."
            echo -e "${YELLOW}[NOTE]${NC} Retry manually after the reboot with: sudo realm join --user=${user} ${domain}"
        fi
        return 0
    fi

    # Leave the current realm only once the new domain is confirmed reachable.
    # This is a LOCAL leave: credentials for the OLD domain were never
    # collected, so the stale computer object has to be deleted in AD by hand.
    if [[ "${ORIGINAL_DOMAIN_STATUS:-Not Joined}" != "Not Joined" ]]; then
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo "[DRY-RUN] realm leave ${ORIGINAL_DOMAIN_STATUS}"
        elif realm leave "$ORIGINAL_DOMAIN_STATUS" > /dev/null 2>&1; then
            echo -e "  ${GREEN}[OK]${NC} Left domain '${ORIGINAL_DOMAIN_STATUS}'."
            echo -e "  ${YELLOW}[NOTE]${NC} The computer object still exists in '${ORIGINAL_DOMAIN_STATUS}' — remove it in AD."
        else
            echo -e "  ${YELLOW}[WARN]${NC} Could not leave '${ORIGINAL_DOMAIN_STATUS}' — attempting the join anyway."
        fi
    fi

    if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
        echo "[DRY-RUN] realm join --user=${user} ${domain} (password supplied on stdin)"
        echo "[DRY-RUN] pam-auth-update --enable mkhomedir"
        if [[ "${AD_BARE_USERNAMES:-yes}" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            echo "[DRY-RUN] set use_fully_qualified_names = False, fallback_homedir = /home/%u in /etc/sssd/sssd.conf"
            echo "[DRY-RUN] systemctl restart sssd"
        else
            echo "[DRY-RUN] bare-username logins not requested — sssd left at its own default (qualified)"
        fi
        AD_JOIN_STATUS="Joined (dry-run)"
        apply_realm_permit
        install_ad_sudoers
        # Not "pending" — the generic pending-backfill further down would
        # otherwise turn this into "Not checked (join failed)", which is
        # false: the join didn't fail, it just never really ran.
        AD_IDENTITY_STATUS="Skipped (dry-run)"
        return 0
    fi

    # The trailing newline matters: several adcli/realm builds read the
    # password with a line-oriented read and block on a bare, unterminated
    # string when stdin is not a tty.
    if realm_output=$(printf '%s\n' "$AD_PASSWORD" \
            | realm join --user="$user" "$domain" 2>&1); then
        AD_JOIN_STATUS="Joined (${domain})"
        echo -e "${GREEN}[OK]${NC} Joined Active Directory domain '${domain}'."
        # sssd authenticates domain users but creates no home directory, so a
        # first login lands in a non-existent $HOME. pam-auth-update is the
        # supported non-interactive way to enable pam_mkhomedir. Warn-only.
        if pam-auth-update --enable mkhomedir > /dev/null 2>&1; then
            echo -e "  ${GREEN}[OK]${NC} Home-directory creation on first login enabled (pam_mkhomedir)."
        else
            echo -e "  ${YELLOW}[WARN]${NC} Could not enable pam_mkhomedir — domain users may log in without a home directory."
            echo -e "  ${YELLOW}[WARN]${NC} Enable it manually with: sudo pam-auth-update --enable mkhomedir"
        fi
        # Bare-username logins (see _configure_sssd_login_format). Runs before
        # permit/sudoers/identity-check so they all see the final name format.
        if [[ "${AD_BARE_USERNAMES:-yes}" =~ ^([yY][eE][sS]|[yY])$ ]]; then
            _configure_sssd_login_format "$domain"
        else
            echo -e "  ${YELLOW}[SKIP]${NC} Bare-username logins not requested — leaving sssd at its own default (qualified username@domain)."
        fi
        # Who may log in, then who may sudo. Both warn-and-continue and
        # neither can downgrade AD_JOIN_STATUS — the join itself succeeded.
        apply_realm_permit
        install_ad_sudoers
        # Confirm the join account resolves via NSS, plus any named sudo user
        # (that box is usually being set up for that person). The join account
        # drives AD_IDENTITY_STATUS because it just authenticated successfully,
        # so an NSS miss is unambiguously a broken chain rather than a
        # nonexistent account. Louder than a [WARN] since AD_JOIN_STATUS would
        # still read "Joined" while nobody can actually use the box.
        if _verify_ad_identity "$user" "join account" "$domain"; then
            AD_IDENTITY_STATUS="Verified"
        else
            AD_IDENTITY_STATUS="Failed (NSS not resolving despite Joined)"
            echo -e "  ${RED}[ERROR]${NC} realm join reported success, but NSS could not resolve the join account."
            echo -e "  ${RED}[ERROR]${NC} This usually means domain logins will NOT work despite 'Joined' above."
            echo -e "  ${RED}[ERROR]${NC} Check: systemctl status sssd ; journalctl -u sssd -n 50 ; getent passwd ${user}"
        fi
        # Comma-delimited exact match: AD_SUDO_STATUS is a comma-joined list,
        # and a bare substring test would false-positive on usernames contained
        # in "Domain Admins" or in a failure string.
        if [[ -n "${AD_SUDO_EXTRA_USER:-}" ]] && [[ ",${AD_SUDO_STATUS}," == *",${AD_SUDO_EXTRA_USER},"* ]]; then
            # Guarded: _verify_ad_identity legitimately returns 1 right after a
            # join while sssd is still warming up, which must not abort the run.
            _verify_ad_identity "$AD_SUDO_EXTRA_USER" "sudo user" "$domain" || true
        fi
    else
        AD_JOIN_STATUS="Failed (see error above)"
        echo -e "${RED}[ERROR]${NC} Failed to join '${domain}' — continuing with TUBSS hardening."
        # Redact the credential before logging realmd's diagnostics. AD_PASSWORD
        # is quoted inside the pattern so glob metacharacters in the password
        # match literally; unquoted, a password containing "[" would leak.
        printf '%s\n' "${realm_output//"$AD_PASSWORD"/[REDACTED]}"
        echo -e "${RED}[ERROR]${NC} Retry manually with: sudo realm join --user=${user} ${domain}"
    fi
    return 0
}

join_ad_domain() {
    if [[ "$JOIN_DOMAIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}[TUBSS] Joining Active Directory domain...${NC}"
        perform_realm_join
        # Credential hygiene — fires on every outcome (joined, failed, aborted).
        unset -v AD_PASSWORD AD_DOMAIN AD_USER 2>/dev/null || true
    else
        AD_JOIN_STATUS="Skipped"
        AD_PERMIT_STATUS="Skipped"
        AD_SUDO_STATUS="Skipped"
        AD_IDENTITY_STATUS="Skipped"
        echo -e "${YELLOW}[SKIPPED]${NC} AD domain join."
    fi
    # A join that never reached the permit/sudo/identity steps configured none
    # of them — say so rather than leave the summary showing the intent.
    if [[ "$AD_PERMIT_STATUS" == "pending" ]]; then
        AD_PERMIT_STATUS="Not applied (join failed)"
    fi
    if [[ "$AD_SUDO_STATUS" == "pending" ]]; then
        AD_SUDO_STATUS="Not applied (join failed)"
    fi
    if [[ "$AD_IDENTITY_STATUS" == "pending" ]]; then
        AD_IDENTITY_STATUS="Not checked (join failed)"
    fi
    NEW_DOMAIN_SUMMARY="$AD_JOIN_STATUS"
}

# --- Step 5: Final Summary and Reboot Prompt ---
reboot_prompt() {
    # With netplan apply deferred, mark the state file "pending_reboot" rather
    # than "completed" so the next run knows the box isn't in the declared state.
    if (( NETPLAN_APPLY_PENDING == 1 )); then
        finalize_run_state "pending_reboot"
    else
        finalize_run_state
    fi
    echo ""
    echo -e "${YELLOW}Configuration changes have been applied.${NC}"
    echo "A summary of the changes has been saved to: $SUMMARY_FILE"
    echo "--------------------------------------------------------"
    echo ""

    # Write summary to file
    # Reuses display_config_summary() rather than a second hand-maintained copy
    # of the same rows, which had drifted. Colors are blanked for this call
    # only (subshell) since ANSI codes don't belong in a plain text file.
    cat << EOF > "$SUMMARY_FILE"
TUBSS - The Ubuntu/Debian Basic Setup Script - Configuration Summary
Provided by Joka.ca

Date: $(date)
Hostname: $HOSTNAME

Configuration Changes:
$(YELLOW='' NC='' display_config_summary)
Script provided by Joka.ca
EOF

    echo ""
    echo -e "${GREEN}[OK]${NC} A summary of the configuration changes has been saved to:"
    echo -e "${GREEN}      $SUMMARY_FILE${NC}"
    echo ""

    # Display summary table using shared function
    echo -e "$SUMMARY_ART"
    display_config_summary

    # Consolidated end-of-run issue summary. Only the warn-and-continue steps
    # (package upgrade, the AD sub-steps, SSH hardening) can reach here with a
    # problem — everything else is fatal under `set -e`. Requires acknowledgment
    # interactively so it can't scroll past unnoticed.
    local -a _run_issues=()
    [[ "$PACKAGE_UPDATES_STATUS" == Partial* ]] && _run_issues+=("Package Updates: ${PACKAGE_UPDATES_STATUS}")
    [[ "$AD_JOIN_STATUS" == Failed* ]] && _run_issues+=("AD Domain Join: ${AD_JOIN_STATUS}")
    [[ "$AD_PERMIT_STATUS" == Failed* ]] && _run_issues+=("AD Login Permitted: ${AD_PERMIT_STATUS}")
    [[ "$AD_SUDO_STATUS" == Failed* ]] && _run_issues+=("AD Sudo Granted: ${AD_SUDO_STATUS}")
    [[ "$AD_IDENTITY_STATUS" == Failed* ]] && _run_issues+=("AD Identity Check: ${AD_IDENTITY_STATUS}")
    [[ "$SSH_HARDENING_STATUS" == Failed* ]] && _run_issues+=("SSH Hardening: ${SSH_HARDENING_STATUS}")
    if (( ${#_run_issues[@]} > 0 )); then
        echo ""
        echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"
        echo -e "${RED}  ${#_run_issues[@]} issue(s) need your attention (the run itself completed):${NC}"
        local _issue
        for _issue in "${_run_issues[@]}"; do
            echo -e "${RED}    - ${_issue}${NC}"
        done
        echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"
        echo "Once you've addressed these, it's safe to run TUBSS again — it checks"
        echo "current state before making changes and won't redo work already applied."
        if [[ ${TUBSS_UNATTENDED:-0} -ne 1 ]]; then
            prompt REPLY "Press Enter to acknowledge and continue..."
        fi
    fi

    # Final Prompt
    echo ""
    echo -e "$CLOSING_ART"

    # A deferred netplan try/apply makes the reboot mandatory to pick up the
    # static config. Warn loudly; declining is allowed but flagged.
    if (( NETPLAN_APPLY_PENDING == 1 )); then
        echo -e "${RED}!! A REBOOT IS REQUIRED !!${NC}"
        echo -e "${YELLOW}TUBSS could not apply the new network configuration live (netplan try/apply deferred).${NC}"
        echo -e "${YELLOW}Until you reboot, this host will keep using its previous DHCP/static settings.${NC}"
    fi

    if (( TUBSS_UNATTENDED == 1 )); then
        if (( TUBSS_DRY_RUN == 1 )); then
            echo -e "${YELLOW}[DRY-RUN]${NC} Skipping reboot in dry-run mode."
        elif (( ${TUBSS_SKIP_REBOOT:-0} == 1 )); then
            echo -e "${YELLOW}[TUBSS]${NC} TUBSS_SKIP_REBOOT=1 — skipping reboot (test mode)"
        else
            echo -e "${YELLOW}Rebooting the system now (unattended) to apply all changes.${NC}"
            reboot
        fi
        return
    fi

    prompt REBOOT_PROMPT "Configuration is complete. Would you like to reboot the system now? (yes/no) [yes]: "
    REBOOT_PROMPT=${REBOOT_PROMPT:-yes}

    if [[ "$REBOOT_PROMPT" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo -e "${YELLOW}[DRY-RUN]${NC} Would reboot — skipping in dry-run mode."
        else
            echo -e "${YELLOW}Rebooting the system now to apply all changes.${NC}"
            reboot
        fi
    else
        if (( NETPLAN_APPLY_PENDING == 1 )); then
            echo -e "${RED}[WARN]${NC} Reboot skipped — static network config is NOT active yet. Reboot ASAP."
        else
            echo -e "${YELLOW}Reboot has been skipped. Please reboot the system manually for all changes to take effect.${NC}"
        fi
    fi
}

# --- Feature 4: Rollback UI ---
run_rollback_ui() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} Rollback requires root. Run with sudo."
        exit 1
    fi

    echo ""
    echo -e "${YELLOW}+---------------------------------------------+${NC}"
    echo -e "${YELLOW}|    T U B S S  —  Rollback / Restore        |${NC}"
    echo -e "${YELLOW}+---------------------------------------------+${NC}"
    echo -e "${YELLOW}|    Snapshot-Based System Recovery           |${NC}"
    echo -e "${YELLOW}+---------------------------------------------+${NC}"
    echo ""

    local has_timeshift=0
    local has_zfs=0
    local has_btrfs=0

    command -v timeshift > /dev/null 2>&1 && has_timeshift=1 || true
    command -v zfs      > /dev/null 2>&1 && has_zfs=1      || true
    command -v btrfs    > /dev/null 2>&1 && has_btrfs=1    || true

    # Collect snapshots
    local -a snap_names=()
    local -a snap_backends=()

    if (( has_timeshift )); then
        echo -e "${YELLOW}[INFO]${NC} Scanning Timeshift snapshots..."
        while IFS= read -r line; do
            local snap_name
            snap_name=$(echo "$line" | awk '{print $3}')
            if [[ -n "$snap_name" ]]; then
                snap_names+=("$snap_name")
                snap_backends+=("timeshift")
            fi
        done < <(timeshift --list 2>/dev/null | grep -i tubss || true)
    fi

    if (( has_zfs )); then
        echo -e "${YELLOW}[INFO]${NC} Scanning ZFS snapshots..."
        while IFS= read -r line; do
            local snap_name
            snap_name=$(echo "$line" | awk '{print $1}')
            if [[ -n "$snap_name" ]]; then
                snap_names+=("$snap_name")
                snap_backends+=("zfs")
            fi
        done < <(zfs list -t snapshot 2>/dev/null | grep -i tubss || true)
    fi

    if (( has_btrfs )); then
        echo -e "${YELLOW}[INFO]${NC} Scanning Btrfs subvolumes..."
        while IFS= read -r line; do
            local snap_name
            snap_name=$(echo "$line" | awk '{print $NF}')
            if [[ -n "$snap_name" ]]; then
                snap_names+=("$snap_name")
                snap_backends+=("btrfs")
            fi
        done < <(btrfs subvolume list / 2>/dev/null | grep -i tubss || true)
    fi

    if (( ${#snap_names[@]} == 0 )); then
        echo ""
        echo -e "${YELLOW}[INFO]${NC} No TUBSS-tagged snapshots found on this system."
        echo -e "       Create a snapshot during setup by answering 'yes' to the snapshot prompt."
        echo ""
        return 0
    fi

    # Display numbered list
    echo ""
    echo -e "${YELLOW}Available TUBSS snapshots:${NC}"
    local i
    for (( i=0; i<${#snap_names[@]}; i++ )); do
        printf "  [%d] %-50s  (backend: %s)\n" "$(( i+1 ))" "${snap_names[$i]}" "${snap_backends[$i]}"
    done
    echo ""

    # Prompt user to select
    local selection
    while true; do
        prompt selection "Select a snapshot to restore (1-${#snap_names[@]}, or 0 to cancel): "
        if [[ "$selection" == "0" ]]; then
            echo -e "${YELLOW}Rollback cancelled.${NC}"
            return 0
        fi
        if [[ "$selection" =~ ^[0-9]+$ ]] && (( selection >= 1 && selection <= ${#snap_names[@]} )); then
            break
        else
            echo -e "${RED}Invalid selection. Enter a number between 1 and ${#snap_names[@]}, or 0 to cancel.${NC}"
        fi
    done

    local chosen_name="${snap_names[$(( selection - 1 ))]}"
    local chosen_backend="${snap_backends[$(( selection - 1 ))]}"

    echo ""
    prompt confirm_restore "Restore to '${chosen_name}'? This cannot be undone. (yes/no) [no]: "
    confirm_restore=${confirm_restore:-no}
    confirm_restore=$(echo "$confirm_restore" | tr '[:upper:]' '[:lower:]')

    if [[ ! "$confirm_restore" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}Rollback cancelled.${NC}"
        return 0
    fi

    echo ""
    case "$chosen_backend" in
        timeshift)
            echo -e "${YELLOW}[INFO]${NC} Restoring Timeshift snapshot: ${chosen_name}"
            timeshift --restore --snapshot "${chosen_name}" --yes
            echo -e "${GREEN}[OK]${NC} Timeshift restore initiated. A system reboot is required."
            ;;
        zfs)
            echo -e "${YELLOW}[INFO]${NC} Checking for intermediate ZFS snapshots..."
            local dataset intermediate_count
            dataset=$(echo "$chosen_name" | cut -d@ -f1)
            # Count snapshots created after the chosen one on the same dataset
            intermediate_count=$(zfs list -t snapshot -H -o name "$dataset" 2>/dev/null \
                | awk -v target="$chosen_name" 'found{count++} $0==target{found=1} END{print count+0}' || echo "0")

            if (( intermediate_count > 0 )); then
                echo -e "${YELLOW}[WARN]${NC} ${intermediate_count} snapshot(s) exist after '${chosen_name}'."
                echo -e "${YELLOW}       ZFS rollback requires destroying intermediate snapshots.${NC}"
                echo -e "${YELLOW}       To proceed manually, run:${NC}"
                echo -e "         sudo zfs rollback -r ${chosen_name}"
                echo -e "${YELLOW}       WARNING: -r will destroy all snapshots newer than the target.${NC}"
            else
                echo -e "${YELLOW}[INFO]${NC} No intermediate snapshots detected. Proceeding with rollback..."
                zfs rollback "${chosen_name}"
                echo -e "${GREEN}[OK]${NC} ZFS rollback complete. A system reboot is required."
            fi
            ;;
        btrfs)
            echo -e "${YELLOW}[WARN]${NC} Btrfs live rollback is not executed automatically due to the risk of data loss."
            echo -e "${YELLOW}       To restore manually, boot from a live environment and run:${NC}"
            echo ""
            echo -e "         # Mount the Btrfs volume"
            echo -e "         sudo mount /dev/sdXY /mnt"
            echo -e ""
            echo -e "         # Move the current root subvolume aside"
            echo -e "         sudo mv /mnt/@ /mnt/@.broken"
            echo -e ""
            echo -e "         # Create a read-write snapshot from the TUBSS snapshot"
            echo -e "         sudo btrfs subvolume snapshot /mnt/@snapshots/${chosen_name} /mnt/@"
            echo -e ""
            echo -e "         # Unmount and reboot"
            echo -e "         sudo umount /mnt && sudo reboot"
            echo ""
            echo -e "${YELLOW}[INFO]${NC} No changes have been made to your system."
            ;;
        *)
            echo -e "${RED}[ERROR]${NC} Unknown backend '${chosen_backend}'. No action taken."
            ;;
    esac

    echo ""
    echo -e "${YELLOW}[INFO]${NC} Reboot is required for the restore to take full effect."
    prompt do_reboot "Would you like to reboot the system now? (yes/no) [no]: "
    do_reboot=${do_reboot:-no}
    if [[ "$do_reboot" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if [[ ${TUBSS_DRY_RUN:-0} -eq 1 ]]; then
            echo -e "${YELLOW}[DRY-RUN]${NC} Would reboot — skipping in dry-run mode."
        else
            echo -e "${YELLOW}Rebooting...${NC}"
            reboot
        fi
    else
        echo -e "${YELLOW}Please reboot manually when ready.${NC}"
    fi
}

main "$@"
