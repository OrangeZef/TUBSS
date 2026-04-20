#!/bin/bash
set -euo pipefail

#==============================================================================
# TUBSS Launcher Script
# Downloads and executes the latest version of the TUBSS setup script from
# the official GitHub repository.
#
# Usage:
#   sudo ./tubss_launcher.sh [setup-script-flags...]
#
# Environment:
#   TUBSS_REF   — git ref to download from (branch or tag). Default: main.
#                 Example: TUBSS_REF=v2.7.1 sudo -E ./tubss_launcher.sh
#
# Examples:
#   sudo ./tubss_launcher.sh                       # interactive run
#   sudo ./tubss_launcher.sh --unattended --dry-run
#   sudo ./tubss_launcher.sh --rollback
#   TUBSS_REF=v2.7.0 sudo -E ./tubss_launcher.sh   # pin to a release tag
#==============================================================================

YELLOW='\033[1;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- Root check -----------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run with root privileges. Please use 'sudo'.${NC}" >&2
    echo -e "${YELLOW}Example: sudo ./tubss_launcher.sh${NC}" >&2
    exit 1
fi

# --- OS detection (sourced from /etc/os-release) --------------------------
# Shell-native, no grep/cut/tr pipeline. All we need is to validate that
# this is an OS TUBSS supports; the downloaded setup script does its own
# full detection.
if [[ ! -r /etc/os-release ]]; then
    echo -e "${RED}[ERROR]${NC} /etc/os-release not found — unsupported OS." >&2
    exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release

if [[ "${ID:-}" != "ubuntu" && "${ID:-}" != "debian" ]]; then
    echo -e "${RED}[ERROR]${NC} Unsupported OS: ${ID:-unknown}. TUBSS supports Ubuntu and Debian only." >&2
    exit 1
fi

# --- Welcome --------------------------------------------------------------
TUBSS_REF="${TUBSS_REF:-main}"

echo -e "${YELLOW}============================================================${NC}"
echo -e "${YELLOW}  Welcome to the TUBSS Launcher!${NC}"
echo -e "${YELLOW}  This script will download TUBSS from ref: ${TUBSS_REF}${NC}"
echo -e "${YELLOW}============================================================${NC}"
echo ""
echo -e "${GREEN}[INFO]${NC} Detected OS: ${ID} ${VERSION_ID:-unknown}"
echo ""

# --- Confirmation (reads from /dev/tty for consistency with setup script) -
if { : > /dev/tty; } 2>/dev/null; then
    printf "Proceed? [y/N]: " > /dev/tty
    read -r confirm < /dev/tty
else
    # No controlling TTY (CI, piped input) — require explicit opt-in.
    echo -e "${RED}[ERROR]${NC} No TTY detected. Re-run in an interactive terminal," >&2
    echo -e "${RED}[ERROR]${NC} or invoke tubss_setup.sh directly with --unattended." >&2
    exit 2
fi

confirm="${confirm,,}"
if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
    echo -e "${YELLOW}Aborted.${NC}"
    exit 0
fi

# --- Download -------------------------------------------------------------
echo ""
echo -e "${YELLOW}Starting download...${NC}"

BASE_URL="https://raw.githubusercontent.com/OrangeZef/TUBSS/${TUBSS_REF}"
DOWNLOAD_URL="${BASE_URL}/tubss_setup.sh"
CHECKSUM_URL="${BASE_URL}/tubss_setup.sha256"

echo -e "${GREEN}[INFO]${NC} Fetching unified TUBSS setup script from ${TUBSS_REF}"

TMPDIR_="${TMPDIR:-/tmp}"
TEMP_SCRIPT="$(mktemp "${TMPDIR_}/tubss_setup.XXXXXX.sh")"
TEMP_CHECKSUM="$(mktemp "${TMPDIR_}/tubss_checksum.XXXXXX")"
trap 'rm -f "$TEMP_SCRIPT" "$TEMP_CHECKSUM"' EXIT

if ! curl -fsSL --proto '=https' --tlsv1.2 "$DOWNLOAD_URL" -o "$TEMP_SCRIPT"; then
    echo -e "${RED}[ERROR]${NC} Failed to download TUBSS script from ${DOWNLOAD_URL}" >&2
    echo -e "${RED}[ERROR]${NC} Check network connectivity and that TUBSS_REF='${TUBSS_REF}' exists." >&2
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Download successful."

# --- Integrity check ------------------------------------------------------
if ! curl -fsSL --proto '=https' --tlsv1.2 "$CHECKSUM_URL" -o "$TEMP_CHECKSUM"; then
    echo -e "${RED}[ERROR]${NC} SHA256 checksum file missing at ${CHECKSUM_URL}" >&2
    echo -e "${RED}[ERROR]${NC} Cannot verify integrity — aborting." >&2
    exit 1
fi

echo -e "${GREEN}[INFO]${NC} Verifying script integrity..."
EXPECTED_HASH="$(awk '{print $1}' "$TEMP_CHECKSUM")"
ACTUAL_HASH="$(sha256sum "$TEMP_SCRIPT" | awk '{print $1}')"

if [[ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]]; then
    echo -e "${RED}[ERROR]${NC} Integrity check FAILED — expected ${EXPECTED_HASH}, got ${ACTUAL_HASH}" >&2
    echo -e "${RED}[ERROR]${NC} Aborting for security." >&2
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Integrity check passed."

# --- Execute --------------------------------------------------------------
echo -e "${YELLOW}Executing the TUBSS setup script now...${NC}"
bash "$TEMP_SCRIPT" "$@"
