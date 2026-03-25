#!/bin/bash
set -euo pipefail

#==============================================================================
# TUBSS Launcher Script
# This script downloads and executes the latest version of the TUBSS setup script
# from the official GitHub repository.
#
# To use:
# 1. Save this file to your desktop as "tubss_launcher.sh".
# 2. Make it executable with: chmod +x ~/Desktop/tubss_launcher.sh
# 3. Run it with: sudo ~/Desktop/tubss_launcher.sh
#==============================================================================

# Define colors for the terminal
YELLOW='\033[1;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# --- Function to display an error and exit gracefully ---
handle_error() {
    local exit_code=$?
    echo -e "${RED}--------------------------------------------------------${NC}"
    echo -e "${RED}An error occurred. The script could not be downloaded or executed.${NC}"
    echo -e "${RED}Exit Code: ${exit_code}${NC}"
    echo -e "${RED}--------------------------------------------------------${NC}"
    exit 1
}

# --- Set a trap for errors to call our error handler ---
trap handle_error ERR

# --- Initial check for root privileges ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run with root privileges. Please use 'sudo'.${NC}"
    echo -e "${YELLOW}Example: sudo ./tubss_launcher.sh${NC}"
    exit 1
fi

# Detect Ubuntu version early
VERSION_ID=$(grep VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"')

# Display a friendly welcome message
echo -e "${YELLOW}============================================================${NC}"
echo -e "${YELLOW}  Welcome to the TUBSS Launcher!${NC}"
echo -e "${YELLOW}  This script will download the latest version of TUBSS.${NC}"
echo -e "${YELLOW}============================================================${NC}"
echo ""
echo -e "${GREEN}[INFO]${NC} Detected Ubuntu version: ${VERSION_ID}"
echo ""

# --- Ask for user confirmation before proceeding ---
read -rp "Proceed? [y/N]: " confirm
confirm="${confirm,,}"  # lowercase
if [[ "$confirm" != "y" && "$confirm" != "yes" ]]; then
    echo -e "${YELLOW}Aborted.${NC}"
    exit 0
fi

echo ""
echo -e "${YELLOW}Starting download...${NC}"

# Build download URL — try version-specific first, fall back to main
BASE_URL="https://raw.githubusercontent.com/OrangeZef/TUBSS/main"
VERSION_URL="${BASE_URL}/versions/${VERSION_ID}/tubss_setup.sh"
FALLBACK_URL="${BASE_URL}/tubss_setup.sh"

# Use mktemp for an unpredictable temp filename
TEMP_SCRIPT=$(mktemp /tmp/tubss_setup.XXXXXX.sh)

# Register EXIT trap to clean up temp files
trap 'rm -f "$TEMP_SCRIPT"' EXIT

# Check if version-specific script exists
if curl --silent --fail --head "$VERSION_URL" > /dev/null 2>&1; then
    DOWNLOAD_URL="$VERSION_URL"
    echo -e "${GREEN}[INFO]${NC} Found Ubuntu ${VERSION_ID}-specific setup script"
else
    DOWNLOAD_URL="$FALLBACK_URL"
    echo -e "${YELLOW}[WARN]${NC} No Ubuntu ${VERSION_ID}-specific script found, using default"
fi

# --- Download the script securely using curl ---
# The -s option makes curl silent.
# The -f option makes curl fail silently on HTTP errors (e.g., 404).
# The -S option shows an error message even with -s.
# The -L option follows redirects.
# -o specifies the output file.
if ! curl -fsSL "$DOWNLOAD_URL" -o "$TEMP_SCRIPT"; then
    echo -e "${RED}Error: Failed to download the TUBSS script from GitHub.${NC}"
    exit 1
fi

echo -e "${GREEN}[OK]${NC} Download successful."

# --- Download SHA256 checksum and verify if available ---
CHECKSUM_URL="${DOWNLOAD_URL%.sh}.sha256"
TEMP_CHECKSUM=$(mktemp /tmp/tubss_checksum.XXXXXX)

curl --silent --fail "$CHECKSUM_URL" -o "$TEMP_CHECKSUM" 2>/dev/null || true
if [[ ! -s "$TEMP_CHECKSUM" ]]; then
    echo -e "${RED}[ERROR] SHA256 checksum file not found at remote. Cannot verify integrity. Aborting.${NC}"
    rm -f "$TEMP_SCRIPT" "$TEMP_CHECKSUM"
    exit 1
fi
echo -e "${GREEN}[INFO]${NC} Verifying script integrity..."
EXPECTED_HASH=$(awk '{print $1}' "$TEMP_CHECKSUM")
ACTUAL_HASH=$(sha256sum "$TEMP_SCRIPT" | awk '{print $1}')
if [[ "$EXPECTED_HASH" == "$ACTUAL_HASH" ]]; then
    echo -e "${GREEN}[OK]${NC} Integrity check passed"
else
    echo -e "${RED}[ERROR]${NC} Integrity check FAILED — aborting for security"
    rm -f "$TEMP_SCRIPT" "$TEMP_CHECKSUM"
    exit 1
fi
rm -f "$TEMP_CHECKSUM"

# --- Run the downloaded script with the current shell ---
echo -e "${YELLOW}Executing the TUBSS setup script now...${NC}"

if [[ "${1:-}" == "--rollback" ]]; then
    bash "$TEMP_SCRIPT" --rollback
else
    bash "$TEMP_SCRIPT"
fi
exit $?
