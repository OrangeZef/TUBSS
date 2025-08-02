#!/bin/bash

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

# Define the URL for the raw script on GitHub
TUBSS_URL="https://raw.githubusercontent.com/OrangeZef/TUBSS/main/tubss_setup.sh"

# Define a temporary file path for the downloaded script
TEMP_SCRIPT="/tmp/tubss_setup_temp_$(date +%s).sh"

# --- Function to display an error and exit gracefully ---
handle_error() {
    local exit_code=$?
    echo -e "${RED}--------------------------------------------------------${NC}"
    echo -e "${RED}An error occurred. The script could not be downloaded or executed.${NC}"
    echo -e "${RED}Exit Code: ${exit_code}${NC}"
    echo -e "${RED}--------------------------------------------------------${NC}"
    # Clean up the temporary file if it exists
    if [ -f "$TEMP_SCRIPT" ]; then
        rm "$TEMP_SCRIPT"
    fi
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

# Display a friendly welcome message
echo -e "${YELLOW}============================================================${NC}"
echo -e "${YELLOW}  Welcome to the TUBSS Launcher!${NC}"
echo -e "${YELLOW}  This script will download the latest version of TUBSS.${NC}"
echo -e "${YELLOW}============================================================${NC}"
echo ""

# --- Ask for user confirmation before proceeding ---
read -p "Are you sure you want to download and run the TUBSS setup script? (yes/no) [yes]: " CONFIRM_RUN
CONFIRM_RUN=${CONFIRM_RUN:-yes}
CONFIRM_RUN=$(echo "$CONFIRM_RUN" | tr '[:upper:]' '[:lower:]')

if [[ "$CONFIRM_RUN" != "yes" ]]; then
    echo -e "${RED}Execution aborted by user.${NC}"
    exit 0
fi

echo ""
echo -e "${YELLOW}Starting download...${NC}"

# --- Download the script securely using curl ---
# The -s option makes curl silent.
# The -f option makes curl fail silently on HTTP errors (e.g., 404).
# The -S option shows an error message even with -s.
# The -L option follows redirects.
# -o specifies the output file.
if ! curl -fsSL "$TUBSS_URL" -o "$TEMP_SCRIPT"; then
    echo -e "${RED}Error: Failed to download the TUBSS script from GitHub.${NC}"
    exit 1
fi

echo -e "${GREEN}[OK]${NC} Download successful."

# --- Run the downloaded script with the current shell ---
echo -e "${YELLOW}Executing the TUBSS setup script now...${NC}"

# Use 'bash' to run the temporary script with the current user's privileges (which are root via sudo)
# Use 'exec' to replace the current process with the new script, preventing double-prompting for sudo.
if ! exec bash "$TEMP_SCRIPT"; then
    echo -e "${RED}Error: Failed to execute the TUBSS setup script.${NC}"
    exit 1
fi
