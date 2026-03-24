#!/bin/bash

#==============================================================================
# The Ubuntu Basic Setup Script (TUBSS)
# Version: 2.4 (Pre-flight validation, custom UFW rules, post-apply
#               connectivity test, rollback UI)
# Author: OrangeZef
#
# This script automates the initial setup and hardening of a new Ubuntu server.
#
# Changelog:
# - [v2.2] Integrated all code review recommendations.
# - [v2.2] Added "strict mode" (set -euo pipefail) for improved script robustness.
# - [v2.2] Spinner function now uses a more reliable process check (kill -0).
# - [v2.2] User detection prefers $SUDO_USER for better reliability.
# - [v2.2] Added an explicit warning for risky static IP configuration.
# - [v2.2] Fixed a bug where Webmin installation would fail by adding its repository.
# - [v2.2] Hardened all "yes/no" prompts to be more flexible.
# - [v2.2] Improved disk usage retrieval logic to prevent "df" errors with strict mode.
# - [v2.2] Corrected Btrfs filesystem detection to prevent "df: no file systems processed" error.
# - [v2.2] Addressed an issue where Fail2ban configuration would fail on line 731 by using a more reliable `systemctl` command.
# - [v2.3] Spinner now captures and reports background job exit codes (fail-fast).
# - [v2.3] Fixed configure_ufw called BEFORE configure_fail2ban (banaction=ufw requires UFW active first).
# - [v2.3] Added idempotency checks — hostname, UFW, fail2ban, auto-updates, telemetry, netplan, packages.
# - [v2.3] Added netplan generate validation before netplan apply to prevent network lockout.
# - [v2.3] Added Ubuntu version check at startup with supported version list.
# - [v2.3] handle_error() now explicitly calls exit 1.
# - [v2.3] Converted packages_to_install from string to bash array.
# - [v2.3] Extracted display_config_summary() to eliminate DRY violation between show_summary_and_confirm() and reboot_prompt().
# - [v2.3] Fixed logname fallback: uses ${SUDO_USER:-${USER:-root}} to avoid logname failure in non-TTY contexts.
# - [v2.3] Added `unset AD_PASSWORD` at end of join_ad_domain() for credential hygiene.
# - [v2.4] Added run_preflight() with disk, OS version, package server, and apt state checks.
# - [v2.4] Added collect_custom_ufw_rules() and apply_custom_ufw_rules() for user-defined firewall rules.
# - [v2.4] Added test_static_ip_connectivity() for post-apply network validation.
# - [v2.4] Added run_rollback_ui() and --rollback flag for snapshot-based system recovery.
# - [v2.5] Added run-state persistence (init/update/mark/finalize) with display at preflight.
# - [v2.5] Fixed DHCP restore path — restore_dhcp_config() restores backup or writes minimal fallback.
# - [v2.5] Added second-run skip warning for static netplan config.
# - [v2.5] Added disable_cloud_init_network() to prevent cloud-init from overwriting managed netplan.
# - [v2.5] Timestamped backup subdirectory for netplan conflict backups.
# - [v2.5] Replaced test_static_ip_connectivity() with warn_if_gateway_unreachable() pre-write check.
#
# Provided by Joka.ca
#==============================================================================

# --- Strict Mode ---
# set -e: Exit immediately if a command exits with a non-zero status.
# set -u: Treat unset variables as an error.
# set -o pipefail: The return value of a pipeline is the status of the last command to exit with a non-zero status.
set -euo pipefail

# --- Global Variables & Colors ---
YELLOW='\033[1;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Define ANSI art for headers
BANNER_ART="
+---------------------------------------------+
|    T U B S S                                |
+---------------------------------------------+
|    The Ubuntu Basic Setup Script            |
|    Version 2.5                              |
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
 __________________________________________________________________
< Thank you for using TUBSS - The Ubuntu Basic Setup Script! >
 ------------------------------------------------------------------
          \
           \    .--.
            \  ( o  o)
             >  )  (
           /    '--'
          (____)__
            /  /
           /  /
         /  /
       /\\_//\\
      (oo) (oo)
      / |  | \\
     |  |  |  |
     \\_/_ \\_/_/
        \_/
"

# --- Global Summary Variables (for DRY principle) ---
NEW_WEBMIN_SUMMARY=""
NEW_UFW_SUMMARY=""
NEW_AUTO_UPDATES_SUMMARY=""
NEW_FAIL2BAN_SUMMARY=""
NEW_TELEMETRY_SUMMARY=""
NEW_DOMAIN_SUMMARY=""
NEW_NFS_SUMMARY=""
NEW_SMB_SUMMARY=""
NEW_GIT_SUMMARY=""
NEW_IP_ADDRESS_SUMMARY=""
NEW_GATEWAY_SUMMARY=""
NEW_DNS_SUMMARY=""

# --- Custom UFW rules array ---
# Elements: "port|protocol|direction|description"
# Port ranges use hyphen: "5000-5010|tcp|allow|Dev range"
CUSTOM_UFW_RULES=()

# --- Pre-flight state ---
PREFLIGHT_FAILED=0

# --- Package installation state (used by cleanup guard) ---
PACKAGES_INSTALLED=0

# --- Version detection globals (set by run_preflight, read by run_prereqs) ---
DETECTED_VERSION=""
SUPPORTED_VERSIONS=("20.04" "22.04" "24.04")

# --- Network globals (safe defaults to avoid unbound variable under set -u) ---
ORIGINAL_IP=""

# --- Run-state persistence ---
TUBSS_SCRIPT_VERSION="2.5"
TUBSS_STATE_DIR="/var/lib/tubss"
TUBSS_STATE_FILE="/var/lib/tubss/last_run"
CURRENT_STEP=""
DHCP_RESTORE_FILE=""


# --- Utility Functions ---

# Function to handle errors and exit gracefully
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
    exit 1
}

# Function to display a simple progress spinner with task name
spinner() {
    local pid=$1
    local task_name=$2
    local delay=0.1
    local spinstr='|/-\'
    echo -ne "${YELLOW}[TUBSS] ${task_name} ... ${NC}"
    # Use kill -0 for a more robust check
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf "\b${spinstr:0:1}"
        spinstr=$temp${spinstr:0:1}
        sleep $delay
    done
    printf "\b \n"
}

# Function to convert CIDR prefix to a dotted-decimal subnet mask
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

# Cleanup function to be executed on script exit
cleanup() {
    echo ""
    echo -e "${YELLOW}============================================================${NC}"
    echo -e "${YELLOW}                  Final Cleanup and Exit${NC}"
    echo -e "${YELLOW}============================================================${NC}"
    if (( PACKAGES_INSTALLED == 1 )); then
        apt-get autoremove -y > /dev/null 2>&1 &
        bg_pid=$!
        spinner $bg_pid "Removing unused packages"
        wait $bg_pid || { echo -e "\n${RED}[ERROR]${NC} Removing unused packages failed (exit $?)"; exit 1; }
    fi
    echo -e "${GREEN}[OK]${NC} Cleanup complete."
    # Revert terminal colors
    echo -e "${NC}\033[0m"
}

# --- Set traps for error handling and cleanup ---
# Trap the ERR signal to call our handle_error function
trap 'handle_error' ERR
# Trap the EXIT signal to call our cleanup function
trap 'cleanup' EXIT

# --- Main script starts here ---

# Check for root privileges
main() {
    # Intercept --rollback before anything else
    if [[ "${1:-}" == "--rollback" ]]; then
        run_rollback_ui
        exit 0
    fi

    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run with root privileges. Please use sudo.${NC}"
        exit 1
    fi

    # Change terminal colors
    echo -e "${NC}" # Reset first
    clear

    # Display banner art and system info
    echo -e "$BANNER_ART"
    echo -e "--------------------------------------------------------"

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

    # Check 2: Ubuntu version supported — warn only (duplicate check removed from run_prereqs)
    DETECTED_VERSION=$(grep VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"')
    if [[ ! " ${SUPPORTED_VERSIONS[*]} " =~ " ${DETECTED_VERSION} " ]]; then
        echo -e "${YELLOW}[PREFLIGHT] [WARN]${NC} Ubuntu ${DETECTED_VERSION} is not officially supported. Tested versions: ${SUPPORTED_VERSIONS[*]}"
        echo -e "${YELLOW}[PREFLIGHT] [WARN]${NC} Proceeding anyway — some features may not work correctly."
    else
        echo -e "${GREEN}[PREFLIGHT] [OK]${NC} Ubuntu ${DETECTED_VERSION} detected — fully supported."
    fi

    # Check 3: Package server reachable — warn only
    if curl --silent --max-time 5 --head http://archive.ubuntu.com > /dev/null 2>&1; then
        echo -e "${GREEN}[PREFLIGHT] [OK]${NC} Package server archive.ubuntu.com is reachable."
    else
        echo -e "${YELLOW}[PREFLIGHT] [WARN]${NC} Package server archive.ubuntu.com is not reachable. Package installation may fail."
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

    read -p "[PREFLIGHT] All checks passed. Press Enter to continue..."
    echo ""
}

# --- Step 1: System Prereqs and Info ---
run_prereqs() {
    local disk_usage_output original_user original_user_home

    # Ubuntu version already detected and checked in run_preflight
    # Display the result here for the info screen
    if [[ ! " ${SUPPORTED_VERSIONS[*]} " =~ " ${DETECTED_VERSION} " ]]; then
        echo -e "${YELLOW}[WARN]${NC} Ubuntu ${DETECTED_VERSION} is not officially supported. Tested versions: ${SUPPORTED_VERSIONS[*]}"
        echo -e "${YELLOW}[WARN]${NC} Proceeding anyway — some features may not work correctly."
    else
        echo -e "${GREEN}[OK]${NC} Ubuntu ${DETECTED_VERSION} detected — fully supported"
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
    ORIGINAL_IP_CIDR=$(ip -o -4 a | awk '{print $4}' | grep -v 'lo' | head -n 1)
    if [[ "$ORIGINAL_IP_CIDR" =~ "/" ]]; then
        ORIGINAL_IP=$(echo "$ORIGINAL_IP_CIDR" | cut -d/ -f1)
        ORIGINAL_NETMASK_CIDR=$(echo "$ORIGINAL_IP_CIDR" | cut -d/ -f2)
        ORIGINAL_NETMASK=$(cidr2mask "$ORIGINAL_NETMASK_CIDR")
    else
        ORIGINAL_IP=$ORIGINAL_IP_CIDR
        ORIGINAL_NETMASK_CIDR="24"
        ORIGINAL_NETMASK="255.255.255.0"
    fi
    ORIGINAL_INTERFACE=$(ip -o -4 a | awk '{print $2}' | grep -v 'lo' | head -n 1)
    ORIGINAL_GATEWAY=$(ip r | grep default | awk '{print $3}' | head -n 1)
    if grep -q "dhcp4: true" /etc/netplan/* &>/dev/null; then
        ORIGINAL_NET_TYPE="dhcp"
    elif grep -q "dhcp4: false" /etc/netplan/* &>/dev/null; then
        ORIGINAL_NET_TYPE="static"
    else
        ORIGINAL_NET_TYPE="unknown"
    fi

    ORIGINAL_HOSTNAME=$(hostname)
    ORIGINAL_DNS=$(resolvectl status | grep 'DNS Servers' | awk '{print $3}' | head -n 1 || echo "N/A")
    ORIGINAL_WEBMIN_STATUS=$(dpkg -s webmin &>/dev/null && echo "Installed" || echo "Not Installed")
    ORIGINAL_UFW_STATUS=$(ufw status | grep 'Status:' | awk '{print $2}')
    ORIGINAL_AUTO_UPDATES_STATUS=$(grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades &>/dev/null && echo "Enabled" || echo "Disabled")
    ORIGINAL_FAIL2BAN_STATUS=$(dpkg -s fail2ban &>/dev/null && echo "Installed" || echo "Not Installed")
    ORIGINAL_DOMAIN_STATUS=$(realm list 2>/dev/null | grep 'realm-name:' | awk '{print $2}' || echo "Not Joined")
    ORIGINAL_TELEMETRY_STATUS=$(dpkg -s ubuntu-report &>/dev/null && grep -q 'enable = true' /etc/ubuntu-report/ubuntu-report.conf &>/dev/null && echo "Enabled" || echo "Disabled")
    ORIGINAL_NFS_STATUS=$(dpkg -s nfs-common &>/dev/null && echo "Installed" || echo "Not Installed")
    ORIGINAL_SMB_STATUS=$(dpkg -s cifs-utils &>/dev/null && echo "Installed" || echo "Not Installed")
    ORIGINAL_GIT_STATUS=$(dpkg -s git &>/dev/null && echo "Installed" || echo "Not Installed")

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
    read -p "Press Enter to begin the configuration..."
}

# --- Step 2: Get User Configuration ---
get_user_configuration() {
    local first_interface
    # Initial Prompt for Defaults
    echo ""
    read -p "Would you like to use the default configuration or manually configure each option? (default/manual) [default]: " CONFIG_CHOICE
    CONFIG_CHOICE=${CONFIG_CHOICE:-default}
    CONFIG_CHOICE=$(echo "$CONFIG_CHOICE" | tr '[:upper:]' '[:lower:]')

    # User Configuration Prompts
    echo -e "${YELLOW}--------------------------------------------------------${NC}"
    echo -e "${YELLOW}     Please provide your configuration choices.${NC}"
    echo -e "${YELLOW}--------------------------------------------------------${NC}"
    echo ""

    # Filesystem Snapshot
    SNAPSHOT_STATUS="Not Applicable"
    CREATE_SNAPSHOT="no" # Default to no
    if command -v timeshift &> /dev/null; then
        echo -e "${YELLOW}Timeshift snapshot utility detected.${NC}"
        if [[ "$CONFIG_CHOICE" == "default" ]]; then
            CREATE_SNAPSHOT="yes"
        else
            read -p "Do you want to create a Timeshift snapshot? (yes/no) [yes]: " CREATE_SNAPSHOT
            CREATE_SNAPSHOT=${CREATE_SNAPSHOT:-yes}
        fi
    elif command -v zfs &> /dev/null; then
        if zfs list -o name,mountpoint -t filesystem | grep -q " /$"; then
            echo -e "${YELLOW}ZFS root filesystem detected.${NC}"
            if [[ "$CONFIG_CHOICE" == "default" ]]; then
                CREATE_SNAPSHOT="yes"
            else
                read -p "Do you want to create a ZFS snapshot for rollback? (yes/no) [yes]: " CREATE_SNAPSHOT
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
                read -p "Do you want to create a Btrfs snapshot for rollback? (yes/no) [yes]: " CREATE_SNAPSHOT
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
            read -p "Enter the desired hostname for this machine [$ORIGINAL_HOSTNAME]: " HOSTNAME
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
            read -p "Do you want to use DHCP or a static IP? (dhcp/static) [dhcp]: " NET_TYPE
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
            ls /sys/class/net | grep -v 'lo'
            first_interface=$(ls /sys/class/net | grep -v 'lo' | head -n 1)
            while true; do
                read -p "Enter the network interface name (e.g., enp0s3) [$first_interface]: " INTERFACE_NAME
                INTERFACE_NAME=${INTERFACE_NAME:-$first_interface}
                if [[ -d "/sys/class/net/$INTERFACE_NAME" ]]; then
                    break
                else
                    echo "Error: Interface '$INTERFACE_NAME' not found. Please enter a valid interface name."
                fi
            done
            while true; do
                read -p "Enter the static IP address (e.g., ${ORIGINAL_IP}): " STATIC_IP
                STATIC_IP=${STATIC_IP:-$ORIGINAL_IP}
                if [[ "$STATIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                else
                    echo -e "${RED}Invalid IP address format. Please try again.${NC}"
                fi
            done
            while true; do
                read -p "Enter the network mask (CIDR notation, e.g., 24) [${ORIGINAL_NETMASK_CIDR}]: " NETMASK_CIDR
                NETMASK_CIDR=${NETMASK_CIDR:-$ORIGINAL_NETMASK_CIDR}
                if [[ "$NETMASK_CIDR" =~ ^(8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32)$ ]]; then
                    break
                else
                    echo -e "${RED}Invalid CIDR mask. Please enter a number between 8 and 32.${NC}"
                fi
            done
            while true; do
                read -p "Enter the gateway IP address (e.g., $ORIGINAL_GATEWAY) [$ORIGINAL_GATEWAY]: " GATEWAY
                GATEWAY=${GATEWAY:-$ORIGINAL_GATEWAY}
                if [[ "$GATEWAY" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                else
                    echo -e "${RED}Invalid IP address format. Please try again.${NC}"
                fi
            done
            while true; do
                read -p "Enter the DNS server IP address (e.g., $ORIGINAL_DNS) [$ORIGINAL_DNS]: " DNS_SERVER
                DNS_SERVER=${DNS_SERVER:-$ORIGINAL_DNS}
                if [[ "$DNS_SERVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    break
                else
                    echo -e "${RED}Invalid IP address format. Please try again.${NC}"
                fi
            done
        fi
        # RECOMMENDED: Add explicit warning for risky static IP change
        echo ""
        echo -e "${RED}!! WARNING !!${NC}"
        echo -e "${YELLOW}You have chosen to configure a static IP address.${NC}"
        echo -e "${YELLOW}Incorrect network settings (IP, Gateway, etc.) can result in a loss of network connectivity, requiring console access to fix.${NC}"
        echo -e "${YELLOW}Please double-check your entries in the summary screen.${NC}"
        read -p "Press Enter to acknowledge and continue..."
    fi

    # Service and Security Prompts
    if [[ "$CONFIG_CHOICE" == "default" ]]; then
        INSTALL_WEBMIN="no"
        ENABLE_UFW="yes"
        ENABLE_AUTO_UPDATES="yes"
        INSTALL_FAIL2BAN="yes"
        DISABLE_TELEMETRY="yes"
        JOIN_DOMAIN="no"
        INSTALL_NFS="yes"
        INSTALL_SMB="yes"
        INSTALL_GIT="yes"
    else
        read -p "Do you want to install Webmin? (yes/no) [no]: " INSTALL_WEBMIN
        INSTALL_WEBMIN=${INSTALL_WEBMIN:-no}
        read -p "Do you want to enable the UFW firewall? (yes/no) [yes]: " ENABLE_UFW
        ENABLE_UFW=${ENABLE_UFW:-yes}
        read -p "Do you want to enable automatic security updates? (yes/no) [yes]: " ENABLE_AUTO_UPDATES
        ENABLE_AUTO_UPDATES=${ENABLE_AUTO_UPDATES:-yes}
        read -p "Do you want to install Fail2ban? (yes/no) [yes]: " INSTALL_FAIL2BAN
        INSTALL_FAIL2BAN=${INSTALL_FAIL2BAN:-yes}
        read -p "Do you want to disable optional telemetry and analytics? (yes/no) [yes]: " DISABLE_TELEMETRY
        DISABLE_TELEMETRY=${DISABLE_TELEMETRY:-yes}

        if [ "$ORIGINAL_DOMAIN_STATUS" != "Not Joined" ]; then
            echo -e "${YELLOW}Your system is currently joined to the domain: ${ORIGINAL_DOMAIN_STATUS}${NC}"
            read -p "Do you want to leave this domain and join another? (yes/no) [no]: " JOIN_DOMAIN
            JOIN_DOMAIN=${JOIN_DOMAIN:-no}
        else
            read -p "Do you want to join an Active Directory domain? (yes/no) [no]: " JOIN_DOMAIN
            JOIN_DOMAIN=${JOIN_DOMAIN:-no}
        fi

        read -p "Do you want to install and configure NFS Client? (yes/no) [yes]: " INSTALL_NFS
        INSTALL_NFS=${INSTALL_NFS:-yes}
        read -p "Do you want to install and configure SMB Client? (yes/no) [yes]: " INSTALL_SMB
        INSTALL_SMB=${INSTALL_SMB:-yes}
        read -p "Do you want to install Git? (yes/no) [yes]: " INSTALL_GIT
        INSTALL_GIT=${INSTALL_GIT:-yes}
    fi
    # Use tr for flexible input handling
    CREATE_SNAPSHOT=$(echo "$CREATE_SNAPSHOT" | tr '[:upper:]' '[:lower:]')
    INSTALL_WEBMIN=$(echo "$INSTALL_WEBMIN" | tr '[:upper:]' '[:lower:]')
    ENABLE_UFW=$(echo "$ENABLE_UFW" | tr '[:upper:]' '[:lower:]')
    ENABLE_AUTO_UPDATES=$(echo "$ENABLE_AUTO_UPDATES" | tr '[:upper:]' '[:lower:]')
    INSTALL_FAIL2BAN=$(echo "$INSTALL_FAIL2BAN" | tr '[:upper:]' '[:lower:]')
    DISABLE_TELEMETRY=$(echo "$DISABLE_TELEMETRY" | tr '[:upper:]' '[:lower:]')
    JOIN_DOMAIN=$(echo "$JOIN_DOMAIN" | tr '[:upper:]' '[:lower:]')
    INSTALL_NFS=$(echo "$INSTALL_NFS" | tr '[:upper:]' '[:lower:]')
    INSTALL_SMB=$(echo "$INSTALL_SMB" | tr '[:upper:]' '[:lower:]')
    INSTALL_GIT=$(echo "$INSTALL_GIT" | tr '[:upper:]' '[:lower:]')


    # AD details if requested
    if [[ "$JOIN_DOMAIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo ""
        echo -e "${YELLOW}--- Active Directory Details ---${NC}"
        read -p "Enter the Active Directory domain name (e.g., joka.ca): " AD_DOMAIN
        read -p "Enter the domain administrator username (e.g., admin.user): " AD_USER
        echo "Enter the password for the administrator account."
        echo "Note: The password will not be displayed as you type."
        read -s -p "Password: " AD_PASSWORD
    fi

    # Custom UFW rules — only in manual mode with UFW enabled
    if [[ "$ENABLE_UFW" =~ ^([yY][eE][sS]|[yY])$ ]] && [[ "$CONFIG_CHOICE" == "manual" ]]; then
        collect_custom_ufw_rules
    fi
}

# --- Feature 2: Collect Custom UFW Rules ---
collect_custom_ufw_rules() {
    local add_rule port proto dir desc rule_count=0
    echo ""
    echo -e "${YELLOW}--- Custom Firewall Rules ---${NC}"
    echo -e "You may add up to 20 custom UFW rules. Port ranges use a hyphen (e.g., 5000-5010)."
    echo ""

    while true; do
        if (( rule_count >= 20 )); then
            echo -e "${YELLOW}[WARN]${NC} Maximum of 20 custom rules reached."
            break
        fi

        read -p "Add a custom firewall rule? (yes/no) [no]: " add_rule
        add_rule=${add_rule:-no}
        add_rule=$(echo "$add_rule" | tr '[:upper:]' '[:lower:]')

        if [[ ! "$add_rule" =~ ^([yY][eE][sS]|[yY]|yes)$ ]]; then
            break
        fi

        # Prompt for port (single or range)
        while true; do
            read -p "  Port or range (e.g., 8080 or 5000-5010): " port
            if [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" =~ ^[0-9]+-[0-9]+$ ]]; then
                break
            else
                echo -e "  ${RED}Invalid port. Enter a number (e.g., 8080) or range (e.g., 5000-5010).${NC}"
            fi
        done

        # Prompt for protocol
        while true; do
            read -p "  Protocol (tcp/udp/both) [tcp]: " proto
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
            read -p "  Direction (allow/deny) [allow]: " dir
            dir=${dir:-allow}
            dir=$(echo "$dir" | tr '[:upper:]' '[:lower:]')
            if [[ "$dir" == "allow" || "$dir" == "deny" ]]; then
                break
            else
                echo -e "  ${RED}Invalid direction. Enter allow or deny.${NC}"
            fi
        done

        # Prompt for description (optional)
        read -p "  Description (optional, free text): " desc
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
# Extracted to eliminate DRY violation between show_summary_and_confirm() and reboot_prompt()
display_config_summary() {
    printf "%-30b | %-20s | %-20s\n" "Setting" "Original Value" "New Value"
    printf "%-30s | %-20s | %-20s\n" "------------------------------" "--------------------" "--------------------"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Hostname:${NC}" "${ORIGINAL_HOSTNAME}" "${HOSTNAME}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Network Type:${NC}" "${ORIGINAL_NET_TYPE}" "${NET_TYPE}"
    if [[ "$NET_TYPE" == "static" ]]; then
        printf "%-30b | %-20s | %-20s\n" "${YELLOW}IP Address:${NC}" "${ORIGINAL_IP:-N/A}" "${NEW_IP_ADDRESS_SUMMARY}"
        printf "%-30b | %-20s | %-20s\n" "${YELLOW}Gateway:${NC}" "${ORIGINAL_GATEWAY:-N/A}" "${NEW_GATEWAY_SUMMARY}"
        printf "%-30b | %-20s | %-20s\n" "${YELLOW}DNS Server:${NC}" "${ORIGINAL_DNS:-N/A}" "${NEW_DNS_SUMMARY}"
    fi
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Filesystem Snapshot:${NC}" "N/A" "${CREATE_SNAPSHOT}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Webmin Status:${NC}" "${ORIGINAL_WEBMIN_STATUS}" "${NEW_WEBMIN_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}UFW Firewall Status:${NC}" "${ORIGINAL_UFW_STATUS}" "${NEW_UFW_SUMMARY}"
    local custom_rule_count="${#CUSTOM_UFW_RULES[@]}"
    if (( custom_rule_count > 0 )); then
        printf "%-30b | %-20s | %-20s\n" "${YELLOW}Custom UFW Rules:${NC}" "none" "${custom_rule_count} custom rules"
    else
        printf "%-30b | %-20s | %-20s\n" "${YELLOW}Custom UFW Rules:${NC}" "none" "none"
    fi
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Auto Updates Status:${NC}" "${ORIGINAL_AUTO_UPDATES_STATUS}" "${NEW_AUTO_UPDATES_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Fail2ban Status:${NC}" "${ORIGINAL_FAIL2BAN_STATUS}" "${NEW_FAIL2BAN_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Telemetry/Analytics:${NC}" "${ORIGINAL_TELEMETRY_STATUS}" "${NEW_TELEMETRY_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}AD Domain Join:${NC}" "${ORIGINAL_DOMAIN_STATUS:-Not Joined}" "${NEW_DOMAIN_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}NFS Client Status:${NC}" "${ORIGINAL_NFS_STATUS}" "${NEW_NFS_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}SMB Client Status:${NC}" "${ORIGINAL_SMB_STATUS}" "${NEW_SMB_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Git Status:${NC}" "${ORIGINAL_GIT_STATUS}" "${NEW_GIT_SUMMARY}"
    echo -e "--------------------------------------------------------"
}

# --- Step 3: Show Summary and Confirm ---
show_summary_and_confirm() {
    # Calculate and assign to global summary variables
    NEW_WEBMIN_SUMMARY=$(if [[ "$INSTALL_WEBMIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Installed"; else echo "Skipped"; fi)
    NEW_UFW_SUMMARY=$(if [[ "$ENABLE_UFW" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Enabled"; else echo "Skipped"; fi)
    NEW_AUTO_UPDATES_SUMMARY=$(if [[ "$ENABLE_AUTO_UPDATES" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Enabled"; else echo "Skipped"; fi)
    NEW_FAIL2BAN_SUMMARY=$(if [[ "$INSTALL_FAIL2BAN" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Installed"; else echo "Skipped"; fi)
    NEW_TELEMETRY_SUMMARY=$(if [[ "$DISABLE_TELEMETRY" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Disabled"; else echo "Skipped"; fi)
    NEW_DOMAIN_SUMMARY=$(if [[ "$JOIN_DOMAIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Joined"; else echo "Skipped"; fi)
    NEW_NFS_SUMMARY=$(if [[ "$INSTALL_NFS" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Installed"; else echo "Skipped"; fi)
    NEW_SMB_SUMMARY=$(if [[ "$INSTALL_SMB" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Installed"; else echo "Skipped"; fi)
    NEW_GIT_SUMMARY=$(if [[ "$INSTALL_GIT" =~ ^([yY][eE][sS]|[yY])$ ]]; then echo "To be Installed"; else echo "Skipped"; fi)

    NEW_IP_ADDRESS_SUMMARY=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$STATIC_IP/$NETMASK_CIDR"; else echo "N/A"; fi)
    NEW_GATEWAY_SUMMARY=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$GATEWAY"; else echo "N/A"; fi)
    NEW_DNS_SUMMARY=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$DNS_SERVER"; else echo "N/A"; fi)

    echo ""
    echo -e "$SUMMARY_ART"
    display_config_summary

    read -p "Does the above configuration look correct? (yes/no) [yes]: " CONFIRM_EXECUTION
    CONFIRM_EXECUTION=${CONFIRM_EXECUTION:-yes}

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

    local ver start end status last_step failed_step host
    ver=$(grep "^TUBSS_VERSION=" "$TUBSS_STATE_FILE" | cut -d= -f2)
    start=$(grep "^RUN_START=" "$TUBSS_STATE_FILE" | cut -d= -f2)
    end=$(grep "^RUN_END=" "$TUBSS_STATE_FILE" | cut -d= -f2)
    status=$(grep "^STATUS=" "$TUBSS_STATE_FILE" | cut -d= -f2)
    last_step=$(grep "^LAST_STEP=" "$TUBSS_STATE_FILE" | cut -d= -f2)
    failed_step=$(grep "^FAILED_STEP=" "$TUBSS_STATE_FILE" | cut -d= -f2)
    host=$(grep "^HOSTNAME=" "$TUBSS_STATE_FILE" | cut -d= -f2)

    echo ""
    echo -e "============================================================"
    echo -e "                   Prior Run State"
    echo -e "============================================================"
    echo -e "  Last run:    ${start:-unknown}"
    if [[ "$status" == "completed" ]]; then
        echo -e "  Status:      ${GREEN}completed${NC}"
        echo -e "  Finished:    ${end:-unknown}"
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
    echo ""
}

init_run_state() {
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
    [[ ! -f "$TUBSS_STATE_FILE" ]] && return 0
    sed -i "s|^STATUS=.*|STATUS=completed|" "$TUBSS_STATE_FILE"
    sed -i "s|^RUN_END=.*|RUN_END=$(date -Iseconds)|" "$TUBSS_STATE_FILE"
}

# --- Step 4: Apply Configuration ---
apply_configuration() {
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

    CURRENT_STEP="configure_ufw"
    configure_ufw
    update_run_state_step "configure_ufw"

    CURRENT_STEP="configure_fail2ban"
    configure_fail2ban
    update_run_state_step "configure_fail2ban"

    CURRENT_STEP="configure_auto_updates"
    configure_auto_updates
    update_run_state_step "configure_auto_updates"

    CURRENT_STEP="disable_telemetry"
    disable_telemetry
    update_run_state_step "disable_telemetry"

    CURRENT_STEP="join_ad_domain"
    join_ad_domain
    update_run_state_step "join_ad_domain"

    # Network Configuration — done last so all other steps complete before
    # the network changes on reboot
    CURRENT_STEP="configure_network"
    configure_network
    update_run_state_step "configure_network"
}

configure_snapshot() {
    local snapshot_name zfs_root_dataset
    if [[ "$CREATE_SNAPSHOT" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        if command -v timeshift &> /dev/null; then
            snapshot_name="tubss-pre-config-$(date +%Y%m%d-%H%M)"
            timeshift --create --comments "TUBSS Pre-Setup Snapshot" &>/dev/null &
            bg_pid=$!
            spinner $bg_pid "Creating Timeshift snapshot"
            wait $bg_pid || { echo -e "\n${RED}[ERROR]${NC} Creating Timeshift snapshot failed (exit $?)"; exit 1; }
            SNAPSHOT_STATUS="Created: Timeshift"
            echo -e "${GREEN}[OK]${NC} Timeshift snapshot created successfully."
        elif command -v zfs &> /dev/null && zfs list -o name,mountpoint -t filesystem | grep -q " /$"; then
            zfs_root_dataset=$(zfs list -o name,mountpoint -t filesystem | grep " /$" | awk '{print $1}')
            snapshot_name="tubss-pre-config-$(date +%Y%m%d-%H%M)"
            zfs snapshot "${zfs_root_dataset}@${snapshot_name}" &>/dev/null &
            bg_pid=$!
            spinner $bg_pid "Creating ZFS snapshot"
            wait $bg_pid || { echo -e "\n${RED}[ERROR]${NC} Creating ZFS snapshot failed (exit $?)"; exit 1; }
            SNAPSHOT_STATUS="Created: $snapshot_name (ZFS)"
            echo -e "${GREEN}[OK]${NC} ZFS snapshot created successfully."
        elif command -v btrfs &> /dev/null && df -t btrfs / 2>/dev/null | grep -q ' /$'; then
            snapshot_name="tubss-pre-config-$(date +%Y%m%d-%H%M)"
            btrfs subvolume create /@snapshots &>/dev/null
            btrfs subvolume snapshot -r "/@" "/@snapshots/$snapshot_name" &>/dev/null &
            bg_pid=$!
            spinner $bg_pid "Creating Btrfs snapshot"
            wait $bg_pid || { echo -e "\n${RED}[ERROR]${NC} Creating Btrfs snapshot failed (exit $?)"; exit 1; }
            SNAPSHOT_STATUS="Created: $snapshot_name (Btrfs)"
            echo -e "${GREEN}[OK]${NC} Btrfs snapshot created successfully."
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
    else
        hostnamectl set-hostname "$NEW_HOSTNAME"
        echo -e "${GREEN}[OK]${NC} Hostname set to '$NEW_HOSTNAME'."
    fi
}

install_packages() {
    local packages_to_install=()
    echo -ne "${YELLOW}[TUBSS] Updating package lists...${NC}"
    apt-get update -y > /dev/null 2>&1 &
    bg_pid=$!
    spinner $bg_pid "Updating package lists"
    wait $bg_pid || { echo -e "\n${RED}[ERROR]${NC} Updating package lists failed (exit $?)"; exit 1; }
    echo -e "${GREEN}[OK]${NC} Package lists updated."

    local PACKAGES=("curl" "ufw" "unattended-upgrades" "apparmor" "net-tools" "htop" "neofetch" "vim" "build-essential" "rsync")

    if [[ "$INSTALL_FAIL2BAN" =~ ^([yY][eE][sS]|[yY])$ ]]; then PACKAGES+=("fail2ban"); fi
    if [[ "$INSTALL_GIT" =~ ^([yY][eE][sS]|[yY])$ ]]; then PACKAGES+=("git"); fi
    if [[ "$INSTALL_WEBMIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then PACKAGES+=("webmin"); fi
    if [[ "$INSTALL_NFS" =~ ^([yY][eE][sS]|[yY])$ ]]; then PACKAGES+=("nfs-common"); fi
    if [[ "$INSTALL_SMB" =~ ^([yY][eE][sS]|[yY])$ ]]; then PACKAGES+=("cifs-utils"); fi

    for pkg in "${PACKAGES[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -qE '^ii'; then
            echo -e "  ${GREEN}[SKIP]${NC} $pkg already installed"
        else
            packages_to_install+=("$pkg")
        fi
    done

    if [[ ${#packages_to_install[@]} -gt 0 ]]; then
        echo -ne "${YELLOW}[TUBSS] Installing packages...${NC}"
        apt-get install -y "${packages_to_install[@]}" > /dev/null 2>&1 &
        bg_pid=$!
        spinner $bg_pid "Installing packages"
        wait $bg_pid || { echo -e "\n${RED}[ERROR]${NC} Installing packages failed (exit $?)"; exit 1; }
        echo -e "${GREEN}[OK]${NC} All selected packages installed successfully."
    else
        echo -e "  ${GREEN}[SKIP]${NC} All packages already installed"
    fi
    PACKAGES_INSTALLED=1
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

    # Try to restore a previously backed-up DHCP config
    most_recent=$(find /etc/netplan/tubss-backup/ -maxdepth 2 \
        \( -name "*.yaml" -o -name "*.yml" \) \
        -printf "%T@ %p\n" 2>/dev/null \
        | sort -rn | head -1 | awk '{print $2}')

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

configure_network() {
    local network_config_file
    echo -ne "${YELLOW}[TUBSS] Configuring Network... ${NC}"
    network_config_file="/etc/netplan/01-static-network.yaml"
    if [[ "$NET_TYPE" == "dhcp" ]]; then
        if [ -f "$network_config_file" ]; then
            DHCP_RESTORE_FILE=""
            restore_dhcp_config "$network_config_file"
            local static_temp="/tmp/tubss-static-rollback.yaml"
            mv "$network_config_file" "$static_temp"
            if ! netplan generate > /dev/null 2>&1; then
                mv "$static_temp" "$network_config_file"
                [[ -n "$DHCP_RESTORE_FILE" ]] && rm -f "$DHCP_RESTORE_FILE"
                echo -e "${RED}[ERROR]${NC} Netplan configuration validation failed — rolled back to static config"
                exit 1
            fi
            rm -f "$static_temp"
            echo -e "${GREEN}[OK]${NC} DHCP config restored — will apply on reboot."
        else
            echo -e "${YELLOW}[SKIPPED]${NC} Already using DHCP."
        fi
    else
        if [[ -f "$network_config_file" ]]; then
            echo -e "  ${GREEN}[SKIP]${NC} Static network config already exists — skipping."
            echo -e "  ${YELLOW}[WARN]${NC} If you added netplan files since the last run, delete /etc/netplan/01-static-network.yaml and re-run to trigger cleanup."
        else
            warn_if_gateway_unreachable
            # Backup and remove conflicting netplan configs to prevent IP merging
            local backup_timestamp
            backup_timestamp=$(date +%Y%m%d-%H%M%S)
            local backup_dir="/etc/netplan/tubss-backup/${backup_timestamp}"
            mkdir -p "$backup_dir"
            for f in /etc/netplan/*.yaml /etc/netplan/*.yml; do
                [[ -f "$f" ]] || continue
                [[ "$f" == "$network_config_file" ]] && continue
                mv "$f" "$backup_dir/"
                echo -e "  ${YELLOW}[NETPLAN]${NC} Backed up conflicting config: $(basename "$f")"
            done
            cat << EOF > "$network_config_file"
network:
  version: 2
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
            if ! netplan generate > /dev/null 2>&1; then
                echo -e "${RED}[ERROR]${NC} Netplan configuration validation failed — not applying to avoid network lockout"
                exit 1
            fi
            disable_cloud_init_network
            echo -e "${GREEN}[OK]${NC} Static IP config written for '$INTERFACE_NAME' — will apply on reboot."
        fi
    fi
}

# --- Feature 3: Pre-write Gateway Reachability Check ---
warn_if_gateway_unreachable() {
    [[ "$NET_TYPE" != "static" ]] && return 0
    [[ -z "${GATEWAY:-}" ]] && return 0

    echo -ne "${YELLOW}[TUBSS] Checking gateway reachability before writing config... ${NC}"
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
        echo -ne "${YELLOW}[TUBSS] Configuring UFW... ${NC}"
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            echo -e "  ${GREEN}[SKIP]${NC} UFW already active"
        else
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow ssh
            ufw --force enable > /dev/null 2>&1 &
            bg_pid=$!
            spinner $bg_pid "Enabling UFW"
            wait $bg_pid || { echo -e "\n${RED}[ERROR]${NC} Enabling UFW failed (exit $?)"; exit 1; }
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
        echo -ne "${YELLOW}[TUBSS] Configuring Fail2ban... ${NC}"
        jail_file="/etc/fail2ban/jail.local"

        if [[ -f "$jail_file" ]]; then
            echo -e "  ${GREEN}[SKIP]${NC} Fail2ban already configured — skipping (delete /etc/fail2ban/jail.local to reconfigure)"
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
            systemctl daemon-reload > /dev/null 2>&1 &
            bg_pid=$!
            spinner $bg_pid "Reloading systemd daemon"
            wait $bg_pid || { echo -e "\n${RED}[ERROR]${NC} Reloading systemd daemon failed (exit $?)"; exit 1; }

            systemctl enable --now fail2ban > /dev/null 2>&1 &
            bg_pid=$!
            spinner $bg_pid "Starting and enabling Fail2ban"
            wait $bg_pid || { echo -e "\n${RED}[ERROR]${NC} Starting and enabling Fail2ban failed (exit $?)"; exit 1; }

            echo -e "${GREEN}[OK]${NC} Fail2ban configured and running."
        fi
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Fail2ban configuration."
    fi
}

configure_auto_updates() {
    if [[ "$ENABLE_AUTO_UPDATES" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -ne "${YELLOW}[TUBSS] Enabling Automatic Security Updates... ${NC}"
        if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
            echo -e "  ${GREEN}[SKIP]${NC} Auto-updates already configured"
        else
            echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
            echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
            echo -e "${GREEN}[OK]${NC} Automatic security updates enabled."
        fi
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Automatic security updates."
    fi
}

disable_telemetry() {
    if [[ "$DISABLE_TELEMETRY" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -ne "${YELLOW}[TUBSS] Disabling Ubuntu Telemetry... ${NC}"
        if grep -q "^enable = false" /etc/ubuntu-report/ubuntu-report.conf 2>/dev/null; then
            echo -e "  ${GREEN}[SKIP]${NC} Telemetry already disabled"
        elif [ -f /etc/ubuntu-report/ubuntu-report.conf ]; then
            sed -i 's/^enable = true/enable = false/' /etc/ubuntu-report/ubuntu-report.conf
            echo -e "${GREEN}[OK]${NC} Ubuntu telemetry disabled."
        else
            echo -e "${YELLOW}Warning: Ubuntu telemetry configuration file not found. Skipping.${NC}"
        fi
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Telemetry disablement."
    fi
}

join_ad_domain() {
    if [[ "$JOIN_DOMAIN" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -ne "${YELLOW}[TUBSS] Joining Active Directory domain... ${NC}"
        echo -e "${YELLOW}Placeholder: Domain join logic is not implemented in this script due to security concerns.${NC}"
        unset AD_PASSWORD AD_DOMAIN AD_USER
    else
        echo -e "${YELLOW}[SKIPPED]${NC} AD domain join."
    fi
}

# --- Step 5: Final Summary and Reboot Prompt ---
reboot_prompt() {
    finalize_run_state
    echo ""
    echo -e "${YELLOW}Configuration changes have been applied.${NC}"
    echo "A summary of the changes has been saved to: $SUMMARY_FILE"
    echo "--------------------------------------------------------"
    echo ""

    # Write summary to file
    cat << EOF > "$SUMMARY_FILE"
TUBSS - The Ubuntu Basic Setup Script - Configuration Summary
Provided by Joka.ca

Date: $(date)
Hostname: $HOSTNAME

Configuration Changes:
---------------------------------------------------------------------------------
Setting                      | Original Value             | New Value
-----------------------------|----------------------------|----------------------------
Hostname                     | $ORIGINAL_HOSTNAME           | $HOSTNAME
Filesystem Snapshot          | N/A                        | $SNAPSHOT_STATUS
Network Type                 | $ORIGINAL_NET_TYPE           | $NET_TYPE
IP Address                   | ${ORIGINAL_IP:-N/A}        | ${NEW_IP_ADDRESS_SUMMARY}
Gateway                      | ${ORIGINAL_GATEWAY:-N/A}   | ${NEW_GATEWAY_SUMMARY}
DNS Server                   | ${ORIGINAL_DNS:-N/A}       | ${NEW_DNS_SUMMARY}
Webmin Status                | $ORIGINAL_WEBMIN_STATUS    | ${NEW_WEBMIN_SUMMARY}
UFW Status                   | $ORIGINAL_UFW_STATUS       | ${NEW_UFW_SUMMARY}
Custom UFW Rules             | none                       | ${#CUSTOM_UFW_RULES[@]} rule(s)
Auto Updates Status          | $ORIGINAL_AUTO_UPDATES_STATUS | ${NEW_AUTO_UPDATES_SUMMARY}
Fail2ban Status              | $ORIGINAL_FAIL2BAN_STATUS  | ${NEW_FAIL2BAN_SUMMARY}
Telemetry/Analytics          | $ORIGINAL_TELEMETRY_STATUS | ${NEW_TELEMETRY_SUMMARY}
AD Domain Join               | ${ORIGINAL_DOMAIN_STATUS:-Not Joined} | ${NEW_DOMAIN_SUMMARY}
NFS Client Status            | $ORIGINAL_NFS_STATUS       | ${NEW_NFS_SUMMARY}
SMB Client Status            | $ORIGINAL_SMB_STATUS       | ${NEW_SMB_SUMMARY}
Git Status                   | $ORIGINAL_GIT_STATUS       | ${NEW_GIT_SUMMARY}
---------------------------------------------------------------------------------
Script provided by Joka.ca
EOF

    echo ""
    echo -e "${GREEN}[OK]${NC} A summary of the configuration changes has been saved to:"
    echo -e "${GREEN}      $SUMMARY_FILE${NC}"
    echo ""

    # Display summary table using shared function
    echo -e "$SUMMARY_ART"
    display_config_summary

    # Final Prompt
    echo ""
    echo -e "$CLOSING_ART"
    read -p "Configuration is complete. Would you like to reboot the system now? (yes/no) [yes]: " REBOOT_PROMPT
    REBOOT_PROMPT=${REBOOT_PROMPT:-yes}

    if [[ "$REBOOT_PROMPT" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}Rebooting the system now to apply all changes.${NC}"
        reboot
    else
        echo -e "${YELLOW}Reboot has been skipped. Please reboot the system manually for all changes to take effect.${NC}"
    fi
}

# --- Feature 4: Rollback UI ---
run_rollback_ui() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] Rollback requires root. Run with sudo.${NC}"
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
        read -p "Select a snapshot to restore (1-${#snap_names[@]}, or 0 to cancel): " selection
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
    read -p "Restore to '${chosen_name}'? This cannot be undone. (yes/no) [no]: " confirm_restore
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
            local dataset snap_short intermediate_count
            dataset=$(echo "$chosen_name" | cut -d@ -f1)
            snap_short=$(echo "$chosen_name" | cut -d@ -f2)
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
    read -p "Would you like to reboot now? (yes/no) [no]: " do_reboot
    do_reboot=${do_reboot:-no}
    if [[ "$do_reboot" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo -e "${YELLOW}Rebooting...${NC}"
        reboot
    else
        echo -e "${YELLOW}Please reboot manually when ready.${NC}"
    fi
}

main "$@"
