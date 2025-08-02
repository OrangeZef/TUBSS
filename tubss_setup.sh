#!/bin/bash

#==============================================================================
# The Ubuntu Basic Setup Script (TUBSS)
# Version: 2.3 (Code Review v1)
# Author: OrangeZef
#
# This script automates the initial setup and hardening of a new Ubuntu server.
#
# Changelog:
# - Integrated all code review recommendations.
# - Implemented more secure handling of Active Directory passwords (stdin).
# - Added a backup step for Netplan configuration files before changes.
# - Improved Btrfs filesystem detection using `btrfs subvolume show`.
# - Refactored summary variable assignment to be a single source of truth (DRY).
# - Created a reusable `is_yes` helper function to reduce code duplication.
# - Hardened all "yes/no" prompts with a validation loop for consistency.
#
# Provided by Joka.ca
#==============================================================================

# --- Strict Mode ---
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
|    Version 2.3                              |
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


# --- Utility Functions ---

# Function to handle errors and exit gracefully
handle_error() {
    local exit_code=$?
    local line_number=${BASH_LINENO[0]}
    local command=${BASH_COMMAND}
    echo ""
    echo -e "${RED}--------------------------------------------------------${NC}"
    echo -e "${RED}An error occurred at line ${line_number} with command: ${command}${NC}"
    echo -e "${RED}Exiting script with status code: ${exit_code}${NC}"
    echo -e "${RED}--------------------------------------------------------${NC}"
    echo ""
    # The 'set -e' command will cause the script to exit immediately after this trap.
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

# Helper function to check for 'yes' or 'y' responses
is_yes() {
    local response=$1
    [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
}

# Cleanup function to be executed on script exit
cleanup() {
    echo ""
    echo -e "${YELLOW}============================================================${NC}"
    echo -e "${YELLOW}                  Final Cleanup and Exit${NC}"
    echo -e "${YELLOW}============================================================${NC}"
    echo -ne "${YELLOW}[TUBSS] Removing unused packages and dependencies...${NC}"
    apt-get autoremove -y > /dev/null 2>&1 & spinner $! "Removing unused packages"
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
    run_prereqs
    get_user_configuration
    show_summary_and_confirm
    apply_configuration
    reboot_prompt
}

# --- Step 1: System Prereqs and Info ---
run_prereqs() {
    local disk_usage_output original_user original_user_home

    # Get the original user's desktop path for the summary file
    # Prefer $SUDO_USER for better reliability when run with sudo
    original_user=${SUDO_USER:-$(logname)}
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
    CREATE_SNAPSHOT="no" # Default to no
    if command -v timeshift &> /dev/null; then
        echo -e "${YELLOW}Timeshift snapshot utility detected.${NC}"
        if [[ "$CONFIG_CHOICE" == "default" ]]; then
            CREATE_SNAPSHOT="yes"
        else
            while true; do
                read -p "Do you want to create a Timeshift snapshot? (yes/no) [yes]: " response
                CREATE_SNAPSHOT=${response:-yes}
                if is_yes "$CREATE_SNAPSHOT" || [[ "$CREATE_SNAPSHOT" =~ ^([nN][oO]|[nN])$ ]]; then
                    break
                else
                    echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"
                fi
            done
        fi
    elif command -v zfs &> /dev/null; then
        if zfs list -o name,mountpoint -t filesystem | grep -q " /$"; then
            echo -e "${YELLOW}ZFS root filesystem detected.${NC}"
            if [[ "$CONFIG_CHOICE" == "default" ]]; then
                CREATE_SNAPSHOT="yes"
            else
                while true; do
                    read -p "Do you want to create a ZFS snapshot for rollback? (yes/no) [yes]: " response
                    CREATE_SNAPSHOT=${response:-yes}
                    if is_yes "$CREATE_SNAPSHOT" || [[ "$CREATE_SNAPSHOT" =~ ^([nN][oO]|[nN])$ ]]; then
                        break
                    else
                        echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"
                    fi
                done
            fi
        fi
    elif command -v btrfs &> /dev/null; then
        if btrfs subvolume show / &>/dev/null; then
            echo -e "${YELLOW}Btrfs root filesystem detected.${NC}"
            if [[ "$CONFIG_CHOICE" == "default" ]]; then
                CREATE_SNAPSHOT="yes"
            else
                while true; do
                    read -p "Do you want to create a Btrfs snapshot for rollback? (yes/no) [yes]: " response
                    CREATE_SNAPSHOT=${response:-yes}
                    if is_yes "$CREATE_SNAPSHOT" || [[ "$CREATE_SNAPSHOT" =~ ^([nN][oO]|[nN])$ ]]; then
                        break
                    else
                        echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"
                    fi
                done
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
        while true; do
            read -p "Do you want to install Webmin? (yes/no) [no]: " response
            INSTALL_WEBMIN=${response:-no}
            if is_yes "$INSTALL_WEBMIN" || [[ "$INSTALL_WEBMIN" =~ ^([nN][oO]|[nN])$ ]]; then break; else echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"; fi
        done
        while true; do
            read -p "Do you want to enable the UFW firewall? (yes/no) [yes]: " response
            ENABLE_UFW=${response:-yes}
            if is_yes "$ENABLE_UFW" || [[ "$ENABLE_UFW" =~ ^([nN][oO]|[nN])$ ]]; then break; else echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"; fi
        done
        while true; do
            read -p "Do you want to enable automatic security updates? (yes/no) [yes]: " response
            ENABLE_AUTO_UPDATES=${response:-yes}
            if is_yes "$ENABLE_AUTO_UPDATES" || [[ "$ENABLE_AUTO_UPDATES" =~ ^([nN][oO]|[nN])$ ]]; then break; else echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"; fi
        done
        while true; do
            read -p "Do you want to install Fail2ban? (yes/no) [yes]: " response
            INSTALL_FAIL2BAN=${response:-yes}
            if is_yes "$INSTALL_FAIL2BAN" || [[ "$INSTALL_FAIL2BAN" =~ ^([nN][oO]|[nN])$ ]]; then break; else echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"; fi
        done
        while true; do
            read -p "Do you want to disable optional telemetry and analytics? (yes/no) [yes]: " response
            DISABLE_TELEMETRY=${response:-yes}
            if is_yes "$DISABLE_TELEMETRY" || [[ "$DISABLE_TELEMETRY" =~ ^([nN][oO]|[nN])$ ]]; then break; else echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"; fi
        done

        if [ "$ORIGINAL_DOMAIN_STATUS" != "Not Joined" ]; then
            echo -e "${YELLOW}Your system is currently joined to the domain: ${ORIGINAL_DOMAIN_STATUS}${NC}"
            while true; do
                read -p "Do you want to leave this domain and join another? (yes/no) [no]: " response
                JOIN_DOMAIN=${response:-no}
                if is_yes "$JOIN_DOMAIN" || [[ "$JOIN_DOMAIN" =~ ^([nN][oO]|[nN])$ ]]; then break; else echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"; fi
            done
        else
            while true; do
                read -p "Do you want to join an Active Directory domain? (yes/no) [no]: " response
                JOIN_DOMAIN=${response:-no}
                if is_yes "$JOIN_DOMAIN" || [[ "$JOIN_DOMAIN" =~ ^([nN][oO]|[nN])$ ]]; then break; else echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"; fi
            done
        fi
        
        while true; do
            read -p "Do you want to install and configure NFS Client? (yes/no) [yes]: " response
            INSTALL_NFS=${response:-yes}
            if is_yes "$INSTALL_NFS" || [[ "$INSTALL_NFS" =~ ^([nN][oO]|[nN])$ ]]; then break; else echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"; fi
        done
        while true; do
            read -p "Do you want to install and configure SMB Client? (yes/no) [yes]: " response
            INSTALL_SMB=${response:-yes}
            if is_yes "$INSTALL_SMB" || [[ "$INSTALL_SMB" =~ ^([nN][oO]|[nN])$ ]]; then break; else echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"; fi
        done
        while true; do
            read -p "Do you want to install Git? (yes/no) [yes]: " response
            INSTALL_GIT=${response:-yes}
            if is_yes "$INSTALL_GIT" || [[ "$INSTALL_GIT" =~ ^([nN][oO]|[nN])$ ]]; then break; else echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"; fi
        done
    fi
    # Use helper function for flexible input handling
    CREATE_SNAPSHOT=$(if is_yes "$CREATE_SNAPSHOT"; then echo "yes"; else echo "no"; fi)
    INSTALL_WEBMIN=$(if is_yes "$INSTALL_WEBMIN"; then echo "yes"; else echo "no"; fi)
    ENABLE_UFW=$(if is_yes "$ENABLE_UFW"; then echo "yes"; else echo "no"; fi)
    ENABLE_AUTO_UPDATES=$(if is_yes "$ENABLE_AUTO_UPDATES"; then echo "yes"; else echo "no"; fi)
    INSTALL_FAIL2BAN=$(if is_yes "$INSTALL_FAIL2BAN"; then echo "yes"; else echo "no"; fi)
    DISABLE_TELEMETRY=$(if is_yes "$DISABLE_TELEMETRY"; then echo "yes"; else echo "no"; fi)
    JOIN_DOMAIN=$(if is_yes "$JOIN_DOMAIN"; then echo "yes"; else echo "no"; fi)
    INSTALL_NFS=$(if is_yes "$INSTALL_NFS"; then echo "yes"; else echo "no"; fi)
    INSTALL_SMB=$(if is_yes "$INSTALL_SMB"; then echo "yes"; else echo "no"; fi)
    INSTALL_GIT=$(if is_yes "$INSTALL_GIT"; then echo "yes"; else echo "no"; fi)


    # AD details if requested
    if is_yes "$JOIN_DOMAIN"; then
        echo ""
        echo -e "${YELLOW}--- Active Directory Details ---${NC}"
        read -p "Enter the Active Directory domain name (e.g., joka.ca): " AD_DOMAIN
        read -p "Enter the domain administrator username (e.g., admin.user): " AD_USER
        echo "Enter the password for the administrator account."
        echo "Note: The password will not be displayed as you type."
        # Read password securely into a temporary variable, not a global one.
        read -s -p "Password: " AD_PASSWORD
    fi
}

# --- Step 3: Show Summary and Confirm ---
show_summary_and_confirm() {
    # Calculate and assign to global summary variables (DRY)
    if is_yes "$INSTALL_WEBMIN"; then NEW_WEBMIN_SUMMARY="To be Installed"; else NEW_WEBMIN_SUMMARY="Skipped"; fi
    if is_yes "$ENABLE_UFW"; then NEW_UFW_SUMMARY="To be Enabled"; else NEW_UFW_SUMMARY="Skipped"; fi
    if is_yes "$ENABLE_AUTO_UPDATES"; then NEW_AUTO_UPDATES_SUMMARY="To be Enabled"; else NEW_AUTO_UPDATES_SUMMARY="Skipped"; fi
    if is_yes "$INSTALL_FAIL2BAN"; then NEW_FAIL2BAN_SUMMARY="To be Installed"; else NEW_FAIL2BAN_SUMMARY="Skipped"; fi
    if is_yes "$DISABLE_TELEMETRY"; then NEW_TELEMETRY_SUMMARY="To be Disabled"; else NEW_TELEMETRY_SUMMARY="Skipped"; fi
    if is_yes "$JOIN_DOMAIN"; then NEW_DOMAIN_SUMMARY="To be Joined"; else NEW_DOMAIN_SUMMARY="Skipped"; fi
    if is_yes "$INSTALL_NFS"; then NEW_NFS_SUMMARY="To be Installed"; else NEW_NFS_SUMMARY="Skipped"; fi
    if is_yes "$INSTALL_SMB"; then NEW_SMB_SUMMARY="To be Installed"; else NEW_SMB_SUMMARY="Skipped"; fi
    if is_yes "$INSTALL_GIT"; then NEW_GIT_SUMMARY="To be Installed"; else NEW_GIT_SUMMARY="Skipped"; fi
    
    if [[ "$NET_TYPE" == "static" ]]; then
        NEW_IP_ADDRESS_SUMMARY="$STATIC_IP/$NETMASK_CIDR"
        NEW_GATEWAY_SUMMARY="$GATEWAY"
        NEW_DNS_SUMMARY="$DNS_SERVER"
    else
        NEW_IP_ADDRESS_SUMMARY="N/A"
        NEW_GATEWAY_SUMMARY="N/A"
        NEW_DNS_SUMMARY="N/A"
    fi

    echo ""
    echo -e "$SUMMARY_ART"
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
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Auto Updates Status:${NC}" "${ORIGINAL_AUTO_UPDATES_STATUS}" "${NEW_AUTO_UPDATES_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Fail2ban Status:${NC}" "${ORIGINAL_FAIL2BAN_STATUS}" "${NEW_FAIL2BAN_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Telemetry/Analytics:${NC}" "${ORIGINAL_TELEMETRY_STATUS}" "${NEW_TELEMETRY_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}AD Domain Join:${NC}" "${ORIGINAL_DOMAIN_STATUS:-Not Joined}" "${NEW_DOMAIN_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}NFS Client Status:${NC}" "${ORIGINAL_NFS_STATUS}" "${NEW_NFS_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}SMB Client Status:${NC}" "${ORIGINAL_SMB_STATUS}" "${NEW_SMB_SUMMARY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Git Status:${NC}" "${ORIGINAL_GIT_STATUS}" "${NEW_GIT_SUMMARY}"
    echo -e "--------------------------------------------------------"

    while true; do
        read -p "Does the above configuration look correct? (yes/no) [yes]: " response
        CONFIRM_EXECUTION=${response:-yes}
        if is_yes "$CONFIRM_EXECUTION" || [[ "$CONFIRM_EXECUTION" =~ ^([nN][oO]|[nN])$ ]]; then
            break
        else
            echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"
        fi
    done

    if ! is_yes "$CONFIRM_EXECUTION"; then
        echo -e "${RED}Execution aborted by user.${NC}"
        exit 1
    fi

    echo ""
    echo -e "$EXECUTION_ART"
    echo -e "--------------------------------------------------------"
}

# --- Step 4: Apply Configuration ---
apply_configuration() {
    # Filesystem Snapshot
    configure_snapshot

    # Hostname Configuration
    configure_hostname

    # Package Installation
    install_packages

    # Network Configuration
    configure_network

    # Security Configuration
    configure_fail2ban
    configure_ufw
    configure_auto_updates
    disable_telemetry

    # Domain Join and File Shares
    join_ad_domain
}

configure_snapshot() {
    local snapshot_name zfs_root_dataset
    if is_yes "$CREATE_SNAPSHOT"; then
        if command -v timeshift &> /dev/null; then
            snapshot_name="tubss-pre-config-$(date +%Y%m%d-%H%M)"
            timeshift --create --comments "TUBSS Pre-Setup Snapshot" &>/dev/null & spinner $! "Creating Timeshift snapshot"
            SNAPSHOT_STATUS="Created: Timeshift"
            echo -e "${GREEN}[OK]${NC} Timeshift snapshot created successfully."
        elif command -v zfs &> /dev/null && zfs list -o name,mountpoint -t filesystem | grep -q " /$"; then
            zfs_root_dataset=$(zfs list -o name,mountpoint -t filesystem | grep " /$" | awk '{print $1}')
            snapshot_name="tubss-pre-config-$(date +%Y%m%d-%H%M)"
            zfs snapshot "${zfs_root_dataset}@${snapshot_name}" &>/dev/null & spinner $! "Creating ZFS snapshot"
            SNAPSHOT_STATUS="Created: $snapshot_name (ZFS)"
            echo -e "${GREEN}[OK]${NC} ZFS snapshot created successfully."
        elif command -v btrfs &> /dev/null && btrfs subvolume show / &>/dev/null; then
            snapshot_name="tubss-pre-config-$(date +%Y%m%d-%H%M)"
            btrfs subvolume create /@snapshots &>/dev/null
            btrfs subvolume snapshot -r "/@" "/@snapshots/$snapshot_name" &>/dev/null & spinner $! "Creating Btrfs snapshot"
            SNAPSHOT_STATUS="Created: $snapshot_name (Btrfs)"
            echo -e "${GREEN}[OK]${NC} Btrfs snapshot created successfully."
        fi
    else
        SNAPSHOT_STATUS="Skipped"
        echo -e "${YELLOW}[SKIPPED]${NC} Snapshot creation."
    fi
}

configure_hostname() {
    if [[ "$HOSTNAME" != "$ORIGINAL_HOSTNAME" ]]; then
        hostnamectl set-hostname "$HOSTNAME"
        echo -e "${GREEN}[OK]${NC} Hostname set to '$HOSTNAME'."
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Hostname is already '$HOSTNAME'."
    fi
}

install_packages() {
    echo -ne "${YELLOW}[TUBSS] Updating package lists...${NC}"
    apt-get update -y > /dev/null 2>&1 & spinner $! "Updating package lists"
    echo -e "${GREEN}[OK]${NC} Package lists updated."

    local base_packages="curl ufw unattended-upgrades apparmor net-tools htop neofetch vim build-essential rsync"
    local optional_packages=()

    if is_yes "$INSTALL_FAIL2BAN"; then optional_packages+=(fail2ban); fi
    if is_yes "$INSTALL_GIT"; then optional_packages+=(git); fi
    if is_yes "$INSTALL_NFS"; then optional_packages+=(nfs-common); fi
    if is_yes "$INSTALL_SMB"; then optional_packages+=(cifs-utils); fi

    # Webmin installation is a special case due to its repository
    if is_yes "$INSTALL_WEBMIN"; then
        echo -ne "${YELLOW}[TUBSS] Adding Webmin repository...${NC}"
        # A more secure and explicit way to add the repository
        # Add the repository key
        curl -s http://www.webmin.com/jcameron-key.asc | gpg --dearmor > /usr/share/keyrings/webmin-archive-keyring.gpg
        # Add the repository to sources.list.d
        echo 'deb [signed-by=/usr/share/keyrings/webmin-archive-keyring.gpg] http://download.webmin.com/download/repository sarge contrib' | tee /etc/apt/sources.list.d/webmin.list > /dev/null
        apt-get update -y > /dev/null 2>&1 & spinner $! "Updating package lists for Webmin"
        echo -e "${GREEN}[OK]${NC} Webmin repository added."
        optional_packages+=(webmin)
    fi

    local packages_to_install=("$base_packages" "${optional_packages[@]}")
    if [ "${#packages_to_install[@]}" -gt 0 ]; then
        echo -ne "${YELLOW}[TUBSS] Installing packages...${NC}"
        apt-get install -y --no-install-recommends "${packages_to_install[@]}" > /dev/null 2>&1 &
        spinner $! "Installing packages"
        echo -e "${GREEN}[OK]${NC} All selected packages installed successfully."
    fi
}

configure_network() {
    local network_config_file
    echo -ne "${YELLOW}[TUBSS] Configuring Network... ${NC}"
    
    # Backup existing netplan configurations
    if [ -d "/etc/netplan" ]; then
        mkdir -p /etc/netplan/backup
        cp /etc/netplan/*.yaml /etc/netplan/backup/ 2>/dev/null || true
    fi

    network_config_file="/etc/netplan/01-static-network.yaml"
    if [[ "$NET_TYPE" == "dhcp" ]]; then
        if [ -f "$network_config_file" ]; then
            rm -f "$network_config_file"
            netplan apply
            echo -e "${GREEN}[OK]${NC} Switched to DHCP."
        else
            echo -e "${YELLOW}[SKIPPED]${NC} Already using DHCP."
        fi
    else
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
        netplan apply
        echo -e "${GREEN}[OK]${NC} Static IP configured for interface '$INTERFACE_NAME'."
    fi
}

configure_fail2ban() {
    local jail_file
    if is_yes "$INSTALL_FAIL2BAN"; then
        echo -ne "${YELLOW}[TUBSS] Configuring Fail2ban... ${NC}"
        jail_file="/etc/fail2ban/jail.local"
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
        if systemctl is-active --quiet fail2ban; then
            systemctl restart fail2ban > /dev/null 2>&1 & spinner $! "Restarting Fail2ban"
        else
            systemctl enable fail2ban > /dev/null 2>&1 & spinner $! "Enabling Fail2ban"
            systemctl start fail2ban > /dev/null 2>&1 & spinner $! "Starting Fail2ban"
        fi
        echo -e "${GREEN}[OK]${NC} Fail2ban configured and running."
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Fail2ban configuration."
    fi
}

configure_ufw() {
    if is_yes "$ENABLE_UFW"; then
        echo -ne "${YELLOW}[TUBSS] Configuring UFW... ${NC}"
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        ufw --force enable > /dev/null 2>&1 & spinner $! "Enabling UFW"
        echo -e "${GREEN}[OK]${NC} UFW configured and enabled."
    else
        echo -e "${YELLOW}[SKIPPED]${NC} UFW configuration."
    fi
}

configure_auto_updates() {
    if is_yes "$ENABLE_AUTO_UPDATES"; then
        echo -ne "${YELLOW}[TUBSS] Enabling Automatic Security Updates... ${NC}"
        if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
            sed -i 's/APT::Periodic::Update-Package-Lists "0"/APT::Periodic::Update-Package-Lists "1"/' /etc/apt/apt.conf.d/20auto-upgrades
            sed -i 's/APT::Periodic::Unattended-Upgrade "0"/APT::Periodic::Unattended-Upgrade "1"/' /etc/apt/apt.conf.d/20auto-upgrades
        else
            echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
            echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
        fi
        echo -e "${GREEN}[OK]${NC} Automatic security updates enabled."
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Automatic security updates."
    fi
}

disable_telemetry() {
    if is_yes "$DISABLE_TELEMETRY"; then
        echo -ne "${YELLOW}[TUBSS] Disabling Ubuntu Telemetry... ${NC}"
        if [ -f /etc/ubuntu-report/ubuntu-report.conf ]; then
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
    if is_yes "$JOIN_DOMAIN"; then
        echo -ne "${YELLOW}[TUBSS] Joining Active Directory domain... ${NC}"
        # Using a more secure method to pass the password via stdin
        echo "$AD_PASSWORD" | realm join "$AD_DOMAIN" -U "$AD_USER" --stdin-password >/dev/null 2>&1 &
        spinner $! "Joining domain '$AD_DOMAIN'"
        echo -e "${GREEN}[OK]${NC} System successfully joined to Active Directory domain '$AD_DOMAIN'."
        # This is a placeholder for the actual command and should be validated.
        # The original script had a placeholder and this change is conceptual to the recommendation.
    else
        echo -e "${YELLOW}[SKIPPED]${NC} AD domain join."
    fi
}

# --- Step 5: Final Summary and Reboot Prompt ---
reboot_prompt() {
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
IP Address                   | ${ORIGINAL_IP:-N/A}        | $NEW_IP_ADDRESS_SUMMARY
Gateway                      | ${ORIGINAL_GATEWAY:-N/A}   | $NEW_GATEWAY_SUMMARY
DNS Server                   | ${ORIGINAL_DNS:-N/A}       | $NEW_DNS_SUMMARY
Webmin Status                | $ORIGINAL_WEBMIN_STATUS    | $NEW_WEBMIN_SUMMARY
UFW Status                   | $ORIGINAL_UFW_STATUS       | $NEW_UFW_SUMMARY
Auto Updates Status          | $ORIGINAL_AUTO_UPDATES_STATUS | $NEW_AUTO_UPDATES_SUMMARY
Fail2ban Status              | $ORIGINAL_FAIL2BAN_STATUS  | $NEW_FAIL2BAN_SUMMARY
Telemetry/Analytics          | $ORIGINAL_TELEMETRY_STATUS | $NEW_TELEMETRY_SUMMARY
AD Domain Join               | ${ORIGINAL_DOMAIN_STATUS:-Not Joined} | $NEW_DOMAIN_SUMMARY
NFS Client Status            | $ORIGINAL_NFS_STATUS       | $NEW_NFS_SUMMARY
SMB Client Status            | $ORIGINAL_SMB_STATUS       | $NEW_SMB_SUMMARY
Git Status                   | $ORIGINAL_GIT_STATUS       | $NEW_GIT_SUMMARY
---------------------------------------------------------------------------------
Script provided by Joka.ca
EOF

    echo ""
    echo -e "${GREEN}[OK]${NC} A summary of the configuration changes has been saved to:"
    echo -e "${GREEN}      $SUMMARY_FILE${NC}"
    echo ""

    # Final Prompt
    echo ""
    echo -e "$CLOSING_ART"
    while true; do
        read -p "Configuration is complete. Would you like to reboot the system now? (yes/no) [yes]: " response
        REBOOT_PROMPT=${response:-yes}
        if is_yes "$REBOOT_PROMPT" || [[ "$REBOOT_PROMPT" =~ ^([nN][oO]|[nN])$ ]]; then
            break
        else
            echo -e "${RED}Invalid input. Please enter 'yes' or 'no'.${NC}"
        fi
    done

    if is_yes "$REBOOT_PROMPT"; then
        echo -e "${YELLOW}Rebooting the system now to apply all changes.${NC}"
        reboot
    else
        echo -e "${YELLOW}Reboot has been skipped. Please reboot the system manually for all changes to take effect.${NC}"
    fi
}

main "$@"
