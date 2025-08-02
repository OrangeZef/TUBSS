#!/bin/bash

#==============================================================================
# The Ubuntu Basic Setup Script (TUBSS)
# Version: 1.1
# Author: OrangeZef
#
# This script automates the initial setup and hardening of a new Ubuntu server.
#
# Changelog:
# - Added robust input validation to prevent command injection.
# - Refactored script into modular functions for better readability and maintenance.
# - Improved error handling and exit traps.
# - Ensured all function variables are declared as local.
# - Simplified summary generation logic for increased reliability.
#
# Features:
# - Automated Security (UFW, Fail2ban)
# - Essential Utilities (Git, NFS Client, SMB Client, networking tools)
# - Optional Network Configuration for a static IP
# - Automatic Security Updates
# - Telemetry Disablement
# - Summary of proposed changes and final report
#
# Provided by Joka.ca
#==============================================================================

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

# Exit immediately if a command exits with a non-zero status. This is a
# crucial security and robustness feature.
set -e

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
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
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
    echo -e "${BLACK}${YELLOW}"
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
    local original_user_home original_user

    # Get the original user's desktop path for the summary file
    original_user=$(logname)
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
    ORIGINAL_DNS=$(resolvectl status | grep 'DNS Servers' | awk '{print $3}' | head -n 1)
    ORIGINAL_WEBMIN_STATUS=$(dpkg -s webmin &>/dev/null && echo "Installed" || echo "Not Installed")
    ORIGINAL_UFW_STATUS=$(ufw status | grep 'Status:' | awk '{print $2}')
    ORIGINAL_AUTO_UPDATES_STATUS=$(grep -q "Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades &>/dev/null && echo "Enabled" || echo "Disabled")
    ORIGINAL_FAIL2BAN_STATUS=$(dpkg -s fail2ban &>/dev/null && echo "Installed" || echo "Not Installed")
    ORIGINAL_DOMAIN_STATUS=$(realm list 2>/dev/null | grep 'realm-name:' | awk '{print $2}')
    ORIGINAL_TELEMETRY_STATUS=$(dpkg -s ubuntu-report &>/dev/null && echo "Enabled" || echo "Disabled")
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
    echo -e "${YELLOW}Disk Usage (/):     ${NC}$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 " used)"}')"
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
        CREATE_SNAPSHOT=$(echo "$CREATE_SNAPSHOT" | tr '[:upper:]' '[:lower:]')
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
        CREATE_SNAPSHOT=$(echo "$CREATE_SNAPSHOT" | tr '[:upper:]' '[:lower:]')
    elif command -v btrfs &> /dev/null; then
        if df -t btrfs / | grep -q ' /$'; then
            echo -e "${YELLOW}Btrfs root filesystem detected.${NC}"
            if [[ "$CONFIG_CHOICE" == "default" ]]; then
                CREATE_SNAPSHOT="yes"
            else
                read -p "Do you want to create a Btrfs snapshot for rollback? (yes/no) [yes]: " CREATE_SNAPSHOT
                CREATE_SNAPSHOT=${CREATE_SNAPSHOT:-yes}
            fi
        fi
        CREATE_SNAPSHOT=$(echo "$CREATE_SNAPSHOT" | tr '[:upper:]' '[:lower:]')
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

        if [ -n "$ORIGINAL_DOMAIN_STATUS" ]; then
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
    if [[ "$JOIN_DOMAIN" == "yes" ]]; then
        echo ""
        echo -e "${YELLOW}--- Active Directory Details ---${NC}"
        read -p "Enter the Active Directory domain name (e.g., joka.ca): " AD_DOMAIN
        read -p "Enter the domain administrator username (e.g., admin.user): " AD_USER
        echo "Enter the password for the administrator account."
        echo "Note: The password will not be displayed as you type."
        read -s -p "Password: " AD_PASSWORD
    fi
}

# --- Step 3: Show Summary and Confirm ---
show_summary_and_confirm() {
    local new_webmin_summary new_ufw_summary new_auto_updates_summary new_fail2ban_summary
    local new_telemetry_summary new_domain_summary new_nfs_summary new_smb_summary new_git_summary
    local new_ip_address_summary new_gateway_summary new_dns_summary

    new_webmin_summary=$(if [ "$INSTALL_WEBMIN" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)
    new_ufw_summary=$(if [ "$ENABLE_UFW" == "yes" ]; then echo "To be Enabled"; else echo "Skipped"; fi)
    new_auto_updates_summary=$(if [ "$ENABLE_AUTO_UPDATES" == "yes" ]; then echo "To be Enabled"; else echo "Skipped"; fi)
    new_fail2ban_summary=$(if [ "$INSTALL_FAIL2BAN" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)
    new_telemetry_summary=$(if [ "$DISABLE_TELEMETRY" == "yes" ]; then echo "To be Disabled"; else echo "Skipped"; fi)
    new_domain_summary=$(if [ "$JOIN_DOMAIN" == "yes" ]; then echo "To be Joined"; else echo "Skipped"; fi)
    new_nfs_summary=$(if [ "$INSTALL_NFS" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)
    new_smb_summary=$(if [ "$INSTALL_SMB" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)
    new_git_summary=$(if [ "$INSTALL_GIT" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)

    new_ip_address_summary=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$STATIC_IP/$NETMASK_CIDR"; else echo "N/A"; fi)
    new_gateway_summary=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$GATEWAY"; else echo "N/A"; fi)
    new_dns_summary=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$DNS_SERVER"; else echo "N/A"; fi)

    echo ""
    echo -e "$SUMMARY_ART"
    printf "%-30b | %-20s | %-20s\n" "Setting" "Original Value" "New Value"
    printf "%-30s | %-20s | %-20s\n" "------------------------------" "--------------------" "--------------------"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Hostname:${NC}" "${ORIGINAL_HOSTNAME}" "${HOSTNAME}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Network Type:${NC}" "${ORIGINAL_NET_TYPE}" "${NET_TYPE}"
    if [[ "$NET_TYPE" == "static" ]]; then
        printf "%-30b | %-20s | %-20s\n" "${YELLOW}IP Address:${NC}" "${ORIGINAL_IP:-N/A}" "${new_ip_address_summary}"
        printf "%-30b | %-20s | %-20s\n" "${YELLOW}Gateway:${NC}" "${ORIGINAL_GATEWAY:-N/A}" "${new_gateway_summary}"
        printf "%-30b | %-20s | %-20s\n" "${YELLOW}DNS Server:${NC}" "${ORIGINAL_DNS:-N/A}" "${new_dns_summary}"
    fi
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Filesystem Snapshot:${NC}" "N/A" "${CREATE_SNAPSHOT}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Webmin Status:${NC}" "${ORIGINAL_WEBMIN_STATUS}" "${new_webmin_summary}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}UFW Firewall Status:${NC}" "${ORIGINAL_UFW_STATUS}" "${new_ufw_summary}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Auto Updates Status:${NC}" "${ORIGINAL_AUTO_UPDATES_STATUS}" "${new_auto_updates_summary}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Fail2ban Status:${NC}" "${ORIGINAL_FAIL2BAN_STATUS}" "${new_fail2ban_summary}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Telemetry/Analytics:${NC}" "${ORIGINAL_TELEMETRY_STATUS}" "${new_telemetry_summary}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}AD Domain Join:${NC}" "${ORIGINAL_DOMAIN_STATUS:-Not Joined}" "${new_domain_summary}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}NFS Client Status:${NC}" "${ORIGINAL_NFS_STATUS}" "${new_nfs_summary}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}SMB Client Status:${NC}" "${ORIGINAL_SMB_STATUS}" "${new_smb_summary}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Git Status:${NC}" "${ORIGINAL_GIT_STATUS}" "${new_git_summary}"
    echo -e "--------------------------------------------------------"

    read -p "Does the above configuration look correct? (yes/no) [yes]: " CONFIRM_EXECUTION
    CONFIRM_EXECUTION=${CONFIRM_EXECUTION:-yes}
    CONFIRM_EXECUTION=$(echo "$CONFIRM_EXECUTION" | tr '[:upper:]' '[:lower:]')

    if [[ "$CONFIRM_EXECUTION" != "yes" ]]; then
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
    if [[ "$CREATE_SNAPSHOT" == "yes" ]]; then
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
        elif command -v btrfs &> /dev/null && df -t btrfs / | grep -q ' /$'; then
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
    local packages_to_install
    echo -ne "${YELLOW}[TUBSS] Updating package lists...${NC}"
    apt-get update -y > /dev/null 2>&1 & spinner $! "Updating package lists"
    echo -e "${GREEN}[OK]${NC} Package lists updated."

    packages_to_install="curl ufw unattended-upgrades apparmor net-tools htop neofetch vim build-essential rsync"
    
    if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then packages_to_install+=" fail2ban"; fi
    if [[ "$INSTALL_GIT" == "yes" ]]; then packages_to_install+=" git"; fi
    if [[ "$INSTALL_WEBMIN" == "yes" ]]; then packages_to_install+=" webmin"; fi
    if [[ "$INSTALL_NFS" == "yes" ]]; then packages_to_install+=" nfs-common"; fi
    if [[ "$INSTALL_SMB" == "yes" ]]; then packages_to_install+=" cifs-utils"; fi

    if [ -n "$packages_to_install" ]; then
        echo -ne "${YELLOW}[TUBSS] Installing packages...${NC}"
        apt-get install -y $packages_to_install > /dev/null 2>&1 & spinner $! "Installing packages"
        echo -e "${GREEN}[OK]${NC} All selected packages installed successfully."
    fi
}

configure_network() {
    local network_config_file
    echo -ne "${YELLOW}[TUBSS] Configuring Network... ${NC}"
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
    if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
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
    if [[ "$ENABLE_UFW" == "yes" ]]; then
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
    if [[ "$ENABLE_AUTO_UPDATES" == "yes" ]]; then
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
    if [[ "$DISABLE_TELEMETRY" == "yes" ]]; then
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
    if [[ "$JOIN_DOMAIN" == "yes" ]]; then
        echo -ne "${YELLOW}[TUBSS] Joining Active Directory domain... ${NC}"
        echo -e "${YELLOW}Placeholder: Domain join logic is not implemented in this script due to security concerns.${NC}"
    else
        echo -e "${YELLOW}[SKIPPED]${NC} AD domain join."
    fi
}

# --- Step 5: Final Summary and Reboot Prompt ---
reboot_prompt() {
    # Pre-calculate new status values before writing to the file to avoid syntax issues.
    local new_webmin_summary=$(if [ "$INSTALL_WEBMIN" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)
    local new_ufw_summary=$(if [ "$ENABLE_UFW" == "yes" ]; then echo "To be Enabled"; else echo "Skipped"; fi)
    local new_auto_updates_summary=$(if [ "$ENABLE_AUTO_UPDATES" == "yes" ]; then echo "To be Enabled"; else echo "Skipped"; fi)
    local new_fail2ban_summary=$(if [ "$INSTALL_FAIL2BAN" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)
    local new_telemetry_summary=$(if [ "$DISABLE_TELEMETRY" == "yes" ]; then echo "To be Disabled"; else echo "Skipped"; fi)
    local new_domain_summary=$(if [ "$JOIN_DOMAIN" == "yes" ]; then echo "To be Joined"; else echo "Skipped"; fi)
    local new_nfs_summary=$(if [ "$INSTALL_NFS" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)
    local new_smb_summary=$(if [ "$INSTALL_SMB" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)
    local new_git_summary=$(if [ "$INSTALL_GIT" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)
    local new_ip_address_summary=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$STATIC_IP/$NETMASK_CIDR"; else echo "N/A"; fi)
    local new_gateway_summary=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$GATEWAY"; else echo "N/A"; fi)
    local new_dns_summary=$(if [[ "$NET_TYPE" == "static" ]]; then echo "$DNS_SERVER"; else echo "N/A"; fi)

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
--------------------------------------------------------
Setting                      | Original Value             | New Value
-----------------------------|----------------------------|----------------------------
Hostname                     | $ORIGINAL_HOSTNAME           | $HOSTNAME
Filesystem Snapshot          | N/A                        | $SNAPSHOT_STATUS
Network Type                 | $ORIGINAL_NET_TYPE           | $NET_TYPE
IP Address                   | ${ORIGINAL_IP:-N/A}        | $new_ip_address_summary
Gateway                      | ${ORIGINAL_GATEWAY:-N/A}   | $new_gateway_summary
DNS Server                   | ${ORIGINAL_DNS:-N/A}       | $new_dns_summary
Webmin Status                | $ORIGINAL_WEBMIN_STATUS    | $new_webmin_summary
UFW Status                   | $ORIGINAL_UFW_STATUS       | $new_ufw_summary
Auto Updates Status          | $ORIGINAL_AUTO_UPDATES_STATUS | $new_auto_updates_summary
Fail2ban Status              | $ORIGINAL_FAIL2BAN_STATUS  | $new_fail2ban_summary
Telemetry/Analytics          | $ORIGINAL_TELEMETRY_STATUS | $new_telemetry_summary
AD Domain Join               | ${ORIGINAL_DOMAIN_STATUS:-Not Joined} | $new_domain_summary
NFS Client Status            | $ORIGINAL_NFS_STATUS       | $new_nfs_summary
SMB Client Status            | $ORIGINAL_SMB_STATUS       | $new_smb_summary
Git Status                   | $ORIGINAL_GIT_STATUS       | $new_git_summary
--------------------------------------------------------
Script provided by Joka.ca
EOF

    echo ""
    echo -e "${GREEN}[OK]${NC} A summary of the configuration changes has been saved to:"
    echo -e "${GREEN}      $SUMMARY_FILE${NC}"
    echo ""

    # Final Prompt
    echo ""
    echo -e "$CLOSING_ART"
    read -p "Configuration is complete. Would you like to reboot the system now? (yes/no) [yes]: " REBOOT_PROMPT
    REBOOT_PROMPT=${REBOOT_PROMPT:-yes}
    REBOOT_PROMPT=$(echo "$REBOOT_PROMPT" | tr '[:upper:]' '[:lower:]')

    if [[ "$REBOOT_PROMPT" == "yes" ]]; then
        echo -e "${YELLOW}Rebooting the system now to apply all changes.${NC}"
        reboot
    else
        echo -e "${YELLOW}Reboot has been skipped. Please reboot the system manually for all changes to take effect.${NC}"
    fi
}

main "$@"
