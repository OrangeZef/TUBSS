#!/bin/bash

#==============================================================================
# The Ubuntu Basic Setup Script (TUBSS)
# Version: 1.0
# Author: OrangeZef
#
# This script automates the initial setup and hardening of a new Ubuntu server.
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

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Utility Functions ---

# Function to handle errors and exit gracefully
handle_error() {
    local exit_code=$?
    echo ""
    echo -e "${RED}--------------------------------------------------------${NC}"
    echo -e "${RED}An error occurred at line ${BASH_LINENO[0]} with command: ${BASH_COMMAND}${NC}"
    echo -e "${RED}Exit Code: ${exit_code}${NC}"
    echo -e "${RED}--------------------------------------------------------${NC}"
    echo ""

    while true; do
        read -p "$(echo -e "${RED}Would you like to continue? (yes/no):${NC} ")" choice
        case "$choice" in
            [Yy][Ee][Ss]|[Yy])
                echo -e "${YELLOW}Continuing with the script...${NC}"
                return 0
                ;;
            [Nn][Oo]|[Nn])
                echo -e "${RED}Exiting script due to user request.${NC}"
                exit 1
                ;;
            *)
                echo -e "${RED}Please answer 'yes' or 'no'.${NC}"
                ;;
        esac
    done
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
trap handle_error ERR
trap cleanup EXIT

# --- Main script ---
# Change terminal colors
echo -e "${BLACK}${YELLOW}"
clear

# Display banner art and system info
echo -e "$BANNER_ART"
echo -e "--------------------------------------------------------"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run with root privileges. Please use sudo.${NC}"
    exit 1
fi

# --- Get the original user's desktop path for the summary file ---
ORIGINAL_USER=$(logname)
ORIGINAL_USER_HOME=$(getent passwd "$ORIGINAL_USER" | cut -d: -f6)
DESKTOP_DIR="$ORIGINAL_USER_HOME/Desktop"
if [ ! -d "$DESKTOP_DIR" ]; then
    DESKTOP_DIR="$ORIGINAL_USER_HOME"
fi
SUMMARY_FILE="$DESKTOP_DIR/tubss_configuration_summary_$(date +%Y%m%d_%H%M%S).txt"

# --- Capture Before Values ---
# Use a more reliable way to get the primary IP, gateway, and interface.
ORIGINAL_IP_CIDR=$(ip -o -4 a | awk '{print $4}' | grep -v 'lo' | head -n 1)
if [[ "$ORIGINAL_IP_CIDR" =~ "/" ]]; then
    ORIGINAL_IP=$(echo "$ORIGINAL_IP_CIDR" | cut -d/ -f1)
    ORIGINAL_NETMASK_CIDR=$(echo "$ORIGINAL_IP_CIDR" | cut -d/ -f2)
    ORIGINAL_NETMASK=$(cidr2mask "$ORIGINAL_NETMASK_CIDR")
else
    # Fallback if no CIDR is found
    ORIGINAL_IP=$ORIGINAL_IP_CIDR
    ORIGINAL_NETMASK_CIDR="24" # A safe default
    ORIGINAL_NETMASK="255.255.255.0"
fi
ORIGINAL_INTERFACE=$(ip -o -4 a | awk '{print $2}' | grep -v 'lo' | head -n 1)
ORIGINAL_GATEWAY=$(ip r | grep default | awk '{print $3}' | head -n 1)

# Add a new variable to detect the original network type (DHCP or static)
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

# --- System Information Screen ---
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

# --- Initial Prompt for Defaults ---
echo ""
read -p "Would you like to use the default configuration or manually configure each option? (default/manual) [default]: " CONFIG_CHOICE
CONFIG_CHOICE=${CONFIG_CHOICE:-default}
CONFIG_CHOICE=$(echo "$CONFIG_CHOICE" | tr '[:upper:]' '[:lower:]')

# --- User Configuration Prompts ---
echo -e "${YELLOW}--------------------------------------------------------${NC}"
echo -e "${YELLOW}     Please provide your configuration choices.${NC}"
echo -e "${YELLOW}--------------------------------------------------------${NC}"
echo ""

# Filesystem Snapshot
SNAPSHOT_STATUS="Not Applicable"
CREATE_SNAPSHOT="no" # Default to no
# Check if Timeshift is installed first, then ZFS/Btrfs
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
    ZFS_ROOT_DATASET=$(zfs list -o name,mountpoint -t filesystem | grep " /$" | awk '{print $1}')
    if [ -n "$ZFS_ROOT_DATASET" ]; then
        echo -e "${YELLOW}ZFS root filesystem detected: ${ZFS_ROOT_DATASET}${NC}"
        if [[ "$CONFIG_CHOICE" == "default" ]]; then
            CREATE_SNAPSHOT="yes"
        else
            read -p "Do you want to create a ZFS snapshot for rollback? (yes/no) [yes]: " CREATE_SNAPSHOT
            CREATE_SNAPSHOT=${CREATE_SNAPSHOT:-yes}
        fi
    else
        echo -e "${YELLOW}ZFS tools found but no ZFS root filesystem detected. Skipping snapshot.${NC}"
    fi
    CREATE_SNAPSHOT=$(echo "$CREATE_SNAPSHOT" | tr '[:upper:]' '[:lower:]')
elif command -v btrfs &> /dev/null; then
    if [ -n "$(df -t btrfs / | grep -q ' /$' && echo 'found')" ]; then
        echo -e "${YELLOW}Btrfs root filesystem detected.${NC}"
        if [[ "$CONFIG_CHOICE" == "default" ]]; then
            CREATE_SNAPSHOT="yes"
        else
            read -p "Do you want to create a Btrfs snapshot for rollback? (yes/no) [yes]: " CREATE_SNAPSHOT
            CREATE_SNAPSHOT=${CREATE_SNAPSHOT:-yes}
        fi
    else
        echo -e "${YELLOW}Btrfs tools found but no Btrfs root filesystem detected. Skipping snapshot.${NC}"
    fi
    CREATE_SNAPSHOT=$(echo "$CREATE_SNAPSHOT" | tr '[:upper:]' '[:lower:]')
else
    echo -e "${YELLOW}No supported snapshot utilities (Timeshift, ZFS, or Btrfs) detected. Skipping snapshot.${NC}"
fi

# Hostname
if [[ "$CONFIG_CHOICE" == "default" ]]; then
    HOSTNAME="$ORIGINAL_HOSTNAME"
else
    read -p "Enter the desired hostname for this machine [$ORIGINAL_HOSTNAME]: " HOSTNAME
    HOSTNAME=${HOSTNAME:-$ORIGINAL_HOSTNAME}
fi

# Network Configuration
if [[ "$CONFIG_CHOICE" == "default" ]]; then
    NET_TYPE="dhcp"
else
    read -p "Do you want to use DHCP or a static IP? (dhcp/static) [dhcp]: " NET_TYPE
    NET_TYPE=${NET_TYPE:-dhcp}
    NET_TYPE=$(echo "$NET_TYPE" | tr '[:upper:]' '[:lower:]')
fi

# Static IP specific prompts
if [[ "$NET_TYPE" == "static" ]]; then
    if [[ "$CONFIG_CHOICE" == "default" ]]; then
        STATIC_IP="192.168.1.100" # A common but generic default
        NETMASK_CIDR="24"
        GATEWAY="192.168.1.1"
        DNS_SERVER="8.8.8.8"
    else
        echo ""
        echo "Please provide the network interface name for the static IP configuration."
        echo "Available network interfaces are:"
        ls /sys/class/net | grep -v 'lo'
        FIRST_INTERFACE=$(ls /sys/class/net | grep -v 'lo' | head -n 1)
        while true; do
            read -p "Enter the network interface name (e.g., enp0s3) [$FIRST_INTERFACE]: " INTERFACE_NAME
            INTERFACE_NAME=${INTERFACE_NAME:-$FIRST_INTERFACE}
            if [ -d "/sys/class/net/$INTERFACE_NAME" ]; then
                break
            else
                echo "Error: Interface '$INTERFACE_NAME' not found. Please enter a valid interface name."
            fi
        done
        read -p "Enter the static IP address (e.g., ${ORIGINAL_IP}): " STATIC_IP
        read -p "Enter the network mask (CIDR notation, e.g., 24) [${ORIGINAL_NETMASK_CIDR}]: " NETMASK_CIDR
        NETMASK_CIDR=${NETMASK_CIDR:-$ORIGINAL_NETMASK_CIDR}
        read -p "Enter the gateway IP address (e.g., $ORIGINAL_GATEWAY) [$ORIGINAL_GATEWAY]: " GATEWAY
        GATEWAY=${GATEWAY:-$ORIGINAL_GATEWAY}
        read -p "Enter the DNS server IP address (e.g., $ORIGINAL_DNS) [$ORIGINAL_DNS]: " DNS_SERVER
        DNS_SERVER=${DNS_SERVER:-$ORIGINAL_DNS}
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

    # SSSD prompts if joining a domain
    if [ -n "$ORIGINAL_DOMAIN_STATUS" ]; then
        echo -e "${YELLOW}Your system is currently joined to the domain: ${ORIGINAL_DOMAIN_STATUS}${NC}"
        read -p "Do you want to leave this domain and join another? (yes/no) [no]: " JOIN_DOMAIN
        JOIN_DOMAIN=${JOIN_DOMAIN:-no}
    else
        read -p "Do you want to join an Active Directory domain? (yes/no) [no]: " JOIN_DOMAIN
        JOIN_DOMAIN=${JOIN_DOMAIN:-no}
    fi

    # New services
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

# --- Pre-Execution Configuration Review ---
echo ""
echo -e "$SUMMARY_ART"
# Use %-30b to enable color interpretation in printf
printf "%-30b | %-20s | %-20s\n" "Setting" "Original Value" "New Value"
printf "%-30s | %-20s | %-20s\n" "------------------------------" "--------------------" "--------------------"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}Hostname:${NC}" "${ORIGINAL_HOSTNAME}" "${HOSTNAME}"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}Network Type:${NC}" "${ORIGINAL_NET_TYPE}" "${NET_TYPE}"
if [[ "$NET_TYPE" == "static" ]]; then
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}IP Address:${NC}" "${ORIGINAL_IP:-N/A}" "${STATIC_IP}/${NETMASK_CIDR}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}Gateway:${NC}" "${ORIGINAL_GATEWAY:-N/A}" "${GATEWAY}"
    printf "%-30b | %-20s | %-20s\n" "${YELLOW}DNS Server:${NC}" "${ORIGINAL_DNS:-N/A}" "${DNS_SERVER}"
fi
printf "%-30b | %-20s | %-20s\n" "${YELLOW}Filesystem Snapshot:${NC}" "N/A" "${CREATE_SNAPSHOT}"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}Webmin Status:${NC}" "${ORIGINAL_WEBMIN_STATUS}" "$(if [ "$INSTALL_WEBMIN" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}UFW Firewall Status:${NC}" "${ORIGINAL_UFW_STATUS}" "$(if [ "$ENABLE_UFW" == "yes" ]; then echo "To be Enabled"; else echo "Skipped"; fi)"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}Auto Updates Status:${NC}" "${ORIGINAL_AUTO_UPDATES_STATUS}" "$(if [ "$ENABLE_AUTO_UPDATES" == "yes" ]; then echo "To be Enabled"; else echo "Skipped"; fi)"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}Fail2ban Status:${NC}" "${ORIGINAL_FAIL2BAN_STATUS}" "$(if [ "$INSTALL_FAIL2BAN" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}Telemetry/Analytics:${NC}" "${ORIGINAL_TELEMETRY_STATUS}" "$(if [ "$DISABLE_TELEMETRY" == "yes" ]; then echo "To be Disabled"; else echo "Skipped"; fi)"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}AD Domain Join:${NC}" "${ORIGINAL_DOMAIN_STATUS:-Not Joined}" "$(if [ "$JOIN_DOMAIN" == "yes" ]; then echo "To be Joined"; else echo "Skipped"; fi)"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}NFS Client Status:${NC}" "${ORIGINAL_NFS_STATUS}" "$(if [[ "$INSTALL_NFS" == "yes" ]]; then echo "To be Installed"; else echo "Skipped"; fi)"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}SMB Client Status:${NC}" "${ORIGINAL_SMB_STATUS}" "$(if [[ "$INSTALL_SMB" == "yes" ]]; then echo "To be Installed"; else echo "Skipped"; fi)"
printf "%-30b | %-20s | %-20s\n" "${YELLOW}Git Status:${NC}" "${ORIGINAL_GIT_STATUS}" "$(if [[ "$INSTALL_GIT" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)"
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

# --- Main Configuration Steps ---

# --- Filesystem Snapshot ---
if [[ "$CREATE_SNAPSHOT" == "yes" ]]; then
    if command -v timeshift &> /dev/null; then
        SNAPSHOT_NAME="tubss-pre-config-$(date +%Y%m%d-%H%M)"
        timeshift --create --comments "TUBSS Pre-Setup Snapshot" &>/dev/null & spinner $! "Creating Timeshift snapshot"
        SNAPSHOT_STATUS="Created: Timeshift"
        echo -e "${GREEN}[OK]${NC} Timeshift snapshot created successfully."
    elif [ -n "$ZFS_ROOT_DATASET" ]; then
        SNAPSHOT_NAME="tubss-pre-config-$(date +%Y%m%d-%H%M)"
        zfs snapshot "${ZFS_ROOT_DATASET}@${SNAPSHOT_NAME}" &>/dev/null & spinner $! "Creating ZFS snapshot"
        SNAPSHOT_STATUS="Created: $SNAPSHOT_NAME (ZFS)"
        echo -e "${GREEN}[OK]${NC} ZFS snapshot created successfully."
    elif [ -n "$(df -t btrfs / | grep -q ' /$' && echo 'found')" ]; then
        SNAPSHOT_NAME="tubss-pre-config-$(date +%Y%m%d-%H%M)"
        btrfs subvolume create /@snapshots &>/dev/null
        btrfs subvolume snapshot -r "/@" "/@snapshots/$SNAPSHOT_NAME" &>/dev/null & spinner $! "Creating Btrfs snapshot"
        SNAPSHOT_STATUS="Created: $SNAPSHOT_NAME (Btrfs)"
        echo -e "${GREEN}[OK]${NC} Btrfs snapshot created successfully."
    fi
else
    SNAPSHOT_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} Snapshot creation."
fi

# --- Hostname Configuration ---
echo -ne "${YELLOW}[TUBSS] Setting Hostname... ${NC}"
if [[ "$HOSTNAME" != "$ORIGINAL_HOSTNAME" ]]; then
    hostnamectl set-hostname "$HOSTNAME"
    NEW_HOSTNAME=$(hostname)
    echo -e "${GREEN}[OK]${NC} Hostname set to '$NEW_HOSTNAME'."
else
    NEW_HOSTNAME=$ORIGINAL_HOSTNAME
    echo -e "${YELLOW}[SKIPPED]${NC} Hostname is already '$HOSTNAME'."
fi

# --- Package Installation ---
echo -ne "${YELLOW}[TUBSS] Updating package lists...${NC}"
apt-get update -y > /dev/null 2>&1 & spinner $! "Updating package lists"
echo -e "${GREEN}[OK]${NC} Package lists updated."

PACKAGES_TO_INSTALL=""
if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then PACKAGES_TO_INSTALL+=" fail2ban"; fi
if [[ "$INSTALL_GIT" == "yes" ]]; then PACKAGES_TO_INSTALL+=" git"; fi
if [[ "$INSTALL_WEBMIN" == "yes" ]]; then PACKAGES_TO_INSTALL+=" webmin"; fi
if [[ "$INSTALL_NFS" == "yes" ]]; then PACKAGES_TO_INSTALL+=" nfs-common"; fi
if [[ "$INSTALL_SMB" == "yes" ]]; then PACKAGES_TO_INSTALL+=" cifs-utils"; fi

PACKAGES_TO_INSTALL+=" curl ufw unattended-upgrades apparmor net-tools htop neofetch vim build-essential rsync"

if [ -n "$PACKAGES_TO_INSTALL" ]; then
    echo -ne "${YELLOW}[TUBSS] Installing packages...${NC}"
    apt-get install -y $PACKAGES_TO_INSTALL > /dev/null 2>&1 & spinner $! "Installing packages"
    echo -e "${GREEN}[OK]${NC} All selected packages installed successfully."
fi

# --- Network Configuration ---
echo -ne "${YELLOW}[TUBSS] Configuring Network... ${NC}"
NETWORK_CONFIG_FILE="/etc/netplan/01-static-network.yaml"
if [[ "$NET_TYPE" == "dhcp" ]]; then
    if [ -f "$NETWORK_CONFIG_FILE" ]; then
        rm -f "$NETWORK_CONFIG_FILE"
        netplan apply
        echo -e "${GREEN}[OK]${NC} Switched to DHCP."
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Already using DHCP."
    fi
else
    # Create the Netplan YAML file for static IP
    cat << EOF > "$NETWORK_CONFIG_FILE"
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

# --- Fail2ban Configuration ---
if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
    echo -ne "${YELLOW}[TUBSS] Configuring Fail2ban... ${NC}"
    JAIL_FILE="/etc/fail2ban/jail.local"
    # Create or modify the jail.local file with basic, common configurations
    cat << EOF > "$JAIL_FILE"
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
    # Check if the fail2ban service is running, and restart it to apply changes
    if systemctl is-active --quiet fail2ban; then
        systemctl restart fail2ban > /dev/null 2>&1 & spinner $! "Restarting Fail2ban"
    else
        systemctl enable fail2ban > /dev/null 2>&1 & spinner $! "Enabling Fail2ban"
        systemctl start fail2ban > /dev/null 2>&1 & spinner $! "Starting Fail2ban"
    fi
    NEW_FAIL2BAN_STATUS="Configured"
    echo -e "${GREEN}[OK]${NC} Fail2ban configured and running."
else
    NEW_FAIL2BAN_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} Fail2ban configuration."
fi

# --- UFW Configuration ---
if [[ "$ENABLE_UFW" == "yes" ]]; then
    echo -ne "${YELLOW}[TUBSS] Configuring UFW... ${NC}"
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw --force enable > /dev/null 2>&1 & spinner $! "Enabling UFW"
    NEW_UFW_STATUS=$(ufw status | grep 'Status:' | awk '{print $2}')
    echo -e "${GREEN}[OK]${NC} UFW configured and enabled."
else
    NEW_UFW_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} UFW configuration."
fi

# --- Auto-Updates Configuration ---
if [[ "$ENABLE_AUTO_UPDATES" == "yes" ]]; then
    echo -ne "${YELLOW}[TUBSS] Enabling Automatic Security Updates... ${NC}"
    # Configure unattended upgrades
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
        sed -i 's/APT::Periodic::Update-Package-Lists "0"/APT::Periodic::Update-Package-Lists "1"/' /etc/apt/apt.conf.d/20auto-upgrades
        sed -i 's/APT::Periodic::Unattended-Upgrade "0"/APT::Periodic::Unattended-Upgrade "1"/' /etc/apt/apt.conf.d/20auto-upgrades
    else
        echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
        echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
    fi
    NEW_AUTO_UPDATES_STATUS="Enabled"
    echo -e "${GREEN}[OK]${NC} Automatic security updates enabled."
else
    NEW_AUTO_UPDATES_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} Automatic security updates."
fi

# --- Telemetry Disablement ---
if [[ "$DISABLE_TELEMETRY" == "yes" ]]; then
    echo -ne "${YELLOW}[TUBSS] Disabling Ubuntu Telemetry... ${NC}"
    if [ -f /etc/ubuntu-report/ubuntu-report.conf ]; then
        sed -i 's/^enable = true/enable = false/' etc/ubuntu-report/ubuntu-report.conf
        NEW_TELEMETRY_STATUS="Disabled"
        echo -e "${GREEN}[OK]${NC} Ubuntu telemetry disabled."
    else
        echo -e "${YELLOW}Warning: Ubuntu telemetry configuration file not found. Skipping.${NC}"
        NEW_TELEMETRY_STATUS="Skipped (File not found)"
    fi
else
    NEW_TELEMETRY_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} Telemetry disablement."
fi

# --- Active Directory Domain Join ---
if [[ "$JOIN_DOMAIN" == "yes" ]]; then
    echo -ne "${YELLOW}[TUBSS] Joining Active Directory domain... ${NC}"
    # The domain join logic is omitted for safety and requires more specific details.
    # A placeholder is provided here.
    # The real logic would involve `apt-get install realmd sssd ...` and `realm join ...`
    echo -e "${YELLOW}Placeholder: Domain join logic is not implemented in this script due to security concerns.${NC}"
    NEW_DOMAIN_STATUS="Skipped (Manual Action Required)"
else
    NEW_DOMAIN_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} AD domain join."
fi

# --- Final Summary & Reboot Prompt ---
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
IP Address                   | ${ORIGINAL_IP:-N/A}        | $(if [[ "$NET_TYPE" == "static" ]]; then echo "$STATIC_IP/$NETMASK_CIDR"; else echo "N/A"; fi)
Gateway                      | ${ORIGINAL_GATEWAY:-N/A}   | $(if [[ "$NET_TYPE" == "static" ]]; then echo "$GATEWAY"; else echo "N/A"; fi)
DNS Server                   | ${ORIGINAL_DNS:-N/A}       | $(if [[ "$NET_TYPE" == "static" ]]; then echo "$DNS_SERVER"; else echo "N/A"; fi)
Webmin Status                | $ORIGINAL_WEBMIN_STATUS    | $(if [[ "$INSTALL_WEBMIN" == "yes" ]]; then echo "To be Installed"; else echo "Skipped"; fi)
UFW Status                   | $ORIGINAL_UFW_STATUS       | $NEW_UFW_STATUS
Auto Updates Status          | $ORIGINAL_AUTO_UPDATES_STATUS | $(if [[ "$ENABLE_AUTO_UPDATES" == "yes" ]]; then echo "To be Enabled"; else echo "Skipped"; fi)
Fail2ban Status              | $ORIGINAL_FAIL2BAN_STATUS  | $NEW_FAIL2BAN_STATUS
Telemetry/Analytics          | $ORIGINAL_TELEMETRY_STATUS | $(if [[ "$DISABLE_TELEMETRY" == "yes" ]]; then echo "To be Disabled"; else echo "Skipped"; fi)
AD Domain Join               | ${ORIGINAL_DOMAIN_STATUS:-Not Joined} | $NEW_DOMAIN_STATUS
NFS Client Status            | $ORIGINAL_NFS_STATUS       | $(if [[ "$INSTALL_NFS" == "yes" ]]; then echo "To be Installed"; else echo "Skipped"; fi)
SMB Client Status            | $ORIGINAL_SMB_STATUS       | $(if [[ "$INSTALL_SMB" == "yes" ]]; then echo "To be Installed"; else echo "Skipped"; fi)
Git Status                   | $ORIGINAL_GIT_STATUS       | $(if [[ "$INSTALL_GIT" == "yes" ]]; then echo "To be Installed"; else echo "Skipped"; fi)
--------------------------------------------------------
Script provided by Joka.ca
EOF

echo ""
echo -e "${GREEN}[OK]${NC} A summary of the configuration changes has been saved to:"
echo -e "${GREEN}      $SUMMARY_FILE${NC}"
echo ""

# --- Final Prompt ---
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

