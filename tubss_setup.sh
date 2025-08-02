#!/bin/bash

# Define colors for the terminal
YELLOW='\033[1;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLACK='\033[40m'
NC='\033[0m' # No Color

# Define ANSI art for headers
BANNER_ART="
  _   _   _   _   _   _   _   _   _   _   _   _   _   _   _ 
 / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ 
( T | U | B | S | S |   | S | e | t | u | p |   | S | c | r |
 \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ 
  _   _   _   _   _   _   _   _   _   _   _   _   _   _   _ 
 / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ / \ 
( i | p | t |   | T | o | o | l | s |   | B | a | s | i | c |
 \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/
  _   _   _   _   _   _   _
 / \ / \ / \ / \ / \ / \ / \ 
( S | e | c | u | r | e )
 \_/ \_/ \_/ \_/ \_/ \_/ \_/
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
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
"

# --- Function to handle errors and exit gracefully ---
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

# --- Function to display a simple progress spinner with task name ---
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

# --- Cleanup function to be executed on script exit ---
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
echo -e "${YELLOW}Provided by Joka.ca${NC}"
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
ORIGINAL_HOSTNAME=$(hostname)
ORIGINAL_IP=$(ip -o -4 a | awk '{print $4}' | grep -v 'lo' | head -n 1)
ORIGINAL_GATEWAY=$(ip r | grep default | awk '{print $3}' | head -n 1)
ORIGINAL_DNS=$(resolvectl status | grep 'DNS Servers' | awk '{print $3}' | head -n 1)
ORIGINAL_WEBMIN_STATUS=$(dpkg -s webmin &>/dev/null && echo "Installed" || echo "Not Installed")
ORIGINAL_UFW_STATUS=$(ufw status | grep 'Status:' | awk '{print $2}')
ORIGINAL_AUTO_UPDATES_STATUS=$(grep -q "Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades &>/dev/null && echo "Enabled" || echo "Disabled")
ORIGINAL_FAIL2BAN_STATUS=$(dpkg -s fail2ban &>/dev/null && echo "Installed" || echo "Not Installed")
ORIGINAL_DOMAIN_STATUS=$(realm list 2>/dev/null | grep 'realm-name:' | awk '{print $2}')
ORIGINAL_TELEMETRY_STATUS=$(dpkg -s ubuntu-report &>/dev/null && echo "Enabled" || echo "Disabled")
ORIGINAL_NFS_STATUS=$(dpkg -s nfs-kernel-server &>/dev/null && echo "Installed" || echo "Not Installed")
ORIGINAL_SMB_STATUS=$(dpkg -s samba &>/dev/null && echo "Installed" || echo "Not Installed")
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
read -p "Do you want to use all default settings for the configuration? (yes/no) [yes]: " USE_DEFAULTS
USE_DEFAULTS=${USE_DEFAULTS:-yes}
USE_DEFAULTS=$(echo "$USE_DEFAULTS" | tr '[:upper:]' '[:lower:]')

# --- User Configuration Prompts ---
echo -e "${YELLOW}--------------------------------------------------------${NC}"
echo -e "${YELLOW}     Please provide your configuration choices.${NC}"
echo -e "${YELLOW}--------------------------------------------------------${NC}"
echo ""

# Filesystem Snapshot
SNAPSHOT_STATUS="Not Applicable"
CREATE_SNAPSHOT="no" # Default to no
ZFS_ROOT_DATASET=$(zfs list -o name,mountpoint -t filesystem | grep " /$" | awk '{print $1}')
BTRFS_ROOT_DATASET=$(df -t btrfs / | grep -q " /$" && echo "/@")
if [ -n "$ZFS_ROOT_DATASET" ]; then
    echo -e "${YELLOW}ZFS root filesystem detected: ${ZFS_ROOT_DATASET}${NC}"
    if [[ "$USE_DEFAULTS" == "yes" ]]; then
        CREATE_SNAPSHOT="yes"
    else
        read -p "Do you want to create a ZFS snapshot for rollback? (yes/no) [yes]: " CREATE_SNAPSHOT
        CREATE_SNAPSHOT=${CREATE_SNAPSHOT:-yes}
    fi
elif [ -n "$BTRFS_ROOT_DATASET" ]; then
    echo -e "${YELLOW}Btrfs root filesystem detected.${NC}"
    if [[ "$USE_DEFAULTS" == "yes" ]]; then
        CREATE_SNAPSHOT="yes"
    else
        read -p "Do you want to create a Btrfs snapshot for rollback? (yes/no) [yes]: " CREATE_SNAPSHOT
        CREATE_SNAPSHOT=${CREATE_SNAPSHOT:-yes}
    fi
else
    echo -e "${YELLOW}No ZFS or Btrfs root filesystem detected. Skipping snapshot.${NC}"
fi
CREATE_SNAPSHOT=$(echo "$CREATE_SNAPSHOT" | tr '[:upper:]' '[:lower:]')

# Hostname
if [[ "$USE_DEFAULTS" == "yes" ]]; then
    HOSTNAME="$ORIGINAL_HOSTNAME"
else
    read -p "Enter the desired hostname for this machine [$ORIGINAL_HOSTNAME]: " HOSTNAME
    HOSTNAME=${HOSTNAME:-$ORIGINAL_HOSTNAME}
fi

# Network Configuration
if [[ "$USE_DEFAULTS" == "yes" ]]; then
    NET_TYPE="dhcp"
else
    read -p "Do you want to use DHCP or a static IP? (dhcp/static) [dhcp]: " NET_TYPE
    NET_TYPE=${NET_TYPE:-dhcp}
    NET_TYPE=$(echo "$NET_TYPE" | tr '[:upper:]' '[:lower:]')
fi

# Static IP specific prompts
if [[ "$NET_TYPE" == "static" ]]; then
    INTERFACE_NAME=$(ip -o -4 a | grep -v 'lo' | awk '{print $2, $4}' | grep -v '127.0.0.1' | awk '{print $1}' | head -n 1)
    if [[ "$USE_DEFAULTS" == "yes" ]]; then
        STATIC_IP="192.168.1.100" # A common but generic default
        NETMASK="24"
        GATEWAY="192.168.1.1"
        DNS_SERVER="8.8.8.8"
        if [ -n "$INTERFACE_NAME" ]; then
            DEFAULT_IP_CIDR=$(ip -o -4 a | grep -v 'lo' | awk '{print $2, $4}' | grep "$INTERFACE_NAME" | awk '{print $2}' | head -n 1)
            DEFAULT_IP=$(echo "$DEFAULT_IP_CIDR" | cut -d/ -f1)
            DEFAULT_NETMASK_CIDR=$(echo "$DEFAULT_IP_CIDR" | cut -d/ -f2)
            DEFAULT_GATEWAY=$(ip r | grep default | awk '{print $3}' | head -n 1)
            DEFAULT_DNS=$(resolvectl status "$INTERFACE_NAME" | grep 'DNS Servers' | awk '{print $3}' | head -n 1)
            STATIC_IP="$DEFAULT_IP"
            NETMASK="$DEFAULT_NETMASK_CIDR"
            GATEWAY="$DEFAULT_GATEWAY"
            DNS_SERVER="$DEFAULT_DNS"
        fi
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
        read -p "Enter the static IP address (e.g., ${ORIGINAL_IP%/*}): " STATIC_IP
        read -p "Enter the network mask (e.g., ${ORIGINAL_IP#*/}): " NETMASK
        read -p "Enter the gateway IP address (e.g., $ORIGINAL_GATEWAY): " GATEWAY
        read -p "Enter the DNS server IP address (e.g., $ORIGINAL_DNS): " DNS_SERVER
    fi
fi

# Service and Security Prompts
if [[ "$USE_DEFAULTS" == "yes" ]]; then
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
    read -p "Do you want to install and configure NFS? (yes/no) [yes]: " INSTALL_NFS
    INSTALL_NFS=${INSTALL_NFS:-yes}
    read -p "Do you want to install and configure SMB? (yes/no) [yes]: " INSTALL_SMB
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
printf "%-30s | %-20s | %-20s\n" "Setting" "Original Value" "New Value"
printf "%-30s | %-20s | %-20s\n" "------------------------------" "--------------------" "--------------------"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Hostname:${NC}" "${ORIGINAL_HOSTNAME}" "${HOSTNAME}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Network Type:${NC}" "${ORIGINAL_IP:-N/A}" "${NET_TYPE}"
if [[ "$NET_TYPE" == "static" ]]; then
    printf "%-30s | %-20s | %-20s\n" "${YELLOW}IP Address:${NC}" "${ORIGINAL_IP:-N/A}" "${STATIC_IP}/${NETMASK}"
    printf "%-30s | %-20s | %-20s\n" "${YELLOW}Gateway:${NC}" "${ORIGINAL_GATEWAY:-N/A}" "${GATEWAY}"
    printf "%-30s | %-20s | %-20s\n" "${YELLOW}DNS Server:${NC}" "${ORIGINAL_DNS:-N/A}" "${DNS_SERVER}"
fi
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Filesystem Snapshot:${NC}" "N/A" "${CREATE_SNAPSHOT}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Webmin Status:${NC}" "${ORIGINAL_WEBMIN_STATUS}" "$(if [ "$INSTALL_WEBMIN" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}UFW Firewall Status:${NC}" "${ORIGINAL_UFW_STATUS}" "$(if [ "$ENABLE_UFW" == "yes" ]; then echo "To be Enabled"; else echo "Skipped"; fi)"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Auto Updates Status:${NC}" "${ORIGINAL_AUTO_UPDATES_STATUS}" "$(if [ "$ENABLE_AUTO_UPDATES" == "yes" ]; then echo "To be Enabled"; else echo "Skipped"; fi)"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Fail2ban Status:${NC}" "${ORIGINAL_FAIL2BAN_STATUS}" "$(if [ "$INSTALL_FAIL2BAN" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Telemetry/Analytics:${NC}" "${ORIGINAL_TELEMETRY_STATUS}" "$(if [ "$DISABLE_TELEMETRY" == "yes" ]; then echo "To be Disabled"; else echo "Skipped"; fi)"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}AD Domain Join:${NC}" "${ORIGINAL_DOMAIN_STATUS:-Not Joined}" "$(if [ "$JOIN_DOMAIN" == "yes" ]; then echo "To be Joined"; else echo "Skipped"; fi)"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}NFS Status:${NC}" "${ORIGINAL_NFS_STATUS}" "$(if [ "$INSTALL_NFS" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}SMB Status:${NC}" "${ORIGINAL_SMB_STATUS}" "$(if [ "$INSTALL_SMB" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Git Status:${NC}" "${ORIGINAL_GIT_STATUS}" "$(if [ "$INSTALL_GIT" == "yes" ]; then echo "To be Installed"; else echo "Skipped"; fi)"
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
    if [ -n "$ZFS_ROOT_DATASET" ]; then
        SNAPSHOT_NAME="tubss-pre-config-$(date +%Y%m%d-%H%M)"
        zfs snapshot "${ZFS_ROOT_DATASET}@${SNAPSHOT_NAME}" &>/dev/null & spinner $! "Creating ZFS snapshot"
        SNAPSHOT_STATUS="Created: $SNAPSHOT_NAME (ZFS)"
        echo -e "${GREEN}[OK]${NC} ZFS snapshot created successfully."
    elif [ -n "$BTRFS_ROOT_DATASET" ]; then
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
    NEW_IP=$(ip -o -4 a | awk '{print $4}' | grep -v 'lo' | head -n 1)
    NEW_GATEWAY=$(ip r | grep default | awk '{print $3}' | head -n 1)
    NEW_DNS=$(resolvectl status | grep 'DNS Servers' | awk '{print $3}' | head -n 1)
    NETWORK_CONFIG_STATUS="DHCP"
elif [[ "$NET_TYPE" == "static" ]]; then
    cat <<EOF > "$NETWORK_CONFIG_FILE"
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE_NAME:
      dhcp4: no
      addresses:
        - $STATIC_IP/$NETMASK
      routes:
        - to: default
          via: $GATEWAY
      nameservers:
        addresses:
          - $DNS_SERVER
EOF
    chmod 600 "$NETWORK_CONFIG_FILE"
    netplan apply
    NEW_IP="$STATIC_IP/$NETMASK"
    NEW_GATEWAY="$GATEWAY"
    NEW_DNS="$DNS_SERVER"
    NETWORK_CONFIG_STATUS="Static IP"
    echo -e "${GREEN}[OK]${NC} Static IP configured."
fi

# --- System Update and Package Installation ---
echo -ne "${YELLOW}[TUBSS] Updating package lists...${NC}"
apt-get update > /dev/null 2>&1 & spinner $! "Updating package lists"
echo -e "${GREEN}[OK]${NC} Package lists updated."

PACKAGES_TO_INSTALL=""
if [[ "$ENABLE_UFW" == "yes" ]] && ! dpkg -s ufw &>/dev/null; then PACKAGES_TO_INSTALL+=" ufw"; fi
if [[ "$INSTALL_WEBMIN" == "yes" ]] && ! dpkg -s webmin &>/dev/null; then PACKAGES_TO_INSTALL+=" webmin"; fi
if [[ "$INSTALL_FAIL2BAN" == "yes" ]] && ! dpkg -s logrotate &>/dev/null; then PACKAGES_TO_INSTALL+=" logrotate"; fi
if [[ "$INSTALL_FAIL2BAN" == "yes" ]] && ! dpkg -s fail2ban &>/dev/null; then PACKAGES_TO_INSTALL+=" fail2ban"; fi
if [[ "$JOIN_DOMAIN" == "yes" ]] && ! dpkg -s sssd realmd adcli &>/dev/null; then PACKAGES_TO_INSTALL+=" sssd realmd adcli"; fi
if ! dpkg -s openssh-server apt-transport-https net-tools &>/dev/null; then PACKAGES_TO_INSTALL+=" openssh-server apt-transport-https net-tools"; fi
if [[ "$INSTALL_NFS" == "yes" ]] && ! dpkg -s nfs-kernel-server &>/dev/null; then PACKAGES_TO_INSTALL+=" nfs-kernel-server"; fi
if [[ "$INSTALL_SMB" == "yes" ]] && ! dpkg -s samba &>/dev/null; then PACKAGES_TO_INSTALL+=" samba"; fi
if [[ "$INSTALL_GIT" == "yes" ]] && ! dpkg -s git &>/dev/null; then PACKAGES_TO_INSTALL+=" git"; fi

if [ -n "$PACKAGES_TO_INSTALL" ]; then
    echo -ne "${YELLOW}[TUBSS] Installing selected packages...${NC}"
    apt-get install -y $PACKAGES_TO_INSTALL > /dev/null 2>&1 & spinner $! "Installing packages"
    echo -e "${GREEN}[OK]${NC} Installation complete."
else
    echo -e "${YELLOW}[SKIPPED]${NC} No new packages to install."
fi

# --- Hardware-specific Tools ---
echo -ne "${YELLOW}[TUBSS] Installing hardware tools...${NC}"
if systemd-detect-virt &>/dev/null; then
    apt-get install -y open-vm-tools > /dev/null 2>&1 & spinner $! "Installing Open-VM-Tools"
    echo -e "${GREEN}[OK]${NC} Open-VM-Tools installed."
    HW_TOOLS_STATUS="Open-VM-Tools (VM)"
else
    apt-get install -y lshw pciutils usbutils > /dev/null 2>&1 & spinner $! "Installing hardware tools"
    echo -e "${GREEN}[OK]${NC} Hardware tools installed."
    HW_TOOLS_STATUS="lshw, pciutils, usbutils (Physical)"
fi

# --- Telemetry and Analytics Configuration ---
if [[ "$DISABLE_TELEMETRY" == "yes" ]]; then
    if dpkg -s ubuntu-report &>/dev/null; then
        echo -ne "${YELLOW}[TUBSS] Disabling 'ubuntu-report'...${NC}"
        systemctl disable --now ubuntu-report.service > /dev/null 2>&1
        apt-get purge -y ubuntu-report > /dev/null 2>&1 & spinner $! "Uninstalling ubuntu-report"
        echo -e "${GREEN}[OK]${NC} 'ubuntu-report' removed."
    fi
    if dpkg -s popularity-contest &>/dev/null; then
        echo -ne "${YELLOW}[TUBSS] Uninstalling 'popularity-contest'...${NC}"
        apt-get purge -y popularity-contest > /dev/null 2>&1 & spinner $! "Uninstalling popularity-contest"
        echo -e "${GREEN}[OK]${NC} 'popularity-contest' removed."
    fi
    NEW_TELEMETRY_STATUS="Disabled"
else
    NEW_TELEMETRY_STATUS="Enabled"
    echo -e "${YELLOW}[SKIPPED]${NC} Telemetry and analytics will remain enabled."
fi

# --- Webmin Configuration ---
if [[ "$INSTALL_WEBMIN" == "yes" ]]; then
    if [[ "$ORIGINAL_WEBMIN_STATUS" != "Installed" ]]; then
        wget -q http://www.webmin.com/jcameron-key.asc -O- | sudo apt-key add - &>/dev/null & spinner $! "Adding Webmin repository key"
        echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list
        apt-get update > /dev/null 2>&1
        apt-get install -y webmin > /dev/null 2>&1 & spinner $! "Installing Webmin"
        NEW_WEBMIN_STATUS="Installed"
        if [[ "$ENABLE_UFW" == "yes" ]]; then ufw allow 10000/tcp > /dev/null 2>&1; fi
        echo -e "${GREEN}[OK]${NC} Webmin installed and configured."
    else
        NEW_WEBMIN_STATUS="Installed"
        echo -e "${YELLOW}[SKIPPED]${NC} Webmin is already installed."
    fi
else
    NEW_WEBMIN_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} Webmin installation."
fi

# --- UFW Configuration ---
if [[ "$ENABLE_UFW" == "yes" ]]; then
    if [[ "$ORIGINAL_UFW_STATUS" != "active" ]]; then
        echo -ne "${YELLOW}[TUBSS] Enabling UFW and allowing SSH...${NC}"
        ufw enable > /dev/null 2>&1
        ufw allow ssh > /dev/null 2>&1
        echo -e "${GREEN}[OK]${NC} UFW enabled."
        NEW_UFW_STATUS="Enabled"
    else
        echo -e "${YELLOW}[SKIPPED]${NC} UFW is already enabled."
        NEW_UFW_STATUS="Enabled"
    fi
else
    NEW_UFW_STATUS="Disabled"
    echo -e "${YELLOW}[SKIPPED]${NC} UFW configuration."
fi

# --- Unattended-Upgrades Configuration ---
if [[ "$ENABLE_AUTO_UPDATES" == "yes" ]]; then
    if [[ "$ORIGINAL_AUTO_UPDATES_STATUS" != "Enabled" ]]; then
        echo -ne "${YELLOW}[TUBSS] Enabling automatic security updates...${NC}"
        dpkg-reconfigure --priority=low unattended-upgrades > /dev/null 2>&1
        echo -e "${GREEN}[OK]${NC} Automatic updates enabled."
        NEW_UNATTENDED_STATUS="Enabled"
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Automatic updates already enabled."
        NEW_UNATTENDED_STATUS="Enabled"
    fi
else
    NEW_UNATTENDED_STATUS="Disabled"
    echo -e "${YELLOW}[SKIPPED]${NC} Automatic updates configuration."
fi

# --- Fail2ban Configuration ---
if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
    if [[ "$ORIGINAL_FAIL2BAN_STATUS" != "Installed" ]]; then
        echo -ne "${YELLOW}[TUBSS] Installing Fail2ban...${NC}"
        apt-get install -y fail2ban > /dev/null 2>&1 & spinner $! "Installing Fail2ban"
        echo -e "${GREEN}[OK]${NC} Fail2ban installed."
    fi
    echo -ne "${YELLOW}[TUBSS] Configuring Fail2ban for SSH...${NC}"
    cat <<EOF > /etc/fail2ban/jail.d/ssh.local
[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 3
bantime = 1h
EOF
    chmod 644 /etc/fail2ban/jail.d/ssh.local
    systemctl restart fail2ban > /dev/null 2>&1
    echo -e "${GREEN}[OK]${NC} Fail2ban configured."
    NEW_FAIL2BAN_STATUS="Installed"
else
    NEW_FAIL2BAN_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} Fail2ban installation."
fi

# --- Log Rotation Configuration ---
if dpkg -s logrotate &>/dev/null && [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
    echo -ne "${YELLOW}[TUBSS] Creating log rotation policy for Fail2ban...${NC}"
    cat <<EOF > "/etc/logrotate.d/fail2ban"
/var/log/fail2ban.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    postrotate
        /usr/bin/systemctl reload fail2ban.service > /dev/null 2>&1 || true
    endscript
}
EOF
    echo -e "${GREEN}[OK]${NC} Log rotation configured."
    LOGROTATE_STATUS="Configured"
else
    LOGROTATE_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} Log rotation configuration."
fi

# --- SSSD and Active Directory Configuration ---
if [[ "$JOIN_DOMAIN" == "yes" ]]; then
    if [ -n "$ORIGINAL_DOMAIN_STATUS" ]; then
        echo -ne "${YELLOW}[TUBSS] Leaving existing domain...${NC}"
        realm leave > /dev/null 2>&1
        echo -e "${GREEN}[OK]${NC} Left ${ORIGINAL_DOMAIN_STATUS}."
    fi
    echo -ne "${YELLOW}[TUBSS] Joining domain '$AD_DOMAIN'...${NC}"
    echo "$AD_PASSWORD" | realm join "$AD_DOMAIN" --user="$AD_USER" > /dev/null 2>&1 & spinner $! "Joining Active Directory"
    unset AD_PASSWORD
    echo -e "${GREEN}[OK]${NC} Domain join successful."

    echo -ne "${YELLOW}[TUBSS] Enabling automatic home directory creation...${NC}"
    pam-auth-update --enable mkhomedir > /dev/null 2>&1
    echo -e "${GREEN}[OK]${NC} mkhomedir enabled."

    echo -ne "${YELLOW}[TUBSS] Configuring SSSD for AD integration...${NC}"
    cat <<EOF > "/etc/sssd/sssd.conf"
[sssd]
domains = $AD_DOMAIN
config_file_version = 2
services = nss, pam
default_domain_suffix = $AD_DOMAIN

[domain/$AD_DOMAIN]
ad_domain = $AD_DOMAIN
krb5_realm = $(echo "$AD_DOMAIN" | tr '[:lower:]' '[:upper:]')
realmd_tags = manages-system
cache_credentials = True
id_provider = ad
krb5_auth_timeout = 5
ldap_search_base = $(echo "$AD_DOMAIN" | sed 's/\./,dc=/g' | sed 's/^/dc=/')
ldap_schema = ad
ldap_uri = ldap://$AD_DOMAIN
use_fully_qualified_names = False
EOF
    chmod 600 /etc/sssd/sssd.conf
    systemctl restart sssd > /dev/null 2>&1
    systemctl enable sssd > /dev/null 2>&1
    echo -e "${GREEN}[OK]${NC} SSSD configured."

    echo -ne "${YELLOW}[TUBSS] Configuring sudo permissions for AD groups...${NC}"
    cat <<EOF > /etc/sudoers.d/ad_admins
%Domain\\ Admins ALL=(ALL:ALL) ALL
%Linux\\ Admins ALL=(ALL:ALL) ALL
EOF
    chmod 440 /etc/sudoers.d/ad_admins
    echo -e "${GREEN}[OK]${NC} Sudo permissions configured."
    NEW_DOMAIN_STATUS="Configured"
else
    NEW_DOMAIN_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} Active Directory join."
fi

# --- NFS Configuration ---
if [[ "$INSTALL_NFS" == "yes" ]]; then
    if [[ "$ORIGINAL_NFS_STATUS" != "Installed" ]]; then
        echo -ne "${YELLOW}[TUBSS] Installing NFS server...${NC}"
        apt-get install -y nfs-kernel-server > /dev/null 2>&1 & spinner $! "Installing NFS"
        echo -e "${GREEN}[OK]${NC} NFS server installed."
    fi
    echo -ne "${YELLOW}[TUBSS] Configuring NFS share at /srv/nfs_share...${NC}"
    mkdir -p /srv/nfs_share
    chown nobody:nogroup /srv/nfs_share
    echo "/srv/nfs_share *(rw,sync,no_subtree_check,crossmnt,fsid=0)" >> /etc/exports
    exportfs -a > /dev/null 2>&1
    systemctl restart nfs-kernel-server > /dev/null 2>&1
    if [[ "$ENABLE_UFW" == "yes" ]]; then ufw allow from 192.168.1.0/24 to any port nfs > /dev/null 2>&1; fi
    NEW_NFS_STATUS="Installed & Configured"
    echo -e "${GREEN}[OK]${NC} NFS share configured."
else
    NEW_NFS_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} NFS configuration."
fi

# --- SMB Configuration ---
if [[ "$INSTALL_SMB" == "yes" ]]; then
    if [[ "$ORIGINAL_SMB_STATUS" != "Installed" ]]; then
        echo -ne "${YELLOW}[TUBSS] Installing SMB server (Samba)...${NC}"
        apt-get install -y samba > /dev/null 2>&1 & spinner $! "Installing SMB"
        echo -e "${GREEN}[OK]${NC} SMB server installed."
    fi
    echo -ne "${YELLOW}[TUBSS] Configuring SMB share at /srv/smb_share...${NC}"
    mkdir -p /srv/smb_share
    chown root:smb_user /srv/smb_share
    chmod 2770 /srv/smb_share
    mv /etc/samba/smb.conf /etc/samba/smb.conf.bak
    cat <<EOF > /etc/samba/smb.conf
[global]
   workgroup = WORKGROUP
   server role = standalone server
   log file = /var/log/samba/log.%m
   max log size = 1000
   idmap config * : backend = tdb
   cups options = raw

[Share]
   comment = SMB Share
   path = /srv/smb_share
   browsable = yes
   writable = yes
   read only = no
   guest ok = yes
   force create mode = 0660
   force directory mode = 2770
   create mask = 0660
   directory mask = 2770
   valid users = smb_user
EOF
    useradd --no-create-home smb_user
    echo -e "smb_user\nsmb_user" | smbpasswd -a -s smb_user > /dev/null 2>&1
    systemctl restart smbd nmbd > /dev/null 2>&1
    if [[ "$ENABLE_UFW" == "yes" ]]; then ufw allow 'Samba' > /dev/null 2>&1; fi
    NEW_SMB_STATUS="Installed & Configured"
    echo -e "${GREEN}[OK]${NC} SMB share configured."
else
    NEW_SMB_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} SMB configuration."
fi

# --- Git Configuration ---
if [[ "$INSTALL_GIT" == "yes" ]]; then
    if [[ "$ORIGINAL_GIT_STATUS" != "Installed" ]]; then
        echo -ne "${YELLOW}[TUBSS] Installing Git...${NC}"
        apt-get install -y git > /dev/null 2>&1 & spinner $! "Installing Git"
        echo -e "${GREEN}[OK]${NC} Git installed."
    else
        echo -e "${YELLOW}[SKIPPED]${NC} Git is already installed."
    fi
    NEW_GIT_STATUS="Installed"
else
    NEW_GIT_STATUS="Skipped"
    echo -e "${YELLOW}[SKIPPED]${NC} Git installation."
fi

echo ""
echo -e "${YELLOW}--------------------------------------------------------${NC}"
echo -e "${YELLOW}                 Configuration complete!${NC}"
echo -e "${YELLOW}--------------------------------------------------------${NC}"

# --- Final Summary and Reboot ---
echo ""
echo -e "$SUMMARY_ART"
printf "%-30s | %-20s | %-20s\n" "Setting" "Original Value" "Final Value"
printf "%-30s | %-20s | %-20s\n" "------------------------------" "--------------------" "--------------------"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Hostname:${NC}" "${ORIGINAL_HOSTNAME}" "${NEW_HOSTNAME}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}IP Address:${NC}" "${ORIGINAL_IP:-N/A}" "${NEW_IP:-N/A}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Default Gateway:${NC}" "${ORIGINAL_GATEWAY:-N/A}" "${NEW_GATEWAY:-N/A}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}DNS Server:${NC}" "${ORIGINAL_DNS:-N/A}" "${NEW_DNS:-N/A}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Filesystem Snapshot:${NC}" "N/A" "${SNAPSHOT_STATUS}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Webmin Status:${NC}" "${ORIGINAL_WEBMIN_STATUS}" "${NEW_WEBMIN_STATUS}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}UFW Firewall Status:${NC}" "${ORIGINAL_UFW_STATUS}" "${NEW_UFW_STATUS}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Auto Updates Status:${NC}" "${ORIGINAL_AUTO_UPDATES_STATUS}" "${NEW_UNATTENDED_STATUS}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Fail2ban Status:${NC}" "${ORIGINAL_FAIL2BAN_STATUS}" "${NEW_FAIL2BAN_STATUS}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Telemetry/Analytics:${NC}" "${ORIGINAL_TELEMETRY_STATUS}" "${NEW_TELEMETRY_STATUS}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}AD Domain Join:${NC}" "${ORIGINAL_DOMAIN_STATUS:-Not Joined}" "${NEW_DOMAIN_STATUS}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}NFS Status:${NC}" "${ORIGINAL_NFS_STATUS}" "${NEW_NFS_STATUS}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}SMB Status:${NC}" "${ORIGINAL_SMB_STATUS}" "${NEW_SMB_STATUS}"
printf "%-30s | %-20s | %-20s\n" "${YELLOW}Git Status:${NC}" "${ORIGINAL_GIT_STATUS}" "${NEW_GIT_STATUS}"
echo -e "--------------------------------------------------------"
echo "Script provided by Joka.ca"

# --- Save summary to file ---
cat <<EOF > "$SUMMARY_FILE"
============================================================
           Configuration Summary from TUBSS
============================================================
Date: $(date)

Setting                      | Original Value       | Final Value          
------------------------------ | -------------------- | --------------------
Hostname                       | $ORIGINAL_HOSTNAME           | $NEW_HOSTNAME                
IP Address                     | ${ORIGINAL_IP:-N/A}         | ${NEW_IP:-N/A}              
Default Gateway                | ${ORIGINAL_GATEWAY:-N/A}    | ${NEW_GATEWAY:-N/A}        
DNS Server                     | ${ORIGINAL_DNS:-N/A}       | ${NEW_DNS:-N/A}            
Filesystem Snapshot            | N/A                  | $SNAPSHOT_STATUS            
Webmin Status                  | $ORIGINAL_WEBMIN_STATUS   | $NEW_WEBMIN_STATUS           
UFW Firewall Status            | $ORIGINAL_UFW_STATUS       | $NEW_UFW_STATUS              
Auto Updates Status            | $ORIGINAL_AUTO_UPDATES_STATUS | $NEW_UNATTENDED_STATUS        
Fail2ban Status                | $ORIGINAL_FAIL2BAN_STATUS | $NEW_FAIL2BAN_STATUS         
Telemetry/Analytics            | $ORIGINAL_TELEMETRY_STATUS | $NEW_TELEMETRY_STATUS       
AD Domain Join                 | ${ORIGINAL_DOMAIN_STATUS:-Not Joined} | $NEW_DOMAIN_STATUS             
NFS Status                     | $ORIGINAL_NFS_STATUS       | $NEW_NFS_STATUS            
SMB Status                     | $ORIGINAL_SMB_STATUS       | $NEW_SMB_STATUS            
Git Status                     | $ORIGINAL_GIT_STATUS       | $NEW_GIT_STATUS            

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
    echo -e "${YELLOW}Reboot not requested. The system will not reboot. Please remember to reboot manually at your convenience.${NC}"
fi
