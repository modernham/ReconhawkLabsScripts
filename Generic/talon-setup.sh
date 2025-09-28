#!/bin/bash

# Proxmox Cyber Security Assessment Device Setup Script
# Based on ReconhawkLabs "Build the Ultimate Cyber Security Assessment Device - Part 1"
# Run this script on first boot of Proxmox installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root"
   exit 1
fi

log "Starting Proxmox Cyber Security Assessment Device Setup"

# Detect primary network interface
detect_network_interface() {
    local interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$interface" ]]; then
        # Fallback: find first ethernet interface
        interface=$(ip link show | grep -E "^[0-9]+:" | grep -E "(eth|enp|ens)" | head -n1 | cut -d':' -f2 | tr -d ' ')
    fi
    echo "$interface"
}

# Get current FQDN
get_current_fqdn() {
    local fqdn=$(hostname -f 2>/dev/null || hostname)
    echo "$fqdn"
}

# Get hostname from FQDN
get_hostname() {
    local fqdn="$1"
    echo "${fqdn%%.*}"
}

# Configure DHCP networking
setup_dhcp_networking() {
    log "Configuring DHCP networking with VLAN support..."

    local interface=$(detect_network_interface)
    if [[ -z "$interface" ]]; then
        error "Could not detect network interface"
        exit 1
    fi

    info "Detected network interface: $interface"

    # Backup original interfaces file
    cp /etc/network/interfaces /etc/network/interfaces.backup

    # Create new interfaces configuration
    cat > /etc/network/interfaces << EOF
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# Physical interface
iface $interface inet manual

# Bridge interface with DHCP and VLAN support
auto vmbr0
iface vmbr0 inet dhcp
    bridge-ports $interface
    bridge-stp off
    bridge-fd 0
    bridge-vlan-aware yes
    bridge-vids 2-4094
EOF

    # Install DHCP client
    log "Installing DHCP client..."
    apt update
    apt install -y isc-dhcp-client

    # Create DHCP exit hooks for dynamic /etc/hosts update
    local fqdn=$(get_current_fqdn)
    local hostname=$(get_hostname "$fqdn")

    log "Setting up DHCP exit hooks for FQDN: $fqdn"

    mkdir -p /etc/dhcp/dhclient-exit-hooks.d
    cat > /etc/dhcp/dhclient-exit-hooks.d/update-etc-hosts << EOF
#!/bin/bash
if [ "\$reason" = "BOUND" ] || [ "\$reason" = "RENEW" ]; then
    sed -i "s/^.*\s$fqdn\s.*$/\${new_ip_address} $fqdn $hostname/" /etc/hosts
fi
EOF
    chmod +x /etc/dhcp/dhclient-exit-hooks.d/update-etc-hosts

    # Bring up interfaces
    log "Bringing up network interfaces..."
    ifup $interface || true
    ifup vmbr0 || true
}

# Configure WiFi (optional)
setup_wifi() {
    read -p "Do you want to configure WiFi? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return
    fi

    log "Configuring WiFi..."

    # Check for WiFi interface
    local wifi_interface=$(ip link show | grep -E "^[0-9]+:" | grep -E "(wlan|wlp)" | head -n1 | cut -d':' -f2 | tr -d ' ')
    if [[ -z "$wifi_interface" ]]; then
        warn "No WiFi interface found. Skipping WiFi configuration."
        return
    fi

    info "Detected WiFi interface: $wifi_interface"

    # Install WiFi tools
    apt install -y wpasupplicant

    # Get WiFi credentials
    read -p "Enter WiFi SSID: " wifi_ssid
    read -s -p "Enter WiFi password: " wifi_password
    echo

    # Generate WiFi configuration
    wpa_passphrase "$wifi_ssid" "$wifi_password" > /etc/wpa_supplicant/wpa_supplicant.conf

    # Create WiFi service
    cp /lib/systemd/system/wpa_supplicant.service /etc/systemd/system/wpa_supplicant.service

    # Update service configuration
    sed -i "s|ExecStart=/usr/sbin/wpa_supplicant -u -s -O.*|ExecStart=/sbin/wpa_supplicant -u -s -c /etc/wpa_supplicant/wpa_supplicant.conf -i $wifi_interface|" /etc/systemd/system/wpa_supplicant.service
    echo "Restart=always" >> /etc/systemd/system/wpa_supplicant.service

    # Create DHCP client service for WiFi
    cat > /etc/systemd/system/dhclient.service << EOF
[Unit]
Description=DHCP Client
Before=network.target
After=wpa_supplicant.service

[Service]
Type=forking
ExecStart=/sbin/dhclient $wifi_interface -v
ExecStop=/sbin/dhclient $wifi_interface -r
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Enable services
    systemctl daemon-reload
    systemctl enable wpa_supplicant.service
    systemctl enable dhclient.service

    log "WiFi configuration completed"
}

# Create user account
create_user_account() {
    read -p "Enter username for new user account: " username
    if [[ -z "$username" ]]; then
        error "Username cannot be empty"
        exit 1
    fi

    log "Creating user account: $username"

    # Install sudo if not present
    apt install -y sudo

    # Create user
    adduser "$username"

    # Add to sudo group
    usermod -aG sudo "$username"

    log "User $username created and added to sudo group"
}

# Install KDE Desktop Environment
install_kde_desktop() {
    log "Installing KDE Desktop Environment..."

    apt update && apt upgrade -y

    # Install KDE Plasma Desktop (slim version)
    apt install -y kde-plasma-desktop sddm-theme-breeze kwin-addons

    # Remove network manager if installed (we're using manual networking)
    apt remove --purge -y network-manager || true

    log "KDE Desktop Environment installed"
}

# Configure power management
configure_power_management() {
    log "Configuring power management settings..."

    # Create power management configuration
    mkdir -p /etc/kde
    cat > /etc/kde/powermanagementprofilesrc << EOF
[AC][DPMSControl]
idleTime=0

[AC][DimDisplay]
idleTime=0

[AC][HandleButtonEvents]
lidAction=1
powerButtonAction=0

[AC][SuspendSession]
idleTime=0
suspendThenHibernate=false
suspendType=0

[Battery][DPMSControl]
idleTime=0

[Battery][DimDisplay]
idleTime=0

[Battery][HandleButtonEvents]
lidAction=1
powerButtonAction=0

[Battery][SuspendSession]
idleTime=0
suspendThenHibernate=false
suspendType=0

[LowBattery][DPMSControl]
idleTime=0

[LowBattery][DimDisplay]
idleTime=0

[LowBattery][HandleButtonEvents]
lidAction=1
powerButtonAction=0

[LowBattery][SuspendSession]
idleTime=0
suspendThenHibernate=false
suspendType=0
EOF

    log "Power management configured for server operation"
}

# Expand filesystem storage
expand_filesystem() {
    log "Expanding filesystem storage..."

    # Remove LVM data volume and expand root
    lvremove -f /dev/pve/data || warn "Could not remove /dev/pve/data (may not exist)"
    lvresize -l +100%FREE /dev/pve/root || warn "Could not resize root volume"
    resize2fs /dev/mapper/pve-root || warn "Could not resize filesystem"

    log "Filesystem expansion completed"
}

# Install additional useful tools
install_additional_tools() {
    log "Installing additional useful tools..."

    apt install -y \
        curl \
        wget \
        tcpdump \
        nmap \
        git \
        firefox-esr \
        konsole \
        dolphin \
        kate

    log "Additional tools installed"
}

# Configure Proxmox web interface access
configure_proxmox_access() {
    log "Configuring Proxmox web interface..."

    info "Proxmox web interface will be available at: https://127.0.0.1:8006"
    info "Or via the current IP address on port 8006"

    # Ensure pveproxy is enabled and running
    systemctl enable pveproxy
    systemctl enable pvedaemon
    systemctl enable pvestatd
}

# Main execution
main() {
    log "=== Proxmox Cyber Security Assessment Device Setup ==="

    # Network configuration
    setup_dhcp_networking

    # WiFi setup (optional)
    setup_wifi

    # User account creation
    create_user_account

    # Desktop environment
    install_kde_desktop

    # Power management
    configure_power_management

    # Storage expansion
    expand_filesystem

    # Additional tools
    install_additional_tools

    # Proxmox configuration
    configure_proxmox_access

    log "=== Setup Complete ==="
    info "The system will reboot in 10 seconds..."
    info "After reboot:"
    info "1. Log in with the created user account"
    info "2. Access Proxmox web interface at https://localhost:8006"
    info "3. Configure power settings in KDE System Settings"
    info "4. Begin creating your assessment VMs"

    sleep 10
    reboot
}

# Run main function
main "$@"