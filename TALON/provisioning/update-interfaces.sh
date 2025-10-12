#!/bin/bash

################################################################################
# Network Interface Configuration Script
# Purpose: Automatically configure network interfaces for single or dual-NIC
#          systems using OVS bridge configuration templates
# Usage: sudo ./Configure_Network.sh
################################################################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_SINGLE="${SCRIPT_DIR}/interfaces_single"
TEMPLATE_SINGLE_MIRROR="${SCRIPT_DIR}/interfaces_single_mirror"
TEMPLATE_MIRROR="${SCRIPT_DIR}/interfaces_mirror"
TARGET_FILE="/etc/network/interfaces"
BACKUP_DIR="/root/network_backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

################################################################################
# Functions
################################################################################

print_header() {
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}  Network Interface Configuration Script${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        echo "Usage: sudo $0"
        exit 1
    fi
}

# Check if template files exist
check_templates() {
    local missing=0

    if [[ ! -f "$TEMPLATE_SINGLE" ]]; then
        print_error "Template file not found: $TEMPLATE_SINGLE"
        missing=1
    fi

    if [[ ! -f "$TEMPLATE_SINGLE_MIRROR" ]]; then
        print_error "Template file not found: $TEMPLATE_SINGLE_MIRROR"
        missing=1
    fi

    if [[ ! -f "$TEMPLATE_MIRROR" ]]; then
        print_error "Template file not found: $TEMPLATE_MIRROR"
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        print_error "Required template files are missing. Exiting."
        exit 1
    fi

    print_success "Template files found"
}

# Detect physical ethernet interfaces (excluding virtual, wireless, loopback)
detect_ethernet_interfaces() {
    local interfaces=()

    # Get all network interfaces from /sys/class/net
    for iface in /sys/class/net/*; do
        iface_name=$(basename "$iface")

        # Skip loopback
        [[ "$iface_name" == "lo" ]] && continue

        # Skip virtual interfaces (common patterns)
        [[ "$iface_name" =~ ^(veth|docker|br-|virbr|vmbr|tap|tun|vlan) ]] && continue

        # Skip wireless interfaces
        [[ "$iface_name" =~ ^(wlan|wlp|wl) ]] && continue

        # Check if it's a physical interface by checking for device directory
        if [[ -d "/sys/class/net/$iface_name/device" ]]; then
            # Additional check: verify it's ethernet (not wireless)
            if [[ ! -d "/sys/class/net/$iface_name/wireless" ]] && \
               [[ ! -d "/sys/class/net/$iface_name/phy80211" ]]; then
                interfaces+=("$iface_name")
            fi
        fi
    done

    echo "${interfaces[@]}"
}

# Display interfaces with details
display_interfaces() {
    local ifaces=("$@")
    echo ""
    print_info "Detected ethernet interfaces:"
    echo ""

    local idx=1
    for iface in "${ifaces[@]}"; do
        # Get MAC address
        local mac=""
        if [[ -f "/sys/class/net/$iface/address" ]]; then
            mac=$(cat "/sys/class/net/$iface/address")
        fi

        # Get link status
        local status="DOWN"
        if [[ -f "/sys/class/net/$iface/operstate" ]]; then
            local state=$(cat "/sys/class/net/$iface/operstate")
            [[ "$state" == "up" ]] && status="UP"
        fi

        # Get driver info
        local driver=""
        if [[ -L "/sys/class/net/$iface/device/driver" ]]; then
            driver=$(basename "$(readlink "/sys/class/net/$iface/device/driver")")
        fi

        printf "  %d) %-10s  MAC: %-17s  Status: %-4s" "$idx" "$iface" "$mac" "$status"
        [[ -n "$driver" ]] && printf "  Driver: %s" "$driver"
        echo ""

        ((idx++))
    done
    echo ""
}

# Prompt user to select an interface
select_interface() {
    local ifaces=("$@")
    local choice

    echo "" >&2
    echo "Available interfaces:" >&2
    echo "" >&2

    # Display numbered interface list
    local idx=1
    for iface in "${ifaces[@]}"; do
        # Get MAC address
        local mac=""
        if [[ -f "/sys/class/net/$iface/address" ]]; then
            mac=$(cat "/sys/class/net/$iface/address")
        fi

        # Get link status
        local status="DOWN"
        if [[ -f "/sys/class/net/$iface/operstate" ]]; then
            local state=$(cat "/sys/class/net/$iface/operstate")
            [[ "$state" == "up" ]] && status="UP"
        fi

        # Get driver info
        local driver=""
        if [[ -L "/sys/class/net/$iface/device/driver" ]]; then
            driver=$(basename "$(readlink "/sys/class/net/$iface/device/driver")")
        fi

        printf "  %d) %-10s  MAC: %-17s  Status: %-4s" "$idx" "$iface" "$mac" "$status" >&2
        [[ -n "$driver" ]] && printf "  Driver: %s" "$driver" >&2
        echo "" >&2

        ((idx++))
    done
    echo "" >&2

    # Prompt for selection AFTER showing the list
    while true; do
        read -p "Enter your choice (1-${#ifaces[@]}): " choice

        # Validate input
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#ifaces[@]} ]]; then
            echo "${ifaces[$((choice-1))]}"
            return 0
        else
            echo -e "${RED}[✗]${NC} Invalid selection. Please enter a number between 1 and ${#ifaces[@]}" >&2
        fi
    done
}

# Backup current interfaces file
backup_interfaces() {
    if [[ -f "$TARGET_FILE" ]]; then
        # Create backup directory if it doesn't exist
        mkdir -p "$BACKUP_DIR"

        local backup_file="${BACKUP_DIR}/interfaces_${TIMESTAMP}.bak"

        cp "$TARGET_FILE" "$backup_file"
        print_success "Backed up current interfaces file to: $backup_file"
    else
        print_warning "No existing $TARGET_FILE found (fresh installation?)"
    fi
}

# Configure single interface mode
configure_single_mode() {
    local eth_interface="$1"
    local temp_file="/tmp/interfaces_${TIMESTAMP}"

    print_info "Configuring single ethernet mode..."
    print_info "Using interface: $eth_interface"

    # Copy template and replace interface names
    sed "s/\benp5s0\b/$eth_interface/g" "$TEMPLATE_SINGLE" > "$temp_file"

    # Verify the temp file was created successfully
    if [[ ! -f "$temp_file" ]]; then
        print_error "Failed to create temporary configuration file"
        return 1
    fi

    # Replace the target file
    mv "$temp_file" "$TARGET_FILE"
    chmod 644 "$TARGET_FILE"

    print_success "Configuration completed successfully!"
    echo ""
    print_info "Interface configuration summary:"
    echo "  - Primary interface: $eth_interface (connected to vmbr0)"
    echo "  - VLAN1: DHCP enabled on vmbr0"
    echo "  - LOCAL bridge: 192.168.99.1/24"
    echo "  - Mirror bridge: mirrorbr (no ports assigned)"
}

# Configure single interface mirror mode
configure_single_mirror_mode() {
    local eth_interface="$1"
    local temp_file="/tmp/interfaces_${TIMESTAMP}"

    print_warning "Configuring single ethernet mirror mode..."
    print_warning "WARNING: This configuration dedicates your ONLY ethernet port to Security Onion mirror traffic"
    print_warning "Regular network connectivity will NOT be available with this configuration!"
    echo ""
    print_info "Using interface: $eth_interface"

    # Copy template and replace interface names
    sed "s/\benp5s0\b/$eth_interface/g" "$TEMPLATE_SINGLE_MIRROR" > "$temp_file"

    # Verify the temp file was created successfully
    if [[ ! -f "$temp_file" ]]; then
        print_error "Failed to create temporary configuration file"
        return 1
    fi

    # Replace the target file
    mv "$temp_file" "$TARGET_FILE"
    chmod 644 "$TARGET_FILE"

    print_success "Configuration completed successfully!"
    echo ""
    print_info "Interface configuration summary:"
    echo "  - Mirror interface: $eth_interface (connected to mirrorbr for Security Onion)"
    echo "  - LOCAL bridge: 192.168.99.1/24"
    echo ""
    print_warning "IMPORTANT: Regular network traffic (internet access) is NOT available in this mode"
    print_warning "To restore network connectivity, run this script again and select regular single mode"
}

# Configure mirror mode
configure_mirror_mode() {
    local primary_interface="$1"
    local mirror_interface="$2"
    local temp_file="/tmp/interfaces_${TIMESTAMP}"

    print_info "Configuring dual ethernet (mirror) mode..."
    print_info "Primary interface: $primary_interface"
    print_info "Mirror interface: $mirror_interface"

    # Copy template and replace interface names
    sed -e "s/\benp5s0\b/$primary_interface/g" \
        -e "s/\benp4s0\b/$mirror_interface/g" \
        "$TEMPLATE_MIRROR" > "$temp_file"

    # Verify the temp file was created successfully
    if [[ ! -f "$temp_file" ]]; then
        print_error "Failed to create temporary configuration file"
        return 1
    fi

    # Replace the target file
    mv "$temp_file" "$TARGET_FILE"
    chmod 644 "$TARGET_FILE"

    print_success "Configuration completed successfully!"
    echo ""
    print_info "Interface configuration summary:"
    echo "  - Primary interface: $primary_interface (connected to vmbr0)"
    echo "  - Mirror interface: $mirror_interface (connected to mirrorbr for Security Onion)"
    echo "  - VLAN1: DHCP enabled on vmbr0"
    echo "  - LOCAL bridge: 192.168.99.1/24"
}

# Prompt for system restart
prompt_restart() {
    echo ""
    echo -e "${YELLOW}============================================${NC}"
    print_warning "Network configuration has been updated"
    print_warning "A system restart is required to apply changes"
    echo -e "${YELLOW}============================================${NC}"
    echo ""

    read -p "Would you like to restart now? (yes/no): " restart_choice

    case "${restart_choice,,}" in
        yes|y)
            print_info "Restarting system in 5 seconds..."
            print_info "Press Ctrl+C to cancel"
            sleep 5
            reboot
            ;;
        *)
            print_info "Please restart the system manually when ready:"
            echo "  sudo reboot"
            ;;
    esac
}

# Verify OVS is installed (optional warning)
check_ovs() {
    if ! command -v ovs-vsctl &> /dev/null; then
        print_warning "Open vSwitch (openvswitch-switch) does not appear to be installed"
        print_warning "The configuration uses OVS bridges and may not work without it"
        echo ""
        read -p "Continue anyway? (yes/no): " continue_choice
        case "${continue_choice,,}" in
            yes|y)
                return 0
                ;;
            *)
                print_info "Exiting. Install openvswitch-switch and try again:"
                echo "  sudo apt-get install openvswitch-switch"
                exit 0
                ;;
        esac
    fi
}

################################################################################
# Main Script
################################################################################

main() {
    print_header

    # Perform pre-flight checks
    check_root
    check_templates
    check_ovs

    # Detect ethernet interfaces
    print_info "Detecting physical ethernet interfaces..."
    eth_interfaces=($(detect_ethernet_interfaces))

    # Check if any interfaces were found
    if [[ ${#eth_interfaces[@]} -eq 0 ]]; then
        print_error "No physical ethernet interfaces detected!"
        print_error "This script requires at least one ethernet adapter"
        exit 1
    fi

    print_success "Found ${#eth_interfaces[@]} ethernet interface(s)"
    display_interfaces "${eth_interfaces[@]}"

    # Backup current configuration
    backup_interfaces

    # Configure based on number of interfaces
    if [[ ${#eth_interfaces[@]} -eq 1 ]]; then
        # Single interface mode - prompt user for configuration type
        print_info "Single ethernet interface detected: ${eth_interfaces[0]}"
        echo ""
        echo "========================================"
        echo -e "${YELLOW}Select configuration mode:${NC}"
        echo "========================================"
        echo ""
        echo "  1) Regular mode (internet access and normal networking)"
        echo "  2) Mirror mode (Security Onion mirror traffic ONLY - no internet access)"
        echo ""

        while true; do
            read -p "Enter your choice (1-2): " mode_choice

            case "$mode_choice" in
                1)
                    print_success "Selected: Regular single interface mode"
                    configure_single_mode "${eth_interfaces[0]}"
                    break
                    ;;
                2)
                    print_success "Selected: Single interface mirror mode"
                    echo ""
                    print_warning "WARNING: This will dedicate your ONLY ethernet port to mirror traffic!"
                    print_warning "You will NOT have regular network/internet access with this configuration."
                    echo ""
                    read -p "Are you sure you want to continue? (yes/no): " confirm_mirror

                    case "${confirm_mirror,,}" in
                        yes|y)
                            configure_single_mirror_mode "${eth_interfaces[0]}"
                            break
                            ;;
                        *)
                            print_info "Cancelled. Returning to mode selection..."
                            echo ""
                            ;;
                    esac
                    ;;
                *)
                    print_error "Invalid selection. Please enter 1 or 2"
                    ;;
            esac
        done

    else
        # Multiple interfaces - prompt user
        print_info "Multiple ethernet interfaces detected - configuring in mirror mode"
        echo ""

        # Display primary selection prompt BEFORE calling function
        echo "========================================"
        echo -e "${YELLOW}Select PRIMARY interface (for network connectivity):${NC}"
        echo "========================================"
        primary_iface=$(select_interface "${eth_interfaces[@]}")
        print_success "Selected primary interface: $primary_iface"
        echo ""

        # Create array of remaining interfaces for mirror selection
        remaining_ifaces=()
        for iface in "${eth_interfaces[@]}"; do
            [[ "$iface" != "$primary_iface" ]] && remaining_ifaces+=("$iface")
        done

        # Display mirror selection prompt BEFORE calling function
        echo "========================================"
        echo -e "${YELLOW}Select MIRROR interface (for Security Onion monitoring):${NC}"
        echo "========================================"
        mirror_iface=$(select_interface "${remaining_ifaces[@]}")
        print_success "Selected mirror interface: $mirror_iface"
        echo ""

        # Confirm selection
        echo -e "${YELLOW}Configuration Summary:${NC}"
        echo "  Primary (network): $primary_iface"
        echo "  Mirror (Security Onion): $mirror_iface"
        echo ""
        read -p "Proceed with this configuration? (yes/no): " confirm

        case "${confirm,,}" in
            yes|y)
                configure_mirror_mode "$primary_iface" "$mirror_iface"
                ;;
            *)
                print_info "Configuration cancelled by user"
                exit 0
                ;;
        esac
    fi

    # Prompt for restart
    prompt_restart

    print_success "Script completed successfully"
}

# Run main function
main

exit 0
