# Proxmox Cyber Security Assessment Device Setup

## Overview

This script automates the setup of a Proxmox-based cyber security assessment device as described in the ReconhawkLabs article "Build the Ultimate Cyber Security Assessment Device - Part 1".

## What This Script Does

The script transforms a fresh Proxmox installation into a portable cyber security assessment platform with:

- **DHCP Networking**: Configures Proxmox to use DHCP instead of static IP for client operation
- **VLAN Support**: Enables bridge-vlan-aware configuration for trunk/access ports (VLANs 2-4094)
- **WiFi Support**: Optional WiFi configuration with WPA supplicant
- **Desktop Environment**: Installs KDE Plasma desktop on top of Proxmox
- **Power Management**: Laptop-friendly power settings (prevents sleep/suspend)
- **Storage Optimization**: Expands filesystem to use full disk capacity
- **User Management**: Creates non-root user with sudo access
- **Dynamic IP Updates**: Automatically updates /etc/hosts with DHCP IP changes

## Prerequisites

1. Fresh Proxmox VE installation
2. Laptop with 16GB+ RAM and virtualization support
3. 256GB+ storage
4. Internet connection
5. Root access to Proxmox host

## Usage

### Step 1: Download and Run Script

```bash
# SSH into fresh Proxmox installation as root
ssh root@proxmox-ip

# Download the script
wget https://raw.githubusercontent.com/your-repo/proxmox-assessment-device-setup.sh

# Make executable (if needed)
chmod +x proxmox-assessment-device-setup.sh

# Run the script
./proxmox-assessment-device-setup.sh
```

### Step 2: Follow Interactive Prompts

The script will prompt for:
- WiFi configuration (optional)
- Username for new user account
- User password

### Step 3: Post-Reboot Configuration

After the automatic reboot:

1. **Login**: Use the created user account
2. **Proxmox Access**: Open Firefox and navigate to `https://localhost:8006`
3. **Power Settings**: Verify power management in KDE System Settings
4. **Storage**: Check Proxmox storage configuration in web interface

## Network Configuration Details

### Ethernet Interface
- Automatically detects primary network interface
- Configures bridge (vmbr0) with DHCP
- Enables VLAN awareness for VLANs 2-4094

### WiFi Interface (Optional)
- Detects WiFi interface automatically
- Creates WPA supplicant configuration
- Sets up systemd services for auto-connection

## Desktop Environment

- **KDE Plasma Desktop**: Lightweight KDE installation
- **SDDM Display Manager**: Graphical login
- **Essential Applications**: Firefox, Konsole, Dolphin, Kate
- **Network Manager**: Removed (using manual configuration)

## Power Management

Configured for laptop operation:
- **AC Power**: No sleep/suspend
- **Battery**: No sleep/suspend
- **Lid Close**: Screen off only
- **Performance Mode**: Enabled

## Storage Configuration

- Removes default LVM data volume
- Expands root filesystem to full disk
- Enables all content types for local storage

## Troubleshooting

### Network Issues
```bash
# Check interface status
ip a

# Restart networking
systemctl restart networking

# Check DHCP client
systemctl status isc-dhcp-client
```

### WiFi Issues
```bash
# Check WiFi service
systemctl status wpa_supplicant

# Check DHCP for WiFi
systemctl status dhclient
```

### Desktop Issues
```bash
# Restart display manager
systemctl restart sddm

# Check KDE services
systemctl status sddm
```

### Proxmox Access Issues
```bash
# Check Proxmox services
systemctl status pveproxy
systemctl status pvedaemon

# Check firewall
iptables -L
```

## Security Considerations

- Script creates non-root user for daily operations
- Proxmox web interface uses HTTPS
- Network manager removed to prevent conflicts
- Manual network configuration for better control

## Next Steps

After successful setup:

1. **Create VM Templates**: Set up base images for assessment VMs
2. **Configure VLANs**: Create VLAN-specific bridges as needed
3. **Install Assessment Tools**: Deploy Kali, Parrot, or custom assessment VMs
4. **Backup Configuration**: Create snapshots of base configuration
5. **Test VLAN Access**: Verify trunk port functionality

## Support

For issues related to this script, please refer to:
- Original article: ReconhawkLabs "Build the Ultimate Cyber Security Assessment Device"
- Proxmox documentation: https://pve.proxmox.com/wiki/
- Script repository issues

## Disclaimer

This script is for educational and authorized security assessment purposes only. Ensure you have proper authorization before using this device for security assessments.