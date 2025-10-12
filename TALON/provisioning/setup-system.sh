#!/bin/bash

################################################################################
# System Deployment Wizard
# Purpose: Interactive deployment guide for new server installations
# Usage: ./Deploy_System.sh
################################################################################

# Terminal size for whiptail dialogs
TERM_HEIGHT=24
TERM_WIDTH=78

# Color codes for terminal output (when not using whiptail)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Helper Functions
################################################################################

# Display error and exit
error_exit() {
    whiptail --title "Error" --msgbox "$1" 10 60
    exit 1
}

# Display success message
show_success() {
    whiptail --title "Success" --msgbox "$1" 10 60
}

# Ask for confirmation
confirm_step() {
    whiptail --title "$1" --yesno "$2" 12 70
    return $?
}

# Show step completion
mark_complete() {
    whiptail --title "Step Complete" --msgbox "✓ $1 has been completed successfully.\n\nPress OK to continue to the next step." 10 70
}

################################################################################
# Deployment Steps
################################################################################

# Welcome Screen
show_welcome() {
    whiptail --title "System Deployment Wizard" --msgbox \
"Welcome to the System Deployment Wizard!

This interactive guide will walk you through the complete provisioning process for your new installation.

The deployment process includes:
  • Setting up storage partitions
  • Deploying virtual machines
  • Changing system password
  • Configuring network interfaces

Each step will provide detailed instructions. Please read each screen carefully and follow the instructions.

Press OK to view the deployment steps overview." 20 75
}

# Show deployment overview
show_overview() {
    whiptail --title "Deployment Steps Overview" --msgbox \
"DEPLOYMENT STEPS OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Step 1: Setup Storage
  └─ Expand disk partitions using GParted

Step 2: Deploy Virtual Machines
  └─ Clone VMs in Proxmox and configure network adapters

Step 3: Change Password
  └─ Set new system password for security

Step 4: Setup Network
  └─ Configure network interfaces and reboot

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK to begin Step 1..." 22 75
}

################################################################################
# Step 1: Setup Storage
################################################################################

step1_storage() {
    whiptail --title "Step 1 of 4: Setup Storage" --msgbox \
"SETUP STORAGE - Part 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You will now set up the storage partitions.

INSTRUCTIONS:
1. Press the 'Windows' key OR click the KDE icon in the bottom
   left corner of the screen to open the launcher

2. Search for 'gpart' in the launcher

3. Select the 'GParted' application

4. Enter your password when prompted

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when you have GParted open..." 21 75

    whiptail --title "Step 1 of 4: Setup Storage" --msgbox \
"SETUP STORAGE - Part 2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Now you will resize the partition.

INSTRUCTIONS:

1. In GParted, select the FIRST DRIVE from the dropdown
   (This drive will have 3 partitions)

2. Click on the THIRD PARTITION (the large chunk) to select it

3. Click the RESIZE button (white arrows icon next to the
   delete trash icon)

4. Drag the RIGHT ARROW all the way to the right to use
   all remaining free space

5. Click 'Resize' to confirm

6. Click the green checkmark to apply the changes

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when the resize operation is complete..." 26 78

    whiptail --title "Step 1 of 4: Setup Storage" --msgbox \
"SETUP STORAGE - Part 3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Finally, you need to expand the disk.

INSTRUCTIONS:
1. Close GParted

2. On the Desktop, find the 'Expand Disk' icon

3. Double-click the 'Expand Disk' icon

4. Enter your password when prompted

5. Wait for the operation to complete

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when the disk expansion is complete..." 22 75

    if confirm_step "Confirm Step 1 Complete" "Have you successfully completed all storage setup tasks?\n\nThis includes:\n• Resized partition in GParted\n• Run Expand Disk script"; then
        mark_complete "Step 1: Setup Storage"
        return 0
    else
        whiptail --title "Step 1 Not Complete" --msgbox "Please complete all storage setup tasks before proceeding.\n\nRestarting Step 1..." 10 70
        step1_storage
    fi
}

################################################################################
# Step 2: Deploy VMs
################################################################################

step2_deploy_vms() {
    whiptail --title "Step 2 of 4: Deploy Virtual Machines" --msgbox \
"DEPLOY VIRTUAL MACHINES - Part 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You will now deploy the virtual machines in Proxmox.

INSTRUCTIONS:
1. On the Desktop, find and double-click the 'Proxmox' icon

2. Log into the Proxmox web GUI using your credentials

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when you are logged into Proxmox..." 19 75

    whiptail --title "Step 2 of 4: Deploy Virtual Machines" --msgbox \
"DEPLOY VIRTUAL MACHINES - Part 2: Clone Router VM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Clone the Router VM:

INSTRUCTIONS:

1. In the Proxmox left panel, find 'KYCRIRTR-00' VM

2. RIGHT-CLICK on 'KYCRIRTR-00'

3. Select 'Clone' from the context menu

4. Set the VM name to: KYCRIWANRTROPS

5. Leave all other options UNCHANGED

6. Click OK to start cloning

7. Wait for the clone to complete

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when the Router VM clone is complete..." 25 78

    whiptail --title "Step 2 of 4: Deploy Virtual Machines" --msgbox \
"DEPLOY VIRTUAL MACHINES - Part 3: Clone Kali VM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Clone the Kali VM:

INSTRUCTIONS:

1. In the Proxmox left panel, find 'KYCRIKALI-00' VM

2. RIGHT-CLICK on 'KYCRIKALI-00'

3. Select 'Clone' from the context menu

4. Set the VM name to: KYCRIKALIOPS

5. Leave all other options UNCHANGED

6. Click OK to start cloning

7. Wait for the clone to complete

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when the Kali VM clone is complete..." 25 78

    whiptail --title "Step 2 of 4: Deploy Virtual Machines" --msgbox \
"DEPLOY VIRTUAL MACHINES - Part 4: Clone Security Onion VM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Clone the Security Onion VM:

INSTRUCTIONS:

1. In the Proxmox left panel, find 'KYCRISECONION-00' VM

2. RIGHT-CLICK on 'KYCRISECONION-00'

3. Select 'Clone' from the context menu

4. Set the following options:
   • VM ID: 201
   • Name: KYCRISECONIONOPS
   • Mode: Linked Clone

5. Click OK to start cloning

6. Wait for the clone to complete

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when the Security Onion VM clone is complete..." 26 78

    whiptail --title "Step 2 of 4: Deploy Virtual Machines" --msgbox \
"DEPLOY VIRTUAL MACHINES - Part 5: Configure Network Adapters
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Configure the Security Onion VM network adapters:

INSTRUCTIONS:

1. In the Proxmox left panel, LEFT-CLICK the
   'KYCRISECONIONOPS' VM (ID 201)

2. Click the 'Hardware' tab

3. DOUBLE-CLICK the 'net0' network adapter

4. Set the MAC address to: BC:24:11:D5:D5:C7

5. Click OK

6. DOUBLE-CLICK the 'net1' network adapter

7. Set the MAC address to: BC:24:11:F8:2A:BC

8. Click OK

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when both MAC addresses are configured..." 27 78

    whiptail --title "Step 2 of 4: Deploy Virtual Machines" --msgbox \
"DEPLOY VIRTUAL MACHINES - Part 6: Configure Hookscript
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Set up the port mirror hookscript:

INSTRUCTIONS:

1. Open a terminal (Konsole)
   • Press 'Windows' key OR click KDE icon
   • Type 'konsole'
   • Click the Konsole application

2. In the terminal, run this command:

   sudo qm set 201 --hookscript local:snippets/port-mirror.sh

3. Enter your password when prompted

4. Press Enter to execute

5. Wait for the command to complete

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when the hookscript command has completed..." 27 78

    if confirm_step "Confirm Step 2 Complete" "Have you successfully completed all VM deployment tasks?\n\nThis includes:\n• Cloned KYCRIWANRTROPS\n• Cloned KYCRIKALIOPS\n• Cloned KYCRISECONIONOPS\n• Set MAC addresses\n• Configured hookscript"; then
        mark_complete "Step 2: Deploy Virtual Machines"
        return 0
    else
        whiptail --title "Step 2 Not Complete" --msgbox "Please complete all VM deployment tasks before proceeding.\n\nRestarting Step 2..." 10 70
        step2_deploy_vms
    fi
}

################################################################################
# Step 3: Change Password
################################################################################

step3_change_password() {
    whiptail --title "Step 3 of 4: Change Password" --msgbox \
"CHANGE SYSTEM PASSWORD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For security, you must change the default system password.

INSTRUCTIONS:

1. Open a terminal if not already open:
   • Press 'Windows' key OR click KDE icon in bottom left
   • Type 'konsole'
   • Click the Konsole application

2. In the terminal, type: passwd

3. Press Enter

4. Enter your CURRENT password when prompted

5. Enter your NEW password when prompted

6. Re-enter your NEW password to confirm

7. You should see 'password updated successfully'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when you have changed your password..." 27 78

    if confirm_step "Confirm Step 3 Complete" "Have you successfully changed your system password?"; then
        mark_complete "Step 3: Change Password"
        return 0
    else
        whiptail --title "Step 3 Not Complete" --msgbox "Please change your system password before proceeding.\n\nRestarting Step 3..." 10 70
        step3_change_password
    fi
}

################################################################################
# Step 4: Setup Network
################################################################################

step4_setup_network() {
    whiptail --title "Step 4 of 4: Setup Network" --msgbox \
"SETUP NETWORK INTERFACES - Part 1
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Prepare the network interfaces:

IMPORTANT:

If only ONE ethernet interface is currently connected to
the system, you MUST plug in an additional ethernet adapter
before proceeding.

You can use:
  • Built-in secondary ethernet port
  • USB Ethernet adapter
  • PCIe ethernet card

NOTE: The system requires at least 2 ethernet interfaces
for proper operation (1 for network, 1 for mirroring).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when you have at least 2 ethernet adapters
connected..." 26 78

    whiptail --title "Step 4 of 4: Setup Network" --msgbox \
"SETUP NETWORK INTERFACES - Part 2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Configure the network interfaces:

INSTRUCTIONS:

1. On the Desktop, find the 'Update-Interfaces' icon

2. DOUBLE-CLICK the 'Update-Interfaces' icon

3. Follow the on-screen prompts to configure your
   network adapters

4. The script will guide you through selecting:
   • Primary network interface
   • Mirror interface (for Security Onion)

5. Complete the network configuration

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK when network configuration is complete..." 26 78

    whiptail --title "Step 4 of 4: Setup Network" --msgbox \
"SETUP NETWORK INTERFACES - Part 3: REBOOT REQUIRED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IMPORTANT: SYSTEM REBOOT REQUIRED

The network configuration requires a system reboot to
take effect.

After clicking OK on this screen, you will be prompted
to reboot the system.

WHAT HAPPENS NEXT:

1. You will be asked to confirm the reboot

2. The system will restart

3. Log back in after reboot

4. Your deployment will be complete!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Press OK to proceed to reboot confirmation..." 26 78

    if confirm_step "Confirm Step 4 Complete" "Have you successfully configured the network interfaces?\n\nIMPORTANT: The next step will reboot the system."; then
        mark_complete "Step 4: Setup Network"
        return 0
    else
        whiptail --title "Step 4 Not Complete" --msgbox "Please complete the network configuration before proceeding.\n\nRestarting Step 4..." 10 70
        step4_setup_network
    fi
}

################################################################################
# Final Reboot Prompt
################################################################################

final_reboot() {
    if confirm_step "Reboot System" "All deployment steps are complete!\n\nThe system must be rebooted for changes to take effect.\n\nReboot now?"; then
        whiptail --title "Rebooting..." --msgbox "The system will reboot in 5 seconds.\n\nPress OK to continue..." 10 60

        # Countdown
        for i in 5 4 3 2 1; do
            echo "Rebooting in $i seconds..."
            sleep 1
        done

        sudo reboot
    else
        whiptail --title "Deployment Complete" --msgbox \
"DEPLOYMENT COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

All deployment steps have been completed successfully!

IMPORTANT: You chose not to reboot now, but a reboot is
REQUIRED for the network configuration to take effect.

Please reboot the system manually when ready:
  sudo reboot

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Thank you for using the System Deployment Wizard!" 19 75
    fi
}

################################################################################
# Main Function
################################################################################

main() {
    # Check if whiptail is installed
    if ! command -v whiptail &> /dev/null; then
        echo -e "${RED}[✗]${NC} Error: whiptail is not installed"
        echo "Please install whiptail: sudo apt-get install whiptail"
        exit 1
    fi

    # Welcome screen
    show_welcome

    # Show overview
    show_overview

    # Execute deployment steps
    step1_storage
    step2_deploy_vms
    step3_change_password
    step4_setup_network

    # Final reboot prompt
    final_reboot
}

# Run main function
main

exit 0
