#!/bin/bash

################################################################################
# Mythic C2 Framework Installation Script
# For Debian-based Linux distributions (Debian, Ubuntu, Kali, etc.)
# Bulletproof installation with comprehensive error handling
################################################################################

set -e  # Exit immediately if a command exits with a non-zero status
set -u  # Treat unset variables as an error
set -o pipefail  # Return value of a pipeline is the status of the last command to exit with a non-zero status

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

################################################################################
# Functions
################################################################################

# Print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo -e "${CYAN}"
    echo "================================================================"
    echo "        Mythic C2 Framework - Automated Installation"
    echo "================================================================"
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should NOT be run as root directly."
        print_error "Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Check if user has sudo privileges
check_sudo() {
    print_info "Checking sudo privileges..."
    if ! sudo -n true 2>/dev/null; then
        print_warning "This script requires sudo privileges."
        print_info "You may be prompted for your password."
        sudo -v || {
            print_error "Failed to obtain sudo privileges."
            exit 1
        }
    fi
    print_success "Sudo privileges confirmed."
}

# Keep sudo alive throughout the script
keep_sudo_alive() {
    while true; do
        sudo -n true
        sleep 60
        kill -0 "$$" || exit
    done 2>/dev/null &
}

# Check internet connectivity
check_internet() {
    print_info "Checking internet connectivity..."
    if ! ping -c 1 -W 3 8.8.8.8 &> /dev/null; then
        print_error "No internet connection detected."
        print_error "Please check your network connection and try again."
        exit 1
    fi
    print_success "Internet connection confirmed."
}

# Execute command with retry logic
execute_with_retry() {
    local max_attempts=3
    local timeout=5
    local attempt=1
    local command="$@"

    until $command
    do
        if (( attempt == max_attempts ))
        then
            print_error "Command failed after $max_attempts attempts: $command"
            return 1
        else
            print_warning "Command failed (attempt $attempt/$max_attempts). Retrying in $timeout seconds..."
            sleep $timeout
            attempt=$((attempt + 1))
        fi
    done
    return 0
}

# Wait for command to complete with spinner
wait_with_spinner() {
    local pid=$!
    local spin='-\|/'
    local i=0
    while kill -0 $pid 2>/dev/null
    do
        i=$(( (i+1) %4 ))
        printf "\r${spin:$i:1}"
        sleep .1
    done
    printf "\r"
}

################################################################################
# Main Installation
################################################################################

main() {
    print_banner

    # Pre-flight checks
    check_root
    check_sudo
    check_internet
    keep_sudo_alive

    print_info "Starting Mythic C2 installation process..."
    echo ""

    # Step 1: Update package lists
    print_info "Step 1/10: Updating package lists..."
    if execute_with_retry sudo apt update -y; then
        print_success "Package lists updated successfully."
    else
        print_error "Failed to update package lists."
        exit 1
    fi
    echo ""

    # Step 2: Install Linux headers
    print_info "Step 2/10: Installing Linux headers for kernel $(uname -r)..."
    if execute_with_retry sudo apt install -y linux-headers-$(uname -r) 2>/dev/null; then
        print_success "Linux headers installed successfully."
    else
        print_warning "Failed to install exact kernel headers, attempting generic install..."
        if sudo apt install -y linux-headers-generic 2>/dev/null; then
            print_success "Generic Linux headers installed successfully."
        else
            print_warning "Could not install kernel headers, continuing anyway..."
            print_info "Note: This may not affect Mythic installation as it primarily uses Docker."
        fi
    fi
    echo ""

    # Step 3: Upgrade system packages
    print_info "Step 3/10: Upgrading system packages (this may take a while)..."
    if execute_with_retry sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y; then
        print_success "System packages upgraded successfully."
    else
        print_error "Failed to upgrade system packages."
        exit 1
    fi
    echo ""

    # Step 4: Install Docker and dependencies
    print_info "Step 4/10: Installing Docker, Git, Docker Compose, and build tools..."

    # Try to install docker-compose first, fallback to docker-compose-plugin if not available
    DOCKER_COMPOSE_PKG="docker-compose"
    if ! apt-cache show docker-compose &>/dev/null; then
        print_info "docker-compose not found in repositories, will try docker-compose-plugin..."
        DOCKER_COMPOSE_PKG="docker-compose-plugin"
    fi

    if execute_with_retry sudo DEBIAN_FRONTEND=noninteractive apt install -y docker.io git ${DOCKER_COMPOSE_PKG} make build-essential; then
        print_success "Docker and dependencies installed successfully."
    else
        print_warning "Failed to install all packages, attempting without docker-compose..."
        if execute_with_retry sudo DEBIAN_FRONTEND=noninteractive apt install -y docker.io git make build-essential; then
            print_success "Docker and build tools installed successfully."
            print_warning "docker-compose may need to be installed manually if required."
        else
            print_error "Failed to install Docker and dependencies."
            exit 1
        fi
    fi
    echo ""

    # Step 5: Enable and start Docker service
    print_info "Step 5/10: Enabling and starting Docker service..."
    if sudo systemctl enable docker --now; then
        print_success "Docker service enabled and started."
    else
        print_error "Failed to enable Docker service."
        exit 1
    fi

    # Verify Docker is running
    print_info "Verifying Docker is running..."
    if sudo systemctl is-active --quiet docker; then
        print_success "Docker is running."
    else
        print_error "Docker service is not running."
        exit 1
    fi
    echo ""

    # Step 6: Add user to docker group
    print_info "Step 6/10: Adding user '$USER' to docker group..."
    if sudo usermod -aG docker $USER; then
        print_success "User added to docker group."
    else
        print_error "Failed to add user to docker group."
        exit 1
    fi

    # Refresh group membership without logout
    print_info "Refreshing group membership..."
    if newgrp docker << EOFGROUP
exit
EOFGROUP
    then
        print_success "Group membership refreshed (docker group active)."
    else
        print_warning "Could not refresh group membership automatically."
        print_info "You may need to log out and back in, or run: newgrp docker"
    fi
    echo ""

    # Step 7: Clone Mythic repository
    print_info "Step 7/10: Cloning Mythic repository..."
    if [ -d "Mythic" ]; then
        print_warning "Mythic directory already exists."
        print_info "Removing existing directory..."
        rm -rf Mythic
    fi

    if execute_with_retry git clone https://github.com/its-a-feature/Mythic --depth 1 --single-branch; then
        print_success "Mythic repository cloned successfully."
    else
        print_error "Failed to clone Mythic repository."
        exit 1
    fi
    echo ""

    # Step 8: Navigate to Mythic directory and run make
    print_info "Step 8/10: Building Mythic framework..."
    cd Mythic || {
        print_error "Failed to navigate to Mythic directory."
        exit 1
    }

    if sudo make; then
        print_success "Mythic framework built successfully."
    else
        print_error "Failed to build Mythic framework."
        exit 1
    fi
    echo ""

    # Step 9: Install Mythic agents and C2 profiles
    print_info "Step 9/10: Installing Mythic agents and C2 profiles..."
    echo ""

    print_info "Installing Apollo agent..."
    if sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git; then
        print_success "Apollo agent installed successfully."
    else
        print_error "Failed to install Apollo agent."
        exit 1
    fi
    sleep 2
    echo ""

    print_info "Installing Poseidon agent..."
    if sudo -E ./mythic-cli install github https://github.com/MythicAgents/poseidon.git; then
        print_success "Poseidon agent installed successfully."
    else
        print_error "Failed to install Poseidon agent."
        exit 1
    fi
    sleep 2
    echo ""

    print_info "Installing Thanatos agent..."
    if sudo -E ./mythic-cli install github https://github.com/MythicAgents/thanatos; then
        print_success "Thanatos agent installed successfully."
    else
        print_error "Failed to install Thanatos agent."
        exit 1
    fi
    sleep 2
    echo ""

    print_info "Installing HTTP C2 profile..."
    if sudo -E ./mythic-cli install github https://github.com/MythicC2Profiles/http; then
        print_success "HTTP C2 profile installed successfully."
    else
        print_error "Failed to install HTTP C2 profile."
        exit 1
    fi
    sleep 2
    echo ""

    print_info "Installing SMB C2 profile..."
    if sudo -E ./mythic-cli install github https://github.com/MythicC2Profiles/smb; then
        print_success "SMB C2 profile installed successfully."
    else
        print_error "Failed to install SMB C2 profile."
        exit 1
    fi
    sleep 2
    echo ""

    # Step 10: Start Mythic
    print_info "Step 10/10: Starting Mythic C2 framework..."
    if sudo -E ./mythic-cli start; then
        print_success "Mythic C2 framework started successfully!"
    else
        print_error "Failed to start Mythic C2 framework."
        exit 1
    fi
    echo ""

    # Modify .env file
    print_info "Customizing Mythic configuration..."
    if [ -f ".env" ]; then
        sed -i 's/DEFAULT_OPERATION_NAME="Operation Chimera"/DEFAULT_OPERATION_NAME="Operation Bluegrass"/' .env
        sed -i 's/MYTHIC_DOCKER_NETWORKING="bridge"/MYTHIC_DOCKER_NETWORKING="host"/' .env
        sed -i 's/MYTHIC_SERVER_DYNAMIC_PORTS_BIND_LOCALHOST_ONLY="true"/MYTHIC_SERVER_DYNAMIC_PORTS_BIND_LOCALHOST_ONLY="false"/' .env
        print_success "Configuration updated successfully."
    else
        print_error ".env file not found. Cannot customize configuration."
        exit 1
    fi
    echo ""

    # Restart Mythic with new configuration
    print_info "Restarting Mythic with updated configuration..."
    if sudo -E ./mythic-cli start; then
        print_success "Mythic restarted successfully with new configuration!"
    else
        print_error "Failed to restart Mythic C2 framework."
        exit 1
    fi
    echo ""

    # Display credentials
    echo -e "${GREEN}================================================================"
    echo "                 INSTALLATION COMPLETE!"
    echo -e "================================================================${NC}"
    echo ""
    print_info "Mythic C2 is now running!"
    echo ""
    print_warning "IMPORTANT: Your login credentials are stored in the .env file"
    print_info "Displaying credentials from .env file:"
    echo ""
    echo -e "${CYAN}================================================================${NC}"

    if [ -f ".env" ]; then
        cat .env | grep -E "(MYTHIC_ADMIN_USER|MYTHIC_ADMIN_PASSWORD|MYTHIC_SERVER_PORT)" || cat .env
    else
        print_error ".env file not found. Please check the Mythic directory manually."
    fi

    echo -e "${CYAN}================================================================${NC}"
    echo ""
    print_info "Access Mythic at: https://127.0.0.1:7443"
    print_info "Or from another machine: https://<your-ip>:7443"
    echo ""
    print_warning "Note: You may need to log out and back in for docker group changes to take full effect."
    print_info "Alternatively, you can run: newgrp docker"
    echo ""
    print_success "Installation script completed successfully!"
}

################################################################################
# Error handler
################################################################################

error_handler() {
    local line_number=$1
    print_error "Script failed at line $line_number"
    print_error "Please check the error messages above for details."
    exit 1
}

trap 'error_handler ${LINENO}' ERR

################################################################################
# Execute main function
################################################################################

main "$@"
