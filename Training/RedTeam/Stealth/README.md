# Advanced Stealth Lateral Movement & Persistence Techniques

## Overview

This directory contains bulletproof, production-ready scripts for advanced Active Directory attack techniques designed for authorized red team operations and purple team training exercises.

**Purpose:** To provide realistic, sophisticated attack scenarios that challenge blue team detection capabilities using Security Onion and Elastic SIEM solutions.

**Authorization:** These tools are ONLY for use in authorized cyber security training ranges and penetration testing engagements. Unauthorized use is illegal.

---

## Techniques Included

### 1. WMI-Based Lateral Movement (Fileless)
**Difficulty:** Moderate
**Stealth Level:** High
**Prerequisites:** Domain Admin or Local Admin

**Description:**
Uses Windows Management Instrumentation for fileless lateral movement. Executes commands remotely without dropping binaries, blending with legitimate administrative activity.

**Files:**
- `WMI-LateralMovement.ps1` - Automated script with 3 execution methods
- `WMI-LateralMovement-GUIDE.md` - Complete guide with manual commands

**Key Features:**
- Multiple fallback execution methods (Win32_Process, WMI Events, CIM)
- Automatic target validation
- Encrypted WMI sessions
- Comprehensive error handling
- Living off the land techniques

**Detection Challenge:**
Process spawning from `wmiprvse.exe` - how many false positives will blue team tolerate?

---

### 2. DCOM-Based Lateral Movement
**Difficulty:** Moderate-High
**Stealth Level:** Very High
**Prerequisites:** Domain Admin or Local Admin

**Description:**
Leverages Distributed COM objects (MMC20, ShellWindows, Excel, Outlook) for remote execution. Less commonly monitored than WMI/PSExec.

**Files:**
- `DCOM-LateralMovement.ps1` - Multi-method DCOM execution
- `DCOM-LateralMovement-GUIDE.md` - Deep-dive guide with OPSEC notes

**Key Features:**
- 5 different DCOM execution methods
- Automatic method selection for reliability
- Spawns from diverse parent processes (mmc.exe, explorer.exe, excel.exe)
- COM object cleanup
- Credential management

**Detection Challenge:**
Legitimate processes spawning commands - can blue team distinguish attack from admin activity?

---

### 3. DCShadow Attack (Rogue Domain Controller)
**Difficulty:** Very High
**Stealth Level:** Extremely High
**Prerequisites:** Domain Admin, Mimikatz

**Description:**
Registers temporary rogue Domain Controller to push AD modifications via replication, bypassing DC audit logs. One of the most sophisticated AD attacks.

**Files:**
- `DCShadow-Attack.ps1` - Semi-automated DCShadow implementation
- `DCShadow-Attack-GUIDE.md` - Comprehensive guide with manual LDAP techniques

**Key Features:**
- Mimikatz integration
- Native PowerShell fallback methods
- Automatic cleanup
- SID history injection
- User/group creation via "replication"

**Detection Challenge:**
Changes appear to come from DC replication - can blue team detect rogue DC registration?

**WARNING:** Can impact AD replication if misconfigured. Use only in isolated test environments.

---

### 4. Skeleton Key Attack (Master Password)
**Difficulty:** High
**Stealth Level:** Extremely High
**Prerequisites:** Domain Admin, Mimikatz, Access to DC

**Description:**
Patches LSASS on Domain Controllers to accept a master password for ANY account while original passwords continue working. Ultimate stealth persistence.

**Files:**
- `SkeletonKey-Attack.ps1` - Automated skeleton key injection
- `SkeletonKey-Attack-GUIDE.md` - Complete guide with detection methods

**Key Features:**
- Remote LSASS patching via PowerShell Remoting or WMI
- Authentication testing
- LSA Protection detection
- In-memory only (disappears on reboot)
- Universal domain access

**Detection Challenge:**
No AD modifications, no failed logins, no account lockouts - pure memory forensics required for detection.

**WARNING:** Patching LSASS is risky. Can crash DC if done incorrectly.

---

## Usage Guidelines

### Quick Start

```powershell
# 1. WMI Lateral Movement
.\WMI-LateralMovement.ps1 -Target DC01 -Command "whoami"

# 2. DCOM Lateral Movement
.\DCOM-LateralMovement.ps1 -Target DC01 -Command "calc.exe" -Method MMC20

# 3. DCShadow (requires Mimikatz)
.\DCShadow-Attack.ps1 -DomainController DC01 `
                      -RogueDCName SHADOW01 `
                      -Action CreateUser `
                      -TargetUser backdoor `
                      -Password "P@ssw0rd123!"

# 4. Skeleton Key (requires Mimikatz)
.\SkeletonKey-Attack.ps1 -DomainController DC01 `
                         -MasterPassword "Mimikatz123!" `
                         -TestAuth
```

### Training Exercise Scenarios

#### Scenario 1: Stealthy Reconnaissance
1. Use WMI to enumerate domain computers
2. Use DCOM to check admin access
3. Escalate via discovered credentials

#### Scenario 2: Advanced Persistence
1. Inject Skeleton Key on primary DC
2. Use master password to access backup DC
3. Inject Skeleton Key on backup DC for redundancy

#### Scenario 3: AD Manipulation
1. Use DCShadow to create backdoor admin user
2. Use DCShadow to inject SID history
3. Authenticate with elevated privileges

#### Scenario 4: Full Kill Chain
1. WMI lateral movement to admin workstation
2. DCOM execution to deploy credential stealer
3. Obtain Domain Admin credentials
4. Deploy Skeleton Key for persistence
5. Use DCShadow to create backup access

---

## Detection & Purple Team Guidance

### Blue Team Detection Capabilities Required

**For WMI Detection:**
- Sysmon with command-line logging
- WMI-Activity operational logs enabled
- Alert on `wmiprvse.exe` spawning unusual children
- Baseline normal WMI usage

**For DCOM Detection:**
- Process creation monitoring (Event ID 4688 + Sysmon)
- Alert on unusual parent processes (mmc.exe, explorer.exe → cmd.exe)
- DCOM activation event monitoring (Event IDs 10000-10010)
- RPC/DCOM network connection baselines

**For DCShadow Detection:**
- Monitor for new DC registrations (Event ID 4742)
- DNS monitoring for new _ldap/_kerberos SRV records
- Configuration partition auditing
- Baseline DC count and alert on changes
- Replication anomaly detection

**For Skeleton Key Detection:**
- LSASS integrity monitoring
- Memory forensics on DCs
- Behavioral analytics (same password for multiple users)
- Debug privilege usage monitoring (Event ID 4673)
- LSA Protection & Credential Guard enforcement

### Purple Team Exercise Flow

**Phase 1: Baseline (Week 1)**
- Blue team establishes normal activity baselines
- Document current detection capabilities
- Configure SIEM rules

**Phase 2: Attacks (Week 2-3)**
- Red team executes techniques one at a time
- 48-hour window for blue team detection
- Document time-to-detect for each technique

**Phase 3: Analysis (Week 4)**
- Joint review of what was detected/missed
- Tune SIEM rules based on findings
- Re-test with improved detection

**Phase 4: Advanced (Week 5-6)**
- Combine techniques in kill chains
- Test evasion techniques
- Final purple team review

---

## OPSEC Considerations

### Operational Security Best Practices

**1. Timing**
- Execute during business hours when admins are active
- Avoid 3 AM on weekends (obvious anomaly)
- Space out attacks over days/weeks

**2. Blending**
- Use realistic account names
- Mimic normal admin commands
- Don't mass-execute across all systems

**3. Throttling**
- Add random delays between actions
- Don't hit 50 systems in 5 minutes
- Gradual lateral movement

**4. Cleanup**
- Remove temporary files
- Clear PowerShell history
- Remove DCOM artifacts
- Clean event logs (advanced)

**5. Fail-Safes**
- Always have rollback procedures
- Test in isolated environment first
- Document all actions for cleanup
- Have DC recovery plan (DCShadow/Skeleton Key)

---

## Prerequisites & Setup

### Required Software

```powershell
# Active Directory PowerShell Module
Import-Module ActiveDirectory

# For remote operations
Enable-PSRemoting -Force

# Optional: Mimikatz
# Download from: https://github.com/gentilkiwi/mimikatz/releases
# Place in: C:\Tools\mimikatz.exe
```

### Required Permissions

```powershell
# Verify Domain Admin
whoami /groups | findstr "S-1-5-21-.*-512"

# Or check programmatically
$domain = Get-ADDomain
$domainAdminSID = "$($domain.DomainSID)-512"
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole($domainAdminSID)
```

### Network Configuration

```powershell
# Verify required ports open
Test-NetConnection -ComputerName DC01 -Port 135  # RPC
Test-NetConnection -ComputerName DC01 -Port 445  # SMB
Test-NetConnection -ComputerName DC01 -Port 389  # LDAP
Test-NetConnection -ComputerName DC01 -Port 5985 # WinRM
```

### Firewall Rules

```powershell
# On targets, ensure WMI/DCOM allowed
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)"
Enable-NetFirewallRule -DisplayGroup "Remote Event Log Management"

# Enable PowerShell Remoting
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
```

---

## Troubleshooting

### Common Issues

**"Access Denied"**
- Verify Domain Admin membership
- Check UAC settings
- Ensure NTLM/Kerberos authentication working

**"RPC Server Unavailable"**
- Check firewall (port 135)
- Verify target is online
- Test with: `Test-NetConnection -ComputerName TARGET -Port 135`

**"Mimikatz Blocked"**
- Disable Windows Defender temporarily
- Add exclusion path
- Use obfuscated Mimikatz

**"LSASS Access Denied"**
- Verify running as admin
- Check for LSA Protection
- Check for Credential Guard
- Use `privilege::debug` in Mimikatz

---

## References & Further Reading

### MITRE ATT&CK Mappings

- **T1047** - Windows Management Instrumentation
- **T1021.003** - Distributed Component Object Model
- **T1207** - Rogue Domain Controller (DCShadow)
- **T1558** - Steal or Forge Kerberos Tickets (includes Skeleton Key)

### Resources

- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [Microsoft AD Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [DCShadow Whitepaper - Vincent Le Toux & Benjamin Delpy](https://www.dcshadow.com/)

---

## Legal & Ethical Notice

**CRITICAL: READ BEFORE USE**

These tools are designed EXCLUSIVELY for:
- Authorized penetration testing engagements
- Cyber security training ranges
- Red team exercises with explicit authorization
- Purple team collaborative security improvement

**Unauthorized use of these techniques is:**
- **ILLEGAL** under Computer Fraud and Abuse Act (CFAA) and international equivalents
- **UNETHICAL** and violates professional standards
- **DETECTABLE** and will result in incident response
- **PROSECUTABLE** with severe criminal penalties

**Requirements for Authorized Use:**
1. Written authorization from organization leadership
2. Defined scope of testing
3. Documented rules of engagement
4. Tested backup/recovery procedures
5. Incident response plan
6. Legal review

**The authors assume NO LIABILITY for misuse of these tools.**

---

## Support & Contribution

For questions, issues, or improvements:
- File issues in repository
- Contribute improved detection methods
- Share purple team exercise results
- Document evasion techniques encountered

**Remember:** The goal is to improve defensive capabilities, not to enable malicious activity.

---

**Happy Red Teaming (Authorized Only)!**
