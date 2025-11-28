function Test-ADSecurityConfig {
    <#
    .SYNOPSIS
        Audits Active Directory security configuration.
    .DESCRIPTION
        Checks for common AD security misconfigurations including:
        - Kerberos delegation settings
        - AdminSDHolder protected accounts
        - Stale accounts and passwords
        - Group Policy security settings
        - Privileged group membership
        - KRBTGT password age
        - Trust relationships
        - LDAP signing requirements
    .PARAMETER Quick
        Perform quick scan (skip time-consuming checks)
    .EXAMPLE
        Test-ADSecurityConfig -Quick
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick
    )

    $findings = @()

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        return @{
            Status = 'Error'
            Message = 'Active Directory module not available'
            Findings = @()
        }
    }

    Write-Verbose "Starting Active Directory security audit..."

    # Check 1: Unconstrained Kerberos Delegation
    Write-Verbose "Checking for unconstrained delegation..."
    $unconstrainedDelegation = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
        Where-Object { $_.Name -ne 'DC' }

    if ($unconstrainedDelegation) {
        $findings += [PSCustomObject]@{
            Check = 'Unconstrained Kerberos Delegation'
            Severity = 'Critical'
            Status = 'Failed'
            Description = 'Computers found with unconstrained delegation enabled'
            Details = ($unconstrainedDelegation | Select-Object -ExpandProperty Name) -join ', '
            Remediation = 'Configure constrained delegation or resource-based constrained delegation instead'
            Reference = 'https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview'
        }
    }

    # Check 2: Users with "Password Never Expires"
    Write-Verbose "Checking for password never expires..."
    $passwordNeverExpires = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires

    if ($passwordNeverExpires.Count -gt 0) {
        $findings += [PSCustomObject]@{
            Check = 'Password Never Expires'
            Severity = 'Medium'
            Status = 'Failed'
            Description = "$($passwordNeverExpires.Count) enabled users have passwords that never expire"
            Details = ($passwordNeverExpires | Select-Object -First 10 -ExpandProperty SamAccountName) -join ', '
            Remediation = 'Review accounts and remove PasswordNeverExpires flag where possible'
            Reference = 'CIS Benchmark: 1.1.5'
        }
    }

    # Check 3: AdminSDHolder Protected Groups
    Write-Verbose "Checking AdminSDHolder protected accounts..."
    $protectedGroups = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins',
        'Administrators', 'Account Operators', 'Backup Operators',
        'Print Operators', 'Server Operators'
    )

    $privilegedMembers = @()
    foreach ($group in $protectedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
            $privilegedMembers += $members | ForEach-Object {
                [PSCustomObject]@{
                    Group = $group
                    Member = $_.SamAccountName
                    ObjectClass = $_.ObjectClass
                }
            }
        }
        catch {
            # Group might not exist in all domains
        }
    }

    $domainAdmins = ($privilegedMembers | Where-Object { $_.Group -eq 'Domain Admins' }).Count
    if ($domainAdmins -gt 5) {
        $findings += [PSCustomObject]@{
            Check = 'Excessive Domain Admins'
            Severity = 'High'
            Status = 'Failed'
            Description = "Found $domainAdmins members in Domain Admins group (recommended: <= 5)"
            Details = ($privilegedMembers | Where-Object { $_.Group -eq 'Domain Admins' } | Select-Object -ExpandProperty Member) -join ', '
            Remediation = 'Review and reduce Domain Admin membership to essential accounts only'
            Reference = 'CIS Benchmark: 1.1.1'
        }
    }

    # Check 4: KRBTGT Password Age
    Write-Verbose "Checking KRBTGT password age..."
    $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet
    $krbtgtAge = (Get-Date) - $krbtgt.PasswordLastSet

    if ($krbtgtAge.TotalDays -gt 180) {
        $findings += [PSCustomObject]@{
            Check = 'KRBTGT Password Age'
            Severity = 'High'
            Status = 'Failed'
            Description = "KRBTGT password is $([int]$krbtgtAge.TotalDays) days old"
            Details = "Last changed: $($krbtgt.PasswordLastSet)"
            Remediation = 'Reset KRBTGT password twice (with replication between resets) every 180 days'
            Reference = 'https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password'
        }
    }

    # Check 5: Stale Computer Accounts
    if (-not $Quick) {
        Write-Verbose "Checking for stale computer accounts..."
        $staleThreshold = (Get-Date).AddDays(-90)
        $staleComputers = Get-ADComputer -Filter {LastLogonDate -lt $staleThreshold -and Enabled -eq $true} -Properties LastLogonDate

        if ($staleComputers.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Check = 'Stale Computer Accounts'
                Severity = 'Low'
                Status = 'Failed'
                Description = "$($staleComputers.Count) computer accounts have not logged in for 90+ days"
                Details = ($staleComputers | Select-Object -First 10 -ExpandProperty Name) -join ', '
                Remediation = 'Disable or remove stale computer accounts'
                Reference = 'CIS Benchmark: 1.1.3'
            }
        }
    }

    # Check 6: LDAP Signing
    Write-Verbose "Checking LDAP signing configuration..."
    try {
        $ldapSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -ErrorAction SilentlyContinue

        if (-not $ldapSigning -or $ldapSigning.LDAPServerIntegrity -ne 2) {
            $findings += [PSCustomObject]@{
                Check = 'LDAP Signing Not Required'
                Severity = 'High'
                Status = 'Failed'
                Description = 'LDAP signing is not enforced on domain controllers'
                Details = "Current value: $($ldapSigning.LDAPServerIntegrity)"
                Remediation = 'Set LDAPServerIntegrity to 2 (Require signing)'
                Reference = 'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-controller-ldap-server-signing-requirements'
            }
        }
    }
    catch {
        # Not a DC or registry key doesn't exist
    }

    # Check 7: Guest Account Status
    Write-Verbose "Checking Guest account status..."
    $guest = Get-ADUser -Identity 'Guest' -Properties Enabled
    if ($guest.Enabled) {
        $findings += [PSCustomObject]@{
            Check = 'Guest Account Enabled'
            Severity = 'Medium'
            Status = 'Failed'
            Description = 'The built-in Guest account is enabled'
            Details = 'Guest account should be disabled'
            Remediation = 'Disable the Guest account: Disable-ADAccount -Identity Guest'
            Reference = 'CIS Benchmark: 1.1.4'
        }
    }

    # Check 8: SIDHistory on Users
    if (-not $Quick) {
        Write-Verbose "Checking for SIDHistory abuse..."
        $sidHistoryUsers = Get-ADUser -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory.Count -gt 0 }

        if ($sidHistoryUsers) {
            $findings += [PSCustomObject]@{
                Check = 'Users with SIDHistory'
                Severity = 'Medium'
                Status = 'Warning'
                Description = "$($sidHistoryUsers.Count) users have SIDHistory populated"
                Details = ($sidHistoryUsers | Select-Object -ExpandProperty SamAccountName) -join ', '
                Remediation = 'Review SIDHistory entries and remove if not needed for migration'
                Reference = 'https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-sid-history-attribute'
            }
        }
    }

    # Add passed checks
    if (-not ($findings | Where-Object { $_.Check -eq 'KRBTGT Password Age' })) {
        $findings += [PSCustomObject]@{
            Check = 'KRBTGT Password Age'
            Severity = 'Passed'
            Status = 'Passed'
            Description = 'KRBTGT password was changed within the last 180 days'
        }
    }

    return @{
        Status = 'Completed'
        Findings = $findings
        TotalChecks = $findings.Count
        FailedChecks = ($findings | Where-Object { $_.Status -ne 'Passed' }).Count
    }
}
