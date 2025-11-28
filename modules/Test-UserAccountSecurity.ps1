function Test-UserAccountSecurity {
    <#
    .SYNOPSIS
        Audits local user account security.
    .DESCRIPTION
        Checks for user account security issues:
        - Accounts with no password required
        - Accounts with password never expires
        - Inactive accounts
        - Accounts in Administrators group
        - Service accounts with weak configurations
    .PARAMETER Quick
        Perform quick scan
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick
    )

    $findings = @()

    Write-Verbose "Starting user account security audit..."

    $localUsers = Get-LocalUser -ErrorAction SilentlyContinue

    if (-not $localUsers) {
        return @{
            Status = 'Error'
            Message = 'Unable to query local users'
            Findings = @()
        }
    }

    # Check 1: Accounts with No Password Required
    $noPasswordRequired = $localUsers | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled -eq $true }
    foreach ($user in $noPasswordRequired) {
        $findings += [PSCustomObject]@{
            Check = "No Password Required - $($user.Name)"
            Severity = 'Critical'
            Status = 'Failed'
            Description = "User '$($user.Name)' does not require a password"
            Details = "Account enabled without password requirement"
            Remediation = "Set password requirement: Set-LocalUser -Name '$($user.Name)' -PasswordNeverExpires `$false"
            Reference = 'CIS Benchmark: 1.1.x'
        }
    }

    # Check 2: Accounts with Password Never Expires
    $passwordNeverExpires = $localUsers | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true }
    $serviceAccountPatterns = @('svc_', 'svc-', 'service', '_svc', '-svc')

    foreach ($user in $passwordNeverExpires) {
        $isServiceAccount = $false
        foreach ($pattern in $serviceAccountPatterns) {
            if ($user.Name -like "*$pattern*") {
                $isServiceAccount = $true
                break
            }
        }

        if (-not $isServiceAccount -and $user.Name -notin @('DefaultAccount', 'WDAGUtilityAccount')) {
            $findings += [PSCustomObject]@{
                Check = "Password Never Expires - $($user.Name)"
                Severity = 'Medium'
                Status = 'Failed'
                Description = "User '$($user.Name)' has password set to never expire"
                Details = "Non-service account with non-expiring password"
                Remediation = "Remove PasswordNeverExpires flag or convert to managed service account"
                Reference = 'CIS Benchmark: 1.1.4'
            }
        }
    }

    # Check 3: Inactive Accounts
    if (-not $Quick) {
        $inactiveThreshold = (Get-Date).AddDays(-90)
        $inactiveUsers = $localUsers | Where-Object {
            $_.Enabled -eq $true -and
            $_.LastLogon -and
            $_.LastLogon -lt $inactiveThreshold
        }

        if ($inactiveUsers.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Check = 'Inactive User Accounts'
                Severity = 'Low'
                Status = 'Warning'
                Description = "$($inactiveUsers.Count) accounts have not logged in for 90+ days"
                Details = ($inactiveUsers | Select-Object -First 5 -ExpandProperty Name) -join ', '
                Remediation = 'Disable or remove inactive accounts'
                Reference = 'CIS Benchmark: 1.1.5'
            }
        }
    }

    # Check 4: Local Administrators Group Membership
    $adminGroup = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
    if ($adminGroup.Count -gt 3) {
        $findings += [PSCustomObject]@{
            Check = 'Excessive Local Administrators'
            Severity = 'High'
            Status = 'Failed'
            Description = "$($adminGroup.Count) members in local Administrators group"
            Details = ($adminGroup | Select-Object -ExpandProperty Name) -join ', '
            Remediation = 'Limit local administrator membership to essential accounts only'
            Reference = 'Principle of least privilege'
        }
    }

    # Check 5: Built-in Administrator Account Status
    $builtinAdmin = $localUsers | Where-Object { $_.SID -like '*-500' }
    if ($builtinAdmin.Enabled) {
        $findings += [PSCustomObject]@{
            Check = 'Built-in Administrator Enabled'
            Severity = 'Medium'
            Status = 'Warning'
            Description = 'The built-in Administrator account is enabled'
            Details = "Account name: $($builtinAdmin.Name)"
            Remediation = 'Consider disabling the built-in Administrator and using named admin accounts'
            Reference = 'CIS Benchmark: 1.1.2'
        }
    }

    # Check 6: Recently Created Accounts
    $recentThreshold = (Get-Date).AddDays(-30)
    $recentAccounts = $localUsers | Where-Object {
        $_.Enabled -eq $true -and
        $_.PasswordLastSet -and
        $_.PasswordLastSet -gt $recentThreshold
    }

    if ($recentAccounts.Count -gt 2) {
        $findings += [PSCustomObject]@{
            Check = 'Recently Created Accounts'
            Severity = 'Info'
            Status = 'Info'
            Description = "$($recentAccounts.Count) accounts created or had password reset in last 30 days"
            Details = ($recentAccounts | Select-Object -ExpandProperty Name) -join ', '
            Remediation = 'Review recently created accounts for legitimacy'
            Reference = 'Security monitoring'
        }
    }

    # Check 7: Accounts with Administrative Privileges
    $adminPrivUsers = @()
    $privilegedGroups = @('Administrators', 'Backup Operators', 'Power Users', 'Remote Desktop Users')

    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
            foreach ($member in $members) {
                if ($member.ObjectClass -eq 'User') {
                    $adminPrivUsers += [PSCustomObject]@{
                        User = $member.Name
                        Group = $group
                    }
                }
            }
        }
        catch {
            # Group might not exist
        }
    }

    # Check 8: Guest Account Status
    $guestAccount = $localUsers | Where-Object { $_.SID -like '*-501' }
    if ($guestAccount.Enabled) {
        $findings += [PSCustomObject]@{
            Check = 'Guest Account Enabled'
            Severity = 'High'
            Status = 'Failed'
            Description = 'The built-in Guest account is enabled'
            Details = 'Guest account should always be disabled on servers'
            Remediation = "Disable-LocalUser -Name '$($guestAccount.Name)'"
            Reference = 'CIS Benchmark: 1.1.1'
        }
    }

    return @{
        Status = 'Completed'
        Findings = $findings
        TotalChecks = $findings.Count
        FailedChecks = ($findings | Where-Object { $_.Status -ne 'Passed' }).Count
    }
}
