function Test-LocalSecurityPolicy {
    <#
    .SYNOPSIS
        Audits local security policy settings.
    .DESCRIPTION
        Checks Windows local security policies against CIS benchmarks including:
        - Password policies
        - Account lockout policies
        - User rights assignments
        - Security options
    .PARAMETER Quick
        Perform quick scan
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick
    )

    $findings = @()

    Write-Verbose "Starting local security policy audit..."

    # Export security policy to temp file
    $tempFile = Join-Path $env:TEMP "secpol_$(Get-Date -Format 'yyyyMMddHHmmss').cfg"
    $null = secedit /export /cfg $tempFile /quiet 2>&1

    if (-not (Test-Path $tempFile)) {
        return @{
            Status = 'Error'
            Message = 'Failed to export security policy'
            Findings = @()
        }
    }

    $secPolicy = Get-Content $tempFile

    # Check 1: Minimum Password Length
    $minPwdLength = ($secPolicy | Select-String 'MinimumPasswordLength\s*=\s*(\d+)').Matches.Groups[1].Value
    if ([int]$minPwdLength -lt 14) {
        $findings += [PSCustomObject]@{
            Check = 'Minimum Password Length'
            Severity = 'High'
            Status = 'Failed'
            Description = "Minimum password length is $minPwdLength (recommended: >= 14)"
            Details = "Current setting: $minPwdLength characters"
            Remediation = 'Set minimum password length to 14 or greater via Group Policy'
            Reference = 'CIS Benchmark: 1.1.1'
        }
    }

    # Check 2: Password Complexity
    $pwdComplexity = ($secPolicy | Select-String 'PasswordComplexity\s*=\s*(\d+)').Matches.Groups[1].Value
    if ([int]$pwdComplexity -ne 1) {
        $findings += [PSCustomObject]@{
            Check = 'Password Complexity'
            Severity = 'High'
            Status = 'Failed'
            Description = 'Password complexity requirements are not enabled'
            Details = 'Password complexity should be enabled'
            Remediation = 'Enable password complexity requirements via Group Policy'
            Reference = 'CIS Benchmark: 1.1.5'
        }
    }

    # Check 3: Maximum Password Age
    $maxPwdAge = ($secPolicy | Select-String 'MaximumPasswordAge\s*=\s*(\d+)').Matches.Groups[1].Value
    if ([int]$maxPwdAge -gt 60 -or [int]$maxPwdAge -eq 0) {
        $findings += [PSCustomObject]@{
            Check = 'Maximum Password Age'
            Severity = 'Medium'
            Status = 'Failed'
            Description = "Maximum password age is $maxPwdAge days (recommended: <= 60)"
            Details = "Current setting: $maxPwdAge days"
            Remediation = 'Set maximum password age to 60 days or less'
            Reference = 'CIS Benchmark: 1.1.2'
        }
    }

    # Check 4: Account Lockout Threshold
    $lockoutThreshold = ($secPolicy | Select-String 'LockoutBadCount\s*=\s*(\d+)').Matches.Groups[1].Value
    if ([int]$lockoutThreshold -eq 0 -or [int]$lockoutThreshold -gt 5) {
        $findings += [PSCustomObject]@{
            Check = 'Account Lockout Threshold'
            Severity = 'High'
            Status = 'Failed'
            Description = "Account lockout threshold is $lockoutThreshold (recommended: 3-5)"
            Details = "Current setting: $lockoutThreshold attempts"
            Remediation = 'Set account lockout threshold to 3-5 invalid logon attempts'
            Reference = 'CIS Benchmark: 1.2.1'
        }
    }

    # Check 5: Account Lockout Duration
    $lockoutDuration = ($secPolicy | Select-String 'LockoutDuration\s*=\s*(\d+)').Matches.Groups[1].Value
    if ([int]$lockoutDuration -lt 15 -and [int]$lockoutDuration -ne 0) {
        $findings += [PSCustomObject]@{
            Check = 'Account Lockout Duration'
            Severity = 'Medium'
            Status = 'Failed'
            Description = "Account lockout duration is $lockoutDuration minutes (recommended: >= 15)"
            Details = "Current setting: $lockoutDuration minutes"
            Remediation = 'Set account lockout duration to 15 minutes or greater'
            Reference = 'CIS Benchmark: 1.2.2'
        }
    }

    # Check 6: Password History
    $pwdHistory = ($secPolicy | Select-String 'PasswordHistorySize\s*=\s*(\d+)').Matches.Groups[1].Value
    if ([int]$pwdHistory -lt 24) {
        $findings += [PSCustomObject]@{
            Check = 'Password History'
            Severity = 'Medium'
            Status = 'Failed'
            Description = "Password history is $pwdHistory (recommended: >= 24)"
            Details = "Current setting: $pwdHistory passwords remembered"
            Remediation = 'Set password history to 24 passwords'
            Reference = 'CIS Benchmark: 1.1.1'
        }
    }

    # Check 7: Administrator Account Renamed
    $adminAccount = Get-LocalUser | Where-Object { $_.SID -like '*-500' }
    if ($adminAccount.Name -eq 'Administrator') {
        $findings += [PSCustomObject]@{
            Check = 'Administrator Account Renamed'
            Severity = 'Low'
            Status = 'Failed'
            Description = 'The built-in Administrator account has not been renamed'
            Details = 'Renaming the account makes it harder to guess credentials'
            Remediation = 'Rename the Administrator account to a non-obvious name'
            Reference = 'CIS Benchmark: 2.3.1.5'
        }
    }

    # Check 8: Guest Account Disabled
    $guestAccount = Get-LocalUser | Where-Object { $_.SID -like '*-501' }
    if ($guestAccount.Enabled) {
        $findings += [PSCustomObject]@{
            Check = 'Guest Account Disabled'
            Severity = 'High'
            Status = 'Failed'
            Description = 'The built-in Guest account is enabled'
            Details = 'Guest account should be disabled'
            Remediation = 'Disable the Guest account: Disable-LocalUser -Name "Guest"'
            Reference = 'CIS Benchmark: 2.3.1.2'
        }
    }

    # Cleanup temp file
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

    return @{
        Status = 'Completed'
        Findings = $findings
        TotalChecks = $findings.Count
        FailedChecks = ($findings | Where-Object { $_.Status -ne 'Passed' }).Count
    }
}
