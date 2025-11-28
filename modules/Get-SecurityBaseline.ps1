function Get-SecurityBaseline {
    <#
    .SYNOPSIS
        Generates a security baseline from current configuration.
    .DESCRIPTION
        Creates a baseline configuration document that can be used
        for future comparisons to detect configuration drift.
    .PARAMETER OutputPath
        Path to save the baseline file
    .EXAMPLE
        Get-SecurityBaseline -OutputPath C:\Baselines
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = '.\config'
    )

    Write-Verbose "Generating security baseline..."

    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $baseline = [PSCustomObject]@{
        GeneratedOn = Get-Date
        ComputerName = $env:COMPUTERNAME
        Domain = $env:USERDOMAIN
        OSVersion = (Get-WmiObject Win32_OperatingSystem).Caption
        Configuration = @{}
    }

    # Password Policy
    Write-Verbose "Capturing password policy..."
    $tempFile = Join-Path $env:TEMP "secpol_baseline.cfg"
    $null = secedit /export /cfg $tempFile /quiet 2>&1

    if (Test-Path $tempFile) {
        $secPolicy = Get-Content $tempFile
        $baseline.Configuration['PasswordPolicy'] = @{
            MinimumPasswordLength = ($secPolicy | Select-String 'MinimumPasswordLength\s*=\s*(\d+)').Matches.Groups[1].Value
            PasswordComplexity = ($secPolicy | Select-String 'PasswordComplexity\s*=\s*(\d+)').Matches.Groups[1].Value
            MaximumPasswordAge = ($secPolicy | Select-String 'MaximumPasswordAge\s*=\s*(\d+)').Matches.Groups[1].Value
            MinimumPasswordAge = ($secPolicy | Select-String 'MinimumPasswordAge\s*=\s*(\d+)').Matches.Groups[1].Value
            PasswordHistorySize = ($secPolicy | Select-String 'PasswordHistorySize\s*=\s*(\d+)').Matches.Groups[1].Value
            LockoutBadCount = ($secPolicy | Select-String 'LockoutBadCount\s*=\s*(\d+)').Matches.Groups[1].Value
            LockoutDuration = ($secPolicy | Select-String 'LockoutDuration\s*=\s*(\d+)').Matches.Groups[1].Value
        }
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }

    # Firewall Configuration
    Write-Verbose "Capturing firewall configuration..."
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $baseline.Configuration['Firewall'] = @{}

    foreach ($profile in $profiles) {
        $baseline.Configuration['Firewall'][$profile.Name] = @{
            Enabled = $profile.Enabled
            DefaultInboundAction = $profile.DefaultInboundAction.ToString()
            DefaultOutboundAction = $profile.DefaultOutboundAction.ToString()
            LogBlocked = $profile.LogBlocked
            LogAllowed = $profile.LogAllowed
        }
    }

    # Registry Security Settings
    Write-Verbose "Capturing registry security settings..."
    $baseline.Configuration['Registry'] = @{
        SMBServerSigning = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
        SMBClientSigning = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
        LLMNRDisabled = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -ErrorAction SilentlyContinue).EnableMulticast
        WDigest = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -ErrorAction SilentlyContinue).UseLogonCredential
        LSAProtection = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -ErrorAction SilentlyContinue).RunAsPPL
        EnableLUA = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue).EnableLUA
        CachedLogonsCount = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -ErrorAction SilentlyContinue).CachedLogonsCount
    }

    # Audit Policy
    Write-Verbose "Capturing audit policy..."
    $auditPolicy = auditpol /get /category:* 2>&1
    $baseline.Configuration['AuditPolicy'] = @{}

    $categories = @(
        'Credential Validation', 'Computer Account Management', 'Security Group Management',
        'User Account Management', 'Process Creation', 'Account Lockout', 'Logoff', 'Logon',
        'Special Logon', 'Audit Policy Change', 'Authentication Policy Change',
        'Sensitive Privilege Use', 'Security State Change', 'Security System Extension', 'System Integrity'
    )

    foreach ($cat in $categories) {
        $line = $auditPolicy | Where-Object { $_ -match $cat }
        if ($line) {
            $setting = if ($line -match 'Success and Failure') { 'Success and Failure' }
                       elseif ($line -match 'Success') { 'Success' }
                       elseif ($line -match 'Failure') { 'Failure' }
                       else { 'No Auditing' }
            $baseline.Configuration['AuditPolicy'][$cat] = $setting
        }
    }

    # Local Users
    Write-Verbose "Capturing user configuration..."
    $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
    $baseline.Configuration['Users'] = @{
        AdminEnabled = ($localUsers | Where-Object { $_.SID -like '*-500' }).Enabled
        GuestEnabled = ($localUsers | Where-Object { $_.SID -like '*-501' }).Enabled
        AdminRenamed = ($localUsers | Where-Object { $_.SID -like '*-500' }).Name -ne 'Administrator'
        LocalAdminCount = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Count
    }

    # Services
    Write-Verbose "Capturing service configuration..."
    $dangerousServices = @('RemoteRegistry', 'Telnet', 'SNMP', 'Fax')
    $baseline.Configuration['Services'] = @{}

    foreach ($svc in $dangerousServices) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            $baseline.Configuration['Services'][$svc] = @{
                Status = $service.Status.ToString()
                StartType = $service.StartType.ToString()
            }
        }
    }

    # Installed Hotfixes (last 10)
    Write-Verbose "Capturing installed hotfixes..."
    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 10
    $baseline.Configuration['Hotfixes'] = $hotfixes | ForEach-Object {
        @{
            HotFixID = $_.HotFixID
            InstalledOn = $_.InstalledOn
            Description = $_.Description
        }
    }

    # Save baseline
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $baselineFile = Join-Path $OutputPath "Baseline_$($env:COMPUTERNAME)_${timestamp}.json"

    $baseline | ConvertTo-Json -Depth 10 | Out-File -FilePath $baselineFile -Encoding UTF8

    Write-Host "Baseline saved to: $baselineFile" -ForegroundColor Green

    return $baseline
}

function Compare-SecurityBaseline {
    <#
    .SYNOPSIS
        Compares current configuration against a baseline.
    .DESCRIPTION
        Identifies configuration drift from a known-good baseline.
    .PARAMETER Current
        Current audit results
    .PARAMETER BaselinePath
        Path to the baseline JSON file
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Current,

        [Parameter(Mandatory)]
        [string]$BaselinePath
    )

    if (-not (Test-Path $BaselinePath)) {
        Write-Warning "Baseline file not found: $BaselinePath"
        return $null
    }

    $baseline = Get-Content $BaselinePath | ConvertFrom-Json
    $drift = @()

    Write-Verbose "Comparing against baseline from $($baseline.GeneratedOn)..."

    # Compare configurations
    # This is a simplified comparison - extend as needed

    $comparison = [PSCustomObject]@{
        BaselineDate = $baseline.GeneratedOn
        BaselineComputer = $baseline.ComputerName
        CurrentComputer = $Current.ComputerName
        DriftDetected = $false
        Changes = @()
    }

    # Add comparison logic here based on your specific needs
    # This would compare the current findings against the baseline

    return $comparison
}
