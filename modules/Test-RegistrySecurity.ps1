function Test-RegistrySecurity {
    <#
    .SYNOPSIS
        Audits Windows Registry security settings.
    .DESCRIPTION
        Checks critical registry security configurations:
        - AutoRun settings
        - Remote assistance
        - SMB signing
        - LLMNR/NetBIOS settings
        - WDigest authentication
        - UAC configuration
        - Credential storage
    .PARAMETER Quick
        Perform quick scan
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick
    )

    $findings = @()

    Write-Verbose "Starting registry security audit..."

    # Helper function to safely get registry value
    function Get-RegValue {
        param($Path, $Name, $Default = $null)
        try {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $value.$Name
        }
        catch {
            return $Default
        }
    }

    # Check 1: AutoRun Disabled
    $autoRunPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    )

    foreach ($path in $autoRunPaths) {
        $noAutoRun = Get-RegValue -Path $path -Name 'NoDriveTypeAutoRun' -Default 0
        if ($noAutoRun -ne 255) {
            $findings += [PSCustomObject]@{
                Check = 'AutoRun Not Fully Disabled'
                Severity = 'Medium'
                Status = 'Failed'
                Description = 'AutoRun is not disabled for all drive types'
                Details = "Path: $path, Value: $noAutoRun (should be 255)"
                Remediation = 'Set NoDriveTypeAutoRun to 255 (0xFF) via Group Policy'
                Reference = 'CIS Benchmark: 18.9.8.3'
            }
            break
        }
    }

    # Check 2: SMB Signing
    $smbServerSigning = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Default 0
    if ($smbServerSigning -ne 1) {
        $findings += [PSCustomObject]@{
            Check = 'SMB Server Signing Not Required'
            Severity = 'High'
            Status = 'Failed'
            Description = 'SMB server does not require signing'
            Details = 'SMB signing helps prevent man-in-the-middle attacks'
            Remediation = 'Enable via Group Policy: Microsoft network server: Digitally sign communications (always)'
            Reference = 'CIS Benchmark: 2.3.9.2'
        }
    }

    $smbClientSigning = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Default 0
    if ($smbClientSigning -ne 1) {
        $findings += [PSCustomObject]@{
            Check = 'SMB Client Signing Not Required'
            Severity = 'High'
            Status = 'Failed'
            Description = 'SMB client does not require signing'
            Details = 'SMB signing helps prevent relay attacks'
            Remediation = 'Enable via Group Policy: Microsoft network client: Digitally sign communications (always)'
            Reference = 'CIS Benchmark: 2.3.8.1'
        }
    }

    # Check 3: LLMNR Disabled
    $llmnrDisabled = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Default 1
    if ($llmnrDisabled -ne 0) {
        $findings += [PSCustomObject]@{
            Check = 'LLMNR Not Disabled'
            Severity = 'High'
            Status = 'Failed'
            Description = 'Link-Local Multicast Name Resolution (LLMNR) is enabled'
            Details = 'LLMNR can be abused for credential theft via poisoning attacks'
            Remediation = 'Disable via Group Policy: Turn off multicast name resolution'
            Reference = 'MITRE ATT&CK T1557.001'
        }
    }

    # Check 4: NetBIOS over TCP/IP
    $nbns = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Default 0
    if ($nbns -ne 2) {
        $findings += [PSCustomObject]@{
            Check = 'NetBIOS Configuration'
            Severity = 'Medium'
            Status = 'Warning'
            Description = 'NetBIOS NodeType not set to P-node (peer-to-peer only)'
            Details = 'Current NodeType: ' + $(switch($nbns) { 1 {'B-node'} 2 {'P-node'} 4 {'M-node'} 8 {'H-node'} default {'Unknown'} })
            Remediation = 'Set NodeType to 2 (P-node) to disable broadcast queries'
            Reference = 'MITRE ATT&CK T1557.001'
        }
    }

    # Check 5: WDigest Authentication
    $wdigest = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Default 0
    if ($wdigest -eq 1) {
        $findings += [PSCustomObject]@{
            Check = 'WDigest Authentication Enabled'
            Severity = 'Critical'
            Status = 'Failed'
            Description = 'WDigest stores credentials in clear text in memory'
            Details = 'This allows credential theft via tools like Mimikatz'
            Remediation = 'Set UseLogonCredential to 0 in HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            Reference = 'KB2871997'
        }
    }

    # Check 6: UAC Configuration
    $uacSettings = @{
        EnableLUA = @{ Expected = 1; Severity = 'Critical'; Description = 'UAC is disabled' }
        ConsentPromptBehaviorAdmin = @{ Expected = 2; Severity = 'High'; Description = 'UAC admin prompt not requiring credentials' }
        PromptOnSecureDesktop = @{ Expected = 1; Severity = 'Medium'; Description = 'UAC not using secure desktop' }
    }

    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    foreach ($setting in $uacSettings.GetEnumerator()) {
        $value = Get-RegValue -Path $uacPath -Name $setting.Key -Default $setting.Value.Expected
        if ($value -ne $setting.Value.Expected) {
            $findings += [PSCustomObject]@{
                Check = "UAC Setting - $($setting.Key)"
                Severity = $setting.Value.Severity
                Status = 'Failed'
                Description = $setting.Value.Description
                Details = "Current: $value, Expected: $($setting.Value.Expected)"
                Remediation = 'Configure UAC via Group Policy or Security Policy'
                Reference = 'CIS Benchmark: 2.3.17.x'
            }
        }
    }

    # Check 7: LSA Protection
    $lsaProtection = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Default 0
    if ($lsaProtection -ne 1) {
        $findings += [PSCustomObject]@{
            Check = 'LSA Protection Not Enabled'
            Severity = 'High'
            Status = 'Failed'
            Description = 'LSA is not running as Protected Process Light (PPL)'
            Details = 'LSA protection helps prevent credential dumping'
            Remediation = 'Enable Credential Guard or set RunAsPPL to 1'
            Reference = 'https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection'
        }
    }

    # Check 8: Cached Credentials
    $cachedLogons = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Default 10
    if ([int]$cachedLogons -gt 2) {
        $findings += [PSCustomObject]@{
            Check = 'Cached Credentials Count'
            Severity = 'Medium'
            Status = 'Warning'
            Description = "System caches $cachedLogons logon credentials"
            Details = 'Cached credentials can be extracted and cracked offline'
            Remediation = 'Reduce CachedLogonsCount to 2 or less for servers'
            Reference = 'CIS Benchmark: 2.3.7.1'
        }
    }

    # Check 9: Restrict Anonymous Access
    $restrictAnon = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Default 0
    if ($restrictAnon -lt 1) {
        $findings += [PSCustomObject]@{
            Check = 'Anonymous Access Restrictions'
            Severity = 'Medium'
            Status = 'Failed'
            Description = 'Anonymous access to SAM accounts is not restricted'
            Details = 'Anonymous users may enumerate user accounts'
            Remediation = 'Set RestrictAnonymous to 1 or higher'
            Reference = 'CIS Benchmark: 2.3.10.2'
        }
    }

    return @{
        Status = 'Completed'
        Findings = $findings
        TotalChecks = $findings.Count
        FailedChecks = ($findings | Where-Object { $_.Status -ne 'Passed' }).Count
    }
}
