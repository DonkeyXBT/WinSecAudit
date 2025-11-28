function Test-AuditPolicy {
    <#
    .SYNOPSIS
        Audits Windows audit policy configuration.
    .DESCRIPTION
        Checks audit policy settings against security best practices:
        - Account logon events
        - Logon events
        - Object access
        - Privilege use
        - Process tracking
        - Policy change
        - System events
    .PARAMETER Quick
        Perform quick scan
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick
    )

    $findings = @()

    Write-Verbose "Starting audit policy assessment..."

    # Get advanced audit policy
    $auditPolicy = auditpol /get /category:* 2>&1

    if ($LASTEXITCODE -ne 0) {
        return @{
            Status = 'Error'
            Message = 'Unable to query audit policy'
            Findings = @()
        }
    }

    # Define required audit settings (CIS Benchmark recommendations)
    $requiredSettings = @{
        'Credential Validation' = @{ Required = 'Success and Failure'; Severity = 'High' }
        'Computer Account Management' = @{ Required = 'Success'; Severity = 'Medium' }
        'Security Group Management' = @{ Required = 'Success'; Severity = 'High' }
        'User Account Management' = @{ Required = 'Success and Failure'; Severity = 'High' }
        'Process Creation' = @{ Required = 'Success'; Severity = 'High' }
        'Account Lockout' = @{ Required = 'Failure'; Severity = 'High' }
        'Logoff' = @{ Required = 'Success'; Severity = 'Low' }
        'Logon' = @{ Required = 'Success and Failure'; Severity = 'High' }
        'Special Logon' = @{ Required = 'Success'; Severity = 'High' }
        'Audit Policy Change' = @{ Required = 'Success'; Severity = 'High' }
        'Authentication Policy Change' = @{ Required = 'Success'; Severity = 'Medium' }
        'Sensitive Privilege Use' = @{ Required = 'Success and Failure'; Severity = 'High' }
        'Security State Change' = @{ Required = 'Success'; Severity = 'High' }
        'Security System Extension' = @{ Required = 'Success'; Severity = 'High' }
        'System Integrity' = @{ Required = 'Success and Failure'; Severity = 'High' }
    }

    foreach ($setting in $requiredSettings.GetEnumerator()) {
        $policyLine = $auditPolicy | Where-Object { $_ -match $setting.Key }

        if ($policyLine) {
            $currentSetting = if ($policyLine -match 'Success and Failure') {
                'Success and Failure'
            } elseif ($policyLine -match 'Success') {
                'Success'
            } elseif ($policyLine -match 'Failure') {
                'Failure'
            } else {
                'No Auditing'
            }

            $requiredValue = $setting.Value.Required
            $isCompliant = $false

            # Check compliance
            if ($requiredValue -eq 'Success and Failure' -and $currentSetting -eq 'Success and Failure') {
                $isCompliant = $true
            }
            elseif ($requiredValue -eq 'Success' -and ($currentSetting -eq 'Success' -or $currentSetting -eq 'Success and Failure')) {
                $isCompliant = $true
            }
            elseif ($requiredValue -eq 'Failure' -and ($currentSetting -eq 'Failure' -or $currentSetting -eq 'Success and Failure')) {
                $isCompliant = $true
            }

            if (-not $isCompliant) {
                $findings += [PSCustomObject]@{
                    Check = "Audit Policy - $($setting.Key)"
                    Severity = $setting.Value.Severity
                    Status = 'Failed'
                    Description = "Audit policy '$($setting.Key)' is not properly configured"
                    Details = "Current: $currentSetting, Required: $requiredValue"
                    Remediation = "Configure via: auditpol /set /subcategory:`"$($setting.Key)`" /success:enable /failure:enable"
                    Reference = 'CIS Benchmark: 17.x'
                }
            }
        }
    }

    # Check 2: Command Line Process Auditing
    $cmdLineAudit = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue

    if (-not $cmdLineAudit -or $cmdLineAudit.ProcessCreationIncludeCmdLine_Enabled -ne 1) {
        $findings += [PSCustomObject]@{
            Check = 'Command Line in Process Audit Events'
            Severity = 'High'
            Status = 'Failed'
            Description = 'Command line is not included in process creation events'
            Details = 'Process command lines provide valuable forensic information'
            Remediation = 'Enable "Include command line in process creation events" via Group Policy'
            Reference = 'CIS Benchmark: 18.9.27.1'
        }
    }

    # Check 3: PowerShell Script Block Logging
    $psLogging = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue

    if (-not $psLogging -or $psLogging.EnableScriptBlockLogging -ne 1) {
        $findings += [PSCustomObject]@{
            Check = 'PowerShell Script Block Logging'
            Severity = 'High'
            Status = 'Failed'
            Description = 'PowerShell script block logging is not enabled'
            Details = 'Script block logging captures PowerShell commands for analysis'
            Remediation = 'Enable via Group Policy: Turn on PowerShell Script Block Logging'
            Reference = 'https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
        }
    }

    # Check 4: PowerShell Module Logging
    $psModuleLogging = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -ErrorAction SilentlyContinue

    if (-not $psModuleLogging -or $psModuleLogging.EnableModuleLogging -ne 1) {
        $findings += [PSCustomObject]@{
            Check = 'PowerShell Module Logging'
            Severity = 'Medium'
            Status = 'Failed'
            Description = 'PowerShell module logging is not enabled'
            Details = 'Module logging provides visibility into PowerShell activity'
            Remediation = 'Enable via Group Policy: Turn on Module Logging'
            Reference = 'CIS Benchmark: 18.9.97.1'
        }
    }

    # Check 5: Windows Event Log Sizes
    $logChecks = @{
        'Security' = @{ MinSize = 196608; Severity = 'High' }  # 192 MB
        'System' = @{ MinSize = 32768; Severity = 'Medium' }    # 32 MB
        'Application' = @{ MinSize = 32768; Severity = 'Low' }  # 32 MB
    }

    foreach ($log in $logChecks.GetEnumerator()) {
        try {
            $eventLog = Get-WinEvent -ListLog $log.Key -ErrorAction Stop
            if ($eventLog.MaximumSizeInBytes -lt ($log.Value.MinSize * 1024)) {
                $findings += [PSCustomObject]@{
                    Check = "Event Log Size - $($log.Key)"
                    Severity = $log.Value.Severity
                    Status = 'Warning'
                    Description = "$($log.Key) event log max size may be insufficient"
                    Details = "Current: $([math]::Round($eventLog.MaximumSizeInBytes / 1MB, 2)) MB, Recommended: $([math]::Round($log.Value.MinSize / 1024, 2)) MB"
                    Remediation = "Increase log size via: wevtutil sl $($log.Key) /ms:$($log.Value.MinSize * 1024)"
                    Reference = 'CIS Benchmark: 18.9.27.x'
                }
            }
        }
        catch {
            # Unable to query log
        }
    }

    return @{
        Status = 'Completed'
        Findings = $findings
        TotalChecks = $findings.Count
        FailedChecks = ($findings | Where-Object { $_.Status -ne 'Passed' }).Count
    }
}
