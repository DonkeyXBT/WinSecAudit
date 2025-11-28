#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    WinSecAudit - Windows Server Security Auditing Framework
.DESCRIPTION
    A comprehensive PowerShell module for auditing Windows Server security configurations,
    detecting misconfigurations, and identifying potential vulnerabilities in Active Directory,
    network settings, user accounts, and system hardening.
.NOTES
    Author: WinSecAudit Contributors
    Version: 1.0.0
    License: MIT
#>

# Module Variables
$script:ModuleRoot = $PSScriptRoot
$script:ReportPath = Join-Path $ModuleRoot "reports"
$script:ConfigPath = Join-Path $ModuleRoot "config"

# Import all module functions
$Public = @(Get-ChildItem -Path "$ModuleRoot\modules\*.ps1" -ErrorAction SilentlyContinue)

foreach ($import in $Public) {
    try {
        . $import.FullName
        Write-Verbose "Imported $($import.Name)"
    }
    catch {
        Write-Error "Failed to import function $($import.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function @(
    'Invoke-WinSecAudit',
    'Get-SecurityBaseline',
    'Test-ADSecurityConfig',
    'Test-LocalSecurityPolicy',
    'Test-FirewallConfig',
    'Test-ServiceSecurity',
    'Test-RegistrySecurity',
    'Test-UserAccountSecurity',
    'Test-NetworkSecurity',
    'Test-AuditPolicy',
    'Get-SuspiciousProcesses',
    'Get-ScheduledTaskAudit',
    'Export-AuditReport',
    'Compare-SecurityBaseline'
)
