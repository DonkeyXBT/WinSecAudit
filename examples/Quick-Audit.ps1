#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Quick security audit example
.DESCRIPTION
    Runs a quick security audit and outputs results to the console and HTML file.
.EXAMPLE
    .\Quick-Audit.ps1
#>

# Import the module
$modulePath = Join-Path $PSScriptRoot '..' 'WinSecAudit.psm1'
Import-Module $modulePath -Force

# Run quick audit
Write-Host "Starting quick security audit..." -ForegroundColor Cyan
$results = Invoke-WinSecAudit -Quick -Format HTML

# Display summary
Write-Host "`nAudit completed!" -ForegroundColor Green
Write-Host "Critical findings: $($results.Summary.Critical)" -ForegroundColor $(if($results.Summary.Critical -gt 0){'Red'}else{'Green'})
Write-Host "High findings: $($results.Summary.High)" -ForegroundColor $(if($results.Summary.High -gt 0){'Yellow'}else{'Green'})
