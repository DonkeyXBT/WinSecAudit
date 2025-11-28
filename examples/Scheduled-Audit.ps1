#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets up scheduled security audits
.DESCRIPTION
    Creates a scheduled task to run security audits daily and email results.
.PARAMETER Time
    Time to run the audit (default: 02:00)
.PARAMETER OutputPath
    Path to save reports (default: C:\SecurityAudits)
.EXAMPLE
    .\Scheduled-Audit.ps1 -Time "03:00" -OutputPath "D:\Audits"
#>

param(
    [string]$Time = "02:00",
    [string]$OutputPath = "C:\SecurityAudits"
)

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$modulePath = (Get-Item $PSScriptRoot).Parent.FullName

$script = @"
Import-Module '$modulePath\WinSecAudit.psm1' -Force
Invoke-WinSecAudit -Format HTML -OutputPath '$OutputPath'
"@

$scriptPath = Join-Path $OutputPath "RunAudit.ps1"
$script | Out-File -FilePath $scriptPath -Force

# Create scheduled task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
$trigger = New-ScheduledTaskTrigger -Daily -At $Time
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask -TaskName "WinSecAudit Daily Scan" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Daily security audit using WinSecAudit" `
    -Force

Write-Host "Scheduled task created successfully!" -ForegroundColor Green
Write-Host "Audits will run daily at $Time" -ForegroundColor Cyan
Write-Host "Reports will be saved to: $OutputPath" -ForegroundColor Cyan
