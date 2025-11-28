#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Hardens SMB configuration for security
.DESCRIPTION
    Applies security best practices to SMB configuration:
    - Enables SMB signing
    - Disables SMBv1
    - Configures encryption
.PARAMETER WhatIf
    Shows what changes would be made without applying them
.EXAMPLE
    .\Harden-SMB.ps1 -WhatIf
    .\Harden-SMB.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param()

Write-Host "SMB Hardening Script" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan

# 1. Disable SMBv1
Write-Host "`n[1/4] Checking SMBv1 status..." -ForegroundColor Yellow
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue

if ($smb1.State -eq 'Enabled') {
    if ($PSCmdlet.ShouldProcess("SMBv1 Protocol", "Disable")) {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
        Write-Host "  SMBv1 disabled (restart required)" -ForegroundColor Green
    }
} else {
    Write-Host "  SMBv1 already disabled" -ForegroundColor Green
}

# 2. Enable SMB Signing (Server)
Write-Host "`n[2/4] Configuring SMB Server signing..." -ForegroundColor Yellow
$serverSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue

if ($serverSigning.RequireSecuritySignature -ne 1) {
    if ($PSCmdlet.ShouldProcess("SMB Server Signing", "Enable")) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Type DWord
        Write-Host "  SMB Server signing enabled" -ForegroundColor Green
    }
} else {
    Write-Host "  SMB Server signing already enabled" -ForegroundColor Green
}

# 3. Enable SMB Signing (Client)
Write-Host "`n[3/4] Configuring SMB Client signing..." -ForegroundColor Yellow
$clientSigning = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue

if ($clientSigning.RequireSecuritySignature -ne 1) {
    if ($PSCmdlet.ShouldProcess("SMB Client Signing", "Enable")) {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Type DWord
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Type DWord
        Write-Host "  SMB Client signing enabled" -ForegroundColor Green
    }
} else {
    Write-Host "  SMB Client signing already enabled" -ForegroundColor Green
}

# 4. Enable SMB Encryption (Server 2012 R2+)
Write-Host "`n[4/4] Configuring SMB Encryption..." -ForegroundColor Yellow
try {
    $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
    if (-not $smbConfig.EncryptData) {
        if ($PSCmdlet.ShouldProcess("SMB Encryption", "Enable")) {
            Set-SmbServerConfiguration -EncryptData $true -Force
            Write-Host "  SMB Encryption enabled" -ForegroundColor Green
        }
    } else {
        Write-Host "  SMB Encryption already enabled" -ForegroundColor Green
    }
}
catch {
    Write-Host "  SMB Encryption configuration not available" -ForegroundColor Yellow
}

Write-Host "`nSMB hardening complete!" -ForegroundColor Cyan
Write-Host "Note: Some changes may require a restart to take effect." -ForegroundColor Yellow
