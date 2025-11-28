#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Disables legacy and insecure network protocols
.DESCRIPTION
    Disables protocols commonly exploited for attacks:
    - LLMNR (Link-Local Multicast Name Resolution)
    - NetBIOS over TCP/IP
    - WPAD (Web Proxy Auto-Discovery)
.PARAMETER WhatIf
    Shows what changes would be made without applying them
.EXAMPLE
    .\Disable-LegacyProtocols.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param()

Write-Host "Legacy Protocol Disabling Script" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# 1. Disable LLMNR
Write-Host "`n[1/3] Disabling LLMNR..." -ForegroundColor Yellow
$llmnrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'

if (-not (Test-Path $llmnrPath)) {
    New-Item -Path $llmnrPath -Force | Out-Null
}

$llmnr = Get-ItemProperty -Path $llmnrPath -Name 'EnableMulticast' -ErrorAction SilentlyContinue

if ($llmnr.EnableMulticast -ne 0) {
    if ($PSCmdlet.ShouldProcess("LLMNR", "Disable")) {
        Set-ItemProperty -Path $llmnrPath -Name 'EnableMulticast' -Value 0 -Type DWord
        Write-Host "  LLMNR disabled" -ForegroundColor Green
        Write-Host "  This prevents LLMNR poisoning attacks (Responder, etc.)" -ForegroundColor Gray
    }
} else {
    Write-Host "  LLMNR already disabled" -ForegroundColor Green
}

# 2. Disable NetBIOS over TCP/IP on all adapters
Write-Host "`n[2/3] Disabling NetBIOS over TCP/IP..." -ForegroundColor Yellow

$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }

foreach ($adapter in $adapters) {
    $currentSetting = $adapter.TcpipNetbiosOptions
    # 0 = Default, 1 = Enable, 2 = Disable
    if ($currentSetting -ne 2) {
        if ($PSCmdlet.ShouldProcess("NetBIOS on $($adapter.Description)", "Disable")) {
            $result = $adapter.SetTcpipNetbios(2)
            if ($result.ReturnValue -eq 0) {
                Write-Host "  Disabled on: $($adapter.Description)" -ForegroundColor Green
            } else {
                Write-Host "  Failed on: $($adapter.Description)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "  Already disabled on: $($adapter.Description)" -ForegroundColor Green
    }
}

# Also set global NetBIOS node type to P-node (no broadcast)
$netbtPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
if ($PSCmdlet.ShouldProcess("NetBIOS NodeType", "Set to P-node")) {
    Set-ItemProperty -Path $netbtPath -Name 'NodeType' -Value 2 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "  NetBIOS NodeType set to P-node (no broadcasts)" -ForegroundColor Green
}

# 3. Disable WPAD
Write-Host "`n[3/3] Disabling WPAD..." -ForegroundColor Yellow
$wpadPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'

if (-not (Test-Path $wpadPath)) {
    New-Item -Path $wpadPath -Force | Out-Null
}

if ($PSCmdlet.ShouldProcess("WPAD", "Disable")) {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'AutoDetect' -Value 0 -Type DWord -ErrorAction SilentlyContinue

    # Disable WinHTTP AutoProxy Service
    $winhttpSvc = Get-Service -Name 'WinHttpAutoProxySvc' -ErrorAction SilentlyContinue
    if ($winhttpSvc -and $winhttpSvc.StartType -ne 'Disabled') {
        Set-Service -Name 'WinHttpAutoProxySvc' -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name 'WinHttpAutoProxySvc' -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  WPAD disabled" -ForegroundColor Green
    Write-Host "  This prevents WPAD poisoning attacks" -ForegroundColor Gray
}

Write-Host "`nLegacy protocol hardening complete!" -ForegroundColor Cyan
Write-Host @"

Security Impact:
- LLMNR disabled: Prevents credential interception via poisoning
- NetBIOS disabled: Blocks NBT-NS poisoning and enumeration
- WPAD disabled: Prevents web proxy hijacking attacks

These protocols are commonly exploited by tools like:
- Responder
- Inveigh
- mitm6

"@ -ForegroundColor Gray
