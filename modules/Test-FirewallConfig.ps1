function Test-FirewallConfig {
    <#
    .SYNOPSIS
        Audits Windows Firewall configuration.
    .DESCRIPTION
        Checks Windows Firewall settings for security issues:
        - Firewall enabled status for all profiles
        - Inbound/outbound default actions
        - High-risk open ports
        - Rules allowing any source
        - Remote Desktop security
    .PARAMETER Quick
        Perform quick scan
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick
    )

    $findings = @()

    Write-Verbose "Starting firewall configuration audit..."

    # Get firewall profiles
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue

    if (-not $profiles) {
        return @{
            Status = 'Error'
            Message = 'Unable to query Windows Firewall'
            Findings = @()
        }
    }

    # Check 1: Firewall Enabled for All Profiles
    foreach ($profile in $profiles) {
        if (-not $profile.Enabled) {
            $findings += [PSCustomObject]@{
                Check = "Firewall Enabled - $($profile.Name)"
                Severity = 'Critical'
                Status = 'Failed'
                Description = "Windows Firewall is disabled for $($profile.Name) profile"
                Details = "Profile: $($profile.Name), Enabled: $($profile.Enabled)"
                Remediation = "Enable firewall: Set-NetFirewallProfile -Profile $($profile.Name) -Enabled True"
                Reference = 'CIS Benchmark: 9.1.1'
            }
        }

        # Check default inbound action
        if ($profile.DefaultInboundAction -ne 'Block') {
            $findings += [PSCustomObject]@{
                Check = "Default Inbound Action - $($profile.Name)"
                Severity = 'High'
                Status = 'Failed'
                Description = "Default inbound action is not Block for $($profile.Name) profile"
                Details = "Current: $($profile.DefaultInboundAction), Expected: Block"
                Remediation = "Set-NetFirewallProfile -Profile $($profile.Name) -DefaultInboundAction Block"
                Reference = 'CIS Benchmark: 9.1.2'
            }
        }
    }

    # Check 2: High-Risk Inbound Rules
    $highRiskPorts = @(
        @{ Port = 21; Service = 'FTP' },
        @{ Port = 23; Service = 'Telnet' },
        @{ Port = 135; Service = 'RPC' },
        @{ Port = 137; Service = 'NetBIOS' },
        @{ Port = 138; Service = 'NetBIOS' },
        @{ Port = 139; Service = 'NetBIOS' },
        @{ Port = 445; Service = 'SMB' },
        @{ Port = 1433; Service = 'SQL Server' },
        @{ Port = 1434; Service = 'SQL Browser' },
        @{ Port = 3389; Service = 'RDP' },
        @{ Port = 5985; Service = 'WinRM HTTP' },
        @{ Port = 5986; Service = 'WinRM HTTPS' }
    )

    $inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue

    foreach ($risk in $highRiskPorts) {
        $matchingRules = $inboundRules | Where-Object {
            $portFilter = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $portFilter.LocalPort -eq $risk.Port -or $portFilter.LocalPort -eq 'Any'
        }

        if ($matchingRules) {
            # Check if rule allows from any source
            $anySourceRules = $matchingRules | Where-Object {
                $addressFilter = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                $addressFilter.RemoteAddress -eq 'Any'
            }

            if ($anySourceRules) {
                $severity = if ($risk.Port -in @(23, 21, 445, 135)) { 'Critical' } else { 'High' }
                $findings += [PSCustomObject]@{
                    Check = "High-Risk Port Open - $($risk.Service)"
                    Severity = $severity
                    Status = 'Failed'
                    Description = "Port $($risk.Port) ($($risk.Service)) is open to any source"
                    Details = "Rules: $(($anySourceRules.DisplayName | Select-Object -First 3) -join ', ')"
                    Remediation = "Restrict source addresses for port $($risk.Port) or disable if not needed"
                    Reference = 'NIST SP 800-123'
                }
            }
        }
    }

    # Check 3: Logging Configuration
    foreach ($profile in $profiles) {
        if (-not $profile.LogBlocked -or -not $profile.LogAllowed) {
            $findings += [PSCustomObject]@{
                Check = "Firewall Logging - $($profile.Name)"
                Severity = 'Medium'
                Status = 'Failed'
                Description = "Firewall logging not fully enabled for $($profile.Name) profile"
                Details = "LogBlocked: $($profile.LogBlocked), LogAllowed: $($profile.LogAllowed)"
                Remediation = "Enable logging: Set-NetFirewallProfile -Profile $($profile.Name) -LogBlocked True -LogAllowed True"
                Reference = 'CIS Benchmark: 9.1.7'
            }
        }
    }

    # Check 4: Rules with Action Allow and Any Protocol
    if (-not $Quick) {
        $anyProtocolRules = $inboundRules | Where-Object {
            $portFilter = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
            $portFilter.Protocol -eq 'Any'
        }

        if ($anyProtocolRules.Count -gt 5) {
            $findings += [PSCustomObject]@{
                Check = 'Rules Allowing Any Protocol'
                Severity = 'Medium'
                Status = 'Warning'
                Description = "$($anyProtocolRules.Count) inbound rules allow any protocol"
                Details = "Rules: $(($anyProtocolRules.DisplayName | Select-Object -First 5) -join ', ')"
                Remediation = 'Review rules and restrict to specific protocols where possible'
                Reference = 'Defense in depth'
            }
        }
    }

    # Check 5: RDP Specific Checks
    $rdpRules = $inboundRules | Where-Object {
        $portFilter = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $portFilter.LocalPort -eq '3389'
    }

    if ($rdpRules) {
        # Check NLA requirement
        $nlaEnabled = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication

        if ($nlaEnabled -ne 1) {
            $findings += [PSCustomObject]@{
                Check = 'RDP Network Level Authentication'
                Severity = 'High'
                Status = 'Failed'
                Description = 'Network Level Authentication (NLA) is not required for RDP'
                Details = 'NLA should be enabled to prevent unauthenticated access'
                Remediation = 'Enable NLA in System Properties > Remote > Require NLA'
                Reference = 'CIS Benchmark: 18.9.65.3.9.2'
            }
        }
    }

    return @{
        Status = 'Completed'
        Findings = $findings
        TotalChecks = $findings.Count
        FailedChecks = ($findings | Where-Object { $_.Status -ne 'Passed' }).Count
    }
}
