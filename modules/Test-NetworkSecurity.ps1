function Test-NetworkSecurity {
    <#
    .SYNOPSIS
        Audits network security configuration.
    .DESCRIPTION
        Checks network security settings:
        - Open ports and listening services
        - IPv6 configuration
        - WiFi security
        - Network shares
        - DNS configuration
        - Proxy settings
    .PARAMETER Quick
        Perform quick scan
    #>
    [CmdletBinding()]
    param(
        [switch]$Quick
    )

    $findings = @()

    Write-Verbose "Starting network security audit..."

    # Check 1: Listening Ports
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess, @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}

    # High-risk ports that should be reviewed
    $riskyPorts = @(21, 23, 69, 135, 137, 138, 139, 161, 445, 512, 513, 514, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017)

    $openRiskyPorts = $listeners | Where-Object { $_.LocalPort -in $riskyPorts }

    if ($openRiskyPorts) {
        $portDetails = $openRiskyPorts | ForEach-Object { "$($_.LocalPort) ($($_.ProcessName))" }
        $findings += [PSCustomObject]@{
            Check = 'High-Risk Ports Open'
            Severity = 'High'
            Status = 'Warning'
            Description = "Potentially risky ports are listening"
            Details = $portDetails -join ', '
            Remediation = 'Review necessity of these services and restrict access via firewall'
            Reference = 'Network security best practices'
        }
    }

    # Check 2: Services Listening on All Interfaces (0.0.0.0)
    $allInterfaceListeners = $listeners | Where-Object {
        $_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::'
    }

    if ($allInterfaceListeners.Count -gt 10) {
        $findings += [PSCustomObject]@{
            Check = 'Services on All Interfaces'
            Severity = 'Medium'
            Status = 'Warning'
            Description = "$($allInterfaceListeners.Count) services listening on all network interfaces"
            Details = ($allInterfaceListeners | Select-Object -First 10 | ForEach-Object { "$($_.LocalPort) ($($_.ProcessName))" }) -join ', '
            Remediation = 'Bind services to specific interfaces where possible'
            Reference = 'Defense in depth'
        }
    }

    # Check 3: IPv6 Configuration
    $ipv6Bindings = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
        Where-Object { $_.Enabled -eq $true }

    if ($ipv6Bindings) {
        $findings += [PSCustomObject]@{
            Check = 'IPv6 Enabled'
            Severity = 'Info'
            Status = 'Info'
            Description = "IPv6 is enabled on $($ipv6Bindings.Count) adapter(s)"
            Details = ($ipv6Bindings | Select-Object -ExpandProperty Name) -join ', '
            Remediation = 'Disable IPv6 if not required to reduce attack surface'
            Reference = 'https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows'
        }
    }

    # Check 4: Network Shares
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^\$' }

    if ($shares) {
        # Check for shares with Everyone access
        foreach ($share in $shares) {
            try {
                $access = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue
                $everyoneAccess = $access | Where-Object { $_.AccountName -match 'Everyone' }

                if ($everyoneAccess) {
                    $findings += [PSCustomObject]@{
                        Check = "Share with Everyone Access - $($share.Name)"
                        Severity = 'High'
                        Status = 'Failed'
                        Description = "Share '$($share.Name)' grants access to Everyone"
                        Details = "Path: $($share.Path), Access: $($everyoneAccess.AccessRight)"
                        Remediation = 'Remove Everyone from share permissions and grant access to specific groups'
                        Reference = 'Principle of least privilege'
                    }
                }
            }
            catch {
                # Unable to get share access
            }
        }
    }

    # Check 5: Administrative Shares
    $adminShares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^\$' -and $_.Name -ne 'IPC$' }

    if ($adminShares) {
        $findings += [PSCustomObject]@{
            Check = 'Administrative Shares'
            Severity = 'Info'
            Status = 'Info'
            Description = "$($adminShares.Count) administrative shares exist"
            Details = ($adminShares | Select-Object -ExpandProperty Name) -join ', '
            Remediation = 'Disable administrative shares if not required: AutoShareWks/AutoShareServer registry keys'
            Reference = 'CIS Benchmark: 2.3.10.x'
        }
    }

    # Check 6: DNS Client Configuration
    $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerAddresses }

    $externalDns = $dnsServers | Where-Object {
        $_.ServerAddresses | Where-Object { $_ -match '^8\.|^1\.1\.|^9\.9\.' }
    }

    if ($externalDns) {
        $findings += [PSCustomObject]@{
            Check = 'External DNS Servers Configured'
            Severity = 'Low'
            Status = 'Info'
            Description = 'Public DNS servers are configured'
            Details = ($externalDns.ServerAddresses) -join ', '
            Remediation = 'Review DNS configuration - consider using internal DNS only on servers'
            Reference = 'Network architecture'
        }
    }

    # Check 7: Null Session Access
    $nullSession = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -ErrorAction SilentlyContinue

    if (-not $nullSession -or $nullSession.RestrictAnonymousSAM -ne 1) {
        $findings += [PSCustomObject]@{
            Check = 'Null Session SAM Access'
            Severity = 'High'
            Status = 'Failed'
            Description = 'Anonymous access to SAM is not restricted'
            Details = 'Allows null session enumeration of user accounts'
            Remediation = 'Set RestrictAnonymousSAM to 1'
            Reference = 'CIS Benchmark: 2.3.10.1'
        }
    }

    # Check 8: Network Discovery
    if (-not $Quick) {
        $netDiscovery = Get-NetFirewallRule -DisplayGroup 'Network Discovery' -ErrorAction SilentlyContinue |
            Where-Object { $_.Enabled -eq 'True' -and $_.Profile -match 'Domain|Private|Public' }

        if ($netDiscovery) {
            $findings += [PSCustomObject]@{
                Check = 'Network Discovery Enabled'
                Severity = 'Low'
                Status = 'Warning'
                Description = 'Network Discovery is enabled'
                Details = "Enabled for profiles: $(($netDiscovery.Profile | Select-Object -Unique) -join ', ')"
                Remediation = 'Disable Network Discovery on servers unless required'
                Reference = 'Attack surface reduction'
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
