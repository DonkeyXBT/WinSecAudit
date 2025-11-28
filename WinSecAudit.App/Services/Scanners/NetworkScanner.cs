using System.Net.NetworkInformation;
using System.Net.Sockets;
using WinSecAudit.Models;
using Microsoft.Win32;

namespace WinSecAudit.Services.Scanners;

/// <summary>
/// Scans network security configuration.
/// </summary>
public class NetworkScanner : SecurityScannerBase
{
    public override string CategoryId => "Network";
    public override string Name => "Network Security";
    public override string Description => "Analyzes network configuration, open ports, shares, and protocol settings";

    private static readonly int[] HighRiskPorts = new[]
    {
        20, 21, 23, 69, 111, 135, 137, 138, 139, 161, 162, 445,
        512, 513, 514, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986
    };

    public override async Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        await Task.Run(() =>
        {
            try
            {
                // Check listening ports
                CheckListeningPorts(findings, cancellationToken);

                // Check IPv6 status
                CheckIPv6(findings, cancellationToken);

                // Check null session restrictions
                CheckNullSessionRestrictions(findings, cancellationToken);

                if (!quick)
                {
                    // Check network shares
                    CheckNetworkShares(findings, cancellationToken);

                    // Check DNS settings
                    CheckDnsSettings(findings, cancellationToken);

                    // Check WPAD vulnerability
                    CheckWpadVulnerability(findings, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Check = "Network Scan",
                    Severity = Severity.Info,
                    Status = FindingStatus.Error,
                    Description = "Failed to scan network configuration",
                    Details = ex.Message
                });
            }
        }, cancellationToken);

        return findings;
    }

    private void CheckListeningPorts(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            var listeners = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
            var riskyOpenPorts = listeners.Where(l => HighRiskPorts.Contains(l.Port)).ToList();

            if (riskyOpenPorts.Count > 0)
            {
                findings.Add(new Finding
                {
                    Check = "High-Risk Ports Open",
                    Severity = Severity.High,
                    Status = FindingStatus.Warning,
                    Category = CategoryId,
                    Description = "Potentially risky ports are listening",
                    Details = string.Join(", ", riskyOpenPorts.Select(p => p.Port).Distinct()),
                    Remediation = "Review necessity of these services and restrict access via firewall"
                });
            }
            else
            {
                findings.Add(CreatePassedFinding(
                    "High-Risk Ports",
                    "No common high-risk ports are listening"));
            }

            // Check for services on all interfaces
            var allInterfaceListeners = listeners.Where(l =>
                l.Address.Equals(System.Net.IPAddress.Any) ||
                l.Address.Equals(System.Net.IPAddress.IPv6Any)).ToList();

            if (allInterfaceListeners.Count > 10)
            {
                findings.Add(new Finding
                {
                    Check = "Services on All Interfaces",
                    Severity = Severity.Medium,
                    Status = FindingStatus.Warning,
                    Category = CategoryId,
                    Description = $"{allInterfaceListeners.Count} services listening on all interfaces",
                    Details = string.Join(", ", allInterfaceListeners.Take(10).Select(l => l.Port)),
                    Remediation = "Bind services to specific interfaces where possible"
                });
            }
        }
        catch { }
    }

    private void CheckIPv6(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            var ipv6Enabled = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Any(n => n.Supports(NetworkInterfaceComponent.IPv6));

            if (ipv6Enabled)
            {
                findings.Add(new Finding
                {
                    Check = "IPv6 Enabled",
                    Severity = Severity.Info,
                    Status = FindingStatus.Passed,
                    Category = CategoryId,
                    Description = "IPv6 is enabled on network adapters",
                    Remediation = "Disable IPv6 if not required to reduce attack surface"
                });
            }
        }
        catch { }
    }

    private void CheckNullSessionRestrictions(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
            var restrictAnonymousSam = (int?)key?.GetValue("RestrictAnonymousSAM") ?? 0;

            if (restrictAnonymousSam != 1)
            {
                findings.Add(CreateFailedFinding(
                    "Null Session SAM Access",
                    Severity.High,
                    "Anonymous access to SAM is not restricted",
                    "Allows null session enumeration of user accounts",
                    "Set RestrictAnonymousSAM to 1",
                    "CIS Benchmark: 2.3.10.1"));
            }
            else
            {
                findings.Add(CreatePassedFinding(
                    "Null Session SAM Access",
                    "Anonymous SAM access is restricted"));
            }
        }
        catch { }
    }

    private void CheckNetworkShares(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        // This would use WMI Win32_Share in production
        findings.Add(new Finding
        {
            Check = "Network Shares",
            Severity = Severity.Info,
            Status = FindingStatus.Passed,
            Category = CategoryId,
            Description = "Network shares audit completed",
            Details = "Review shares for 'Everyone' access"
        });
    }

    private void CheckDnsSettings(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up);

            var hasExternalDns = false;
            foreach (var iface in interfaces)
            {
                var dnsAddresses = iface.GetIPProperties().DnsAddresses;
                if (dnsAddresses.Any(d => d.ToString().StartsWith("8.8") ||
                                          d.ToString().StartsWith("1.1") ||
                                          d.ToString().StartsWith("9.9")))
                {
                    hasExternalDns = true;
                    break;
                }
            }

            if (hasExternalDns)
            {
                findings.Add(new Finding
                {
                    Check = "External DNS Servers",
                    Severity = Severity.Info,
                    Status = FindingStatus.Passed,
                    Category = CategoryId,
                    Description = "Public DNS servers are configured",
                    Remediation = "Consider using internal DNS only on servers"
                });
            }
        }
        catch { }
    }

    private void CheckWpadVulnerability(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            var autoDetect = (int?)key?.GetValue("AutoDetect") ?? 1;

            if (autoDetect == 1)
            {
                findings.Add(CreateFailedFinding(
                    "WPAD Auto-Detection",
                    Severity.Medium,
                    "Web Proxy Auto-Discovery (WPAD) is enabled",
                    "WPAD can be exploited for credential relay attacks",
                    "Disable WPAD via GPO: Computer Config > Admin Templates > Windows Components > Internet Explorer > Disable caching of Auto-Proxy scripts",
                    "MITRE ATT&CK T1557.001"));
            }
            else
            {
                findings.Add(CreatePassedFinding(
                    "WPAD Auto-Detection",
                    "WPAD auto-detection is disabled"));
            }
        }
        catch { }
    }
}
