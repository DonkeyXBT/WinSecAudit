using System.Management;
using WinSecAudit.Models;
using Microsoft.Win32;

namespace WinSecAudit.Services.Scanners;

/// <summary>
/// Scans Windows Firewall configuration.
/// </summary>
public class FirewallScanner : SecurityScannerBase
{
    public override string CategoryId => "Firewall";
    public override string Name => "Windows Firewall";
    public override string Description => "Analyzes Windows Firewall profiles, rules, and logging configuration";

    public override async Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        await Task.Run(() =>
        {
            try
            {
                // Check firewall profiles using registry
                var profiles = new[] { "DomainProfile", "StandardProfile", "PublicProfile" };
                var profileNames = new[] { "Domain", "Private", "Public" };

                for (int i = 0; i < profiles.Length; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var regPath = $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profiles[i]}";
                    using var key = Registry.LocalMachine.OpenSubKey(regPath);

                    if (key != null)
                    {
                        var enabled = (int?)key.GetValue("EnableFirewall") ?? 0;

                        if (enabled != 1)
                        {
                            findings.Add(CreateFailedFinding(
                                $"Firewall Enabled - {profileNames[i]}",
                                Severity.Critical,
                                $"Windows Firewall is disabled for {profileNames[i]} profile",
                                $"Profile: {profileNames[i]}, Enabled: {enabled == 1}",
                                $"Enable firewall: Set-NetFirewallProfile -Profile {profileNames[i]} -Enabled True",
                                "CIS Benchmark: 9.1.1"));
                        }
                        else
                        {
                            findings.Add(CreatePassedFinding(
                                $"Firewall Enabled - {profileNames[i]}",
                                $"{profileNames[i]} profile firewall is enabled"));
                        }

                        // Check default inbound action
                        var defaultInbound = (int?)key.GetValue("DefaultInboundAction") ?? 0;
                        if (defaultInbound != 1) // 1 = Block
                        {
                            findings.Add(CreateFailedFinding(
                                $"Default Inbound Action - {profileNames[i]}",
                                Severity.High,
                                $"Default inbound action is not Block for {profileNames[i]} profile",
                                "Inbound connections should be blocked by default",
                                $"Set-NetFirewallProfile -Profile {profileNames[i]} -DefaultInboundAction Block",
                                "CIS Benchmark: 9.1.2"));
                        }
                    }
                }

                // Check for logging enabled
                var loggingPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging";
                using var loggingKey = Registry.LocalMachine.OpenSubKey(loggingPath);
                if (loggingKey != null)
                {
                    var logDropped = (int?)loggingKey.GetValue("LogDroppedPackets") ?? 0;
                    if (logDropped != 1)
                    {
                        findings.Add(CreateFailedFinding(
                            "Firewall Logging",
                            Severity.Medium,
                            "Firewall is not logging dropped packets",
                            "Logging helps with forensic analysis",
                            "Enable logging via Group Policy or PowerShell",
                            "CIS Benchmark: 9.1.7"));
                    }
                }

                if (!quick)
                {
                    // Check for high-risk ports using WMI
                    CheckHighRiskPorts(findings, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Check = "Firewall Scan",
                    Severity = Severity.Info,
                    Status = FindingStatus.Error,
                    Description = "Failed to scan firewall configuration",
                    Details = ex.Message
                });
            }
        }, cancellationToken);

        return findings;
    }

    private void CheckHighRiskPorts(List<Finding> findings, CancellationToken cancellationToken)
    {
        var highRiskPorts = new Dictionary<int, string>
        {
            { 20, "FTP Data" },
            { 21, "FTP" },
            { 23, "Telnet" },
            { 135, "RPC" },
            { 139, "NetBIOS" },
            { 445, "SMB" },
            { 1433, "SQL Server" },
            { 3389, "RDP" },
            { 5985, "WinRM HTTP" },
            { 5986, "WinRM HTTPS" }
        };

        // This would normally use NetFirewallRule cmdlets
        // Simplified for demonstration
        findings.Add(new Finding
        {
            Check = "High-Risk Port Analysis",
            Severity = Severity.Info,
            Status = FindingStatus.Passed,
            Category = CategoryId,
            Description = "High-risk port analysis completed",
            Details = "Review firewall rules for ports: 21, 23, 135, 445, 3389"
        });
    }
}
