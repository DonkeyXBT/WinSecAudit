using System.Management;
using System.Text.RegularExpressions;
using WinSecAudit.Models;

namespace WinSecAudit.Services.Scanners;

/// <summary>
/// Scans Windows Services for security issues.
/// </summary>
public class ServiceScanner : SecurityScannerBase
{
    public override string CategoryId => "Services";
    public override string Name => "Windows Services";
    public override string Description => "Analyzes Windows services for security misconfigurations and vulnerabilities";

    private static readonly string[] DangerousServices = new[]
    {
        "RemoteRegistry", "Telnet", "SNMP", "SSDPSRV", "upnphost",
        "Fax", "lltdsvc", "MSiSCSI", "SNMPTRAP", "XblAuthManager",
        "XblGameSave", "XboxGipSvc", "XboxNetApiSvc", "RetailDemo"
    };

    public override async Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        await Task.Run(() =>
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service");
                var services = searcher.Get();

                foreach (ManagementObject service in services)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var name = service["Name"]?.ToString() ?? "";
                    var displayName = service["DisplayName"]?.ToString() ?? "";
                    var pathName = service["PathName"]?.ToString() ?? "";
                    var state = service["State"]?.ToString() ?? "";
                    var startName = service["StartName"]?.ToString() ?? "";

                    // Check for dangerous services running
                    if (DangerousServices.Contains(name) && state == "Running")
                    {
                        findings.Add(CreateFailedFinding(
                            $"Dangerous Service Running - {name}",
                            Severity.Medium,
                            $"{displayName} is running",
                            $"Service: {displayName}, State: {state}",
                            $"Disable service if not needed: Stop-Service -Name '{name}'; Set-Service -Name '{name}' -StartupType Disabled",
                            "CIS Benchmark: 5.x"));
                    }

                    // Check for unquoted service paths
                    if (!string.IsNullOrEmpty(pathName) &&
                        !pathName.StartsWith("\"") &&
                        pathName.Contains(" ") &&
                        !pathName.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(CreateFailedFinding(
                            $"Unquoted Service Path - {name}",
                            Severity.High,
                            $"Service '{displayName}' has an unquoted path with spaces",
                            $"Path: {pathName}",
                            "Quote the service path in the registry or reinstall the software",
                            "CVE-2013-1609"));
                    }
                }

                // Check Windows Defender service
                CheckDefenderService(findings, services, cancellationToken);

                // Check Windows Update service
                CheckWindowsUpdateService(findings, services, cancellationToken);

                // Check Windows Firewall service
                CheckFirewallService(findings, services, cancellationToken);

                if (!quick)
                {
                    // Check for SYSTEM services from non-standard locations
                    CheckSystemServicesLocations(findings, services, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Check = "Service Scan",
                    Severity = Severity.Info,
                    Status = FindingStatus.Error,
                    Description = "Failed to scan Windows services",
                    Details = ex.Message
                });
            }
        }, cancellationToken);

        return findings;
    }

    private void CheckDefenderService(List<Finding> findings, ManagementObjectCollection services, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        foreach (ManagementObject service in services)
        {
            if (service["Name"]?.ToString() == "WinDefend")
            {
                var state = service["State"]?.ToString();
                if (state != "Running")
                {
                    findings.Add(CreateFailedFinding(
                        "Windows Defender Service",
                        Severity.High,
                        "Windows Defender service is not running",
                        $"State: {state}",
                        "Start and enable Windows Defender service",
                        "CIS Benchmark: 18.9.77.x"));
                }
                else
                {
                    findings.Add(CreatePassedFinding(
                        "Windows Defender Service",
                        "Windows Defender is running"));
                }
                return;
            }
        }
    }

    private void CheckWindowsUpdateService(List<Finding> findings, ManagementObjectCollection services, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        foreach (ManagementObject service in services)
        {
            if (service["Name"]?.ToString() == "wuauserv")
            {
                var startMode = service["StartMode"]?.ToString();
                if (startMode == "Disabled")
                {
                    findings.Add(CreateFailedFinding(
                        "Windows Update Service",
                        Severity.High,
                        "Windows Update service is disabled",
                        $"StartMode: {startMode}",
                        "Enable Windows Update service for security patches",
                        "CIS Benchmark: 5.29"));
                }
                return;
            }
        }
    }

    private void CheckFirewallService(List<Finding> findings, ManagementObjectCollection services, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        foreach (ManagementObject service in services)
        {
            if (service["Name"]?.ToString() == "mpssvc")
            {
                var state = service["State"]?.ToString();
                if (state != "Running")
                {
                    findings.Add(CreateFailedFinding(
                        "Windows Firewall Service",
                        Severity.Critical,
                        "Windows Firewall service is not running",
                        $"State: {state}",
                        "Start and enable Windows Firewall service",
                        "CIS Benchmark: 9.1"));
                }
                else
                {
                    findings.Add(CreatePassedFinding(
                        "Windows Firewall Service",
                        "Windows Firewall service is running"));
                }
                return;
            }
        }
    }

    private void CheckSystemServicesLocations(List<Finding> findings, ManagementObjectCollection services, CancellationToken ct)
    {
        var nonStandardSystemServices = new List<string>();

        foreach (ManagementObject service in services)
        {
            ct.ThrowIfCancellationRequested();

            var startName = service["StartName"]?.ToString() ?? "";
            var pathName = service["PathName"]?.ToString() ?? "";
            var state = service["State"]?.ToString() ?? "";

            if ((startName == "LocalSystem" || startName == "NT AUTHORITY\\LocalSystem") &&
                state == "Running" &&
                !string.IsNullOrEmpty(pathName))
            {
                // Extract executable path
                var exePath = Regex.Match(pathName, @"^""?([^""]+)""?").Groups[1].Value;

                if (!exePath.StartsWith(@"C:\Windows\", StringComparison.OrdinalIgnoreCase) &&
                    !exePath.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase))
                {
                    nonStandardSystemServices.Add(service["DisplayName"]?.ToString() ?? "");
                }
            }
        }

        if (nonStandardSystemServices.Count > 0)
        {
            findings.Add(new Finding
            {
                Check = "SYSTEM Services from Non-Standard Locations",
                Severity = Severity.Medium,
                Status = FindingStatus.Warning,
                Category = CategoryId,
                Description = $"{nonStandardSystemServices.Count} services running as SYSTEM from non-standard locations",
                Details = string.Join(", ", nonStandardSystemServices.Take(5)),
                Remediation = "Review services and configure to run with least privilege accounts"
            });
        }
    }
}
