using System.Diagnostics;
using System.Management;
using System.Text.RegularExpressions;
using WinSecAudit.Models;

namespace WinSecAudit.Services.Scanners;

/// <summary>
/// Scans running processes for suspicious activity.
/// </summary>
public class ProcessScanner : SecurityScannerBase
{
    public override string CategoryId => "Processes";
    public override string Name => "Running Processes";
    public override string Description => "Detects suspicious processes, masquerading, and malicious command lines";

    private static readonly string[] SuspiciousNames = new[]
    {
        "mimikatz", "mimi", "sekurlsa", "procdump", "lazagne",
        "rubeus", "kerberoast", "bloodhound", "sharphound",
        "psexec", "crackmapexec", "nc", "ncat", "netcat",
        "powercat", "empire", "cobaltstrike", "beacon",
        "winpeas", "linpeas", "chisel", "plink", "ngrok",
        "invoke-obfuscation", "certutil", "bitsadmin"
    };

    private static readonly Dictionary<string, string> SystemProcessPaths = new()
    {
        ["csrss"] = @"C:\Windows\System32",
        ["smss"] = @"C:\Windows\System32",
        ["svchost"] = @"C:\Windows\System32",
        ["services"] = @"C:\Windows\System32",
        ["lsass"] = @"C:\Windows\System32",
        ["winlogon"] = @"C:\Windows\System32"
    };

    public override async Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        await Task.Run(() =>
        {
            try
            {
                var processes = Process.GetProcesses();

                foreach (var proc in processes)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        var name = proc.ProcessName.ToLower();
                        string? path = null;

                        try { path = proc.MainModule?.FileName; } catch { }

                        // Check for suspicious process names
                        foreach (var suspicious in SuspiciousNames)
                        {
                            if (name.Contains(suspicious))
                            {
                                findings.Add(CreateFailedFinding(
                                    $"Suspicious Process - {proc.ProcessName}",
                                    Severity.Critical,
                                    $"Potentially malicious process detected: {proc.ProcessName}",
                                    $"PID: {proc.Id}, Path: {path ?? "Unknown"}",
                                    "Investigate process immediately",
                                    "Threat hunting"));
                                break;
                            }
                        }

                        // Check system processes running from wrong locations
                        if (path != null && SystemProcessPaths.TryGetValue(name, out var expectedPath))
                        {
                            if (!path.StartsWith(expectedPath, StringComparison.OrdinalIgnoreCase))
                            {
                                findings.Add(CreateFailedFinding(
                                    $"System Process Masquerade - {proc.ProcessName}",
                                    Severity.Critical,
                                    "System process running from unexpected location",
                                    $"Expected: {expectedPath}, Actual: {path}",
                                    "Investigate - possible process masquerading or malware",
                                    "MITRE ATT&CK T1036"));
                            }
                        }
                    }
                    catch { }
                }

                // Check for encoded PowerShell commands
                CheckEncodedPowerShell(findings, cancellationToken);

                // Check for multiple instances of single-instance processes
                CheckSingleInstanceProcesses(findings, processes, cancellationToken);

                if (findings.Count == 0 || findings.All(f => f.Severity == Severity.Passed))
                {
                    findings.Add(CreatePassedFinding(
                        "Process Analysis",
                        "No suspicious processes detected"));
                }
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Check = "Process Scan",
                    Severity = Severity.Info,
                    Status = FindingStatus.Error,
                    Description = "Failed to scan processes",
                    Details = ex.Message
                });
            }
        }, cancellationToken);

        return findings;
    }

    private void CheckEncodedPowerShell(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name LIKE '%powershell%' OR Name LIKE '%pwsh%'");

            foreach (ManagementObject obj in searcher.Get())
            {
                var cmdLine = obj["CommandLine"]?.ToString() ?? "";
                var pid = obj["ProcessId"]?.ToString() ?? "";

                // Check for encoded commands
                if (Regex.IsMatch(cmdLine, @"-e[ncodedcommand]*\s+[A-Za-z0-9+/=]{50,}", RegexOptions.IgnoreCase))
                {
                    findings.Add(new Finding
                    {
                        Check = "Encoded PowerShell Command",
                        Severity = Severity.High,
                        Status = FindingStatus.Warning,
                        Category = CategoryId,
                        Description = "PowerShell running with encoded command",
                        Details = $"PID: {pid}",
                        Remediation = "Decode and analyze the command for malicious content",
                        MitreId = "T1059.001"
                    });
                }

                // Check for execution policy bypass
                if (Regex.IsMatch(cmdLine, @"-ExecutionPolicy\s+(Bypass|Unrestricted)", RegexOptions.IgnoreCase))
                {
                    findings.Add(new Finding
                    {
                        Check = "PowerShell Execution Policy Bypass",
                        Severity = Severity.Medium,
                        Status = FindingStatus.Warning,
                        Category = CategoryId,
                        Description = "PowerShell running with execution policy bypass",
                        Details = $"PID: {pid}",
                        Remediation = "Review if bypass is legitimate",
                        MitreId = "T1059.001"
                    });
                }
            }
        }
        catch { }
    }

    private void CheckSingleInstanceProcesses(List<Finding> findings, Process[] processes, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var singleInstance = new Dictionary<string, int>
        {
            ["lsass"] = 1,
            ["services"] = 1,
            ["wininit"] = 1,
            ["csrss"] = 2,
            ["smss"] = 2
        };

        foreach (var check in singleInstance)
        {
            var count = processes.Count(p =>
                p.ProcessName.Equals(check.Key, StringComparison.OrdinalIgnoreCase));

            if (count > check.Value)
            {
                findings.Add(CreateFailedFinding(
                    $"Multiple {check.Key} Instances",
                    Severity.Critical,
                    $"Multiple instances of {check.Key} detected ({count})",
                    $"Expected max: {check.Value}, Found: {count}",
                    "Investigate - possible process injection or malware",
                    "MITRE ATT&CK T1055"));
            }
        }
    }
}
