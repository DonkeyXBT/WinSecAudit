using System.Diagnostics;
using Microsoft.Win32;
using WinSecAudit.Models;

namespace WinSecAudit.Services.Scanners;

/// <summary>
/// Scans Windows audit policy configuration.
/// </summary>
public class AuditPolicyScanner : SecurityScannerBase
{
    public override string CategoryId => "AuditPolicy";
    public override string Name => "Audit Policy";

    private static readonly Dictionary<string, (string Required, Severity Severity)> RequiredSettings = new()
    {
        ["Credential Validation"] = ("Success and Failure", Severity.High),
        ["Security Group Management"] = ("Success", Severity.High),
        ["User Account Management"] = ("Success and Failure", Severity.High),
        ["Process Creation"] = ("Success", Severity.High),
        ["Logon"] = ("Success and Failure", Severity.High),
        ["Special Logon"] = ("Success", Severity.High),
        ["Audit Policy Change"] = ("Success", Severity.High)
    };

    public override async Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        await Task.Run(async () =>
        {
            try
            {
                // Get audit policy using auditpol
                var auditPolicy = await GetAuditPolicyAsync(cancellationToken);

                foreach (var setting in RequiredSettings)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    var currentValue = GetAuditSettingValue(auditPolicy, setting.Key);
                    var isCompliant = IsCompliant(currentValue, setting.Value.Required);

                    if (!isCompliant)
                    {
                        findings.Add(CreateFailedFinding(
                            $"Audit Policy - {setting.Key}",
                            setting.Value.Severity,
                            $"Audit policy '{setting.Key}' is not properly configured",
                            $"Current: {currentValue}, Required: {setting.Value.Required}",
                            $"auditpol /set /subcategory:\"{setting.Key}\" /success:enable /failure:enable",
                            "CIS Benchmark: 17.x"));
                    }
                    else
                    {
                        findings.Add(CreatePassedFinding(
                            $"Audit Policy - {setting.Key}",
                            $"{setting.Key} auditing is properly configured"));
                    }
                }

                // Check command line auditing
                CheckCommandLineAuditing(findings, cancellationToken);

                // Check PowerShell logging
                CheckPowerShellLogging(findings, cancellationToken);

                if (!quick)
                {
                    // Check event log sizes
                    CheckEventLogSizes(findings, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Check = "Audit Policy Scan",
                    Severity = Severity.Info,
                    Status = FindingStatus.Error,
                    Description = "Failed to scan audit policy",
                    Details = ex.Message
                });
            }
        }, cancellationToken);

        return findings;
    }

    private async Task<string> GetAuditPolicyAsync(CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "auditpol",
            Arguments = "/get /category:*",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true
        };

        using var process = Process.Start(psi);
        if (process == null) return string.Empty;

        var output = await process.StandardOutput.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);

        return output;
    }

    private string GetAuditSettingValue(string auditPolicy, string settingName)
    {
        var lines = auditPolicy.Split('\n');
        foreach (var line in lines)
        {
            if (line.Contains(settingName, StringComparison.OrdinalIgnoreCase))
            {
                if (line.Contains("Success and Failure")) return "Success and Failure";
                if (line.Contains("Success")) return "Success";
                if (line.Contains("Failure")) return "Failure";
                return "No Auditing";
            }
        }
        return "Not Found";
    }

    private bool IsCompliant(string current, string required)
    {
        if (required == "Success and Failure")
            return current == "Success and Failure";
        if (required == "Success")
            return current == "Success" || current == "Success and Failure";
        if (required == "Failure")
            return current == "Failure" || current == "Success and Failure";
        return false;
    }

    private void CheckCommandLineAuditing(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit");
            var value = (int?)key?.GetValue("ProcessCreationIncludeCmdLine_Enabled") ?? 0;

            if (value != 1)
            {
                findings.Add(CreateFailedFinding(
                    "Command Line in Process Audit Events",
                    Severity.High,
                    "Command line is not included in process creation events",
                    "Process command lines provide valuable forensic information",
                    "Enable via Group Policy: Include command line in process creation events",
                    "CIS Benchmark: 18.9.27.1"));
            }
            else
            {
                findings.Add(CreatePassedFinding(
                    "Command Line Auditing",
                    "Command line is included in process creation events"));
            }
        }
        catch { }
    }

    private void CheckPowerShellLogging(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            // Script Block Logging
            using var sbKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
            var sbEnabled = (int?)sbKey?.GetValue("EnableScriptBlockLogging") ?? 0;

            if (sbEnabled != 1)
            {
                findings.Add(CreateFailedFinding(
                    "PowerShell Script Block Logging",
                    Severity.High,
                    "PowerShell script block logging is not enabled",
                    "Script block logging captures PowerShell commands for analysis",
                    "Enable via Group Policy: Turn on PowerShell Script Block Logging",
                    "CIS Benchmark: 18.9.97.x"));
            }
            else
            {
                findings.Add(CreatePassedFinding(
                    "PowerShell Script Block Logging",
                    "Script block logging is enabled"));
            }

            // Module Logging
            using var mlKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging");
            var mlEnabled = (int?)mlKey?.GetValue("EnableModuleLogging") ?? 0;

            if (mlEnabled != 1)
            {
                findings.Add(CreateFailedFinding(
                    "PowerShell Module Logging",
                    Severity.Medium,
                    "PowerShell module logging is not enabled",
                    "Module logging provides visibility into PowerShell activity",
                    "Enable via Group Policy: Turn on Module Logging",
                    "CIS Benchmark: 18.9.97.1"));
            }
        }
        catch { }
    }

    private void CheckEventLogSizes(List<Finding> findings, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var logChecks = new Dictionary<string, (long MinSize, Severity Severity)>
        {
            ["Security"] = (196608 * 1024, Severity.High),
            ["System"] = (32768 * 1024, Severity.Medium),
            ["Application"] = (32768 * 1024, Severity.Low)
        };

        foreach (var log in logChecks)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\EventLog\{log.Key}");
                var maxSize = (int?)key?.GetValue("MaxSize") ?? 0;

                if (maxSize < log.Value.MinSize)
                {
                    findings.Add(new Finding
                    {
                        Check = $"Event Log Size - {log.Key}",
                        Severity = log.Value.Severity,
                        Status = FindingStatus.Warning,
                        Category = CategoryId,
                        Description = $"{log.Key} event log max size may be insufficient",
                        Details = $"Current: {maxSize / 1024 / 1024} MB",
                        Remediation = $"Increase log size: wevtutil sl {log.Key} /ms:{log.Value.MinSize}"
                    });
                }
            }
            catch { }
        }
    }
}
