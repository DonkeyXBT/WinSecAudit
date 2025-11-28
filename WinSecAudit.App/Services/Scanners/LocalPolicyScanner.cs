using System.Diagnostics;
using System.Text.RegularExpressions;
using WinSecAudit.Models;

namespace WinSecAudit.Services.Scanners;

/// <summary>
/// Scans local security policy settings.
/// </summary>
public class LocalPolicyScanner : SecurityScannerBase
{
    public override string CategoryId => "LocalPolicy";
    public override string Name => "Local Security Policy";

    public override async Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        try
        {
            var secPolicy = await ExportSecurityPolicyAsync(cancellationToken);

            // Check password length
            var minPwdLength = GetPolicyValue(secPolicy, "MinimumPasswordLength", 0);
            if (minPwdLength < 14)
            {
                findings.Add(CreateFailedFinding(
                    "Minimum Password Length",
                    Severity.High,
                    $"Minimum password length is {minPwdLength} (recommended: >= 14)",
                    $"Current setting: {minPwdLength} characters",
                    "Set minimum password length to 14 or greater via Group Policy",
                    "CIS Benchmark: 1.1.1"));
            }
            else
            {
                findings.Add(CreatePassedFinding(
                    "Minimum Password Length",
                    $"Password length requirement is {minPwdLength} characters"));
            }

            // Check password complexity
            var pwdComplexity = GetPolicyValue(secPolicy, "PasswordComplexity", 0);
            if (pwdComplexity != 1)
            {
                findings.Add(CreateFailedFinding(
                    "Password Complexity",
                    Severity.High,
                    "Password complexity requirements are not enabled",
                    "Complexity should be enabled to ensure strong passwords",
                    "Enable password complexity requirements via Group Policy",
                    "CIS Benchmark: 1.1.5"));
            }
            else
            {
                findings.Add(CreatePassedFinding(
                    "Password Complexity",
                    "Password complexity is enabled"));
            }

            // Check lockout threshold
            var lockoutThreshold = GetPolicyValue(secPolicy, "LockoutBadCount", 0);
            if (lockoutThreshold == 0 || lockoutThreshold > 5)
            {
                findings.Add(CreateFailedFinding(
                    "Account Lockout Threshold",
                    Severity.High,
                    $"Account lockout threshold is {lockoutThreshold} (recommended: 3-5)",
                    $"Current: {(lockoutThreshold == 0 ? "Disabled" : lockoutThreshold.ToString())}",
                    "Set account lockout threshold to 3-5 invalid logon attempts",
                    "CIS Benchmark: 1.2.1"));
            }
            else
            {
                findings.Add(CreatePassedFinding(
                    "Account Lockout Threshold",
                    $"Lockout threshold is set to {lockoutThreshold} attempts"));
            }

            // Check password history
            var pwdHistory = GetPolicyValue(secPolicy, "PasswordHistorySize", 0);
            if (pwdHistory < 24)
            {
                findings.Add(CreateFailedFinding(
                    "Password History",
                    Severity.Medium,
                    $"Password history is {pwdHistory} (recommended: >= 24)",
                    $"Current: {pwdHistory} passwords remembered",
                    "Set password history to 24 passwords",
                    "CIS Benchmark: 1.1.1"));
            }

            // Check max password age
            var maxPwdAge = GetPolicyValue(secPolicy, "MaximumPasswordAge", 0);
            if (maxPwdAge > 60 || maxPwdAge == 0)
            {
                findings.Add(CreateFailedFinding(
                    "Maximum Password Age",
                    Severity.Medium,
                    $"Maximum password age is {maxPwdAge} days (recommended: <= 60)",
                    $"Current: {(maxPwdAge == 0 ? "Never expires" : $"{maxPwdAge} days")}",
                    "Set maximum password age to 60 days or less",
                    "CIS Benchmark: 1.1.2"));
            }
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Check = "Local Policy Scan",
                Severity = Severity.Info,
                Status = FindingStatus.Error,
                Description = "Failed to scan local security policy",
                Details = ex.Message
            });
        }

        return findings;
    }

    private async Task<string> ExportSecurityPolicyAsync(CancellationToken cancellationToken)
    {
        var tempFile = Path.GetTempFileName();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "secedit",
                Arguments = $"/export /cfg \"{tempFile}\" /quiet",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = Process.Start(psi);
            if (process != null)
            {
                await process.WaitForExitAsync(cancellationToken);
            }

            if (File.Exists(tempFile))
            {
                return await File.ReadAllTextAsync(tempFile, cancellationToken);
            }
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }

        return string.Empty;
    }

    private int GetPolicyValue(string policy, string name, int defaultValue)
    {
        var match = Regex.Match(policy, $@"{name}\s*=\s*(\d+)", RegexOptions.IgnoreCase);
        if (match.Success && int.TryParse(match.Groups[1].Value, out var value))
        {
            return value;
        }
        return defaultValue;
    }
}
