using Microsoft.Win32;
using WinSecAudit.Models;

namespace WinSecAudit.Services.Scanners;

/// <summary>
/// Scans registry security settings.
/// </summary>
public class RegistryScanner : SecurityScannerBase
{
    public override string CategoryId => "Registry";
    public override string Name => "Registry Security";
    public override string Description => "Audits security-related registry settings including SMB, UAC, and credential protection";

    public override async Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        await Task.Run(() =>
        {
            // SMB Server Signing
            CheckRegistryValue(
                findings,
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "RequireSecuritySignature",
                1,
                "SMB Server Signing",
                Severity.High,
                "SMB server does not require signing",
                "SMB signing helps prevent man-in-the-middle attacks",
                "Enable via Group Policy: Microsoft network server: Digitally sign communications (always)",
                "CIS Benchmark: 2.3.9.2",
                cancellationToken);

            // SMB Client Signing
            CheckRegistryValue(
                findings,
                @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "RequireSecuritySignature",
                1,
                "SMB Client Signing",
                Severity.High,
                "SMB client does not require signing",
                "SMB signing helps prevent relay attacks",
                "Enable via Group Policy: Microsoft network client: Digitally sign communications (always)",
                "CIS Benchmark: 2.3.8.1",
                cancellationToken);

            // LLMNR
            CheckRegistryValue(
                findings,
                @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "EnableMulticast",
                0,
                "LLMNR Disabled",
                Severity.High,
                "Link-Local Multicast Name Resolution (LLMNR) is enabled",
                "LLMNR can be abused for credential theft via poisoning attacks",
                "Disable via Group Policy: Turn off multicast name resolution",
                "MITRE ATT&CK T1557.001",
                cancellationToken,
                defaultIsVulnerable: true);

            // WDigest
            CheckRegistryValue(
                findings,
                @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                "UseLogonCredential",
                0,
                "WDigest Authentication",
                Severity.Critical,
                "WDigest stores credentials in clear text in memory",
                "This allows credential theft via tools like Mimikatz",
                "Set UseLogonCredential to 0",
                "KB2871997",
                cancellationToken,
                failOnEqual: true);

            // UAC EnableLUA
            CheckRegistryValue(
                findings,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "EnableLUA",
                1,
                "UAC Enabled",
                Severity.Critical,
                "User Account Control (UAC) is disabled",
                "UAC provides important protection against privilege escalation",
                "Enable UAC via Group Policy or Security Policy",
                "CIS Benchmark: 2.3.17.1",
                cancellationToken);

            // LSA Protection
            CheckRegistryValue(
                findings,
                @"SYSTEM\CurrentControlSet\Control\Lsa",
                "RunAsPPL",
                1,
                "LSA Protection",
                Severity.High,
                "LSA is not running as Protected Process Light (PPL)",
                "LSA protection helps prevent credential dumping",
                "Enable Credential Guard or set RunAsPPL to 1",
                "Credential Guard",
                cancellationToken);

            // Cached Logons
            CheckCachedLogons(findings, cancellationToken);

            if (!quick)
            {
                // Restrict Anonymous
                CheckRegistryValue(
                    findings,
                    @"SYSTEM\CurrentControlSet\Control\Lsa",
                    "RestrictAnonymous",
                    1,
                    "Anonymous Access Restrictions",
                    Severity.Medium,
                    "Anonymous access to SAM accounts is not restricted",
                    "Anonymous users may enumerate user accounts",
                    "Set RestrictAnonymous to 1 or higher",
                    "CIS Benchmark: 2.3.10.2",
                    cancellationToken);

                // AutoRun
                CheckRegistryValue(
                    findings,
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    "NoDriveTypeAutoRun",
                    255,
                    "AutoRun Disabled",
                    Severity.Medium,
                    "AutoRun is not fully disabled for all drive types",
                    "AutoRun can be used to execute malware automatically",
                    "Set NoDriveTypeAutoRun to 255 (0xFF) via Group Policy",
                    "CIS Benchmark: 18.9.8.3",
                    cancellationToken);
            }
        }, cancellationToken);

        return findings;
    }

    private void CheckRegistryValue(
        List<Finding> findings,
        string path,
        string valueName,
        int expectedValue,
        string checkName,
        Severity severity,
        string failDescription,
        string details,
        string remediation,
        string reference,
        CancellationToken cancellationToken,
        bool defaultIsVulnerable = false,
        bool failOnEqual = false)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(path);
            var value = key?.GetValue(valueName);

            int? intValue = value switch
            {
                int i => i,
                _ => null
            };

            bool isVulnerable;
            if (failOnEqual)
            {
                isVulnerable = intValue == expectedValue;
            }
            else if (defaultIsVulnerable)
            {
                isVulnerable = intValue != expectedValue;
            }
            else
            {
                isVulnerable = intValue != expectedValue;
            }

            if (isVulnerable)
            {
                findings.Add(CreateFailedFinding(checkName, severity, failDescription, details, remediation, reference));
            }
            else
            {
                findings.Add(CreatePassedFinding(checkName, $"{checkName} is properly configured"));
            }
        }
        catch (Exception)
        {
            if (defaultIsVulnerable)
            {
                findings.Add(CreateFailedFinding(checkName, severity, failDescription, details, remediation, reference));
            }
        }
    }

    private void CheckCachedLogons(List<Finding> findings, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
            var value = key?.GetValue("CachedLogonsCount")?.ToString();

            if (int.TryParse(value, out int count) && count > 2)
            {
                findings.Add(CreateFailedFinding(
                    "Cached Credentials Count",
                    Severity.Medium,
                    $"System caches {count} logon credentials",
                    "Cached credentials can be extracted and cracked offline",
                    "Reduce CachedLogonsCount to 2 or less for servers",
                    "CIS Benchmark: 2.3.7.1"));
            }
            else
            {
                findings.Add(CreatePassedFinding(
                    "Cached Credentials Count",
                    $"Cached logons count is {value ?? "0"}"));
            }
        }
        catch { }
    }
}
