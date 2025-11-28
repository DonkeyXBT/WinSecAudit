using System.DirectoryServices.AccountManagement;
using WinSecAudit.Models;

namespace WinSecAudit.Services.Scanners;

/// <summary>
/// Scans local user account security.
/// </summary>
public class UserAccountScanner : SecurityScannerBase
{
    public override string CategoryId => "Users";
    public override string Name => "User Accounts";
    public override string Description => "Audits local user accounts, administrators group, and password policies";

    public override async Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();

        await Task.Run(() =>
        {
            try
            {
                using var context = new PrincipalContext(ContextType.Machine);

                // Get all local users
                using var userPrincipal = new UserPrincipal(context);
                using var searcher = new PrincipalSearcher(userPrincipal);

                var users = searcher.FindAll().Cast<UserPrincipal>().ToList();
                var noPasswordRequired = new List<string>();
                var passwordNeverExpires = new List<string>();
                var inactiveUsers = new List<string>();

                foreach (var user in users)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (user.Enabled == true)
                    {
                        // Check for accounts that don't require password
                        if (user.PasswordNotRequired)
                        {
                            noPasswordRequired.Add(user.SamAccountName);
                        }

                        // Check for password never expires (non-service accounts)
                        if (user.PasswordNeverExpires &&
                            !user.SamAccountName.Contains("svc", StringComparison.OrdinalIgnoreCase))
                        {
                            passwordNeverExpires.Add(user.SamAccountName);
                        }

                        // Check for inactive users
                        if (!quick && user.LastLogon.HasValue)
                        {
                            var daysSinceLogon = (DateTime.Now - user.LastLogon.Value).TotalDays;
                            if (daysSinceLogon > 90)
                            {
                                inactiveUsers.Add(user.SamAccountName);
                            }
                        }
                    }

                    // Check Guest account
                    if (user.Sid.ToString().EndsWith("-501") && user.Enabled == true)
                    {
                        findings.Add(CreateFailedFinding(
                            "Guest Account Enabled",
                            Severity.High,
                            "The built-in Guest account is enabled",
                            "Guest account should always be disabled on servers",
                            $"Disable-LocalUser -Name '{user.SamAccountName}'",
                            "CIS Benchmark: 1.1.1"));
                    }

                    // Check Administrator account
                    if (user.Sid.ToString().EndsWith("-500"))
                    {
                        if (user.Enabled == true)
                        {
                            findings.Add(new Finding
                            {
                                Check = "Built-in Administrator Enabled",
                                Severity = Severity.Medium,
                                Status = FindingStatus.Warning,
                                Category = CategoryId,
                                Description = "The built-in Administrator account is enabled",
                                Details = $"Account name: {user.SamAccountName}",
                                Remediation = "Consider disabling and using named admin accounts"
                            });
                        }

                        if (user.SamAccountName == "Administrator")
                        {
                            findings.Add(CreateFailedFinding(
                                "Administrator Account Not Renamed",
                                Severity.Low,
                                "The built-in Administrator account has not been renamed",
                                "Renaming makes it harder to guess credentials",
                                "Rename the Administrator account to a non-obvious name",
                                "CIS Benchmark: 2.3.1.5"));
                        }
                    }
                }

                // Report findings
                if (noPasswordRequired.Count > 0)
                {
                    findings.Add(CreateFailedFinding(
                        "Accounts Without Password Requirement",
                        Severity.Critical,
                        $"{noPasswordRequired.Count} enabled accounts do not require a password",
                        string.Join(", ", noPasswordRequired),
                        "Set password requirement for all user accounts",
                        "CIS Benchmark: 1.1.x"));
                }

                if (passwordNeverExpires.Count > 0)
                {
                    findings.Add(CreateFailedFinding(
                        "Accounts with Non-Expiring Passwords",
                        Severity.Medium,
                        $"{passwordNeverExpires.Count} non-service accounts have passwords that never expire",
                        string.Join(", ", passwordNeverExpires.Take(10)),
                        "Remove PasswordNeverExpires flag for non-service accounts",
                        "CIS Benchmark: 1.1.4"));
                }

                if (inactiveUsers.Count > 0)
                {
                    findings.Add(new Finding
                    {
                        Check = "Inactive User Accounts",
                        Severity = Severity.Low,
                        Status = FindingStatus.Warning,
                        Category = CategoryId,
                        Description = $"{inactiveUsers.Count} accounts have not logged in for 90+ days",
                        Details = string.Join(", ", inactiveUsers.Take(10)),
                        Remediation = "Disable or remove inactive accounts"
                    });
                }

                // Check Administrators group membership
                CheckAdministratorsGroup(findings, context, cancellationToken);

                // Check Remote Desktop Users group
                if (!quick)
                {
                    CheckRemoteDesktopUsersGroup(findings, context, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                findings.Add(new Finding
                {
                    Check = "User Account Scan",
                    Severity = Severity.Info,
                    Status = FindingStatus.Error,
                    Description = "Failed to scan user accounts",
                    Details = ex.Message
                });
            }
        }, cancellationToken);

        return findings;
    }

    private void CheckAdministratorsGroup(List<Finding> findings, PrincipalContext context, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            using var adminGroup = GroupPrincipal.FindByIdentity(context, "Administrators");
            if (adminGroup != null)
            {
                var members = adminGroup.GetMembers().ToList();

                if (members.Count > 3)
                {
                    findings.Add(CreateFailedFinding(
                        "Excessive Local Administrators",
                        Severity.High,
                        $"{members.Count} members in local Administrators group",
                        string.Join(", ", members.Select(m => m.SamAccountName)),
                        "Limit local administrator membership to essential accounts only",
                        "Principle of least privilege"));
                }
                else
                {
                    findings.Add(CreatePassedFinding(
                        "Local Administrators Count",
                        $"Only {members.Count} members in Administrators group"));
                }
            }
        }
        catch { }
    }

    private void CheckRemoteDesktopUsersGroup(List<Finding> findings, PrincipalContext context, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        try
        {
            using var rdpGroup = GroupPrincipal.FindByIdentity(context, "Remote Desktop Users");
            if (rdpGroup != null)
            {
                var members = rdpGroup.GetMembers().ToList();

                if (members.Count > 5)
                {
                    findings.Add(CreateFailedFinding(
                        "Excessive Remote Desktop Users",
                        Severity.Medium,
                        $"{members.Count} members in Remote Desktop Users group",
                        string.Join(", ", members.Select(m => m.SamAccountName).Take(10)),
                        "Limit RDP access to essential users only",
                        "Principle of least privilege"));
                }
                else if (members.Count > 0)
                {
                    findings.Add(new Finding
                    {
                        Check = "Remote Desktop Users",
                        Severity = Severity.Info,
                        Status = FindingStatus.Passed,
                        Category = CategoryId,
                        Description = $"{members.Count} members in Remote Desktop Users group",
                        Details = string.Join(", ", members.Select(m => m.SamAccountName))
                    });
                }
            }
        }
        catch { }
    }
}
