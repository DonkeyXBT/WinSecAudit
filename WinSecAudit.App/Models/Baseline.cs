namespace WinSecAudit.Models;

/// <summary>
/// Represents a security baseline configuration.
/// </summary>
public class Baseline
{
    /// <summary>
    /// Unique identifier for the baseline.
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Name of the baseline.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Description of the baseline.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Version of the baseline.
    /// </summary>
    public string Version { get; set; } = "1.0";

    /// <summary>
    /// When the baseline was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Computer name this baseline was generated from.
    /// </summary>
    public string? SourceComputer { get; set; }

    /// <summary>
    /// Operating system of the source computer.
    /// </summary>
    public string? SourceOS { get; set; }

    /// <summary>
    /// Configuration settings in the baseline.
    /// </summary>
    public BaselineConfiguration Configuration { get; set; } = new();
}

/// <summary>
/// Configuration settings for a baseline.
/// </summary>
public class BaselineConfiguration
{
    public PasswordPolicySettings PasswordPolicy { get; set; } = new();
    public FirewallSettings Firewall { get; set; } = new();
    public RegistrySettings Registry { get; set; } = new();
    public AuditPolicySettings AuditPolicy { get; set; } = new();
    public ServiceSettings Services { get; set; } = new();
}

public class PasswordPolicySettings
{
    public int MinimumPasswordLength { get; set; } = 14;
    public bool PasswordComplexity { get; set; } = true;
    public int MaximumPasswordAge { get; set; } = 60;
    public int MinimumPasswordAge { get; set; } = 1;
    public int PasswordHistorySize { get; set; } = 24;
    public int LockoutThreshold { get; set; } = 5;
    public int LockoutDuration { get; set; } = 15;
}

public class FirewallSettings
{
    public bool DomainProfileEnabled { get; set; } = true;
    public bool PrivateProfileEnabled { get; set; } = true;
    public bool PublicProfileEnabled { get; set; } = true;
    public string DefaultInboundAction { get; set; } = "Block";
    public string DefaultOutboundAction { get; set; } = "Allow";
}

public class RegistrySettings
{
    public bool SMBServerSigning { get; set; } = true;
    public bool SMBClientSigning { get; set; } = true;
    public bool LLMNRDisabled { get; set; } = true;
    public bool WDigestDisabled { get; set; } = true;
    public bool LSAProtection { get; set; } = true;
    public bool UACEnabled { get; set; } = true;
    public int CachedLogonsCount { get; set; } = 2;
}

public class AuditPolicySettings
{
    public string CredentialValidation { get; set; } = "Success and Failure";
    public string AccountManagement { get; set; } = "Success and Failure";
    public string Logon { get; set; } = "Success and Failure";
    public string ProcessCreation { get; set; } = "Success";
    public bool CommandLineAuditing { get; set; } = true;
    public bool PowerShellLogging { get; set; } = true;
}

public class ServiceSettings
{
    public List<string> DisabledServices { get; set; } = new()
    {
        "RemoteRegistry",
        "Telnet",
        "SNMP",
        "Fax"
    };
}
