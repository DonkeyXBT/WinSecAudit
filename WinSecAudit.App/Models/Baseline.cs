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

    /// <summary>
    /// Total number of checks in this baseline.
    /// </summary>
    public int CheckCount { get; set; }

    /// <summary>
    /// Categories included in this baseline.
    /// </summary>
    public List<string> Categories { get; set; } = new();

    /// <summary>
    /// URL to the baseline documentation.
    /// </summary>
    public string? DocumentationUrl { get; set; }

    /// <summary>
    /// Validates the baseline configuration.
    /// </summary>
    /// <returns>True if the baseline is valid.</returns>
    public bool IsValid()
    {
        if (string.IsNullOrWhiteSpace(Name)) return false;
        if (string.IsNullOrWhiteSpace(Version)) return false;
        if (Configuration == null) return false;
        return true;
    }

    /// <summary>
    /// Gets validation errors for this baseline.
    /// </summary>
    public IEnumerable<string> GetValidationErrors()
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(Name))
            errors.Add("Baseline name is required");
        if (string.IsNullOrWhiteSpace(Version))
            errors.Add("Baseline version is required");
        if (Configuration == null)
            errors.Add("Baseline configuration is required");
        if (CheckCount < 0)
            errors.Add("Check count cannot be negative");
        return errors;
    }

    /// <summary>
    /// Creates a copy of this baseline with a new ID.
    /// </summary>
    public Baseline Clone(string? newName = null)
    {
        return new Baseline
        {
            Id = Guid.NewGuid().ToString(),
            Name = newName ?? $"{Name} (Copy)",
            Description = Description,
            Version = Version,
            CreatedAt = DateTime.UtcNow,
            SourceComputer = SourceComputer,
            SourceOS = SourceOS,
            Configuration = Configuration,
            CheckCount = CheckCount,
            Categories = new List<string>(Categories),
            DocumentationUrl = DocumentationUrl
        };
    }
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
