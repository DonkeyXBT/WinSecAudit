namespace WinSecAudit.Models;

/// <summary>
/// Represents a category of security checks.
/// </summary>
public class SecurityCategory
{
    /// <summary>
    /// Unique identifier for the category.
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Display name of the category.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Description of what this category checks.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Icon glyph for UI display.
    /// </summary>
    public string IconGlyph { get; set; } = "\uE8D7";

    /// <summary>
    /// Whether this category is enabled for scanning.
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Number of checks in this category.
    /// </summary>
    public int CheckCount { get; set; }

    /// <summary>
    /// Estimated time to complete this category scan.
    /// </summary>
    public TimeSpan EstimatedDuration { get; set; }

    /// <summary>
    /// Whether this category requires elevated privileges.
    /// </summary>
    public bool RequiresAdmin { get; set; } = true;

    /// <summary>
    /// Whether this category requires Active Directory.
    /// </summary>
    public bool RequiresAD { get; set; }

    /// <summary>
    /// Priority for scanning order (lower = higher priority).
    /// </summary>
    public int Priority { get; set; } = 100;

    /// <summary>
    /// MITRE ATT&CK techniques covered by this category.
    /// </summary>
    public List<string> MitreTechniques { get; set; } = new();

    /// <summary>
    /// CIS Benchmark sections covered by this category.
    /// </summary>
    public List<string> CisSections { get; set; } = new();
}

/// <summary>
/// Provides the available security categories.
/// </summary>
public static class SecurityCategories
{
    public static readonly SecurityCategory ActiveDirectory = new()
    {
        Id = "AD",
        Name = "Active Directory",
        Description = "Audit AD security configuration, delegation, and privileged accounts",
        IconGlyph = "\uE716",
        CheckCount = 12,
        EstimatedDuration = TimeSpan.FromSeconds(30),
        RequiresAD = true
    };

    public static readonly SecurityCategory LocalPolicy = new()
    {
        Id = "LocalPolicy",
        Name = "Local Security Policy",
        Description = "Password policies, account lockout, and security options",
        IconGlyph = "\uE8A7",
        CheckCount = 15,
        EstimatedDuration = TimeSpan.FromSeconds(10)
    };

    public static readonly SecurityCategory Firewall = new()
    {
        Id = "Firewall",
        Name = "Windows Firewall",
        Description = "Firewall profiles, rules, and logging configuration",
        IconGlyph = "\uE83D",
        CheckCount = 10,
        EstimatedDuration = TimeSpan.FromSeconds(15)
    };

    public static readonly SecurityCategory Services = new()
    {
        Id = "Services",
        Name = "Windows Services",
        Description = "Service security, unquoted paths, and dangerous services",
        IconGlyph = "\uE912",
        CheckCount = 8,
        EstimatedDuration = TimeSpan.FromSeconds(20)
    };

    public static readonly SecurityCategory Registry = new()
    {
        Id = "Registry",
        Name = "Registry Security",
        Description = "SMB signing, LLMNR, WDigest, UAC, and LSA protection",
        IconGlyph = "\uEDA2",
        CheckCount = 12,
        EstimatedDuration = TimeSpan.FromSeconds(10)
    };

    public static readonly SecurityCategory Users = new()
    {
        Id = "Users",
        Name = "User Accounts",
        Description = "Local user security, administrators, and password settings",
        IconGlyph = "\uE77B",
        CheckCount = 10,
        EstimatedDuration = TimeSpan.FromSeconds(10)
    };

    public static readonly SecurityCategory Network = new()
    {
        Id = "Network",
        Name = "Network Security",
        Description = "Open ports, shares, IPv6, and DNS configuration",
        IconGlyph = "\uE968",
        CheckCount = 8,
        EstimatedDuration = TimeSpan.FromSeconds(15)
    };

    public static readonly SecurityCategory AuditPolicy = new()
    {
        Id = "AuditPolicy",
        Name = "Audit Policy",
        Description = "Windows audit settings and PowerShell logging",
        IconGlyph = "\uE7C3",
        CheckCount = 10,
        EstimatedDuration = TimeSpan.FromSeconds(10)
    };

    public static readonly SecurityCategory Processes = new()
    {
        Id = "Processes",
        Name = "Running Processes",
        Description = "Suspicious processes, encoded commands, and anomalies",
        IconGlyph = "\uE9F5",
        CheckCount = 6,
        EstimatedDuration = TimeSpan.FromSeconds(25)
    };

    public static readonly SecurityCategory Tasks = new()
    {
        Id = "Tasks",
        Name = "Scheduled Tasks",
        Description = "Task persistence, suspicious actions, and SYSTEM tasks",
        IconGlyph = "\uE823",
        CheckCount = 5,
        EstimatedDuration = TimeSpan.FromSeconds(15)
    };

    public static IEnumerable<SecurityCategory> All => new[]
    {
        ActiveDirectory, LocalPolicy, Firewall, Services, Registry,
        Users, Network, AuditPolicy, Processes, Tasks
    };

    public static SecurityCategory? GetById(string id) => All.FirstOrDefault(c => c.Id == id);
}
