namespace WinSecAudit.Models;

/// <summary>
/// Represents a security finding from an audit.
/// </summary>
public class Finding
{
    /// <summary>
    /// Unique identifier for this finding.
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Name of the security check.
    /// </summary>
    public string Check { get; set; } = string.Empty;

    /// <summary>
    /// Severity level of the finding.
    /// </summary>
    public Severity Severity { get; set; }

    /// <summary>
    /// Status of the check.
    /// </summary>
    public FindingStatus Status { get; set; }

    /// <summary>
    /// Category of the finding.
    /// </summary>
    public string Category { get; set; } = string.Empty;

    /// <summary>
    /// Description of what was found.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Technical details about the finding.
    /// </summary>
    public string Details { get; set; } = string.Empty;

    /// <summary>
    /// Steps to remediate the finding.
    /// </summary>
    public string Remediation { get; set; } = string.Empty;

    /// <summary>
    /// Reference to security standard (CIS, NIST, etc.).
    /// </summary>
    public string Reference { get; set; } = string.Empty;

    /// <summary>
    /// MITRE ATT&CK technique ID if applicable.
    /// </summary>
    public string? MitreId { get; set; }

    /// <summary>
    /// CVE identifier if applicable.
    /// </summary>
    public string? CveId { get; set; }

    /// <summary>
    /// Timestamp when this finding was discovered.
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Severity levels for security findings.
/// </summary>
public enum Severity
{
    Info,
    Low,
    Medium,
    High,
    Critical,
    Passed
}

/// <summary>
/// Status of a security finding.
/// </summary>
public enum FindingStatus
{
    Passed,
    Warning,
    Failed,
    Error,
    Skipped
}
