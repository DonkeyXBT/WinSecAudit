namespace WinSecAudit.Models;

/// <summary>
/// Represents the complete result of a security audit.
/// </summary>
public class AuditResult
{
    /// <summary>
    /// Unique identifier for this audit.
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Computer name that was audited.
    /// </summary>
    public string ComputerName { get; set; } = Environment.MachineName;

    /// <summary>
    /// Domain name if joined to a domain.
    /// </summary>
    public string? Domain { get; set; }

    /// <summary>
    /// Operating system information.
    /// </summary>
    public string? OperatingSystem { get; set; }

    /// <summary>
    /// When the audit started.
    /// </summary>
    public DateTime StartTime { get; set; }

    /// <summary>
    /// When the audit completed.
    /// </summary>
    public DateTime? EndTime { get; set; }

    /// <summary>
    /// Duration of the audit.
    /// </summary>
    public TimeSpan Duration => EndTime.HasValue ? EndTime.Value - StartTime : TimeSpan.Zero;

    /// <summary>
    /// Type of audit performed.
    /// </summary>
    public AuditType Type { get; set; }

    /// <summary>
    /// Categories that were scanned.
    /// </summary>
    public List<string> CategoriesScanned { get; set; } = new();

    /// <summary>
    /// All findings from the audit.
    /// </summary>
    public List<Finding> Findings { get; set; } = new();

    /// <summary>
    /// Summary of findings by severity.
    /// </summary>
    public AuditSummary Summary { get; set; } = new();

    /// <summary>
    /// Whether the audit completed successfully.
    /// </summary>
    public bool IsComplete { get; set; }

    /// <summary>
    /// Error message if audit failed.
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Overall security score (0-100).
    /// </summary>
    public int SecurityScore { get; set; }

    /// <summary>
    /// Security grade (A-F).
    /// </summary>
    public string SecurityGrade { get; set; } = "N/A";

    /// <summary>
    /// Baseline used for comparison, if any.
    /// </summary>
    public string? BaselineUsed { get; set; }

    /// <summary>
    /// Compliance percentage against baseline.
    /// </summary>
    public double CompliancePercentage { get; set; }

    // Convenience properties for severity counts
    public int CriticalCount => Findings.Count(f => f.Severity == Severity.Critical);
    public int HighCount => Findings.Count(f => f.Severity == Severity.High);
    public int MediumCount => Findings.Count(f => f.Severity == Severity.Medium);
    public int LowCount => Findings.Count(f => f.Severity == Severity.Low);
}

/// <summary>
/// Summary of audit findings by severity.
/// </summary>
public class AuditSummary
{
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Info { get; set; }
    public int Passed { get; set; }

    public int TotalFindings => Critical + High + Medium + Low + Info;
    public int TotalChecks => TotalFindings + Passed;

    public double PassRate => TotalChecks > 0 ? (double)Passed / TotalChecks * 100 : 0;
}

/// <summary>
/// Type of security audit.
/// </summary>
public enum AuditType
{
    Quick,
    Full,
    Custom,
    Category
}
