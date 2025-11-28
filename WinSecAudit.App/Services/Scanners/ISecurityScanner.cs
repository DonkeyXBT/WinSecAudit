using WinSecAudit.Models;

namespace WinSecAudit.Services.Scanners;

/// <summary>
/// Interface for security scanner implementations.
/// </summary>
public interface ISecurityScanner
{
    /// <summary>
    /// Gets the scanner category ID.
    /// </summary>
    string CategoryId { get; }

    /// <summary>
    /// Gets the scanner display name.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Gets the scanner description.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Gets the estimated scan duration in seconds.
    /// </summary>
    int EstimatedDuration { get; }

    /// <summary>
    /// Runs the security scan.
    /// </summary>
    /// <param name="quick">Whether to run a quick scan.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>List of findings from the scan.</returns>
    Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default);
}

/// <summary>
/// Base class for security scanners.
/// </summary>
public abstract class SecurityScannerBase : ISecurityScanner
{
    public abstract string CategoryId { get; }
    public abstract string Name { get; }
    public virtual string Description => $"Scans {Name} security settings";
    public virtual int EstimatedDuration => 30;

    public abstract Task<IEnumerable<Finding>> ScanAsync(bool quick = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a finding with the specified properties.
    /// </summary>
    protected Finding CreateFinding(
        string check,
        Severity severity,
        FindingStatus status,
        string description,
        string? details = null,
        string? remediation = null,
        string? reference = null,
        string? mitreId = null)
    {
        return new Finding
        {
            Check = check,
            Severity = severity,
            Status = status,
            Category = CategoryId,
            Description = description,
            Details = details ?? string.Empty,
            Remediation = remediation ?? string.Empty,
            Reference = reference ?? string.Empty,
            MitreId = mitreId
        };
    }

    /// <summary>
    /// Creates a passed finding.
    /// </summary>
    protected Finding CreatePassedFinding(string check, string description)
    {
        return CreateFinding(check, Severity.Passed, FindingStatus.Passed, description);
    }

    /// <summary>
    /// Creates a failed finding.
    /// </summary>
    protected Finding CreateFailedFinding(
        string check,
        Severity severity,
        string description,
        string details,
        string remediation,
        string? reference = null)
    {
        return CreateFinding(check, severity, FindingStatus.Failed, description, details, remediation, reference);
    }
}
