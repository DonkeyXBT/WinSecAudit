using WinSecAudit.Models;

namespace WinSecAudit.Services;

/// <summary>
/// Service for running security audits.
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Event raised when audit progress changes.
    /// </summary>
    event EventHandler<AuditProgressEventArgs>? ProgressChanged;

    /// <summary>
    /// Event raised when a finding is discovered.
    /// </summary>
    event EventHandler<Finding>? FindingDiscovered;

    /// <summary>
    /// Gets whether an audit is currently running.
    /// </summary>
    bool IsRunning { get; }

    /// <summary>
    /// Gets the current audit progress (0-100).
    /// </summary>
    int Progress { get; }

    /// <summary>
    /// Runs a quick security audit.
    /// </summary>
    Task<AuditResult> RunQuickAuditAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Runs a full security audit.
    /// </summary>
    Task<AuditResult> RunFullAuditAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Runs an audit on specific categories.
    /// </summary>
    Task<AuditResult> RunCategoryAuditAsync(IEnumerable<string> categoryIds, CancellationToken cancellationToken = default);

    /// <summary>
    /// Cancels the current audit.
    /// </summary>
    void CancelAudit();

    /// <summary>
    /// Gets audit history.
    /// </summary>
    Task<IEnumerable<AuditResult>> GetAuditHistoryAsync();

    /// <summary>
    /// Gets a specific audit result by ID.
    /// </summary>
    Task<AuditResult?> GetAuditResultAsync(string id);

    /// <summary>
    /// Exports an audit result to a file.
    /// </summary>
    Task ExportAuditAsync(AuditResult result, string filePath, ExportFormat format);
}

/// <summary>
/// Progress event arguments for audit operations.
/// </summary>
public class AuditProgressEventArgs : EventArgs
{
    public int Progress { get; }
    public string CurrentCategory { get; }
    public string CurrentCheck { get; }
    public int TotalChecks { get; }
    public int CompletedChecks { get; }
    public TimeSpan ElapsedTime { get; }
    public TimeSpan? EstimatedRemaining { get; }
    public int FindingsCount { get; }

    public AuditProgressEventArgs(
        int progress,
        string category,
        string check,
        int total,
        int completed,
        TimeSpan elapsed = default,
        TimeSpan? estimatedRemaining = null,
        int findings = 0)
    {
        Progress = progress;
        CurrentCategory = category;
        CurrentCheck = check;
        TotalChecks = total;
        CompletedChecks = completed;
        ElapsedTime = elapsed;
        EstimatedRemaining = estimatedRemaining;
        FindingsCount = findings;
    }
}

/// <summary>
/// Export format options.
/// </summary>
public enum ExportFormat
{
    Html,
    Json,
    Csv,
    Pdf
}
