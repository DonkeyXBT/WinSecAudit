using WinSecAudit.Models;
using WinSecAudit.Services.Scanners;

namespace WinSecAudit.Services;

/// <summary>
/// Implementation of the audit service.
/// </summary>
public class AuditService : IAuditService
{
    private CancellationTokenSource? _cts;
    private readonly List<AuditResult> _auditHistory = new();
    private readonly Dictionary<string, ISecurityScanner> _scanners;

    public event EventHandler<AuditProgressEventArgs>? ProgressChanged;
    public event EventHandler<Finding>? FindingDiscovered;

    public bool IsRunning { get; private set; }
    public int Progress { get; private set; }

    public AuditService()
    {
        _scanners = new Dictionary<string, ISecurityScanner>
        {
            ["LocalPolicy"] = new LocalPolicyScanner(),
            ["Firewall"] = new FirewallScanner(),
            ["Services"] = new ServiceScanner(),
            ["Registry"] = new RegistryScanner(),
            ["Users"] = new UserAccountScanner(),
            ["Network"] = new NetworkScanner(),
            ["AuditPolicy"] = new AuditPolicyScanner(),
            ["Processes"] = new ProcessScanner(),
            ["Tasks"] = new ScheduledTaskScanner()
        };
    }

    public async Task<AuditResult> RunQuickAuditAsync(CancellationToken cancellationToken = default)
    {
        var quickCategories = new[] { "LocalPolicy", "Firewall", "Registry", "Users" };
        return await RunAuditInternalAsync(AuditType.Quick, quickCategories, true, cancellationToken);
    }

    public async Task<AuditResult> RunFullAuditAsync(CancellationToken cancellationToken = default)
    {
        var allCategories = _scanners.Keys.ToArray();
        return await RunAuditInternalAsync(AuditType.Full, allCategories, false, cancellationToken);
    }

    public async Task<AuditResult> RunCategoryAuditAsync(IEnumerable<string> categoryIds, CancellationToken cancellationToken = default)
    {
        return await RunAuditInternalAsync(AuditType.Category, categoryIds.ToArray(), false, cancellationToken);
    }

    private async Task<AuditResult> RunAuditInternalAsync(AuditType type, string[] categories, bool quick, CancellationToken cancellationToken)
    {
        if (IsRunning)
            throw new InvalidOperationException("An audit is already running.");

        IsRunning = true;
        Progress = 0;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var result = new AuditResult
        {
            Type = type,
            StartTime = DateTime.UtcNow,
            ComputerName = Environment.MachineName,
            Domain = Environment.UserDomainName,
            OperatingSystem = Environment.OSVersion.ToString()
        };

        try
        {
            int totalCategories = categories.Length;
            int completedCategories = 0;

            foreach (var categoryId in categories)
            {
                _cts.Token.ThrowIfCancellationRequested();

                if (!_scanners.TryGetValue(categoryId, out var scanner))
                    continue;

                result.CategoriesScanned.Add(categoryId);

                var category = SecurityCategories.GetById(categoryId);
                RaiseProgressChanged(
                    (completedCategories * 100) / totalCategories,
                    category?.Name ?? categoryId,
                    "Starting scan...",
                    category?.CheckCount ?? 0,
                    0
                );

                var findings = await scanner.ScanAsync(quick, _cts.Token);

                foreach (var finding in findings)
                {
                    finding.Category = categoryId;
                    result.Findings.Add(finding);
                    FindingDiscovered?.Invoke(this, finding);

                    UpdateSummary(result.Summary, finding.Severity);
                }

                completedCategories++;
                Progress = (completedCategories * 100) / totalCategories;
            }

            result.EndTime = DateTime.UtcNow;
            result.IsComplete = true;
        }
        catch (OperationCanceledException)
        {
            result.EndTime = DateTime.UtcNow;
            result.IsComplete = false;
            result.ErrorMessage = "Audit was cancelled.";
        }
        catch (Exception ex)
        {
            result.EndTime = DateTime.UtcNow;
            result.IsComplete = false;
            result.ErrorMessage = ex.Message;
        }
        finally
        {
            IsRunning = false;
            Progress = 100;
            _cts?.Dispose();
            _cts = null;
        }

        _auditHistory.Insert(0, result);
        return result;
    }

    public void CancelAudit()
    {
        _cts?.Cancel();
    }

    public Task<IEnumerable<AuditResult>> GetAuditHistoryAsync()
    {
        return Task.FromResult<IEnumerable<AuditResult>>(_auditHistory);
    }

    public Task<AuditResult?> GetAuditResultAsync(string id)
    {
        return Task.FromResult(_auditHistory.FirstOrDefault(r => r.Id == id));
    }

    public async Task ExportAuditAsync(AuditResult result, string filePath, ExportFormat format)
    {
        var exporter = new ReportExporter();
        await exporter.ExportAsync(result, filePath, format);
    }

    private void RaiseProgressChanged(int progress, string category, string check, int total, int completed)
    {
        ProgressChanged?.Invoke(this, new AuditProgressEventArgs(progress, category, check, total, completed));
    }

    private static void UpdateSummary(AuditSummary summary, Severity severity)
    {
        switch (severity)
        {
            case Severity.Critical: summary.Critical++; break;
            case Severity.High: summary.High++; break;
            case Severity.Medium: summary.Medium++; break;
            case Severity.Low: summary.Low++; break;
            case Severity.Info: summary.Info++; break;
            case Severity.Passed: summary.Passed++; break;
        }
    }
}
