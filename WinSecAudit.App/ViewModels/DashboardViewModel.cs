using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinSecAudit.Models;
using WinSecAudit.Services;

namespace WinSecAudit.ViewModels;

/// <summary>
/// ViewModel for the Dashboard page.
/// </summary>
public partial class DashboardViewModel : ObservableObject
{
    private readonly IAuditService _auditService;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string _computerName = Environment.MachineName;

    [ObservableProperty]
    private string _operatingSystem = Environment.OSVersion.ToString();

    [ObservableProperty]
    private string _domain = Environment.UserDomainName;

    [ObservableProperty]
    private AuditResult? _lastAudit;

    [ObservableProperty]
    private AuditSummary _summary = new();

    [ObservableProperty]
    private List<Finding> _criticalFindings = new();

    [ObservableProperty]
    private List<Finding> _recentFindings = new();

    [ObservableProperty]
    private int _securityScore;

    [ObservableProperty]
    private string _securityGrade = "N/A";

    [ObservableProperty]
    private string _riskLevel = "Unknown";

    [ObservableProperty]
    private int _totalVulnerabilities;

    [ObservableProperty]
    private DateTime? _lastScanTime;

    public DashboardViewModel(IAuditService auditService)
    {
        _auditService = auditService;
        LoadDashboardData();
    }

    [RelayCommand]
    private async Task RefreshAsync()
    {
        IsLoading = true;
        await Task.Run(() => LoadDashboardData());
        IsLoading = false;
    }

    private async void LoadDashboardData()
    {
        var history = await _auditService.GetAuditHistoryAsync();
        LastAudit = history.FirstOrDefault();

        if (LastAudit != null)
        {
            Summary = LastAudit.Summary;
            LastScanTime = LastAudit.EndTime;

            CriticalFindings = LastAudit.Findings
                .Where(f => f.Severity == Severity.Critical)
                .Take(5)
                .ToList();

            RecentFindings = LastAudit.Findings
                .OrderByDescending(f => f.Timestamp)
                .Take(10)
                .ToList();

            CalculateSecurityScore();
        }
    }

    private void CalculateSecurityScore()
    {
        if (Summary.TotalChecks == 0)
        {
            SecurityScore = 0;
            SecurityGrade = "N/A";
            return;
        }

        // Weighted scoring
        var criticalPenalty = Summary.Critical * 20;
        var highPenalty = Summary.High * 10;
        var mediumPenalty = Summary.Medium * 5;
        var lowPenalty = Summary.Low * 2;

        var maxScore = Summary.TotalChecks * 10;
        var totalPenalty = criticalPenalty + highPenalty + mediumPenalty + lowPenalty;
        var score = Math.Max(0, 100 - (totalPenalty * 100 / maxScore));

        SecurityScore = (int)score;

        SecurityGrade = score switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            _ => "F"
        };
    }

    [RelayCommand]
    private async Task RunQuickScanAsync()
    {
        IsLoading = true;
        try
        {
            LastAudit = await _auditService.RunQuickAuditAsync();
            Summary = LastAudit.Summary;
            LastScanTime = LastAudit.EndTime;
            CalculateSecurityScore();
        }
        finally
        {
            IsLoading = false;
        }
    }
}
