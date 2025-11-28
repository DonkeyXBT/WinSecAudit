using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using WinSecAudit.Models;
using WinSecAudit.ViewModels;

namespace WinSecAudit.Views.Pages;

/// <summary>
/// Dashboard page showing security overview.
/// </summary>
public sealed partial class DashboardPage : Page
{
    private DashboardViewModel _viewModel;
    private List<Finding> _criticalFindings = new();

    public List<Finding> CriticalFindings => _criticalFindings;

    public DashboardPage()
    {
        this.InitializeComponent();
        _viewModel = new DashboardViewModel(App.Current.AuditService);
        LoadDashboardData();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        LoadDashboardData();
    }

    private async void LoadDashboardData()
    {
        ComputerInfo.Text = $"{Environment.MachineName} | {Environment.UserDomainName} | {Environment.OSVersion.Version}";

        var history = await App.Current.AuditService.GetAuditHistoryAsync();
        var lastAudit = history.FirstOrDefault();

        if (lastAudit != null)
        {
            UpdateSummary(lastAudit.Summary);
            UpdateScore(lastAudit);
            _criticalFindings = lastAudit.Findings
                .Where(f => f.Severity == Severity.Critical)
                .Take(5)
                .ToList();
            CriticalFindingsList.ItemsSource = _criticalFindings;

            LastScanText.Text = $"Last scan: {lastAudit.EndTime:g} ({lastAudit.Duration.TotalSeconds:F1}s)";
        }
    }

    private void UpdateSummary(AuditSummary summary)
    {
        CriticalCount.Text = summary.Critical.ToString();
        HighCount.Text = summary.High.ToString();
        MediumCount.Text = summary.Medium.ToString();
        LowCount.Text = summary.Low.ToString();
        InfoCount.Text = summary.Info.ToString();

        PassedText.Text = $"{summary.Passed} Passed";
        FailedText.Text = $"{summary.TotalFindings} Issues";
    }

    private void UpdateScore(AuditResult audit)
    {
        var summary = audit.Summary;
        if (summary.TotalChecks == 0) return;

        var criticalPenalty = summary.Critical * 20;
        var highPenalty = summary.High * 10;
        var mediumPenalty = summary.Medium * 5;
        var lowPenalty = summary.Low * 2;

        var maxScore = summary.TotalChecks * 10;
        var totalPenalty = criticalPenalty + highPenalty + mediumPenalty + lowPenalty;
        var score = Math.Max(0, 100 - (totalPenalty * 100 / maxScore));

        ScoreRing.Value = score;
        ScoreText.Text = score.ToString();
        GradeText.Text = score switch
        {
            >= 90 => "A",
            >= 80 => "B",
            >= 70 => "C",
            >= 60 => "D",
            _ => "F"
        };
    }

    private async void QuickScan_Click(object sender, RoutedEventArgs e)
    {
        QuickScanButton.IsEnabled = false;

        try
        {
            var result = await App.Current.AuditService.RunQuickAuditAsync();
            UpdateSummary(result.Summary);
            UpdateScore(result);
            _criticalFindings = result.Findings
                .Where(f => f.Severity == Severity.Critical)
                .Take(5)
                .ToList();
            CriticalFindingsList.ItemsSource = _criticalFindings;
            LastScanText.Text = $"Last scan: {result.EndTime:g} ({result.Duration.TotalSeconds:F1}s)";
        }
        finally
        {
            QuickScanButton.IsEnabled = true;
        }
    }

    private void Refresh_Click(object sender, RoutedEventArgs e)
    {
        LoadDashboardData();
    }
}
