using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinSecAudit.Models;

namespace WinSecAudit.Views.Pages;

public sealed partial class QuickScanPage : Page
{
    private CancellationTokenSource? _cts;
    private List<Finding> _findings = new();

    public QuickScanPage()
    {
        this.InitializeComponent();
        App.Current.AuditService.ProgressChanged += OnProgressChanged;
        App.Current.AuditService.FindingDiscovered += OnFindingDiscovered;
    }

    private async void StartScan_Click(object sender, RoutedEventArgs e)
    {
        _findings.Clear();
        FindingsList.ItemsSource = null;

        StartButton.Visibility = Visibility.Collapsed;
        CancelButton.Visibility = Visibility.Visible;
        ScanProgress.IsActive = true;
        StatusText.Text = "Scanning...";

        _cts = new CancellationTokenSource();

        try
        {
            var result = await App.Current.AuditService.RunQuickAuditAsync(_cts.Token);
            _findings = result.Findings.Where(f => f.Severity != Severity.Passed).ToList();
            FindingsList.ItemsSource = _findings;
            StatusText.Text = $"Scan complete - {_findings.Count} issues found";
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Scan cancelled";
        }
        finally
        {
            StartButton.Visibility = Visibility.Visible;
            CancelButton.Visibility = Visibility.Collapsed;
            ScanProgress.IsActive = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void CancelScan_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        App.Current.AuditService.CancelAudit();
    }

    private void OnProgressChanged(object? sender, Services.AuditProgressEventArgs e)
    {
        DispatcherQueue.TryEnqueue(() =>
        {
            ProgressText.Text = $"Scanning {e.CurrentCategory}: {e.CurrentCheck}";
        });
    }

    private void OnFindingDiscovered(object? sender, Finding e)
    {
        if (e.Severity != Severity.Passed)
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                _findings.Add(e);
                FindingsList.ItemsSource = null;
                FindingsList.ItemsSource = _findings;
            });
        }
    }
}
