using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinSecAudit.Models;

namespace WinSecAudit.Views.Pages;

public sealed partial class FullAuditPage : Page
{
    private CancellationTokenSource? _cts;

    public FullAuditPage()
    {
        this.InitializeComponent();
        App.Current.AuditService.ProgressChanged += (s, e) =>
        {
            DispatcherQueue.TryEnqueue(() =>
            {
                ProgressBar.Value = e.Progress;
                CategoryText.Text = $"Scanning: {e.CurrentCategory}";
            });
        };
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        StartBtn.Visibility = Visibility.Collapsed;
        CancelBtn.Visibility = Visibility.Visible;
        StatusText.Text = "Running full audit...";
        _cts = new CancellationTokenSource();

        try
        {
            var result = await App.Current.AuditService.RunFullAuditAsync(_cts.Token);
            ResultsList.ItemsSource = result.Findings.Where(f => f.Severity != Severity.Passed);
            StatusText.Text = $"Complete: {result.Summary.TotalFindings} issues found";
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Audit cancelled";
        }
        finally
        {
            StartBtn.Visibility = Visibility.Visible;
            CancelBtn.Visibility = Visibility.Collapsed;
            ProgressBar.Value = 0;
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
    }
}
