using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinSecAudit.Models;
using WinSecAudit.Services;

namespace WinSecAudit.ViewModels;

/// <summary>
/// Main view model for the application.
/// </summary>
public partial class MainViewModel : ObservableObject
{
    private readonly INavigationService _navigationService;
    private readonly IAuditService _auditService;

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private int _scanProgress;

    [ObservableProperty]
    private string _statusMessage = "Ready";

    [ObservableProperty]
    private string _currentCategory = string.Empty;

    [ObservableProperty]
    private AuditResult? _lastAuditResult;

    [ObservableProperty]
    private AuditSummary _summary = new();

    public MainViewModel(INavigationService navigationService, IAuditService auditService)
    {
        _navigationService = navigationService;
        _auditService = auditService;

        _auditService.ProgressChanged += OnAuditProgressChanged;
        _auditService.FindingDiscovered += OnFindingDiscovered;
    }

    [RelayCommand]
    private async Task RunQuickScanAsync()
    {
        if (IsScanning) return;

        IsScanning = true;
        StatusMessage = "Running quick security scan...";

        try
        {
            LastAuditResult = await _auditService.RunQuickAuditAsync();
            Summary = LastAuditResult.Summary;
            StatusMessage = $"Scan complete. Found {Summary.TotalFindings} issues.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Scan failed: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            ScanProgress = 0;
        }
    }

    [RelayCommand]
    private async Task RunFullAuditAsync()
    {
        if (IsScanning) return;

        IsScanning = true;
        StatusMessage = "Running full security audit...";

        try
        {
            LastAuditResult = await _auditService.RunFullAuditAsync();
            Summary = LastAuditResult.Summary;
            StatusMessage = $"Audit complete. Found {Summary.TotalFindings} issues.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Audit failed: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            ScanProgress = 0;
        }
    }

    [RelayCommand]
    private void CancelScan()
    {
        if (!IsScanning) return;

        _auditService.CancelAudit();
        StatusMessage = "Scan cancelled.";
    }

    [RelayCommand]
    private async Task ExportReportAsync(string format)
    {
        if (LastAuditResult == null) return;

        var exportFormat = format.ToLower() switch
        {
            "html" => ExportFormat.Html,
            "json" => ExportFormat.Json,
            "csv" => ExportFormat.Csv,
            _ => ExportFormat.Html
        };

        var fileName = $"WinSecAudit_{DateTime.Now:yyyyMMdd_HHmmss}.{format.ToLower()}";
        var filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), fileName);

        await _auditService.ExportAuditAsync(LastAuditResult, filePath, exportFormat);
        StatusMessage = $"Report exported to {filePath}";
    }

    private void OnAuditProgressChanged(object? sender, AuditProgressEventArgs e)
    {
        ScanProgress = e.Progress;
        CurrentCategory = e.CurrentCategory;
        StatusMessage = $"Scanning {e.CurrentCategory}: {e.CurrentCheck}";
    }

    private void OnFindingDiscovered(object? sender, Finding e)
    {
        // Update summary in real-time
        switch (e.Severity)
        {
            case Severity.Critical: Summary.Critical++; break;
            case Severity.High: Summary.High++; break;
            case Severity.Medium: Summary.Medium++; break;
            case Severity.Low: Summary.Low++; break;
            case Severity.Info: Summary.Info++; break;
            case Severity.Passed: Summary.Passed++; break;
        }
        OnPropertyChanged(nameof(Summary));
    }
}
