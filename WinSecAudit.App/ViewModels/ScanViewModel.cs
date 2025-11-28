using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WinSecAudit.Models;
using WinSecAudit.Services;

namespace WinSecAudit.ViewModels;

/// <summary>
/// ViewModel for scan pages (Quick, Full, Custom).
/// </summary>
public partial class ScanViewModel : ObservableObject
{
    private readonly IAuditService _auditService;
    private CancellationTokenSource? _cts;

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private int _progress;

    [ObservableProperty]
    private string _currentCategory = string.Empty;

    [ObservableProperty]
    private string _currentCheck = string.Empty;

    [ObservableProperty]
    private int _totalChecks;

    [ObservableProperty]
    private int _completedChecks;

    [ObservableProperty]
    private List<SecurityCategory> _availableCategories;

    [ObservableProperty]
    private AuditResult? _result;

    [ObservableProperty]
    private List<Finding> _findings = new();

    [ObservableProperty]
    private AuditSummary _summary = new();

    [ObservableProperty]
    private TimeSpan _elapsedTime;

    [ObservableProperty]
    private string _scanStatus = "Ready";

    [ObservableProperty]
    private bool _canExport;

    private DateTime _startTime;

    public ScanViewModel(IAuditService auditService)
    {
        _auditService = auditService;
        _auditService.ProgressChanged += OnProgressChanged;
        _auditService.FindingDiscovered += OnFindingDiscovered;

        _availableCategories = SecurityCategories.All.ToList();
    }

    [RelayCommand]
    private async Task StartQuickScanAsync()
    {
        await RunScanAsync(() => _auditService.RunQuickAuditAsync(_cts!.Token));
    }

    [RelayCommand]
    private async Task StartFullScanAsync()
    {
        await RunScanAsync(() => _auditService.RunFullAuditAsync(_cts!.Token));
    }

    [RelayCommand]
    private async Task StartCustomScanAsync(IEnumerable<string> categoryIds)
    {
        await RunScanAsync(() => _auditService.RunCategoryAuditAsync(categoryIds, _cts!.Token));
    }

    private async Task RunScanAsync(Func<Task<AuditResult>> scanFunc)
    {
        if (IsScanning) return;

        IsScanning = true;
        Progress = 0;
        Findings.Clear();
        Summary = new AuditSummary();
        _cts = new CancellationTokenSource();
        _startTime = DateTime.Now;
        ScanStatus = "Scanning...";
        CanExport = false;

        // Start elapsed time timer
        _ = UpdateElapsedTimeAsync();

        try
        {
            Result = await scanFunc();
            Summary = Result.Summary;
            Findings = Result.Findings.ToList();
        }
        catch (OperationCanceledException)
        {
            // Scan was cancelled
        }
        finally
        {
            IsScanning = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private async Task UpdateElapsedTimeAsync()
    {
        while (IsScanning)
        {
            ElapsedTime = DateTime.Now - _startTime;
            await Task.Delay(100);
        }
    }

    [RelayCommand]
    private void CancelScan()
    {
        _cts?.Cancel();
        _auditService.CancelAudit();
    }

    [RelayCommand]
    private void ToggleCategory(SecurityCategory category)
    {
        category.IsEnabled = !category.IsEnabled;
    }

    private void OnProgressChanged(object? sender, AuditProgressEventArgs e)
    {
        Progress = e.Progress;
        CurrentCategory = e.CurrentCategory;
        CurrentCheck = e.CurrentCheck;
        TotalChecks = e.TotalChecks;
        CompletedChecks = e.CompletedChecks;
    }

    private void OnFindingDiscovered(object? sender, Finding e)
    {
        Findings.Add(e);
        OnPropertyChanged(nameof(Findings));

        // Update summary
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
