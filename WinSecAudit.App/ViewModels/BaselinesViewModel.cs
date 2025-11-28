using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel; using CommunityToolkit.Mvvm.Input;
using WinSecAudit.Models; using WinSecAudit.Services;
namespace WinSecAudit.ViewModels;
public partial class BaselinesViewModel : ObservableObject
{
    private readonly BaselineService _baselineService = new();
    [ObservableProperty] private ObservableCollection<Baseline> _baselines = new();
    [ObservableProperty] private Baseline? _selectedBaseline;
    [ObservableProperty] private BaselineComparisonResult? _comparisonResult;
    [ObservableProperty] private bool _isComparing;
    public BaselinesViewModel() { LoadBaselines(); }
    private void LoadBaselines()
    {
        foreach (var b in _baselineService.GetAvailableBaselines()) Baselines.Add(b);
        if (Baselines.Count > 0) SelectedBaseline = Baselines[0];
    }
    [RelayCommand]
    private async System.Threading.Tasks.Task CompareAsync()
    {
        if (SelectedBaseline == null) return;
        IsComparing = true;
        var result = await App.Current.AuditService.RunFullAuditAsync();
        ComparisonResult = _baselineService.Compare(result, SelectedBaseline.Name == "CIS Windows Server 2022 Benchmark" ? "CIS" : SelectedBaseline.Name.Contains("STIG") ? "STIG" : "MS");
        IsComparing = false;
    }
}
