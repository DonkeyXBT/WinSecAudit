using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel; using CommunityToolkit.Mvvm.Input;
using WinSecAudit.Models; using WinSecAudit.Services;
namespace WinSecAudit.ViewModels;
public partial class ReportsViewModel : ObservableObject
{
    private readonly ReportExporter _exporter = new();
    [ObservableProperty] private ObservableCollection<string> _recentReports = new();
    [ObservableProperty] private string _selectedFormat = "HTML";
    [ObservableProperty] private AuditResult? _lastAuditResult;
    public string[] ExportFormats => new[] { "HTML", "JSON", "CSV" };
    [RelayCommand]
    private async System.Threading.Tasks.Task ExportAsync()
    {
        if (LastAuditResult == null)
        {
            LastAuditResult = await App.Current.AuditService.RunFullAuditAsync();
        }
        var content = SelectedFormat switch
        {
            "HTML" => _exporter.ExportToHtml(LastAuditResult),
            "JSON" => _exporter.ExportToJson(LastAuditResult),
            "CSV" => _exporter.ExportToCsv(LastAuditResult),
            _ => ""
        };
        var fileName = $"WinSecAudit_{System.DateTime.Now:yyyyMMdd_HHmmss}.{SelectedFormat.ToLower()}";
        RecentReports.Insert(0, fileName);
    }
}
