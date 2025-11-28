using CommunityToolkit.Mvvm.ComponentModel; using CommunityToolkit.Mvvm.Input;
using WinSecAudit.Services;
namespace WinSecAudit.ViewModels;
public partial class SettingsViewModel : ObservableObject
{
    private readonly SettingsService _settings = new();
    [ObservableProperty] private string _selectedTheme = "System";
    [ObservableProperty] private bool _autoScan;
    [ObservableProperty] private string _defaultExportFormat = "HTML";
    [ObservableProperty] private bool _showInfoFindings = true;
    public string[] Themes => new[] { "System", "Light", "Dark" };
    public string[] ExportFormats => new[] { "HTML", "JSON", "CSV" };
    public SettingsViewModel() { LoadSettings(); }
    private void LoadSettings()
    {
        SelectedTheme = _settings.Theme;
        AutoScan = _settings.AutoScan;
        DefaultExportFormat = _settings.DefaultExportFormat;
        ShowInfoFindings = _settings.ShowInfoFindings;
    }
    [RelayCommand]
    private void SaveSettings()
    {
        _settings.Theme = SelectedTheme;
        _settings.AutoScan = AutoScan;
        _settings.DefaultExportFormat = DefaultExportFormat;
        _settings.ShowInfoFindings = ShowInfoFindings;
    }
}
