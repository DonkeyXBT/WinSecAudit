using Windows.Storage;
namespace WinSecAudit.Services;
public class SettingsService
{
    private readonly ApplicationDataContainer _settings = ApplicationData.Current.LocalSettings;
    public string Theme { get => GetSetting("Theme", "System"); set => SetSetting("Theme", value); }
    public bool AutoScan { get => GetSetting("AutoScan", false); set => SetSetting("AutoScan", value); }
    public string DefaultExportFormat { get => GetSetting("DefaultExportFormat", "HTML"); set => SetSetting("DefaultExportFormat", value); }
    public string DefaultBaseline { get => GetSetting("DefaultBaseline", "CIS"); set => SetSetting("DefaultBaseline", value); }
    public bool ShowInfoFindings { get => GetSetting("ShowInfoFindings", true); set => SetSetting("ShowInfoFindings", value); }
    private T GetSetting<T>(string key, T defaultValue)
    {
        if (_settings.Values.TryGetValue(key, out var value)) return (T)value;
        return defaultValue;
    }
    private void SetSetting<T>(string key, T value) => _settings.Values[key] = value;
}
