using Microsoft.UI.Xaml.Data;
namespace WinSecAudit.Helpers;
public class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, System.Type targetType, object parameter, string language)
    {
        if (value is bool b) return !b;
        return true;
    }
    public object ConvertBack(object value, System.Type targetType, object parameter, string language)
    {
        if (value is bool b) return !b;
        return false;
    }
}
