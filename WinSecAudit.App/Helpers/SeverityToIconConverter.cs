using Microsoft.UI.Xaml.Data;
using WinSecAudit.Models;
namespace WinSecAudit.Helpers;
public class SeverityToIconConverter : IValueConverter
{
    public object Convert(object value, System.Type targetType, object parameter, string language)
    {
        if (value is Severity severity)
        {
            return severity switch
            {
                Severity.Critical => "\uE7BA",
                Severity.High => "\uE783",
                Severity.Medium => "\uE7BA",
                Severity.Low => "\uE946",
                Severity.Info => "\uE946",
                _ => "\uE9CE"
            };
        }
        return "\uE9CE";
    }
    public object ConvertBack(object value, System.Type targetType, object parameter, string language) => throw new System.NotImplementedException();
}
