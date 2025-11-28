using Microsoft.UI.Xaml.Data; using Microsoft.UI.Xaml.Media; using Microsoft.UI;
using WinSecAudit.Models;
namespace WinSecAudit.Helpers;
public class SeverityToColorConverter : IValueConverter
{
    public object Convert(object value, System.Type targetType, object parameter, string language)
    {
        if (value is Severity severity)
        {
            return severity switch
            {
                Severity.Critical => new SolidColorBrush(Colors.Red),
                Severity.High => new SolidColorBrush(Colors.OrangeRed),
                Severity.Medium => new SolidColorBrush(Colors.Orange),
                Severity.Low => new SolidColorBrush(Colors.Yellow),
                Severity.Info => new SolidColorBrush(Colors.DodgerBlue),
                _ => new SolidColorBrush(Colors.Gray)
            };
        }
        return new SolidColorBrush(Colors.Gray);
    }
    public object ConvertBack(object value, System.Type targetType, object parameter, string language) => throw new System.NotImplementedException();
}
