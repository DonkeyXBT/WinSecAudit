using Microsoft.UI.Xaml; using Microsoft.UI.Xaml.Controls;
using WinSecAudit.Models;
namespace WinSecAudit.Helpers;
public class FindingTemplateSelector : DataTemplateSelector
{
    public DataTemplate? CriticalTemplate { get; set; }
    public DataTemplate? HighTemplate { get; set; }
    public DataTemplate? MediumTemplate { get; set; }
    public DataTemplate? LowTemplate { get; set; }
    public DataTemplate? InfoTemplate { get; set; }
    public DataTemplate? DefaultTemplate { get; set; }
    protected override DataTemplate? SelectTemplateCore(object item, DependencyObject container)
    {
        if (item is Finding finding)
        {
            return finding.Severity switch
            {
                Severity.Critical => CriticalTemplate ?? DefaultTemplate,
                Severity.High => HighTemplate ?? DefaultTemplate,
                Severity.Medium => MediumTemplate ?? DefaultTemplate,
                Severity.Low => LowTemplate ?? DefaultTemplate,
                Severity.Info => InfoTemplate ?? DefaultTemplate,
                _ => DefaultTemplate
            };
        }
        return DefaultTemplate;
    }
}
