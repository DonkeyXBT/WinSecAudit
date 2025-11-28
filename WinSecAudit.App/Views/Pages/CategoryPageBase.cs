using Microsoft.UI.Xaml.Controls;
using WinSecAudit.Models;

namespace WinSecAudit.Views.Pages;

/// <summary>
/// Base class for category-specific pages.
/// </summary>
public abstract class CategoryPageBase : Page
{
    protected abstract string CategoryId { get; }
    protected abstract string CategoryName { get; }
    protected abstract string CategoryDescription { get; }

    protected List<Finding> Findings { get; } = new();

    protected async Task RunCategoryScanAsync()
    {
        var result = await App.Current.AuditService.RunCategoryAuditAsync(new[] { CategoryId });
        Findings.Clear();
        Findings.AddRange(result.Findings);
    }
}
