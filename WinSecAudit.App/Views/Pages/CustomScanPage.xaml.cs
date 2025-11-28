using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace WinSecAudit.Views.Pages;

public sealed partial class CustomScanPage : Page
{
    private readonly CheckBox[] _categoryChecks;

    public CustomScanPage()
    {
        this.InitializeComponent();
        _categoryChecks = new[] { AdCheck, PolicyCheck, FirewallCheck, ServicesCheck,
            RegistryCheck, UsersCheck, NetworkCheck, AuditCheck, ProcessCheck, TasksCheck };
    }

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var check in _categoryChecks) check.IsChecked = true;
    }

    private void ClearAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var check in _categoryChecks) check.IsChecked = false;
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        var categories = new List<string>();
        if (AdCheck.IsChecked == true) categories.Add("AD");
        if (PolicyCheck.IsChecked == true) categories.Add("LocalPolicy");
        if (FirewallCheck.IsChecked == true) categories.Add("Firewall");
        if (ServicesCheck.IsChecked == true) categories.Add("Services");
        if (RegistryCheck.IsChecked == true) categories.Add("Registry");
        if (UsersCheck.IsChecked == true) categories.Add("Users");
        if (NetworkCheck.IsChecked == true) categories.Add("Network");
        if (AuditCheck.IsChecked == true) categories.Add("AuditPolicy");
        if (ProcessCheck.IsChecked == true) categories.Add("Processes");
        if (TasksCheck.IsChecked == true) categories.Add("Tasks");

        if (categories.Count > 0)
        {
            await App.Current.AuditService.RunCategoryAuditAsync(categories);
        }
    }
}
