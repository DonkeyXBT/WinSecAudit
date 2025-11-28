using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinSecAudit.Views.Pages;

namespace WinSecAudit;

/// <summary>
/// Main application window with navigation shell.
/// </summary>
public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        this.InitializeComponent();

        // Apply Mica backdrop
        SystemBackdrop = new Microsoft.UI.Xaml.Media.MicaBackdrop();

        // Set initial page
        ContentFrame.Navigate(typeof(DashboardPage));

        // Select first item
        NavView.SelectedItem = NavView.MenuItems[0];
    }

    /// <summary>
    /// Handles navigation selection changes.
    /// </summary>
    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItemContainer is NavigationViewItem item && item.Tag is string tag)
        {
            NavigateToPage(tag);
        }
    }

    /// <summary>
    /// Navigates to the specified page.
    /// </summary>
    private void NavigateToPage(string pageTag)
    {
        Type? pageType = pageTag switch
        {
            "Dashboard" => typeof(DashboardPage),
            "QuickScan" => typeof(QuickScanPage),
            "FullAudit" => typeof(FullAuditPage),
            "CustomScan" => typeof(CustomScanPage),
            "ActiveDirectory" => typeof(ActiveDirectoryPage),
            "LocalPolicies" => typeof(LocalPoliciesPage),
            "Firewall" => typeof(FirewallPage),
            "Services" => typeof(ServicesPage),
            "Registry" => typeof(RegistryPage),
            "Users" => typeof(UsersPage),
            "Network" => typeof(NetworkPage),
            "AuditPolicy" => typeof(AuditPolicyPage),
            "Processes" => typeof(ProcessesPage),
            "Tasks" => typeof(TasksPage),
            "Remediation" => typeof(RemediationPage),
            "Reports" => typeof(ReportsPage),
            "Baselines" => typeof(BaselinesPage),
            "Settings" => typeof(SettingsPage),
            "About" => typeof(AboutPage),
            _ => null
        };

        if (pageType != null && ContentFrame.CurrentSourcePageType != pageType)
        {
            ContentFrame.Navigate(pageType);
        }
    }
}
