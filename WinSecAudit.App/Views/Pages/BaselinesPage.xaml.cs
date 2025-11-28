using Microsoft.UI.Xaml; using Microsoft.UI.Xaml.Controls;
namespace WinSecAudit.Views.Pages;
public sealed partial class BaselinesPage : Page
{
    public BaselinesPage() => InitializeComponent();
    private void Cis_Click(object sender, RoutedEventArgs e) => LoadBaseline("CIS Windows Server 2022 Benchmark v1.0");
    private void Stig_Click(object sender, RoutedEventArgs e) => LoadBaseline("DISA Windows Server 2022 STIG v1r1");
    private void Ms_Click(object sender, RoutedEventArgs e) => LoadBaseline("Microsoft Security Baseline for Windows Server 2022");
    private void LoadBaseline(string name) => ComparisonList.ItemsSource = new[] { $"Loaded: {name}", "Comparing against current configuration...", "Results will appear here after scan." };
}
