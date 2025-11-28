using Microsoft.UI.Xaml; using Microsoft.UI.Xaml.Controls;
namespace WinSecAudit.Views.Pages;
public sealed partial class UsersPage : Page { public UsersPage() => InitializeComponent(); private async void Scan_Click(object sender, RoutedEventArgs e) { ScanBtn.IsEnabled = false; Progress.IsActive = true; var result = await App.Current.AuditService.RunCategoryAuditAsync(new[] { "Users" }); FindingsList.ItemsSource = result.Findings; Progress.IsActive = false; ScanBtn.IsEnabled = true; } }
