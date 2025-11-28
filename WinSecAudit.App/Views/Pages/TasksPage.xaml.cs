using Microsoft.UI.Xaml; using Microsoft.UI.Xaml.Controls;
namespace WinSecAudit.Views.Pages;
public sealed partial class TasksPage : Page { public TasksPage() => InitializeComponent(); private async void Scan_Click(object sender, RoutedEventArgs e) { ScanBtn.IsEnabled = false; Progress.IsActive = true; var result = await App.Current.AuditService.RunCategoryAuditAsync(new[] { "Tasks" }); FindingsList.ItemsSource = result.Findings; Progress.IsActive = false; ScanBtn.IsEnabled = true; } }
