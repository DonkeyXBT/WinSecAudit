using Microsoft.UI.Xaml; using Microsoft.UI.Xaml.Controls; using Windows.Storage.Pickers;
namespace WinSecAudit.Views.Pages;
public sealed partial class ReportsPage : Page
{
    public ReportsPage() => InitializeComponent();
    private async void Html_Click(object sender, RoutedEventArgs e) => await SaveReportAsync("html");
    private async void Json_Click(object sender, RoutedEventArgs e) => await SaveReportAsync("json");
    private async void Csv_Click(object sender, RoutedEventArgs e) => await SaveReportAsync("csv");
    private async System.Threading.Tasks.Task SaveReportAsync(string format)
    {
        var picker = new FileSavePicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary, SuggestedFileName = $"WinSecAudit_{System.DateTime.Now:yyyyMMdd}" };
        picker.FileTypeChoices.Add(format.ToUpper(), new[] { $".{format}" });
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(App.Current.MainWindow);
        WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
        var file = await picker.PickSaveFileAsync();
        if (file != null) await Windows.Storage.FileIO.WriteTextAsync(file, $"Report exported at {System.DateTime.Now}");
    }
}
