using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinSecAudit.Services;
using WinSecAudit.ViewModels;

namespace WinSecAudit;

/// <summary>
/// Main application class for WinSecAudit.
/// Provides application-level functionality and lifecycle management.
/// </summary>
public partial class App : Application
{
    private Window? _mainWindow;

    /// <summary>
    /// Gets the current application instance.
    /// </summary>
    public static new App Current => (App)Application.Current;

    /// <summary>
    /// Gets the main application window.
    /// </summary>
    public Window? MainWindow => _mainWindow;

    /// <summary>
    /// Gets the navigation service for page navigation.
    /// </summary>
    public INavigationService NavigationService { get; }

    /// <summary>
    /// Gets the security audit service.
    /// </summary>
    public IAuditService AuditService { get; }

    /// <summary>
    /// Gets the main view model.
    /// </summary>
    public MainViewModel MainViewModel { get; }

    /// <summary>
    /// Initializes a new instance of the App class.
    /// </summary>
    public App()
    {
        this.InitializeComponent();

        // Initialize services
        NavigationService = new NavigationService();
        AuditService = new AuditService();
        MainViewModel = new MainViewModel(NavigationService, AuditService);
    }

    /// <summary>
    /// Invoked when the application is launched.
    /// </summary>
    /// <param name="args">Details about the launch request and process.</param>
    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _mainWindow = new MainWindow();

        // Set minimum window size
        var windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(_mainWindow);
        var windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(windowHandle);
        var appWindow = Microsoft.UI.Windowing.AppWindow.GetFromWindowId(windowId);

        if (appWindow != null)
        {
            appWindow.Title = "WinSecAudit - Windows Security Auditing Tool";
            appWindow.Resize(new Windows.Graphics.SizeInt32(1400, 900));

            // Center the window
            var displayArea = Microsoft.UI.Windowing.DisplayArea.GetFromWindowId(windowId, Microsoft.UI.Windowing.DisplayAreaFallback.Primary);
            var centerX = (displayArea.WorkArea.Width - 1400) / 2;
            var centerY = (displayArea.WorkArea.Height - 900) / 2;
            appWindow.Move(new Windows.Graphics.PointInt32(centerX, centerY));
        }

        _mainWindow.Activate();
    }
}
