namespace WinSecAudit.Services;

/// <summary>
/// Service for handling page navigation.
/// </summary>
public interface INavigationService
{
    /// <summary>
    /// Gets whether navigation can go back.
    /// </summary>
    bool CanGoBack { get; }

    /// <summary>
    /// Navigates to the specified page type.
    /// </summary>
    void NavigateTo(Type pageType);

    /// <summary>
    /// Navigates to the specified page type with a parameter.
    /// </summary>
    void NavigateTo(Type pageType, object? parameter);

    /// <summary>
    /// Navigates back to the previous page.
    /// </summary>
    void GoBack();

    /// <summary>
    /// Sets the frame for navigation.
    /// </summary>
    void SetFrame(Microsoft.UI.Xaml.Controls.Frame frame);
}

/// <summary>
/// Implementation of navigation service.
/// </summary>
public class NavigationService : INavigationService
{
    private Microsoft.UI.Xaml.Controls.Frame? _frame;

    public bool CanGoBack => _frame?.CanGoBack ?? false;

    public void SetFrame(Microsoft.UI.Xaml.Controls.Frame frame)
    {
        _frame = frame;
    }

    public void NavigateTo(Type pageType)
    {
        NavigateTo(pageType, null);
    }

    public void NavigateTo(Type pageType, object? parameter)
    {
        _frame?.Navigate(pageType, parameter);
    }

    public void GoBack()
    {
        if (_frame?.CanGoBack == true)
        {
            _frame.GoBack();
        }
    }
}
