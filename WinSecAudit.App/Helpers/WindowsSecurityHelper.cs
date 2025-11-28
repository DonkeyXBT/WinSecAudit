using System.Security.Principal;
namespace WinSecAudit.Helpers;
public static class WindowsSecurityHelper
{
    public static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
    public static string GetCurrentUserName() => WindowsIdentity.GetCurrent().Name;
    public static string GetMachineName() => System.Environment.MachineName;
    public static string GetOsVersion() => System.Environment.OSVersion.VersionString;
    public static bool IsDomainJoined()
    {
        try { return !string.IsNullOrEmpty(System.Environment.UserDomainName) && System.Environment.UserDomainName != System.Environment.MachineName; }
        catch { return false; }
    }
    public static string GetWindowsEdition()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return key?.GetValue("ProductName")?.ToString() ?? "Unknown";
        }
        catch { return "Unknown"; }
    }
}
