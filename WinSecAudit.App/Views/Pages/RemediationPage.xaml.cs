using Microsoft.UI.Xaml; using Microsoft.UI.Xaml.Controls;
namespace WinSecAudit.Views.Pages;
public sealed partial class RemediationPage : Page
{
    public RemediationPage() => InitializeComponent();
    private void Smb_Click(object sender, RoutedEventArgs e) => OutputText.Text = "SMB hardening would enable SMB signing, disable SMBv1, and require encryption.\nRun as Administrator to apply.";
    private void Legacy_Click(object sender, RoutedEventArgs e) => OutputText.Text = "Legacy protocol remediation would disable LLMNR, NetBIOS, and WPAD.\nRun as Administrator to apply.";
    private void Uac_Click(object sender, RoutedEventArgs e) => OutputText.Text = "UAC strengthening would set ConsentPromptBehaviorAdmin=2 and EnableLUA=1.\nRun as Administrator to apply.";
}
