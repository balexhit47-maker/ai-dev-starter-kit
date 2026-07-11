using System.Windows;
using SecureVault.Core.Abstractions;
using SecureVault.Core.Security;
using SecureVault.Core.Vault;
using SecureVault.Windows.Platform;
using SecureVault.Windows.Views;

namespace SecureVault.Windows;

public partial class App : Application
{
    public static IPlatformSecurity PlatformSecurity { get; private set; } = null!;

    public static ClipboardAutoClearService Clipboard { get; private set; } = null!;

    /// <summary>Swappable (not just settable-once) so changing the vaults folder can rebind it live.</summary>
    public static VaultManager VaultManager { get; set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        PlatformSecurity = new WindowsPlatformSecurity();
        Clipboard = new ClipboardAutoClearService(new WindowsClipboardService());
        VaultManager = new VaultManager(StorageSettings.TryGetCustomVaultsFolder());

        MainWindow = new VaultListWindow();
        MainWindow.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // п.6 of the TOR: clear the clipboard on application close, not just after the 15s timer.
        Clipboard.ClearNow();
        Clipboard.Dispose();
        base.OnExit(e);
    }
}
