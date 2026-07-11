using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using SecureVault.Core.Container;
using SecureVault.Core.Vault;
using SecureVault.Windows.Platform;

namespace SecureVault.Windows.Views;

public partial class UnlockVaultWindow : Window
{
    private readonly VaultDescriptor _descriptor;
    private byte[]? _keyfileBytes;

    public VaultContainer? OpenedContainer { get; private set; }

    public UnlockVaultWindow(VaultDescriptor descriptor)
    {
        InitializeComponent();
        _descriptor = descriptor;
        VaultNameText.Text = descriptor.FileName;
        SourceInitialized += (_, _) => WindowChromeHelper.UseLightTitleBar(new WindowInteropHelper(this).Handle);
        Closed += (_, _) =>
        {
            if (_keyfileBytes is not null)
            {
                CryptographicOperations.ZeroMemory(_keyfileBytes);
            }
        };
    }

    private void OnBrowseKeyfileClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Выберите файл-ключ", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true)
        {
            try
            {
                _keyfileBytes = KeyfileReader.ReadBounded(dialog.FileName);
            }
            catch (InvalidOperationException ex)
            {
                MessageBox.Show(this, ex.Message, "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            KeyfileNameText.Text = Path.GetFileName(dialog.FileName);
            ClearKeyfileButton.IsEnabled = true;
        }
    }

    private void OnClearKeyfileClick(object sender, RoutedEventArgs e)
    {
        if (_keyfileBytes is not null)
        {
            CryptographicOperations.ZeroMemory(_keyfileBytes);
            _keyfileBytes = null;
        }

        KeyfileNameText.Text = "файл не выбран";
        ClearKeyfileButton.IsEnabled = false;
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void OnUnlockClick(object sender, RoutedEventArgs e)
    {
        using var password = SecureStringInterop.ToSecureChars(PasswordBox.SecurePassword, App.PlatformSecurity);

        try
        {
            OpenedContainer = VaultContainer.Open(_descriptor.FilePath, password.Span, _keyfileBytes ?? Array.Empty<byte>(), App.PlatformSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show(this, "Неверный пароль, файл-ключ или повреждённый контейнер.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        catch (InvalidDataException ex)
        {
            MessageBox.Show(this, ex.Message, "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(_keyfileBytes);
        }

        DialogResult = true;
        Close();
    }
}
