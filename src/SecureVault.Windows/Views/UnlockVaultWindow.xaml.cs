using System.IO;
using System.Security.Cryptography;
using System.Windows;
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
            const long maxKeyfileBytes = 10 * 1024 * 1024;
            var info = new FileInfo(dialog.FileName);
            if (info.Length > maxKeyfileBytes)
            {
                MessageBox.Show(this, "Файл-ключ не должен превышать 10 МБ.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            _keyfileBytes = File.ReadAllBytes(dialog.FileName);
            KeyfileNameText.Text = Path.GetFileName(dialog.FileName);
        }
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void OnUnlockClick(object sender, RoutedEventArgs e)
    {
        if (_keyfileBytes is null)
        {
            MessageBox.Show(this, "Выберите файл-ключ.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        using var password = SecureStringInterop.ToSecureChars(PasswordBox.SecurePassword, App.PlatformSecurity);

        try
        {
            OpenedContainer = VaultContainer.Open(_descriptor.FilePath, password.Span, _keyfileBytes, App.PlatformSecurity);
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show(this, "Неверный пароль, файл-ключ или повреждённый контейнер.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        catch (InvalidDataException ex)
        {
            MessageBox.Show(this, ex.Message, "SecureVault", MessageBoxButton.OK, MessageBoxImage.Error);
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
