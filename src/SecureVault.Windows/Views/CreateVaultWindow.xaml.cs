using System.IO;
using System.Security.Cryptography;
using System.Windows;
using Microsoft.Win32;
using SecureVault.Core.Container;
using SecureVault.Windows.Platform;

namespace SecureVault.Windows.Views;

public partial class CreateVaultWindow : Window
{
    private byte[]? _keyfileBytes;

    public VaultContainer? CreatedContainer { get; private set; }

    public CreateVaultWindow()
    {
        InitializeComponent();
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
            // Only the file name is shown for this-session confirmation; the
            // path is never written to disk/registry/settings (п.3.2 ТЗ).
            KeyfileNameText.Text = Path.GetFileName(dialog.FileName);
        }
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void OnCreateClick(object sender, RoutedEventArgs e)
    {
        var name = NameTextBox.Text.Trim();
        if (string.IsNullOrEmpty(name))
        {
            MessageBox.Show(this, "Введите имя сейфа.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!Path.HasExtension(name))
        {
            name += ".vault";
        }

        if (_keyfileBytes is null)
        {
            MessageBox.Show(this, "Выберите файл-ключ.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (NoRecoveryCheckBox.IsChecked != true)
        {
            MessageBox.Show(this, "Подтвердите, что вы понимаете отсутствие восстановления доступа.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        using var password = SecureStringInterop.ToSecureChars(PasswordBox.SecurePassword, App.PlatformSecurity);
        using var confirm = SecureStringInterop.ToSecureChars(ConfirmPasswordBox.SecurePassword, App.PlatformSecurity);

        if (password.Length == 0)
        {
            MessageBox.Show(this, "Введите мастер-пароль.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!password.Span.SequenceEqual(confirm.Span))
        {
            MessageBox.Show(this, "Пароли не совпадают.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            CreatedContainer = App.VaultManager.CreateVault(name, password.Span, _keyfileBytes, App.PlatformSecurity);
        }
        catch (IOException ex)
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
