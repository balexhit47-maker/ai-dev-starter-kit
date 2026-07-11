using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using SecureVault.Core.Container;
using SecureVault.Core.Vault;
using SecureVault.Windows.Platform;

namespace SecureVault.Windows.Views;

public partial class CreateVaultWindow : Window
{
    private static readonly string[] CoverImageExtensions = [".jpg", ".jpeg", ".png"];

    private byte[]? _keyfileBytes;
    private byte[]? _coverImageBytes;
    private string? _coverImageExtension;

    public VaultContainer? CreatedContainer { get; private set; }

    public CreateVaultWindow()
    {
        InitializeComponent();
        FolderText.Text = App.VaultManager.RootDirectory;
        SourceInitialized += (_, _) => WindowChromeHelper.UseLightTitleBar(new WindowInteropHelper(this).Handle);
        Closed += (_, _) =>
        {
            if (_keyfileBytes is not null)
            {
                CryptographicOperations.ZeroMemory(_keyfileBytes);
            }
        };
    }

    private void OnBrowseFolderClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Выберите папку для хранения сейфов",
            InitialDirectory = App.VaultManager.RootDirectory,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        App.VaultManager = new VaultManager(dialog.FolderName);
        StorageSettings.SetVaultsFolder(dialog.FolderName);
        FolderText.Text = App.VaultManager.RootDirectory;
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

            // Only the file name is shown for this-session confirmation; the
            // path is never written to disk/registry/settings (п.3.2 ТЗ).
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

    private void OnCloakAsImageChanged(object sender, RoutedEventArgs e)
    {
        CloakPanel.Visibility = CloakAsImageCheckBox.IsChecked == true ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnBrowseCoverImageClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Выберите фото-обложку",
            Filter = "Изображения (*.jpg;*.jpeg;*.png)|*.jpg;*.jpeg;*.png",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        var extension = Path.GetExtension(dialog.FileName);
        if (!CoverImageExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
        {
            MessageBox.Show(this, "Выберите файл .jpg или .png.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _coverImageBytes = File.ReadAllBytes(dialog.FileName);
        _coverImageExtension = extension;
        CoverImageNameText.Text = Path.GetFileName(dialog.FileName);
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
            MessageBox.Show(this, "Введите имя сейфа.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (CloakAsImageCheckBox.IsChecked == true && _coverImageBytes is null)
        {
            MessageBox.Show(this, "Выберите фото для маскировки.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (NoRecoveryCheckBox.IsChecked != true)
        {
            MessageBox.Show(this, "Подтвердите, что вы понимаете отсутствие восстановления доступа.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        using var password = SecureStringInterop.ToSecureChars(PasswordBox.SecurePassword, App.PlatformSecurity);
        using var confirm = SecureStringInterop.ToSecureChars(ConfirmPasswordBox.SecurePassword, App.PlatformSecurity);

        if (password.Length == 0)
        {
            MessageBox.Show(this, "Введите мастер-пароль.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!password.Span.SequenceEqual(confirm.Span))
        {
            MessageBox.Show(this, "Пароли не совпадают.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            CreatedContainer = App.VaultManager.CreateVault(
                name,
                password.Span,
                _keyfileBytes ?? Array.Empty<byte>(),
                coverImageBytes: _coverImageBytes,
                coverImageExtension: _coverImageExtension,
                memoryGuard: App.PlatformSecurity);
        }
        catch (IOException ex)
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
