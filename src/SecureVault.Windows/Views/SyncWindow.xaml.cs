using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using SecureVault.Core.Sync;
using SecureVault.Windows.Platform;

namespace SecureVault.Windows.Views;

public partial class SyncWindow : Window
{
    private static readonly HttpClient HttpClient = new();

    public SyncWindow()
    {
        InitializeComponent();
        SourceInitialized += (_, _) => WindowChromeHelper.UseLightTitleBar(new WindowInteropHelper(this).Handle);
    }

    private async void OnWebDavUploadClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Выберите сейф для загрузки на Яндекс.Диск",
            InitialDirectory = App.VaultManager.RootDirectory,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        if (!TryGetRemotePath(out var remotePath) || !TryGetLogin(out var login))
        {
            return;
        }

        using var password = SecureStringInterop.ToSecureChars(WebDavPasswordBox.SecurePassword, App.PlatformSecurity);
        try
        {
            StatusText.Text = "Загрузка...";
            var client = new WebDavSyncClient(HttpClient);
            await using var stream = File.OpenRead(dialog.FileName);
            await client.UploadAsync(login, password, remotePath, stream);
            StatusText.Text = "Загружено на Яндекс.Диск.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Ошибка загрузки: {ex.Message}";
        }
    }

    private async void OnWebDavDownloadClick(object sender, RoutedEventArgs e)
    {
        if (!TryGetRemotePath(out var remotePath) || !TryGetLogin(out var login))
        {
            return;
        }

        using var password = SecureStringInterop.ToSecureChars(WebDavPasswordBox.SecurePassword, App.PlatformSecurity);
        try
        {
            StatusText.Text = "Скачивание...";
            var client = new WebDavSyncClient(HttpClient);
            var bytes = await client.DownloadAsync(login, password, remotePath);
            var fileName = Path.GetFileName(remotePath);
            var savedPath = App.VaultManager.ImportVaultBytes(bytes, fileName);
            StatusText.Text = $"Сохранено как {Path.GetFileName(savedPath)}.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Ошибка скачивания: {ex.Message}";
        }
    }

    private async void OnImportLinkClick(object sender, RoutedEventArgs e)
    {
        if (!Uri.TryCreate(LinkUrlTextBox.Text.Trim(), UriKind.Absolute, out var url))
        {
            StatusText.Text = "Введите корректную ссылку.";
            return;
        }

        try
        {
            StatusText.Text = "Импорт...";
            var importer = new YandexDiskLinkImporter(HttpClient);
            var bytes = await importer.DownloadFromPublicLinkAsync(url);
            var suggestedName = Path.GetFileName(url.LocalPath) is { Length: > 0 } name ? name : "imported.vault";
            var savedPath = App.VaultManager.ImportVaultBytes(bytes, suggestedName);
            StatusText.Text = $"Импортировано как {Path.GetFileName(savedPath)}.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Ошибка импорта: {ex.Message}";
        }
    }

    private bool TryGetRemotePath(out string remotePath)
    {
        remotePath = WebDavPathTextBox.Text.Trim();
        if (remotePath.Length == 0)
        {
            StatusText.Text = "Укажите путь на Яндекс.Диске.";
            return false;
        }
        return true;
    }

    private bool TryGetLogin(out string login)
    {
        login = WebDavLoginTextBox.Text.Trim();
        if (login.Length == 0)
        {
            StatusText.Text = "Укажите логин Яндекс ID.";
            return false;
        }
        return true;
    }
}
