using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using SecureVault.Core.Container;
using SecureVault.Core.Vault;
using SecureVault.Windows.Platform;

namespace SecureVault.Windows.Views;

public partial class EntryDetailWindow : Window
{
    private readonly VaultContainer _container;
    private readonly VaultEntryMetadata _metadata;
    private readonly List<FileItem> _files = [];

    private DecodedLogin? _login;
    private DecodedNote? _note;
    private string? _originalPassword;
    private bool _passwordVisible;

    public EntryDetailWindow(VaultContainer container, VaultEntryMetadata metadata)
    {
        InitializeComponent();
        _container = container;
        _metadata = metadata;
        TitleTextBox.Text = metadata.Title;
        TagsTextBox.Text = string.Join(", ", metadata.Tags);
        Closed += (_, _) =>
        {
            foreach (var file in _files)
            {
                CryptographicOperations.ZeroMemory(file.Bytes);
            }
        };
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        App.PlatformSecurity.ProtectWindowFromCapture(hwnd);
        WindowChromeHelper.UseLightTitleBar(hwnd);

        try
        {
            switch (_metadata.Type)
            {
                case EntryType.Login:
                    _login = _container.RevealLogin(_metadata.Id);
                    LoginPanel.Visibility = Visibility.Visible;
                    UsernameText.Text = _login.Username;
                    UrlText.Text = _login.Url;
                    using (var password = _login.RevealPassword())
                    {
                        _originalPassword = new string(password.Span);
                    }
                    using (var notes = _login.RevealNotes())
                    {
                        LoginNotesText.Text = new string(notes.Span);
                    }
                    break;

                case EntryType.Note:
                    _note = _container.RevealNote(_metadata.Id);
                    NotePanel.Visibility = Visibility.Visible;
                    using (var body = _note.RevealBody())
                    {
                        NoteBodyText.Text = new string(body.Span);
                    }
                    break;

                case EntryType.File:
                    FilePanel.Visibility = Visibility.Visible;
                    using (var revealed = _container.RevealFiles(_metadata.Id))
                    {
                        foreach (var item in revealed.Items)
                        {
                            var bytes = item.Bytes.Span.ToArray();
                            var thumbnail = FilePreview.IsImage(item.FileName) ? FilePreview.TryDecode(bytes, 64) : null;
                            _files.Add(new FileItem(item.FileName, bytes, thumbnail));
                        }
                    }
                    RefreshFilesList();
                    break;
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Error);
            Close();
        }
    }

    private void OnTogglePasswordClick(object sender, RoutedEventArgs e)
    {
        if (_login is null)
        {
            return;
        }

        _passwordVisible = !_passwordVisible;
        if (_passwordVisible)
        {
            PasswordText.Text = _originalPassword ?? string.Empty;
            PasswordText.IsReadOnly = false;
            TogglePasswordButton.Content = "Скрыть";
        }
        else
        {
            // Keep whatever was typed while visible so a later Save (without
            // toggling back) still picks up the edit.
            _originalPassword = PasswordText.Text;
            PasswordText.Text = "••••••••";
            PasswordText.IsReadOnly = true;
            TogglePasswordButton.Content = "Показать";
        }
    }

    private void OnCopyPasswordClick(object sender, RoutedEventArgs e)
    {
        if (_originalPassword is null)
        {
            return;
        }

        App.Clipboard.CopyWithAutoClear(_passwordVisible ? PasswordText.Text : _originalPassword);
    }

    private void OnCopyNoteClick(object sender, RoutedEventArgs e)
    {
        App.Clipboard.CopyWithAutoClear(NoteBodyText.Text);
    }

    private void OnAddFileClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Выберите файл(ы)", CheckFileExists = true, Multiselect = true };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        foreach (var path in dialog.FileNames)
        {
            var fileName = Path.GetFileName(path);
            var bytes = File.ReadAllBytes(path);
            var thumbnail = FilePreview.IsImage(fileName) ? FilePreview.TryDecode(bytes, 64) : null;
            _files.Add(new FileItem(fileName, bytes, thumbnail));
        }

        RefreshFilesList();
    }

    private void OnRemoveFileClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: FileItem item })
        {
            return;
        }

        _files.Remove(item);
        CryptographicOperations.ZeroMemory(item.Bytes);
        RefreshFilesList();
    }

    private void OnSaveOneFileClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: FileItem item })
        {
            return;
        }

        var dialog = new SaveFileDialog { FileName = item.FileName };
        if (dialog.ShowDialog(this) == true)
        {
            File.WriteAllBytes(dialog.FileName, item.Bytes);
        }
    }

    private void RefreshFilesList()
    {
        FilesListBox.ItemsSource = null;
        FilesListBox.ItemsSource = _files;
    }

    private void OnSaveEntryClick(object sender, RoutedEventArgs e)
    {
        var title = TitleTextBox.Text.Trim();
        if (string.IsNullOrEmpty(title))
        {
            MessageBox.Show(this, "Введите название.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (_metadata.Type == EntryType.File && _files.Count == 0)
        {
            MessageBox.Show(this, "У записи должен остаться хотя бы один файл — иначе удалите всю запись целиком.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var tags = TagsTextBox.Text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

        try
        {
            switch (_metadata.Type)
            {
                case EntryType.Login:
                    if (_passwordVisible)
                    {
                        _originalPassword = PasswordText.Text;
                    }
                    _container.UpdateLogin(_metadata.Id, title, tags, UsernameText.Text, (_originalPassword ?? string.Empty).AsSpan(), UrlText.Text, LoginNotesText.Text.AsSpan());
                    break;

                case EntryType.Note:
                    _container.UpdateNote(_metadata.Id, title, tags, NoteBodyText.Text.AsSpan());
                    break;

                case EntryType.File:
                    _container.UpdateFiles(_metadata.Id, title, tags, [.. _files.Select(f => (f.FileName, f.Bytes))]);
                    break;
            }

            _container.Save();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        DialogResult = true;
        Close();
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    private void OnClosed(object? sender, EventArgs e)
    {
        _login?.Dispose();
        _note?.Dispose();
    }

    private sealed class FileItem(string fileName, byte[] bytes, BitmapImage? thumbnail)
    {
        public string FileName { get; } = fileName;

        public byte[] Bytes { get; } = bytes;

        public BitmapImage? Thumbnail { get; } = thumbnail;

        public string DisplayText => $"{FileName} ({Bytes.Length:N0} байт)";

        public Visibility ThumbnailVisibility => Thumbnail is not null ? Visibility.Visible : Visibility.Collapsed;
    }
}
