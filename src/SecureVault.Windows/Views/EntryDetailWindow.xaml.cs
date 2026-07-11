using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using SecureVault.Core.Container;
using SecureVault.Core.Vault;
using SecureVault.Windows.Platform;

namespace SecureVault.Windows.Views;

public partial class EntryDetailWindow : Window
{
    private readonly VaultContainer _container;
    private readonly VaultEntryMetadata _metadata;

    private DecodedLogin? _login;
    private DecodedNote? _note;
    private DecodedFile? _file;
    private string? _originalPassword;
    private bool _passwordVisible;
    private byte[]? _replacementFileBytes;
    private string? _replacementFileName;

    public EntryDetailWindow(VaultContainer container, VaultEntryMetadata metadata)
    {
        InitializeComponent();
        _container = container;
        _metadata = metadata;
        TitleTextBox.Text = metadata.Title;
        TagsTextBox.Text = string.Join(", ", metadata.Tags);
        Closed += (_, _) =>
        {
            if (_replacementFileBytes is not null)
            {
                CryptographicOperations.ZeroMemory(_replacementFileBytes);
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
                    _file = _container.RevealFile(_metadata.Id);
                    FilePanel.Visibility = Visibility.Visible;
                    FileNameText.Text = $"{_file.FileName} ({_file.Bytes.Length:N0} байт)";
                    if (FilePreview.IsImage(_file.FileName))
                    {
                        var thumbnail = FilePreview.TryDecode(_file.Bytes.Span, 320);
                        if (thumbnail is not null)
                        {
                            FilePreviewImage.Source = thumbnail;
                            FilePreviewImage.Visibility = Visibility.Visible;
                        }
                    }
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

    private void OnReplaceFileClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Выберите новый файл", CheckFileExists = true };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        _replacementFileName = Path.GetFileName(dialog.FileName);
        _replacementFileBytes = File.ReadAllBytes(dialog.FileName);
        FileNameText.Text = $"{_replacementFileName} ({_replacementFileBytes.Length:N0} байт) — заменится при сохранении";

        FilePreviewImage.Visibility = Visibility.Collapsed;
        if (FilePreview.IsImage(_replacementFileName))
        {
            var thumbnail = FilePreview.TryDecode(_replacementFileBytes, 320);
            if (thumbnail is not null)
            {
                FilePreviewImage.Source = thumbnail;
                FilePreviewImage.Visibility = Visibility.Visible;
            }
        }
    }

    private void OnSaveFileClick(object sender, RoutedEventArgs e)
    {
        if (_replacementFileBytes is not null && _replacementFileName is not null)
        {
            var dialog = new SaveFileDialog { FileName = _replacementFileName };
            if (dialog.ShowDialog(this) == true)
            {
                File.WriteAllBytes(dialog.FileName, _replacementFileBytes);
            }
            return;
        }

        if (_file is null)
        {
            return;
        }

        var saveDialog = new SaveFileDialog { FileName = _file.FileName };
        if (saveDialog.ShowDialog(this) == true)
        {
            using var stream = File.Create(saveDialog.FileName);
            stream.Write(_file.Bytes.Span);
        }
    }

    private void OnSaveEntryClick(object sender, RoutedEventArgs e)
    {
        var title = TitleTextBox.Text.Trim();
        if (string.IsNullOrEmpty(title))
        {
            MessageBox.Show(this, "Введите название.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Warning);
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
                    if (_replacementFileBytes is not null && _replacementFileName is not null)
                    {
                        _container.UpdateFile(_metadata.Id, title, tags, _replacementFileName, _replacementFileBytes);
                    }
                    else if (_file is not null)
                    {
                        _container.UpdateFile(_metadata.Id, title, tags, _file.FileName, _file.Bytes.Span);
                    }
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
        _file?.Dispose();
    }
}
