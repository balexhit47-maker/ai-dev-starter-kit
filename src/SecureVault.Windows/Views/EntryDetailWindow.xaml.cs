using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using SecureVault.Core.Container;
using SecureVault.Core.Vault;

namespace SecureVault.Windows.Views;

public partial class EntryDetailWindow : Window
{
    private readonly VaultContainer _container;
    private readonly VaultEntryMetadata _metadata;

    private DecodedLogin? _login;
    private DecodedNote? _note;
    private DecodedFile? _file;
    private bool _passwordVisible;

    public EntryDetailWindow(VaultContainer container, VaultEntryMetadata metadata)
    {
        InitializeComponent();
        _container = container;
        _metadata = metadata;
        TitleText.Text = metadata.Title;
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        App.PlatformSecurity.ProtectWindowFromCapture(hwnd);

        try
        {
            switch (_metadata.Type)
            {
                case EntryType.Login:
                    _login = _container.RevealLogin(_metadata.Id);
                    LoginPanel.Visibility = Visibility.Visible;
                    UsernameText.Text = _login.Username;
                    UrlText.Text = _login.Url;
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
            MessageBox.Show(this, ex.Message, "SecureVault", MessageBoxButton.OK, MessageBoxImage.Error);
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
            using var password = _login.RevealPassword();
            PasswordText.Text = new string(password.Span);
        }
        else
        {
            PasswordText.Text = "••••••••";
        }
    }

    private void OnCopyPasswordClick(object sender, RoutedEventArgs e)
    {
        if (_login is null)
        {
            return;
        }

        using var password = _login.RevealPassword();
        App.Clipboard.CopyWithAutoClear(password.Span);
    }

    private void OnCopyNoteClick(object sender, RoutedEventArgs e)
    {
        if (_note is null)
        {
            return;
        }

        using var body = _note.RevealBody();
        App.Clipboard.CopyWithAutoClear(body.Span);
    }

    private void OnSaveFileClick(object sender, RoutedEventArgs e)
    {
        if (_file is null)
        {
            return;
        }

        var dialog = new SaveFileDialog { FileName = _file.FileName };
        if (dialog.ShowDialog(this) == true)
        {
            using var stream = System.IO.File.Create(dialog.FileName);
            stream.Write(_file.Bytes.Span);
        }
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    private void OnClosed(object? sender, EventArgs e)
    {
        _login?.Dispose();
        _note?.Dispose();
        _file?.Dispose();
    }
}
