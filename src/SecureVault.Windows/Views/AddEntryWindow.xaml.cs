using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using SecureVault.Core.Container;
using SecureVault.Windows.Platform;

namespace SecureVault.Windows.Views;

public partial class AddEntryWindow : Window
{
    private readonly VaultContainer _container;
    private readonly List<SelectedFileItem> _selectedFiles = [];

    public AddEntryWindow(VaultContainer container)
    {
        InitializeComponent();
        _container = container;
        Closed += (_, _) =>
        {
            foreach (var file in _selectedFiles)
            {
                CryptographicOperations.ZeroMemory(file.Bytes);
            }
        };
    }

    private void OnBrowseFileClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Выберите файл(ы) для вложения", CheckFileExists = true, Multiselect = true };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        foreach (var path in dialog.FileNames)
        {
            var fileName = Path.GetFileName(path);
            var bytes = File.ReadAllBytes(path);
            var thumbnail = FilePreview.IsImage(fileName) ? FilePreview.TryDecode(bytes, 64) : null;
            _selectedFiles.Add(new SelectedFileItem(fileName, bytes, thumbnail));
        }

        SelectedFilesListBox.ItemsSource = null;
        SelectedFilesListBox.ItemsSource = _selectedFiles;
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void OnSaveClick(object sender, RoutedEventArgs e)
    {
        var title = TitleTextBox.Text.Trim();
        var tags = TagsTextBox.Text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

        switch (TypeTabControl.SelectedIndex)
        {
            case 0:
                if (string.IsNullOrEmpty(title))
                {
                    MessageBox.Show(this, "Введите название.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                using (var password = SecureStringInterop.ToSecureChars(LoginPasswordBox.SecurePassword, App.PlatformSecurity))
                {
                    _container.AddLogin(title, tags, UsernameTextBox.Text, password.Span, UrlTextBox.Text, LoginNotesTextBox.Text);
                }
                break;

            case 1:
                if (string.IsNullOrEmpty(title))
                {
                    MessageBox.Show(this, "Введите название.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _container.AddNote(title, tags, NoteBodyTextBox.Text);
                break;

            case 2:
                if (_selectedFiles.Count == 0)
                {
                    MessageBox.Show(this, "Выберите хотя бы один файл.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                foreach (var file in _selectedFiles)
                {
                    var entryTitle = string.IsNullOrEmpty(title)
                        ? file.FileName
                        : _selectedFiles.Count == 1 ? title : $"{title} — {file.FileName}";
                    _container.AddFile(entryTitle, tags, file.FileName, file.Bytes);
                }
                break;
        }

        DialogResult = true;
        Close();
    }

    private sealed class SelectedFileItem(string fileName, byte[] bytes, BitmapImage? thumbnail)
    {
        public string FileName { get; } = fileName;

        public byte[] Bytes { get; } = bytes;

        public BitmapImage? Thumbnail { get; } = thumbnail;

        public string DisplayText => $"{FileName} ({Bytes.Length:N0} байт)";

        public Visibility ThumbnailVisibility => Thumbnail is not null ? Visibility.Visible : Visibility.Collapsed;
    }
}
