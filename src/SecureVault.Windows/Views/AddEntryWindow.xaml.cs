using System.IO;
using System.Security.Cryptography;
using System.Windows;
using Microsoft.Win32;
using SecureVault.Core.Container;
using SecureVault.Windows.Platform;

namespace SecureVault.Windows.Views;

public partial class AddEntryWindow : Window
{
    private readonly VaultContainer _container;
    private byte[]? _selectedFileBytes;
    private string? _selectedFileName;

    public AddEntryWindow(VaultContainer container)
    {
        InitializeComponent();
        _container = container;
        Closed += (_, _) =>
        {
            if (_selectedFileBytes is not null)
            {
                CryptographicOperations.ZeroMemory(_selectedFileBytes);
            }
        };
    }

    private void OnBrowseFileClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Выберите файл для вложения", CheckFileExists = true };
        if (dialog.ShowDialog(this) == true)
        {
            _selectedFileBytes = File.ReadAllBytes(dialog.FileName);
            _selectedFileName = Path.GetFileName(dialog.FileName);
            FileNameText.Text = _selectedFileName;
        }
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void OnSaveClick(object sender, RoutedEventArgs e)
    {
        var title = TitleTextBox.Text.Trim();
        if (string.IsNullOrEmpty(title))
        {
            MessageBox.Show(this, "Введите название.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var tags = TagsTextBox.Text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

        switch (TypeTabControl.SelectedIndex)
        {
            case 0:
                using (var password = SecureStringInterop.ToSecureChars(LoginPasswordBox.SecurePassword, App.PlatformSecurity))
                {
                    _container.AddLogin(title, tags, UsernameTextBox.Text, password.Span, UrlTextBox.Text, LoginNotesTextBox.Text);
                }
                break;

            case 1:
                _container.AddNote(title, tags, NoteBodyTextBox.Text);
                break;

            case 2:
                if (_selectedFileBytes is null || _selectedFileName is null)
                {
                    MessageBox.Show(this, "Выберите файл.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                _container.AddFile(title, tags, _selectedFileName, _selectedFileBytes);
                break;
        }

        DialogResult = true;
        Close();
    }
}
