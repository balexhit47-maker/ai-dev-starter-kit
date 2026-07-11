using System.ComponentModel;
using System.Windows;
using System.Windows.Interop;
using SecureVault.Core.Container;
using SecureVault.Core.Vault;

namespace SecureVault.Windows.Views;

public partial class MainVaultWindow : Window
{
    private readonly VaultContainer _container;

    public MainVaultWindow(VaultContainer container)
    {
        InitializeComponent();
        _container = container;
        TitleText.Text = "Сейф";
        SourceInitialized += OnSourceInitialized;
        Loaded += (_, _) => RefreshList();
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        // п.6 ТЗ: block screenshots/screen recording/RDP capture of this window while secrets may be on screen.
        var hwnd = new WindowInteropHelper(this).Handle;
        App.PlatformSecurity.ProtectWindowFromCapture(hwnd);
    }

    private void RefreshList()
    {
        EntriesListView.ItemsSource = null;
        EntriesListView.ItemsSource = _container.Entries;
    }

    private void OnAddClick(object sender, RoutedEventArgs e)
    {
        var addWindow = new AddEntryWindow(_container) { Owner = this };
        if (addWindow.ShowDialog() == true)
        {
            _container.Save();
            RefreshList();
        }
    }

    private void OnOpenClick(object sender, RoutedEventArgs e)
    {
        OpenSelected();
    }

    private void OnEntriesListViewMouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        OpenSelected();
    }

    private void OpenSelected()
    {
        if (EntriesListView.SelectedItem is not VaultEntryMetadata metadata)
        {
            return;
        }

        var detailWindow = new EntryDetailWindow(_container, metadata) { Owner = this };
        detailWindow.ShowDialog();
    }

    private void OnDeleteClick(object sender, RoutedEventArgs e)
    {
        if (EntriesListView.SelectedItem is not VaultEntryMetadata metadata)
        {
            return;
        }

        var result = MessageBox.Show(this, $"Удалить «{metadata.Title}»?", "SecureVault", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (result != MessageBoxResult.Yes)
        {
            return;
        }

        _container.DeleteEntry(metadata.Id);
        _container.Save();
        RefreshList();
    }

    private void OnStateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized)
        {
            // п.6 ТЗ: clear the clipboard on minimize, not just after the 15s timer.
            App.Clipboard.ClearNow();
        }
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        App.Clipboard.ClearNow();
        _container.Dispose();
    }
}
