using System.Diagnostics;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;
using SecureVault.Core.Vault;
using SecureVault.Windows.Platform;

namespace SecureVault.Windows.Views;

public partial class VaultListWindow : Window
{
    public VaultListWindow()
    {
        InitializeComponent();
        Loaded += (_, _) => RefreshList();
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        WindowChromeHelper.UseLightTitleBar(new WindowInteropHelper(this).Handle);
    }

    private void RefreshList()
    {
        StorageFolderText.Text = App.VaultManager.RootDirectory;
        VaultsListBox.ItemsSource = App.VaultManager.ListVaults(ShowAllFilesCheckBox.IsChecked == true);
    }

    private void OnShowAllFilesChanged(object sender, RoutedEventArgs e) => RefreshList();

    private void OnOpenFolderClick(object sender, RoutedEventArgs e)
    {
        Process.Start(new ProcessStartInfo(App.VaultManager.RootDirectory) { UseShellExecute = true });
    }

    private void OnChangeFolderClick(object sender, RoutedEventArgs e)
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

        App.VaultManager = new SecureVault.Core.Vault.VaultManager(dialog.FolderName);
        StorageSettings.SetVaultsFolder(dialog.FolderName);
        RefreshList();
    }

    private void OnNewVaultClick(object sender, RoutedEventArgs e)
    {
        var createWindow = new CreateVaultWindow { Owner = this };
        if (createWindow.ShowDialog() == true && createWindow.CreatedContainer is not null)
        {
            var vaultWindow = new MainVaultWindow(createWindow.CreatedContainer);
            vaultWindow.Show();
        }

        RefreshList();
    }

    private void OnOpenClick(object sender, RoutedEventArgs e)
    {
        if (VaultsListBox.SelectedItem is VaultDescriptor descriptor)
        {
            OpenVault(descriptor);
        }
        else
        {
            MessageBox.Show(this, "Выберите сейф из списка.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void OnDeleteVaultClick(object sender, RoutedEventArgs e)
    {
        if (VaultsListBox.SelectedItem is not VaultDescriptor descriptor)
        {
            MessageBox.Show(this, "Выберите сейф из списка.", "cryptoAll", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var result = MessageBox.Show(
            this,
            $"Удалить сейф «{descriptor.FileName}» безвозвратно?\n\nВосстановить его будет невозможно — ни мы, ни кто-либо другой.",
            "cryptoAll",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (result != MessageBoxResult.Yes)
        {
            return;
        }

        App.VaultManager.DeleteVault(descriptor.FilePath);
        RefreshList();
    }

    private void OnVaultsListBoxMouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (VaultsListBox.SelectedItem is VaultDescriptor descriptor)
        {
            OpenVault(descriptor);
        }
    }

    private void OpenVault(VaultDescriptor descriptor)
    {
        var unlockWindow = new UnlockVaultWindow(descriptor) { Owner = this };
        if (unlockWindow.ShowDialog() == true && unlockWindow.OpenedContainer is not null)
        {
            var vaultWindow = new MainVaultWindow(unlockWindow.OpenedContainer);
            vaultWindow.Show();
        }
    }

    private void OnSyncClick(object sender, RoutedEventArgs e)
    {
        var syncWindow = new SyncWindow { Owner = this };
        syncWindow.ShowDialog();
        RefreshList();
    }
}
