using System.Windows;
using SecureVault.Core.Vault;

namespace SecureVault.Windows.Views;

public partial class VaultListWindow : Window
{
    public VaultListWindow()
    {
        InitializeComponent();
        Loaded += (_, _) => RefreshList();
    }

    private void RefreshList()
    {
        VaultsListBox.ItemsSource = App.VaultManager.ListVaults();
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
            MessageBox.Show(this, "Выберите сейф из списка.", "SecureVault", MessageBoxButton.OK, MessageBoxImage.Information);
        }
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
