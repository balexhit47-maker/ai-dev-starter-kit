using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using SecureVault.Core.Container;
using SecureVault.Core.Vault;
using SecureVault.Windows.Platform;

namespace SecureVault.Windows.Views;

public partial class MainVaultWindow : Window
{
    private readonly VaultContainer _container;
    private List<VaultEntryMetadata> _allEntries = [];
    private string _sortColumn = "ModifiedAt";
    private bool _sortAscending = false;

    public MainVaultWindow(VaultContainer container)
    {
        InitializeComponent();
        _container = container;
        var vaultName = System.IO.Path.GetFileNameWithoutExtension(_container.Path);
        TitleText.Text = vaultName;
        Title = $"cryptoAll — {vaultName}";
        SourceInitialized += OnSourceInitialized;
        Loaded += (_, _) => RefreshList();
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        var hwnd = new WindowInteropHelper(this).Handle;
        // п.6 ТЗ: block screenshots/screen recording/RDP capture of this window while secrets may be on screen.
        App.PlatformSecurity.ProtectWindowFromCapture(hwnd);
        WindowChromeHelper.UseLightTitleBar(hwnd);
    }

    private void RefreshList()
    {
        _allEntries = [.. _container.Entries];
        ApplyFilterAndSort();
    }

    private void ApplyFilterAndSort()
    {
        IEnumerable<VaultEntryMetadata> view = _allEntries;

        var query = SearchTextBox.Text.Trim();
        if (!string.IsNullOrEmpty(query))
        {
            view = view.Where(entry => MatchesQuery(entry, query));
        }

        view = _sortColumn switch
        {
            "Title" => _sortAscending
                ? view.OrderBy(x => x.Title, StringComparer.CurrentCultureIgnoreCase)
                : view.OrderByDescending(x => x.Title, StringComparer.CurrentCultureIgnoreCase),
            "Type" => _sortAscending ? view.OrderBy(x => x.Type) : view.OrderByDescending(x => x.Type),
            _ => _sortAscending ? view.OrderBy(x => x.ModifiedAt) : view.OrderByDescending(x => x.ModifiedAt),
        };

        EntriesListView.ItemsSource = view.ToList();
        UpdateSortIndicators();
    }

    private void UpdateSortIndicators()
    {
        var arrow = _sortAscending ? " ▲" : " ▼";
        TitleColumn.Header = "Название" + (_sortColumn == "Title" ? arrow : "");
        TypeColumn.Header = "Тип" + (_sortColumn == "Type" ? arrow : "");
        ModifiedColumn.Header = "Изменено" + (_sortColumn == "ModifiedAt" ? arrow : "");
    }

    /// <summary>
    /// Title/tags match instantly from the already-decrypted index; content
    /// match briefly reveals and immediately disposes each entry's payload
    /// (п.4 ТЗ: decrypt on demand, never held longer than needed).
    /// </summary>
    private bool MatchesQuery(VaultEntryMetadata entry, string query)
    {
        if (entry.Title.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
            entry.Tags.Any(tag => tag.Contains(query, StringComparison.CurrentCultureIgnoreCase)))
        {
            return true;
        }

        try
        {
            switch (entry.Type)
            {
                case EntryType.Login:
                    using (var login = _container.RevealLogin(entry.Id))
                    {
                        if (login.Username.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
                            login.Url.Contains(query, StringComparison.CurrentCultureIgnoreCase))
                        {
                            return true;
                        }

                        using var notes = login.RevealNotes();
                        return new string(notes.Span).Contains(query, StringComparison.CurrentCultureIgnoreCase);
                    }

                case EntryType.Note:
                    using (var note = _container.RevealNote(entry.Id))
                    using (var body = note.RevealBody())
                    {
                        return new string(body.Span).Contains(query, StringComparison.CurrentCultureIgnoreCase);
                    }

                case EntryType.File:
                    using (var file = _container.RevealFile(entry.Id))
                    {
                        return file.FileName.Contains(query, StringComparison.CurrentCultureIgnoreCase);
                    }

                default:
                    return false;
            }
        }
        catch
        {
            // Corrupt/undecryptable payload — fall back to the title/tag match already checked above.
            return false;
        }
    }

    private void OnSearchTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        ApplyFilterAndSort();
        ClearSearchButton.Visibility = string.IsNullOrEmpty(SearchTextBox.Text) ? Visibility.Collapsed : Visibility.Visible;
    }

    private void OnClearSearchClick(object sender, RoutedEventArgs e)
    {
        SearchTextBox.Text = string.Empty;
        SearchTextBox.Focus();
    }

    private void OnColumnHeaderClick(object sender, RoutedEventArgs e)
    {
        if (e.OriginalSource is not GridViewColumnHeader { Column: not null } header)
        {
            return;
        }

        string? column = null;
        if (ReferenceEquals(header.Column, TitleColumn))
        {
            column = "Title";
        }
        else if (ReferenceEquals(header.Column, TypeColumn))
        {
            column = "Type";
        }
        else if (ReferenceEquals(header.Column, ModifiedColumn))
        {
            column = "ModifiedAt";
        }

        if (column is null)
        {
            return;
        }

        if (_sortColumn == column)
        {
            _sortAscending = !_sortAscending;
        }
        else
        {
            _sortColumn = column;
            _sortAscending = true;
        }

        ApplyFilterAndSort();
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
        if (detailWindow.ShowDialog() == true)
        {
            RefreshList();
        }
    }

    private void OnDeleteClick(object sender, RoutedEventArgs e)
    {
        if (EntriesListView.SelectedItem is not VaultEntryMetadata metadata)
        {
            return;
        }

        var result = MessageBox.Show(this, $"Удалить «{metadata.Title}»?", "cryptoAll", MessageBoxButton.YesNo, MessageBoxImage.Question);
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
