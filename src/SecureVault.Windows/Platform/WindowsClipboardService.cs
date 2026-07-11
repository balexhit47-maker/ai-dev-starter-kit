using System.Windows;
using SecureVault.Core.Abstractions;

namespace SecureVault.Windows.Platform;

/// <summary>
/// WPF's <see cref="Clipboard"/> API is string-based; this is the one,
/// documented point where secret text is briefly materialized as a
/// <see cref="string"/> (see <see cref="IClipboardService"/> remarks)
/// immediately before handing off to the OS clipboard. It is unavoidable
/// without replacing WPF's clipboard integration entirely.
/// </summary>
public sealed class WindowsClipboardService : IClipboardService
{
    public void SetText(ReadOnlySpan<char> text)
    {
        var value = new string(text);
        RunOnUiThread(() => Clipboard.SetText(value));
    }

    public void Clear()
    {
        // Clipboard.Clear() can throw if another process is holding the
        // clipboard open (common on Windows); swallow, there is nothing
        // actionable for the user to do about a transient clipboard lock.
        RunOnUiThread(() =>
        {
            try
            {
                Clipboard.Clear();
            }
            catch (System.Runtime.InteropServices.COMException)
            {
            }
        });
    }

    /// <summary>
    /// WPF's Clipboard is an STA/OLE API — it must run on the UI thread.
    /// <see cref="ClipboardAutoClearService"/>'s auto-clear timer fires on a
    /// background threadpool thread, so without this marshal, Clear() throws
    /// a COMException that gets silently swallowed above and the clipboard
    /// never actually clears.
    /// </summary>
    private static void RunOnUiThread(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess())
        {
            action();
        }
        else
        {
            dispatcher.Invoke(action);
        }
    }
}
