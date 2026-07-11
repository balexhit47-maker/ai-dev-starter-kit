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
    public void SetText(ReadOnlySpan<char> text) => Clipboard.SetText(new string(text));

    public void Clear()
    {
        // Clipboard.Clear() can throw if another process is holding the
        // clipboard open (common on Windows); swallow, there is nothing
        // actionable for the user to do about a transient clipboard lock.
        try
        {
            Clipboard.Clear();
        }
        catch (System.Runtime.InteropServices.COMException)
        {
        }
    }
}
