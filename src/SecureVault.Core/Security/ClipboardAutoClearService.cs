using SecureVault.Core.Abstractions;

namespace SecureVault.Core.Security;

/// <summary>
/// Implements п.6 of the TOR: a copied secret is wiped from the clipboard
/// after a fixed delay, or immediately on <see cref="ClearNow"/> (the UI
/// layer should call that on app close/minimize). Platform-agnostic —
/// only <see cref="IClipboardService"/> is platform-specific.
/// </summary>
public sealed class ClipboardAutoClearService(IClipboardService clipboard) : IDisposable
{
    public static readonly TimeSpan DefaultClearDelay = TimeSpan.FromSeconds(15);

    private readonly object _lock = new();
    private Timer? _timer;
    private int _copyGeneration;

    public void CopyWithAutoClear(ReadOnlySpan<char> text, TimeSpan? delay = null)
    {
        lock (_lock)
        {
            _copyGeneration++;
            var thisGeneration = _copyGeneration;
            clipboard.SetText(text);
            _timer?.Dispose();
            _timer = new Timer(_ => ClearIfStillOurs(thisGeneration), null, delay ?? DefaultClearDelay, Timeout.InfiniteTimeSpan);
        }
    }

    /// <summary>Clears the clipboard immediately, e.g. on app close or minimize.</summary>
    public void ClearNow()
    {
        lock (_lock)
        {
            _copyGeneration++;
            _timer?.Dispose();
            _timer = null;
            clipboard.Clear();
        }
    }

    private void ClearIfStillOurs(int generation)
    {
        lock (_lock)
        {
            // Don't clobber a newer copy (or a manual clear) that happened after this timer was scheduled.
            if (generation == _copyGeneration)
            {
                clipboard.Clear();
            }
        }
    }

    public void Dispose() => _timer?.Dispose();
}
