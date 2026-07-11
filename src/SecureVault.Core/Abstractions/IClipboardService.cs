namespace SecureVault.Core.Abstractions;

/// <summary>
/// Minimal platform clipboard access. Implementations should push the
/// unavoidable materialization of a <see cref="string"/> as late as
/// possible — the underlying OS clipboard APIs are string-based, so a
/// short-lived string copy at this boundary is an accepted, documented
/// limitation rather than something Core tries to paper over.
/// </summary>
public interface IClipboardService
{
    void SetText(ReadOnlySpan<char> text);

    void Clear();
}
