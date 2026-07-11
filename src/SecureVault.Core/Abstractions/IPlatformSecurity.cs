namespace SecureVault.Core.Abstractions;

/// <summary>
/// Everything about hardening the OS/UI surface that is inherently
/// platform-specific — memory locking plus anti-capture window protection —
/// grouped behind one interface so Core and the UI layer only ever depend
/// on this abstraction. See п.1 of the architecture addendum: today only a
/// Windows implementation exists (<c>WindowsPlatformSecurity</c> in
/// SecureVault.Windows); a future macOS/mobile client implements the same
/// interface without touching Core.
/// </summary>
public interface IPlatformSecurity : IMemoryGuard
{
    /// <summary>
    /// Whether this platform can technically prevent screen capture of a
    /// window at all (Windows can via WDA_MONITOR; macOS/iOS cannot fully —
    /// see the known limitation noted in the architecture addendum).
    /// </summary>
    bool SupportsCaptureProtection { get; }

    /// <summary>Applies capture protection to the given native window handle. No-op where unsupported.</summary>
    void ProtectWindowFromCapture(nint windowHandle);
}
