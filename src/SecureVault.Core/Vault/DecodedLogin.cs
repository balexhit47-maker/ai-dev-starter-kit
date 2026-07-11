using SecureVault.Core.Abstractions;
using SecureVault.Core.Cryptography;

namespace SecureVault.Core.Vault;

/// <summary>
/// Decrypted login entry. <see cref="Password"/> and <see cref="Notes"/> are
/// kept as UTF-8 <see cref="SecureBytes"/> until the caller explicitly asks
/// for characters (<see cref="RevealPassword"/> / <see cref="RevealNotes"/>);
/// dispose promptly once the value has been shown or copied.
/// </summary>
public sealed class DecodedLogin(string username, SecureBytes password, string url, SecureBytes notes) : IDisposable
{
    public string Username { get; } = username;

    public string Url { get; } = url;

    internal SecureBytes Password { get; } = password;

    internal SecureBytes Notes { get; } = notes;

    public SecureChars RevealPassword(IMemoryGuard? memoryGuard = null) => SecureChars.FromUtf8(Password.Span, memoryGuard);

    public SecureChars RevealNotes(IMemoryGuard? memoryGuard = null) => SecureChars.FromUtf8(Notes.Span, memoryGuard);

    public void Dispose()
    {
        Password.Dispose();
        Notes.Dispose();
    }
}
