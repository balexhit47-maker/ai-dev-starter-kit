using SecureVault.Core.Abstractions;
using SecureVault.Core.Cryptography;

namespace SecureVault.Core.Vault;

public sealed class DecodedNote(SecureBytes body) : IDisposable
{
    internal SecureBytes Body { get; } = body;

    public SecureChars RevealBody(IMemoryGuard? memoryGuard = null) => SecureChars.FromUtf8(Body.Span, memoryGuard);

    public void Dispose() => Body.Dispose();
}
