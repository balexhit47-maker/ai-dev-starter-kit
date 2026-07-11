using SecureVault.Core.Cryptography;

namespace SecureVault.Core.Vault;

public sealed class DecodedFile(string fileName, SecureBytes bytes) : IDisposable
{
    public string FileName { get; } = fileName;

    public SecureBytes Bytes { get; } = bytes;

    public void Dispose() => Bytes.Dispose();
}
