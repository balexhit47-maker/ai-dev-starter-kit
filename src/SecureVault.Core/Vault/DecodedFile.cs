using SecureVault.Core.Cryptography;

namespace SecureVault.Core.Vault;

/// <summary>One file within a File-type entry's decrypted payload.</summary>
public sealed class DecodedFileItem(string fileName, SecureBytes bytes) : IDisposable
{
    public string FileName { get; } = fileName;

    public SecureBytes Bytes { get; } = bytes;

    public void Dispose() => Bytes.Dispose();
}

/// <summary>
/// The decrypted payload of a File-type entry — one or more files sharing a
/// single entry (title/tags). Disposing this disposes every item's
/// <see cref="SecureBytes"/>.
/// </summary>
public sealed class DecodedFiles(IReadOnlyList<DecodedFileItem> items) : IDisposable
{
    public IReadOnlyList<DecodedFileItem> Items { get; } = items;

    public void Dispose()
    {
        foreach (var item in Items)
        {
            item.Dispose();
        }
    }
}
