using System.Text.Json;
using SecureVault.Core.Vault;

namespace SecureVault.Core.Container;

/// <summary>Plaintext (pre-encryption) JSON framing for the entry index.</summary>
internal static class VaultIndexCodec
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };

    public static byte[] Encode(IReadOnlyList<VaultEntryMetadata> entries)
        => JsonSerializer.SerializeToUtf8Bytes(entries, Options);

    public static List<VaultEntryMetadata> Decode(ReadOnlySpan<byte> data)
        => JsonSerializer.Deserialize<List<VaultEntryMetadata>>(data, Options)
           ?? throw new InvalidDataException("Vault index could not be parsed.");
}
