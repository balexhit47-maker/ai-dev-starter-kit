namespace SecureVault.Core.Vault;

/// <summary>
/// Metadata for one entry, held in the encrypted index (see
/// <see cref="Container.VaultIndexCodec"/>). This is the one thing that is
/// decrypted for the whole vault as soon as it's unlocked — the actual
/// secret payload (password, note body, file bytes) referenced by
/// <see cref="ContentOffset"/>/<see cref="ContentLength"/> is only ever
/// decrypted on demand, per п.4 of the TOR.
/// </summary>
public sealed class VaultEntryMetadata
{
    public required Guid Id { get; init; }

    public required EntryType Type { get; init; }

    public required string Title { get; set; }

    public List<string> Tags { get; set; } = [];

    public required DateTimeOffset CreatedAt { get; init; }

    public required DateTimeOffset ModifiedAt { get; set; }

    /// <summary>Byte offset of this entry's sealed content blob within the data region.</summary>
    public long ContentOffset { get; set; }

    /// <summary>Length in bytes of this entry's sealed content blob.</summary>
    public int ContentLength { get; set; }
}
