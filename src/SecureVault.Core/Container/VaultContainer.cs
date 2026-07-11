using System.Security.Cryptography;
using System.Text;
using SecureVault.Core.Abstractions;
using SecureVault.Core.Cryptography;
using SecureVault.Core.Vault;

namespace SecureVault.Core.Container;

/// <summary>
/// A single vault file: encrypted index + chaffed data region, per п.5 of
/// the TOR. Holds the derived cascade keys and the decrypted index in
/// memory for as long as it's open; individual entry payloads are only
/// ever decrypted on demand via <see cref="RevealLogin"/>/<see cref="RevealNote"/>/<see cref="RevealFile"/>
/// and must be disposed by the caller promptly after use.
/// </summary>
public sealed class VaultContainer : IDisposable
{
    private readonly string _path;
    private readonly CascadeKeyMaterial _keys;
    private readonly IMemoryGuard? _memoryGuard;
    private readonly byte[] _salt;
    private readonly List<VaultEntryMetadata> _index = [];
    private readonly Dictionary<Guid, byte[]> _sealedContent = [];
    private bool _disposed;

    private VaultContainer(string path, byte[] salt, CascadeKeyMaterial keys, IMemoryGuard? memoryGuard)
    {
        _path = path;
        _salt = salt;
        _keys = keys;
        _memoryGuard = memoryGuard;
    }

    public IReadOnlyList<VaultEntryMetadata> Entries => _index;

    public static VaultContainer Create(string path, ReadOnlySpan<char> password, ReadOnlySpan<byte> keyfileBytes, IMemoryGuard? memoryGuard = null)
    {
        if (File.Exists(path))
        {
            throw new IOException($"A file already exists at '{path}'.");
        }

        var salt = new byte[KeyDerivationParams.SaltSize];
        RandomNumberGenerator.Fill(salt);
        var keys = KeyDerivation.DeriveLayerKeys(password, keyfileBytes, salt, memoryGuard);

        var container = new VaultContainer(path, salt, keys, memoryGuard);
        container.Save();
        return container;
    }

    public static VaultContainer Open(string path, ReadOnlySpan<char> password, ReadOnlySpan<byte> keyfileBytes, IMemoryGuard? memoryGuard = null)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

        var magic = reader.ReadBytes(VaultHeader.MagicBytes.Length);
        if (!magic.AsSpan().SequenceEqual(VaultHeader.MagicBytes))
        {
            throw new InvalidDataException("Not a SecureVault container.");
        }

        var version = reader.ReadByte();
        if (version != VaultHeader.CurrentVersion)
        {
            throw new InvalidDataException($"Unsupported container version {version}.");
        }

        var salt = reader.ReadBytes(KeyDerivationParams.SaltSize);
        _ = reader.ReadInt64(); // Argon2 memory (KiB) — fixed by KeyDerivationParams for now, reserved for future tuning.
        _ = reader.ReadInt64(); // Argon2 passes
        _ = reader.ReadInt32(); // Argon2 parallelism
        var indexCiphertextLength = reader.ReadInt32();
        var indexCiphertext = reader.ReadBytes(indexCiphertextLength);
        var dataRegionStart = stream.Position;

        var keys = KeyDerivation.DeriveLayerKeys(password, keyfileBytes, salt, memoryGuard);

        using var indexPlaintext = CascadeCipher.Open(indexCiphertext, keys, memoryGuard);
        if (indexPlaintext is null)
        {
            keys.Dispose();
            throw new UnauthorizedAccessException("Incorrect password, keyfile, or corrupted container.");
        }

        var index = VaultIndexCodec.Decode(indexPlaintext.Span);
        var container = new VaultContainer(path, salt, keys, memoryGuard);
        container._index.AddRange(index);

        foreach (var entry in index)
        {
            stream.Position = dataRegionStart + entry.ContentOffset;
            container._sealedContent[entry.Id] = reader.ReadBytes(entry.ContentLength);
        }

        return container;
    }

    public Guid AddLogin(string title, IEnumerable<string> tags, string username, ReadOnlySpan<char> password, string url, ReadOnlySpan<char> notes)
    {
        var payload = EntryContentCodec.EncodeLogin(username, password, url, notes);
        return AddEntry(EntryType.Login, title, tags, payload);
    }

    public Guid AddNote(string title, IEnumerable<string> tags, ReadOnlySpan<char> body)
    {
        var payload = EntryContentCodec.EncodeNote(body);
        return AddEntry(EntryType.Note, title, tags, payload);
    }

    public Guid AddFile(string title, IEnumerable<string> tags, string fileName, ReadOnlySpan<byte> fileBytes)
    {
        var payload = EntryContentCodec.EncodeFile(fileName, fileBytes);
        return AddEntry(EntryType.File, title, tags, payload);
    }

    public void DeleteEntry(Guid id)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _index.RemoveAll(e => e.Id == id);
        if (_sealedContent.Remove(id, out var sealedBytes))
        {
            CryptographicOperations.ZeroMemory(sealedBytes);
        }
    }

    public void RenameEntry(Guid id, string newTitle)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var entry = _index.Find(e => e.Id == id) ?? throw new KeyNotFoundException($"No entry with id {id}.");
        entry.Title = newTitle;
        entry.ModifiedAt = DateTimeOffset.UtcNow;
    }

    public DecodedLogin RevealLogin(Guid id)
    {
        using var plaintext = OpenSealedContent(id, EntryType.Login);
        return EntryContentCodec.DecodeLogin(plaintext.Span, _memoryGuard);
    }

    public DecodedNote RevealNote(Guid id)
    {
        using var plaintext = OpenSealedContent(id, EntryType.Note);
        return EntryContentCodec.DecodeNote(plaintext.Span, _memoryGuard);
    }

    public DecodedFile RevealFile(Guid id)
    {
        using var plaintext = OpenSealedContent(id, EntryType.File);
        return EntryContentCodec.DecodeFile(plaintext.Span, _memoryGuard);
    }

    /// <summary>
    /// Re-derives keys, rebuilds the encrypted index, and rewrites the
    /// entire container (fresh nonces, fresh chaff) atomically via a
    /// temp-file-then-replace so a crash mid-write can never corrupt the
    /// existing container.
    /// </summary>
    public void Save()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        using var dataRegion = new MemoryStream();
        foreach (var entry in _index)
        {
            var sealedBytes = _sealedContent[entry.Id];
            entry.ContentOffset = dataRegion.Position;
            entry.ContentLength = sealedBytes.Length;
            dataRegion.Write(sealedBytes);
        }

        var indexPlaintext = VaultIndexCodec.Encode(_index);
        byte[] indexCiphertext;
        try
        {
            indexCiphertext = CascadeCipher.Seal(indexPlaintext, _keys);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(indexPlaintext);
        }

        var headerLength = VaultHeader.MagicBytes.Length + 1 + KeyDerivationParams.SaltSize + 8 + 8 + 4 + 4 + indexCiphertext.Length;
        var usedLength = headerLength + dataRegion.Length;
        var totalLength = PaddingBuckets.NextBucketSize(usedLength);
        var chaffLength = totalLength - usedLength;

        var tempPath = _path + ".tmp";
        using (var stream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(VaultHeader.MagicBytes);
            writer.Write(VaultHeader.CurrentVersion);
            writer.Write(_salt);
            writer.Write(KeyDerivationParams.Argon2MemoryKiB);
            writer.Write(KeyDerivationParams.Argon2Passes);
            writer.Write(KeyDerivationParams.Argon2Parallelism);
            writer.Write(indexCiphertext.Length);
            writer.Write(indexCiphertext);
            dataRegion.Position = 0;
            dataRegion.CopyTo(stream);
            ChaffGenerator.WriteChaff(stream, chaffLength);
        }

        File.Move(tempPath, _path, overwrite: true);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        foreach (var sealedBytes in _sealedContent.Values)
        {
            CryptographicOperations.ZeroMemory(sealedBytes);
        }
        _sealedContent.Clear();
        _keys.Dispose();
    }

    private Guid AddEntry(EntryType type, string title, IEnumerable<string> tags, byte[] payload)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        byte[] sealedBytes;
        try
        {
            sealedBytes = CascadeCipher.Seal(payload, _keys);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }

        var id = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        _index.Add(new VaultEntryMetadata
        {
            Id = id,
            Type = type,
            Title = title,
            Tags = [.. tags],
            CreatedAt = now,
            ModifiedAt = now,
        });
        _sealedContent[id] = sealedBytes;
        return id;
    }

    private SecureBytes OpenSealedContent(Guid id, EntryType expectedType)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var metadata = _index.Find(e => e.Id == id) ?? throw new KeyNotFoundException($"No entry with id {id}.");
        if (metadata.Type != expectedType)
        {
            throw new InvalidOperationException($"Entry {id} is a {metadata.Type}, not a {expectedType}.");
        }

        var sealedBytes = _sealedContent[id];
        var plaintext = CascadeCipher.Open(sealedBytes, _keys, _memoryGuard)
            ?? throw new InvalidDataException("Entry failed authentication — container may be corrupted or tampered with.");
        return plaintext;
    }
}
