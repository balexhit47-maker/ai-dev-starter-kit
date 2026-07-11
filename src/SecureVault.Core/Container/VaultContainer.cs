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
    private readonly KdfParameters _kdfParameters;
    private readonly byte[]? _coverImageBytes;
    private readonly List<VaultEntryMetadata> _index = [];
    private readonly Dictionary<Guid, byte[]> _sealedContent = [];
    private bool _disposed;

    private VaultContainer(string path, byte[] salt, KdfParameters kdfParameters, CascadeKeyMaterial keys, byte[]? coverImageBytes, IMemoryGuard? memoryGuard)
    {
        _path = path;
        _salt = salt;
        _kdfParameters = kdfParameters;
        _keys = keys;
        _coverImageBytes = coverImageBytes;
        _memoryGuard = memoryGuard;
    }

    public IReadOnlyList<VaultEntryMetadata> Entries => _index;

    public string Path => _path;

    /// <summary>True if this vault is steganographically hidden inside a cover image (see <see cref="ImageCloak"/>).</summary>
    public bool IsImageCloaked => _coverImageBytes is not null;

    /// <param name="coverImageBytes">
    /// When non-null, the vault is hidden inside this cover image (see
    /// <see cref="ImageCloak"/>) instead of being written as a standalone
    /// container file.
    /// </param>
    public static VaultContainer Create(string path, ReadOnlySpan<char> password, ReadOnlySpan<byte> keyfileBytes, byte[]? coverImageBytes = null, IMemoryGuard? memoryGuard = null)
    {
        if (File.Exists(path))
        {
            throw new IOException($"Файл «{path}» уже существует.");
        }

        var salt = new byte[KeyDerivationParams.SaltSize];
        RandomNumberGenerator.Fill(salt);
        var kdfParameters = KdfParameters.Default;
        var keys = KeyDerivation.DeriveLayerKeys(password, keyfileBytes, salt, kdfParameters, memoryGuard);

        var container = new VaultContainer(path, salt, kdfParameters, keys, coverImageBytes, memoryGuard);
        container.Save();
        return container;
    }

    public static VaultContainer Open(string path, ReadOnlySpan<char> password, ReadOnlySpan<byte> keyfileBytes, IMemoryGuard? memoryGuard = null)
    {
        var fileBytes = File.ReadAllBytes(path);
        var (containerBytes, coverImageBytes) = ImageCloak.Uncloak(fileBytes);

        using var stream = new MemoryStream(containerBytes.ToArray());
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

        var magic = reader.ReadBytes(VaultHeader.MagicBytes.Length);
        if (!magic.AsSpan().SequenceEqual(VaultHeader.MagicBytes))
        {
            throw new InvalidDataException("Это не сейф cryptoAll.");
        }

        var version = reader.ReadByte();
        if (version != VaultHeader.CurrentVersion)
        {
            throw new InvalidDataException($"Неподдерживаемая версия контейнера: {version}.");
        }

        var salt = reader.ReadBytes(KeyDerivationParams.SaltSize);
        // Always re-derive with the parameters THIS file was created with, not
        // today's KdfParameters.Default — otherwise raising the cost defaults
        // in a future release would silently break opening older vaults.
        var kdfParameters = new KdfParameters(
            MemoryKiB: reader.ReadInt64(),
            Passes: reader.ReadInt64(),
            Parallelism: reader.ReadInt32());
        var indexCiphertextLength = reader.ReadInt32();
        var indexCiphertext = reader.ReadBytes(indexCiphertextLength);
        var dataRegionStart = stream.Position;

        var keys = KeyDerivation.DeriveLayerKeys(password, keyfileBytes, salt, kdfParameters, memoryGuard);

        using var indexPlaintext = CascadeCipher.Open(indexCiphertext, keys, memoryGuard);
        if (indexPlaintext is null)
        {
            keys.Dispose();
            throw new UnauthorizedAccessException("Incorrect password, keyfile, or corrupted container.");
        }

        var index = VaultIndexCodec.Decode(indexPlaintext.Span);
        var container = new VaultContainer(path, salt, kdfParameters, keys, coverImageBytes.Length > 0 ? coverImageBytes.ToArray() : null, memoryGuard);
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

    /// <summary>Adds one entry holding one or more files (e.g. a batch picked together in the UI).</summary>
    public Guid AddFiles(string title, IEnumerable<string> tags, IReadOnlyList<(string FileName, byte[] Bytes)> files)
    {
        var payload = EntryContentCodec.EncodeFiles(files);
        return AddEntry(EntryType.File, title, tags, payload);
    }

    public void UpdateLogin(Guid id, string title, IEnumerable<string> tags, string username, ReadOnlySpan<char> password, string url, ReadOnlySpan<char> notes)
    {
        var payload = EntryContentCodec.EncodeLogin(username, password, url, notes);
        UpdateEntry(id, EntryType.Login, title, tags, payload);
    }

    public void UpdateNote(Guid id, string title, IEnumerable<string> tags, ReadOnlySpan<char> body)
    {
        var payload = EntryContentCodec.EncodeNote(body);
        UpdateEntry(id, EntryType.Note, title, tags, payload);
    }

    /// <summary>Replaces the full set of files held by a File-type entry (add/remove/replace are all just "save this new set").</summary>
    public void UpdateFiles(Guid id, string title, IEnumerable<string> tags, IReadOnlyList<(string FileName, byte[] Bytes)> files)
    {
        var payload = EntryContentCodec.EncodeFiles(files);
        UpdateEntry(id, EntryType.File, title, tags, payload);
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

    public DecodedFiles RevealFiles(Guid id)
    {
        using var plaintext = OpenSealedContent(id, EntryType.File);
        return EntryContentCodec.DecodeFiles(plaintext.Span, _memoryGuard);
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

        using var containerStream = new MemoryStream();
        using (var writer = new BinaryWriter(containerStream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(VaultHeader.MagicBytes);
            writer.Write(VaultHeader.CurrentVersion);
            writer.Write(_salt);
            writer.Write(_kdfParameters.MemoryKiB);
            writer.Write(_kdfParameters.Passes);
            writer.Write(_kdfParameters.Parallelism);
            writer.Write(indexCiphertext.Length);
            writer.Write(indexCiphertext);
            dataRegion.Position = 0;
            dataRegion.CopyTo(containerStream);
            ChaffGenerator.WriteChaff(containerStream, chaffLength);
        }

        var finalBytes = _coverImageBytes is not null
            ? ImageCloak.Cloak(_coverImageBytes, containerStream.ToArray())
            : containerStream.ToArray();

        var tempPath = _path + ".tmp";
        File.WriteAllBytes(tempPath, finalBytes);
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

    private void UpdateEntry(Guid id, EntryType expectedType, string title, IEnumerable<string> tags, byte[] payload)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var entry = _index.Find(e => e.Id == id) ?? throw new KeyNotFoundException($"No entry with id {id}.");
        if (entry.Type != expectedType)
        {
            throw new InvalidOperationException($"Entry {id} is a {entry.Type}, not a {expectedType}.");
        }

        byte[] sealedBytes;
        try
        {
            sealedBytes = CascadeCipher.Seal(payload, _keys);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }

        if (_sealedContent.Remove(id, out var oldSealedBytes))
        {
            CryptographicOperations.ZeroMemory(oldSealedBytes);
        }
        _sealedContent[id] = sealedBytes;

        entry.Title = title;
        entry.Tags = [.. tags];
        entry.ModifiedAt = DateTimeOffset.UtcNow;
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
