using SecureVault.Core.Container;
using SecureVault.Core.Cryptography;
using Xunit;

namespace SecureVault.Core.Tests.Container;

public class VaultContainerEdgeCaseTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("securevault-edge-tests-").FullName;
    private static readonly byte[] Keyfile = "edge-case-keyfile-bytes"u8.ToArray();

    private string NewVaultPath() => Path.Combine(_tempDir, $"{Guid.NewGuid()}.vault");

    [Fact]
    public void Save_CrossingABucketBoundary_GrowsToTheNextBucketExactly()
    {
        var path = NewVaultPath();
        using var vault = VaultContainer.Create(path, "password", Keyfile);
        Assert.Equal(256 * 1024, new FileInfo(path).Length);

        // A ~300 KB attachment pushes the used region past the 256 KB bucket.
        var bigFile = new byte[300 * 1024];
        Random.Shared.NextBytes(bigFile);
        vault.AddFile("big attachment", [], "photo.jpg", bigFile);
        vault.Save();

        Assert.Equal(512 * 1024, new FileInfo(path).Length);
    }

    [Fact]
    public void Open_WithTamperedIndexCiphertext_ThrowsUnauthorized()
    {
        var path = NewVaultPath();
        using (var vault = VaultContainer.Create(path, "password", Keyfile))
        {
            vault.AddNote("note", [], "body");
            vault.Save();
        }

        // The index ciphertext starts right after magic(4) + version(1) + salt(16) +
        // Argon2 params(8+8+4) + a 4-byte length prefix = offset 41.
        var bytes = File.ReadAllBytes(path);
        const int indexCiphertextStart = 4 + 1 + 16 + 8 + 8 + 4 + 4;
        bytes[indexCiphertextStart] ^= 0xFF;
        File.WriteAllBytes(path, bytes);

        Assert.Throws<UnauthorizedAccessException>(() => VaultContainer.Open(path, "password", Keyfile));
    }

    [Fact]
    public void RevealEntry_WithTamperedDataRegionByte_ThrowsInvalidData()
    {
        var path = NewVaultPath();
        Guid id;
        using (var vault = VaultContainer.Create(path, "password", Keyfile))
        {
            id = vault.AddNote("note", [], "the note body");
            vault.Save();
        }

        // Compute exactly where the data region starts (right after the
        // length-prefixed index ciphertext) so we tamper the single note's
        // sealed content blob itself, not the surrounding chaff — which
        // dwarfs it (the file is padded to a 256 KB bucket).
        var bytes = File.ReadAllBytes(path);
        const int indexLengthPrefixOffset = 4 + 1 + 16 + 8 + 8 + 4;
        var indexCiphertextLength = BitConverter.ToInt32(bytes, indexLengthPrefixOffset);
        var dataRegionStart = indexLengthPrefixOffset + 4 + indexCiphertextLength;
        bytes[dataRegionStart] ^= 0xFF;
        File.WriteAllBytes(path, bytes);

        using var reopened = VaultContainer.Open(path, "password", Keyfile);
        Assert.Throws<InvalidDataException>(() => reopened.RevealNote(id));
    }

    [Fact]
    public void Open_RespectsThePersistedKdfParameters_NotHardcodedDefaults()
    {
        // Regression test for the bug where Open() ignored the Argon2
        // parameters stored in the header and always re-derived with
        // whatever KdfParameters.Default happened to be at the time —
        // which would silently break if the defaults were ever tuned.
        var path = NewVaultPath();
        using (VaultContainer.Create(path, "password", Keyfile)) { }

        var bytes = File.ReadAllBytes(path);
        const int passesOffset = 4 + 1 + 16 + 8; // magic + version + salt + memoryKiB
        var originalPasses = BitConverter.ToInt64(bytes, passesOffset);
        BitConverter.GetBytes(originalPasses + 1).CopyTo(bytes, passesOffset);
        File.WriteAllBytes(path, bytes);

        // Same password/keyfile/salt, but a different Argon2 pass count now
        // in the header must derive a different master key and fail to open.
        Assert.Throws<UnauthorizedAccessException>(() => VaultContainer.Open(path, "password", Keyfile));
    }

    [Fact]
    public void KdfParameters_DefaultMeetsTheTorMinimum()
    {
        Assert.True(KdfParameters.Default.MemoryKiB >= 64 * 1024, "п.3.1 ТЗ requires at least 64 MiB for Argon2id.");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // best-effort cleanup
        }
    }
}
