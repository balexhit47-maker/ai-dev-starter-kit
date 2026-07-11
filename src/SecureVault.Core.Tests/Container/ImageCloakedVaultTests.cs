using SecureVault.Core.Container;
using Xunit;

namespace SecureVault.Core.Tests.Container;

public class ImageCloakedVaultTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("securevault-cloak-tests-").FullName;
    private static readonly byte[] Keyfile = "keyfile-bytes"u8.ToArray();

    // Not a real decodable JPEG — just enough to stand in as "some cover image bytes" for these tests.
    private static readonly byte[] CoverImage = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10, .. "fake jpeg body"u8.ToArray(), 0xFF, 0xD9];

    private string NewVaultPath() => Path.Combine(_tempDir, $"{Guid.NewGuid()}.jpg");

    [Fact]
    public void CreateWithCoverImage_FileStartsWithTheCoverImageBytesUnchanged()
    {
        var path = NewVaultPath();
        using var vault = VaultContainer.Create(path, "password", Keyfile, CoverImage);

        var fileBytes = File.ReadAllBytes(path);

        Assert.Equal(CoverImage, fileBytes[..CoverImage.Length]);
        Assert.True(vault.IsImageCloaked);
    }

    [Fact]
    public void CreateWithCoverImage_ThenOpen_RoundTrips()
    {
        var path = NewVaultPath();
        using (var created = VaultContainer.Create(path, "password", Keyfile, CoverImage))
        {
            created.AddNote("Скрытая заметка", [], "секрет внутри фото");
            created.Save();
        }

        using var opened = VaultContainer.Open(path, "password", Keyfile);
        Assert.True(opened.IsImageCloaked);
        var entry = Assert.Single(opened.Entries);
        using var note = opened.RevealNote(entry.Id);
        using var body = note.RevealBody();
        Assert.Equal("секрет внутри фото", new string(body.Span));
    }

    [Fact]
    public void EditingAndResaving_KeepsTheCoverImagePrefixIntact()
    {
        var path = NewVaultPath();
        Guid entryId;
        using (var created = VaultContainer.Create(path, "password", Keyfile, CoverImage))
        {
            entryId = created.AddNote("Заметка", [], "v1");
            created.Save();
        }

        using (var opened = VaultContainer.Open(path, "password", Keyfile))
        {
            opened.UpdateNote(entryId, "Заметка", [], "v2");
            opened.Save();
        }

        var fileBytes = File.ReadAllBytes(path);
        Assert.Equal(CoverImage, fileBytes[..CoverImage.Length]);

        using var reopened = VaultContainer.Open(path, "password", Keyfile);
        using var note = reopened.RevealNote(entryId);
        using var body = note.RevealBody();
        Assert.Equal("v2", new string(body.Span));
    }

    [Fact]
    public void Open_WithWrongPassword_StillThrows_ForACloakedVault()
    {
        var path = NewVaultPath();
        using (VaultContainer.Create(path, "correct password", Keyfile, CoverImage)) { }

        Assert.Throws<UnauthorizedAccessException>(() =>
            VaultContainer.Open(path, "wrong password", Keyfile));
    }

    [Fact]
    public void CreateWithoutCoverImage_IsNotReportedAsCloaked()
    {
        var path = Path.Combine(_tempDir, $"{Guid.NewGuid()}.cavault");
        using var vault = VaultContainer.Create(path, "password", Keyfile);

        Assert.False(vault.IsImageCloaked);
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
