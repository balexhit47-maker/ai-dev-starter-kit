using SecureVault.Core.Container;
using SecureVault.Core.Vault;
using Xunit;

namespace SecureVault.Core.Tests.Container;

public class VaultContainerTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("securevault-tests-").FullName;

    private string NewVaultPath() => Path.Combine(_tempDir, $"{Guid.NewGuid()}.vault");

    private static readonly byte[] Keyfile = "not-a-real-keyfile-just-test-bytes"u8.ToArray();

    [Fact]
    public void CreateThenOpen_EmptyVault_RoundTrips()
    {
        var path = NewVaultPath();
        using (var created = VaultContainer.Create(path, "master password", Keyfile))
        {
            Assert.Empty(created.Entries);
        }

        using var opened = VaultContainer.Open(path, "master password", Keyfile);
        Assert.Empty(opened.Entries);
    }

    [Fact]
    public void Open_WithWrongPassword_Throws()
    {
        var path = NewVaultPath();
        using (VaultContainer.Create(path, "correct password", Keyfile)) { }

        Assert.Throws<UnauthorizedAccessException>(() =>
            VaultContainer.Open(path, "wrong password", Keyfile));
    }

    [Fact]
    public void Open_WithWrongKeyfile_Throws()
    {
        var path = NewVaultPath();
        using (VaultContainer.Create(path, "password", Keyfile)) { }

        Assert.Throws<UnauthorizedAccessException>(() =>
            VaultContainer.Open(path, "password", "different-keyfile-bytes"u8.ToArray()));
    }

    [Fact]
    public void AddLogin_PersistsAcrossSaveAndReopen()
    {
        var path = NewVaultPath();
        Guid id;
        using (var vault = VaultContainer.Create(path, "password", Keyfile))
        {
            id = vault.AddLogin("Gmail", ["email", "personal"], "me@example.com", "p@ssw0rd!", "https://gmail.com", "some notes");
            vault.Save();
        }

        using var reopened = VaultContainer.Open(path, "password", Keyfile);
        var metadata = Assert.Single(reopened.Entries);
        Assert.Equal(id, metadata.Id);
        Assert.Equal("Gmail", metadata.Title);
        Assert.Equal(EntryType.Login, metadata.Type);
        Assert.Equal(["email", "personal"], metadata.Tags);

        using var revealed = reopened.RevealLogin(id);
        Assert.Equal("me@example.com", revealed.Username);
        Assert.Equal("https://gmail.com", revealed.Url);
        using var password = revealed.RevealPassword();
        Assert.Equal("p@ssw0rd!", new string(password.Span));
        using var notes = revealed.RevealNotes();
        Assert.Equal("some notes", new string(notes.Span));
    }

    [Fact]
    public void AddNote_PersistsAcrossSaveAndReopen()
    {
        var path = NewVaultPath();
        Guid id;
        using (var vault = VaultContainer.Create(path, "password", Keyfile))
        {
            id = vault.AddNote("Wi-Fi at the cabin", ["wifi"], "SSID: cabin-net\nPassword: forest123");
            vault.Save();
        }

        using var reopened = VaultContainer.Open(path, "password", Keyfile);
        using var revealed = reopened.RevealNote(id);
        using var body = revealed.RevealBody();
        Assert.Equal("SSID: cabin-net\nPassword: forest123", new string(body.Span));
    }

    [Fact]
    public void AddFile_PersistsBytesExactly()
    {
        var path = NewVaultPath();
        var fileBytes = new byte[12345];
        Random.Shared.NextBytes(fileBytes);

        Guid id;
        using (var vault = VaultContainer.Create(path, "password", Keyfile))
        {
            id = vault.AddFile("passport-scan", [], "passport.jpg", fileBytes);
            vault.Save();
        }

        using var reopened = VaultContainer.Open(path, "password", Keyfile);
        using var revealed = reopened.RevealFile(id);
        Assert.Equal("passport.jpg", revealed.FileName);
        Assert.Equal(fileBytes, revealed.Bytes.Span.ToArray());
    }

    [Fact]
    public void DeleteEntry_RemovesItAfterSave()
    {
        var path = NewVaultPath();
        using (var vault = VaultContainer.Create(path, "password", Keyfile))
        {
            var id = vault.AddNote("temporary", [], "delete me");
            vault.Save();
            vault.DeleteEntry(id);
            vault.Save();
        }

        using var reopened = VaultContainer.Open(path, "password", Keyfile);
        Assert.Empty(reopened.Entries);
    }

    [Fact]
    public void MultipleEntries_EachDecryptsIndependently()
    {
        var path = NewVaultPath();
        Guid loginId, noteId;
        using (var vault = VaultContainer.Create(path, "password", Keyfile))
        {
            loginId = vault.AddLogin("Bank", [], "user1", "secretpass", "https://bank.example", "");
            noteId = vault.AddNote("Recovery codes", [], "AAAA-BBBB-CCCC");
            vault.Save();
        }

        using var reopened = VaultContainer.Open(path, "password", Keyfile);
        Assert.Equal(2, reopened.Entries.Count);

        using var login = reopened.RevealLogin(loginId);
        using var loginPassword = login.RevealPassword();
        Assert.Equal("secretpass", new string(loginPassword.Span));

        using var note = reopened.RevealNote(noteId);
        using var noteBody = note.RevealBody();
        Assert.Equal("AAAA-BBBB-CCCC", new string(noteBody.Span));
    }

    [Fact]
    public void SavedContainer_SizeIsQuantizedToBucketBoundary()
    {
        var path = NewVaultPath();
        using (var vault = VaultContainer.Create(path, "password", Keyfile))
        {
            vault.AddNote("small note", [], "just a little text");
            vault.Save();
        }

        var fileLength = new FileInfo(path).Length;
        Assert.Equal(256 * 1024, fileLength); // smallest bucket
    }

    [Fact]
    public void RevealLogin_OnNoteEntry_Throws()
    {
        var path = NewVaultPath();
        using var vault = VaultContainer.Create(path, "password", Keyfile);
        var id = vault.AddNote("a note", [], "body");

        Assert.Throws<InvalidOperationException>(() => vault.RevealLogin(id));
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
