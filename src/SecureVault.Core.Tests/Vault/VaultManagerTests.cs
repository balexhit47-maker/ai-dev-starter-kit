using SecureVault.Core.Vault;
using Xunit;

namespace SecureVault.Core.Tests.Vault;

public class VaultManagerTests : IDisposable
{
    private readonly string _tempRoot = Directory.CreateTempSubdirectory("securevault-manager-tests-").FullName;
    private static readonly byte[] Keyfile = "keyfile-bytes"u8.ToArray();

    [Fact]
    public void CreateVault_ThenListVaults_ShowsItInTheSameFolder()
    {
        var manager = new VaultManager(_tempRoot);
        using (manager.CreateVault("personal", "password", Keyfile)) { }

        var vaults = manager.ListVaults();

        var descriptor = Assert.Single(vaults);
        Assert.Equal("personal.cavault", descriptor.FileName);
    }

    [Fact]
    public void CreateVault_NormalizesToTheManagedExtension_RegardlessOfWhatWasPassedIn()
    {
        var manager = new VaultManager(_tempRoot);
        using (manager.CreateVault("personal.vault", "password", Keyfile)) { }

        var descriptor = Assert.Single(manager.ListVaults());
        Assert.Equal("personal.cavault", descriptor.FileName);
    }

    [Fact]
    public void ListVaults_IgnoresUnrelatedFilesInTheFolder()
    {
        var manager = new VaultManager(_tempRoot);
        using (manager.CreateVault("personal", "password", Keyfile)) { }
        File.WriteAllText(Path.Combine(_tempRoot, "not-a-vault.txt"), "unrelated");
        File.WriteAllText(Path.Combine(_tempRoot, "installer.exe"), "unrelated");

        var descriptor = Assert.Single(manager.ListVaults());
        Assert.Equal("personal.cavault", descriptor.FileName);
    }

    [Fact]
    public void MultipleVaults_CanUseDifferentPasswordsAndKeyfiles()
    {
        var manager = new VaultManager(_tempRoot);
        using (manager.CreateVault("work", "work-password", "work-keyfile"u8.ToArray())) { }
        using (manager.CreateVault("personal", "personal-password", "personal-keyfile"u8.ToArray())) { }

        Assert.Equal(2, manager.ListVaults().Count);

        // Each vault only opens with its own factors.
        using var work = manager.OpenVault(Path.Combine(_tempRoot, "work.cavault"), "work-password", "work-keyfile"u8.ToArray());
        Assert.Throws<UnauthorizedAccessException>(() =>
            manager.OpenVault(Path.Combine(_tempRoot, "personal.cavault"), "work-password", "work-keyfile"u8.ToArray()));
    }

    [Fact]
    public void ImportVaultBytes_WritesIntoManagedFolder_SameAsCreate()
    {
        var manager = new VaultManager(_tempRoot);
        var sourcePath = Path.Combine(Directory.CreateTempSubdirectory().FullName, "source.cavault");
        using (Core.Container.VaultContainer.Create(sourcePath, "password", Keyfile)) { }
        var bytes = File.ReadAllBytes(sourcePath);

        var importedPath = manager.ImportVaultBytes(bytes, "imported");

        Assert.Equal(Path.Combine(_tempRoot, "imported.cavault"), importedPath);
        using var opened = manager.OpenVault(importedPath, "password", Keyfile);
        Assert.Empty(opened.Entries);
    }

    [Fact]
    public void CreateVault_WithCoverImage_ShowsUpInListVaultsWithTheImageExtension()
    {
        byte[] coverImage = [0xFF, 0xD8, 0xFF, 0xE0, .. "fake jpeg"u8.ToArray(), 0xFF, 0xD9];
        var manager = new VaultManager(_tempRoot);

        using (manager.CreateVault("vacation", "password", Keyfile, coverImage, ".jpg")) { }

        var descriptor = Assert.Single(manager.ListVaults());
        Assert.Equal("vacation.jpg", descriptor.FileName);
    }

    [Fact]
    public void ListVaults_DoesNotMistakeAnOrdinaryImageForACloakedVault()
    {
        var manager = new VaultManager(_tempRoot);
        File.WriteAllBytes(Path.Combine(_tempRoot, "real-photo.jpg"), [0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 0xFF, 0xD9]);

        Assert.Empty(manager.ListVaults());
    }

    [Fact]
    public void ListVaults_ShowAllFiles_IncludesUnrecognizedExtensionsButNotTempFiles()
    {
        var manager = new VaultManager(_tempRoot);
        using (manager.CreateVault("personal", "password", Keyfile)) { }
        File.WriteAllText(Path.Combine(_tempRoot, "renamed-vault.dat"), "some other extension");
        File.WriteAllText(Path.Combine(_tempRoot, "leftover.tmp"), "should never show up");

        var withDefaults = manager.ListVaults();
        Assert.Single(withDefaults);

        var withAllFiles = manager.ListVaults(showAllFiles: true);
        Assert.Equal(2, withAllFiles.Count);
        Assert.Contains(withAllFiles, v => v.FileName == "renamed-vault.dat");
        Assert.DoesNotContain(withAllFiles, v => v.FileName == "leftover.tmp");
    }

    [Fact]
    public void ImportVaultBytes_AvoidsOverwritingExistingVault()
    {
        var manager = new VaultManager(_tempRoot);
        using (manager.CreateVault("shared", "password", Keyfile)) { }
        var originalBytes = File.ReadAllBytes(Path.Combine(_tempRoot, "shared.cavault"));

        var importedPath = manager.ImportVaultBytes(originalBytes, "shared");

        Assert.NotEqual(Path.Combine(_tempRoot, "shared.cavault"), importedPath);
        Assert.Equal(2, manager.ListVaults().Count);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempRoot, recursive: true);
        }
        catch
        {
            // best-effort cleanup
        }
    }
}
