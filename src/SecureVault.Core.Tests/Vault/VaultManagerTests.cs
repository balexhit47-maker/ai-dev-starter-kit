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
