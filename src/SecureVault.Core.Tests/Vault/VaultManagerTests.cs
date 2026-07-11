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
        using (manager.CreateVault("personal.vault", "password", Keyfile)) { }

        var vaults = manager.ListVaults();

        var descriptor = Assert.Single(vaults);
        Assert.Equal("personal.vault", descriptor.FileName);
    }

    [Fact]
    public void MultipleVaults_CanUseDifferentPasswordsAndKeyfiles()
    {
        var manager = new VaultManager(_tempRoot);
        using (manager.CreateVault("work.vault", "work-password", "work-keyfile"u8.ToArray())) { }
        using (manager.CreateVault("personal.vault", "personal-password", "personal-keyfile"u8.ToArray())) { }

        Assert.Equal(2, manager.ListVaults().Count);

        // Each vault only opens with its own factors.
        using var work = manager.OpenVault(Path.Combine(_tempRoot, "work.vault"), "work-password", "work-keyfile"u8.ToArray());
        Assert.Throws<UnauthorizedAccessException>(() =>
            manager.OpenVault(Path.Combine(_tempRoot, "personal.vault"), "work-password", "work-keyfile"u8.ToArray()));
    }

    [Fact]
    public void ImportVaultBytes_WritesIntoManagedFolder_SameAsCreate()
    {
        var manager = new VaultManager(_tempRoot);
        var sourcePath = Path.Combine(Directory.CreateTempSubdirectory().FullName, "source.vault");
        using (Core.Container.VaultContainer.Create(sourcePath, "password", Keyfile)) { }
        var bytes = File.ReadAllBytes(sourcePath);

        var importedPath = manager.ImportVaultBytes(bytes, "imported.vault");

        Assert.Equal(Path.Combine(_tempRoot, "imported.vault"), importedPath);
        using var opened = manager.OpenVault(importedPath, "password", Keyfile);
        Assert.Empty(opened.Entries);
    }

    [Fact]
    public void ImportVaultBytes_AvoidsOverwritingExistingVault()
    {
        var manager = new VaultManager(_tempRoot);
        using (manager.CreateVault("shared.vault", "password", Keyfile)) { }
        var originalBytes = File.ReadAllBytes(Path.Combine(_tempRoot, "shared.vault"));

        var importedPath = manager.ImportVaultBytes(originalBytes, "shared.vault");

        Assert.NotEqual(Path.Combine(_tempRoot, "shared.vault"), importedPath);
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
