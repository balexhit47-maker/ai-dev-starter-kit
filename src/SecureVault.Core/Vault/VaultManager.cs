using SecureVault.Core.Abstractions;
using SecureVault.Core.Container;

namespace SecureVault.Core.Vault;

/// <summary>
/// Manages the single local folder that holds every vault container, per
/// п.6 of the architecture addendum: creating a new vault and importing one
/// downloaded from sync (WebDAV or a shared link) both resolve to "write a
/// file into this folder" — there is no separate index or cache of vault
/// identities, just a plain directory listing.
/// </summary>
public sealed class VaultManager
{
    public string RootDirectory { get; }

    public VaultManager(string? rootDirectory = null)
    {
        RootDirectory = rootDirectory ?? DefaultRootDirectory();
        Directory.CreateDirectory(RootDirectory);
    }

    public static string DefaultRootDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecureVault", "Vaults");

    public IReadOnlyList<VaultDescriptor> ListVaults()
    {
        return [.. Directory.EnumerateFiles(RootDirectory)
            .Where(path => !path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
            .Select(path =>
            {
                var info = new FileInfo(path);
                return new VaultDescriptor(info.FullName, info.Name, info.Length, info.LastWriteTimeUtc);
            })
            .OrderByDescending(v => v.LastModifiedUtc)];
    }

    public VaultContainer CreateVault(string fileName, ReadOnlySpan<char> password, ReadOnlySpan<byte> keyfileBytes, IMemoryGuard? memoryGuard = null)
    {
        var path = ResolvePath(fileName);
        if (File.Exists(path))
        {
            throw new IOException($"A vault named '{fileName}' already exists.");
        }

        return Container.VaultContainer.Create(path, password, keyfileBytes, memoryGuard);
    }

    public VaultContainer OpenVault(string filePath, ReadOnlySpan<char> password, ReadOnlySpan<byte> keyfileBytes, IMemoryGuard? memoryGuard = null)
        => Container.VaultContainer.Open(filePath, password, keyfileBytes, memoryGuard);

    /// <summary>
    /// Writes a vault file obtained from sync (WebDAV download or link
    /// import) into the managed folder. Refuses to silently overwrite an
    /// existing vault with the same name.
    /// </summary>
    public string ImportVaultBytes(ReadOnlySpan<byte> containerBytes, string suggestedFileName)
    {
        var path = ResolvePath(suggestedFileName);
        if (File.Exists(path))
        {
            var extension = Path.GetExtension(suggestedFileName);
            var stem = Path.GetFileNameWithoutExtension(suggestedFileName);
            path = ResolvePath($"{stem}-{DateTime.UtcNow:yyyyMMdd-HHmmss}{extension}");
        }

        using (var stream = File.Create(path))
        {
            stream.Write(containerBytes);
        }

        return path;
    }

    /// <summary>Permanently deletes a vault file. Irreversible — callers must confirm with the user first.</summary>
    public void DeleteVault(string filePath)
    {
        var fullPath = Path.GetFullPath(filePath);
        var fullRoot = Path.GetFullPath(RootDirectory);
        if (!fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Path is outside the managed vaults folder.", nameof(filePath));
        }

        File.Delete(fullPath);
    }

    private string ResolvePath(string fileName)
    {
        var safeName = Path.GetFileName(fileName);
        if (string.IsNullOrWhiteSpace(safeName))
        {
            throw new ArgumentException("Invalid vault file name.", nameof(fileName));
        }

        return Path.Combine(RootDirectory, safeName);
    }
}
