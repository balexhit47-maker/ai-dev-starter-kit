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
    /// <summary>
    /// Distinctive extension so the vaults folder can safely be pointed at a
    /// general-purpose folder (Downloads, a synced Drive folder, etc.)
    /// without the vault list picking up every unrelated file in it.
    /// </summary>
    public const string VaultExtension = ".cavault";

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
            .Where(path => path.EndsWith(VaultExtension, StringComparison.OrdinalIgnoreCase))
            .Select(path =>
            {
                var info = new FileInfo(path);
                return new VaultDescriptor(info.FullName, info.Name, info.Length, info.LastWriteTimeUtc);
            })
            .OrderByDescending(v => v.LastModifiedUtc)];
    }

    public VaultContainer CreateVault(string fileName, ReadOnlySpan<char> password, ReadOnlySpan<byte> keyfileBytes, IMemoryGuard? memoryGuard = null)
    {
        var path = ResolvePath(NormalizeVaultFileName(fileName));
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
        var normalizedName = NormalizeVaultFileName(suggestedFileName);
        var path = ResolvePath(normalizedName);
        if (File.Exists(path))
        {
            var stem = Path.GetFileNameWithoutExtension(normalizedName);
            path = ResolvePath($"{stem}-{DateTime.UtcNow:yyyyMMdd-HHmmss}{VaultExtension}");
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

    /// <summary>Strips whatever extension was given and appends <see cref="VaultExtension"/>, so every vault this manager creates/imports is idempotently nameable and always shows up in <see cref="ListVaults"/>.</summary>
    private static string NormalizeVaultFileName(string fileName)
    {
        var stem = Path.GetFileNameWithoutExtension(fileName);
        if (string.IsNullOrWhiteSpace(stem))
        {
            throw new ArgumentException("Invalid vault file name.", nameof(fileName));
        }

        return stem + VaultExtension;
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
