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

    /// <summary>Extensions a cover image may plausibly use for an image-cloaked vault (see <see cref="ImageCloak"/>).</summary>
    private static readonly string[] ImageExtensions = [".jpg", ".jpeg", ".png"];

    public string RootDirectory { get; }

    public VaultManager(string? rootDirectory = null)
    {
        RootDirectory = rootDirectory ?? DefaultRootDirectory();
        Directory.CreateDirectory(RootDirectory);
    }

    public static string DefaultRootDirectory() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecureVault", "Vaults");

    /// <summary>
    /// By default, lists ".cavault" files outright, plus any image file in
    /// the folder that turns out to have a cloaked vault footer (see
    /// <see cref="ImageCloak"/>) — checked by peeking just the last 16 bytes
    /// of each image, not by reading/decoding it.
    /// </summary>
    /// <param name="showAllFiles">
    /// When true, lists every file in the folder regardless of extension or
    /// content — <see cref="Container.VaultContainer.Open"/> only cares
    /// about a file's actual bytes, never its name, so a vault saved under
    /// an unrecognized extension is still openable; this just widens what
    /// shows up to try.
    /// </param>
    public IReadOnlyList<VaultDescriptor> ListVaults(bool showAllFiles = false)
    {
        var results = new List<VaultDescriptor>();
        foreach (var path in Directory.EnumerateFiles(RootDirectory))
        {
            if (path.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            bool isVault;
            if (showAllFiles)
            {
                isVault = true;
            }
            else
            {
                var extension = Path.GetExtension(path);
                isVault = extension.Equals(VaultExtension, StringComparison.OrdinalIgnoreCase)
                    || (ImageExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase) && HasCloakedFooter(path));
            }

            if (!isVault)
            {
                continue;
            }

            var info = new FileInfo(path);
            results.Add(new VaultDescriptor(info.FullName, info.Name, info.Length, info.LastWriteTimeUtc));
        }

        return [.. results.OrderByDescending(v => v.LastModifiedUtc)];
    }

    /// <param name="coverImageBytes">
    /// When provided (with <paramref name="coverImageExtension"/>), the new
    /// vault is hidden inside this cover image instead of being saved as a
    /// standalone ".cavault" file — see <see cref="ImageCloak"/>.
    /// </param>
    public VaultContainer CreateVault(
        string fileName,
        ReadOnlySpan<char> password,
        ReadOnlySpan<byte> keyfileBytes,
        byte[]? coverImageBytes = null,
        string? coverImageExtension = null,
        IMemoryGuard? memoryGuard = null)
    {
        var extension = coverImageBytes is not null ? (coverImageExtension ?? ".jpg") : VaultExtension;
        var path = ResolvePath(NormalizeVaultFileName(fileName, extension));
        if (File.Exists(path))
        {
            throw new IOException($"Сейф с именем «{fileName}» уже существует.");
        }

        return Container.VaultContainer.Create(path, password, keyfileBytes, coverImageBytes, memoryGuard);
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
        var normalizedName = NormalizeVaultFileName(suggestedFileName, VaultExtension);
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

    private static bool HasCloakedFooter(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length < 16)
            {
                return false;
            }

            stream.Seek(-16, SeekOrigin.End);
            Span<byte> tail = stackalloc byte[16];
            stream.ReadExactly(tail);
            return ImageCloak.HasCloakedFooter(tail);
        }
        catch (IOException)
        {
            // File in use, deleted mid-enumeration, etc. — just not a vault we can show.
            return false;
        }
    }

    /// <summary>Strips whatever extension was given and appends <paramref name="extension"/>, so every vault this manager creates/imports is idempotently nameable and always shows up in <see cref="ListVaults"/>.</summary>
    private static string NormalizeVaultFileName(string fileName, string extension)
    {
        var stem = Path.GetFileNameWithoutExtension(fileName);
        if (string.IsNullOrWhiteSpace(stem))
        {
            throw new ArgumentException("Invalid vault file name.", nameof(fileName));
        }

        return stem + extension;
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
