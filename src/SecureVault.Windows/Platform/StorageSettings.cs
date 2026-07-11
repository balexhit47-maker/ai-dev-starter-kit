using System.IO;

namespace SecureVault.Windows.Platform;

/// <summary>
/// Persists the user's chosen vaults folder across restarts. This is just a
/// filesystem path, not a secret, so a plain text file (separate from the
/// vaults folder itself) is fine — it doesn't weaken the zero-knowledge
/// model the vault contents rely on.
/// </summary>
internal static class StorageSettings
{
    private static readonly string SettingsFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecureVault", "settings.txt");

    public static string? TryGetCustomVaultsFolder()
    {
        try
        {
            if (!File.Exists(SettingsFilePath))
            {
                return null;
            }

            var path = File.ReadAllText(SettingsFilePath).Trim();
            return !string.IsNullOrEmpty(path) && Directory.Exists(path) ? path : null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    public static void SetVaultsFolder(string path)
    {
        var settingsDir = Path.GetDirectoryName(SettingsFilePath)!;
        Directory.CreateDirectory(settingsDir);
        File.WriteAllText(SettingsFilePath, path);
    }
}
