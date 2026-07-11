using System.Text;

namespace SecureVault.Core.Container;

internal static class VaultHeader
{
    public static readonly byte[] MagicBytes = Encoding.ASCII.GetBytes("SVLT");

    public const byte CurrentVersion = 1;
}
