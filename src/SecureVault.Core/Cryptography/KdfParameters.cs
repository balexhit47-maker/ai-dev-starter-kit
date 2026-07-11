namespace SecureVault.Core.Cryptography;

/// <summary>
/// Argon2id cost parameters. Persisted in the container's cleartext header
/// (same trust boundary as the salt, п.3.1 of the TOR) alongside the salt
/// so that a future change to <see cref="Default"/> can never break
/// opening a vault created with the old cost settings — <see cref="Container.VaultContainer.Open"/>
/// always re-derives keys with whatever parameters that specific file was
/// created with, not with today's defaults.
/// </summary>
public readonly record struct KdfParameters(long MemoryKiB, long Passes, int Parallelism)
{
    /// <summary>п.3.1 of the TOR: minimum 64 MiB of memory per derivation.</summary>
    public static readonly KdfParameters Default = new(MemoryKiB: 64 * 1024, Passes: 3, Parallelism: 1);
}
