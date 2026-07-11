using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;
using SecureVault.Core.Abstractions;

namespace SecureVault.Core.Cryptography;

public static class KeyDerivationParams
{
    /// <summary>Salt length per п.3.1 of the TOR — also the fixed size libsodium's Argon2id requires.</summary>
    public const int SaltSize = 16;

    public const int MasterKeySize = 32;

    /// <summary>Both AES-256-GCM and XChaCha20-Poly1305 take 256-bit keys.</summary>
    public const int LayerKeySize = 32;

    /// <summary>Sanity bound for stack-allocated UTF-8 encoding of the password; not a UX limit.</summary>
    public const int MaxPasswordChars = 1024;
}

/// <summary>
/// Combines the master password and keyfile bytes into independent cascade
/// layer keys, per п.3.2-3.3 of the TOR:
/// <code>
///   Secret     = SHA-256(password) || SHA-256(keyfile bytes)
///   MasterKey  = Argon2id(Secret, salt)
///   Layer1Key  = HKDF-Expand(MasterKey, "layer1-aes-gcm")
///   Layer2Key  = HKDF-Expand(MasterKey, "layer2-xchacha")
/// </code>
/// The password is accepted as <see cref="ReadOnlySpan{Char}"/> so callers
/// can source it from a char[] and never materialize a <see cref="string"/>.
/// </summary>
public static class KeyDerivation
{
    private static readonly byte[] Layer1Info = Encoding.ASCII.GetBytes("layer1-aes-gcm");
    private static readonly byte[] Layer2Info = Encoding.ASCII.GetBytes("layer2-xchacha");

    public static CascadeKeyMaterial DeriveLayerKeys(
        ReadOnlySpan<char> password,
        ReadOnlySpan<byte> keyfileBytes,
        ReadOnlySpan<byte> salt,
        KdfParameters kdfParameters,
        IMemoryGuard? memoryGuard = null)
    {
        if (salt.Length != KeyDerivationParams.SaltSize)
        {
            throw new ArgumentException($"Salt must be {KeyDerivationParams.SaltSize} bytes.", nameof(salt));
        }

        if (password.Length > KeyDerivationParams.MaxPasswordChars)
        {
            throw new ArgumentException("Password exceeds the maximum supported length.", nameof(password));
        }

        using var combinedSecret = CombineFactors(password, keyfileBytes, memoryGuard);
        using var masterKey = new SecureBytes(KeyDerivationParams.MasterKeySize, memoryGuard);

        var argon2Parameters = new Argon2Parameters
        {
            DegreeOfParallelism = kdfParameters.Parallelism,
            MemorySize = kdfParameters.MemoryKiB,
            NumberOfPasses = kdfParameters.Passes,
        };
        var argon2id = PasswordBasedKeyDerivationAlgorithm.Argon2id(argon2Parameters);
        argon2id.DeriveBytes(combinedSecret.Span, salt, masterKey.Span);

        var layer1 = new SecureBytes(KeyDerivationParams.LayerKeySize, memoryGuard);
        var layer2 = new SecureBytes(KeyDerivationParams.LayerKeySize, memoryGuard);
        try
        {
            HKDF.Expand(HashAlgorithmName.SHA256, masterKey.Span, layer1.Span, Layer1Info);
            HKDF.Expand(HashAlgorithmName.SHA256, masterKey.Span, layer2.Span, Layer2Info);
        }
        catch
        {
            layer1.Dispose();
            layer2.Dispose();
            throw;
        }

        return new CascadeKeyMaterial(layer1, layer2);
    }

    private static SecureBytes CombineFactors(ReadOnlySpan<char> password, ReadOnlySpan<byte> keyfileBytes, IMemoryGuard? memoryGuard)
    {
        Span<byte> passwordUtf8 = stackalloc byte[Encoding.UTF8.GetMaxByteCount(password.Length)];
        Span<byte> passwordHash = stackalloc byte[32];
        Span<byte> keyfileHash = stackalloc byte[32];
        try
        {
            int written = password.IsEmpty ? 0 : Encoding.UTF8.GetBytes(password, passwordUtf8);
            SHA256.HashData(passwordUtf8[..written], passwordHash);
            SHA256.HashData(keyfileBytes, keyfileHash);

            var combined = new SecureBytes(64, memoryGuard);
            passwordHash.CopyTo(combined.Span[..32]);
            keyfileHash.CopyTo(combined.Span[32..]);
            return combined;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordUtf8);
            CryptographicOperations.ZeroMemory(passwordHash);
            CryptographicOperations.ZeroMemory(keyfileHash);
        }
    }
}
