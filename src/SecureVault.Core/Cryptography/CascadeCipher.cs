using System.Security.Cryptography;
using NSec.Cryptography;
using SecureVault.Core.Abstractions;

namespace SecureVault.Core.Cryptography;

/// <summary>
/// Cascade encryption per п.2 of the TOR: an AES-256-GCM inner layer wrapped
/// by an XChaCha20-Poly1305 outer layer, each with its own independently
/// derived key (see <see cref="KeyDerivation"/>) and a fresh CSPRNG nonce
/// generated for every single seal operation — nonces are never reused.
///
/// Wire format of <see cref="Seal"/>'s output:
/// <code>
///   [nonce2 (24 bytes)] [ XChaCha20-Poly1305( [nonce1 (12 bytes)] [ AES-256-GCM(plaintext) ] ) ]
/// </code>
/// </summary>
public static class CascadeCipher
{
    public const int Aes256GcmNonceSize = 12;
    public const int Aes256GcmTagSize = 16;
    public const int XChaCha20Poly1305NonceSize = 24;

    private static readonly AeadAlgorithm OuterAlgorithm = AeadAlgorithm.XChaCha20Poly1305;

    public static byte[] Seal(ReadOnlySpan<byte> plaintext, CascadeKeyMaterial keys, ReadOnlySpan<byte> associatedData = default)
    {
        Span<byte> nonce1 = stackalloc byte[Aes256GcmNonceSize];
        RandomNumberGenerator.Fill(nonce1);

        var layer1Blob = new byte[Aes256GcmNonceSize + plaintext.Length + Aes256GcmTagSize];
        nonce1.CopyTo(layer1Blob);
        var layer1Ciphertext = layer1Blob.AsSpan(Aes256GcmNonceSize, plaintext.Length);
        var layer1Tag = layer1Blob.AsSpan(Aes256GcmNonceSize + plaintext.Length, Aes256GcmTagSize);

        using (var aes = new AesGcm(keys.Layer1Key.Span, Aes256GcmTagSize))
        {
            aes.Encrypt(nonce1, plaintext, layer1Ciphertext, layer1Tag, associatedData);
        }

        try
        {
            using var outerKey = ImportKey(keys.Layer2Key.Span);
            Span<byte> nonce2 = stackalloc byte[XChaCha20Poly1305NonceSize];
            RandomNumberGenerator.Fill(nonce2);
            var layer2Ciphertext = OuterAlgorithm.Encrypt(outerKey, nonce2, associatedData, layer1Blob);

            var result = new byte[XChaCha20Poly1305NonceSize + layer2Ciphertext.Length];
            nonce2.CopyTo(result);
            layer2Ciphertext.CopyTo(result.AsSpan(XChaCha20Poly1305NonceSize));
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(layer1Blob);
        }
    }

    /// <summary>
    /// Verifies and decrypts both layers, returning the plaintext in a
    /// zero-on-dispose <see cref="SecureBytes"/>, or <c>null</c> if either
    /// layer's authentication tag fails to verify (tampered, corrupt, or
    /// wrong key/keyfile/password) — per п.5, only validated blocks are
    /// ever produced, everything else is rejected outright.
    /// </summary>
    public static SecureBytes? Open(
        ReadOnlySpan<byte> ciphertext,
        CascadeKeyMaterial keys,
        IMemoryGuard? memoryGuard = null,
        ReadOnlySpan<byte> associatedData = default)
    {
        int minimumLength = XChaCha20Poly1305NonceSize + OuterAlgorithm.TagSize + Aes256GcmNonceSize + Aes256GcmTagSize;
        if (ciphertext.Length < minimumLength)
        {
            return null;
        }

        var nonce2 = ciphertext[..XChaCha20Poly1305NonceSize];
        var layer2Ciphertext = ciphertext[XChaCha20Poly1305NonceSize..];

        using var outerKey = ImportKey(keys.Layer2Key.Span);
        var layer1Blob = new byte[layer2Ciphertext.Length - OuterAlgorithm.TagSize];
        try
        {
            if (!OuterAlgorithm.Decrypt(outerKey, nonce2, associatedData, layer2Ciphertext, layer1Blob))
            {
                return null;
            }

            var nonce1 = layer1Blob.AsSpan(0, Aes256GcmNonceSize);
            var layer1Ciphertext = layer1Blob.AsSpan(Aes256GcmNonceSize);
            var plainLength = layer1Ciphertext.Length - Aes256GcmTagSize;

            var plaintext = new SecureBytes(plainLength, memoryGuard);
            try
            {
                using var aes = new AesGcm(keys.Layer1Key.Span, Aes256GcmTagSize);
                aes.Decrypt(nonce1, layer1Ciphertext[..plainLength], layer1Ciphertext[plainLength..], plaintext.Span, associatedData);
                return plaintext;
            }
            catch (CryptographicException)
            {
                plaintext.Dispose();
                return null;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(layer1Blob);
        }
    }

    private static Key ImportKey(ReadOnlySpan<byte> rawKey)
    {
        var creationParameters = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None };
        return Key.Import(OuterAlgorithm, rawKey, KeyBlobFormat.RawSymmetricKey, in creationParameters);
    }
}
