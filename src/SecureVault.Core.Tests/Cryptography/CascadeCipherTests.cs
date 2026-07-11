using System.Security.Cryptography;
using System.Text;
using SecureVault.Core.Cryptography;
using Xunit;

namespace SecureVault.Core.Tests.Cryptography;

public class CascadeCipherTests
{
    private static byte[] RandomSalt() => RandomNumberGenerator.GetBytes(KeyDerivationParams.SaltSize);

    private static byte[] RandomKeyfile(int length = 4096) => RandomNumberGenerator.GetBytes(length);

    [Fact]
    public void SealThenOpen_RoundTripsPlaintextExactly()
    {
        var salt = RandomSalt();
        var keyfile = RandomKeyfile();
        using var keys = KeyDerivation.DeriveLayerKeys("correct horse battery staple", keyfile, salt);

        var plaintext = Encoding.UTF8.GetBytes("совершенно секретная заметка про доступы");
        var ciphertext = CascadeCipher.Seal(plaintext, keys);

        using var opened = CascadeCipher.Open(ciphertext, keys);

        Assert.NotNull(opened);
        Assert.Equal(plaintext, opened!.Span.ToArray());
    }

    [Fact]
    public void Seal_ProducesDifferentCiphertextForIdenticalPlaintext_BecauseNoncesAreFresh()
    {
        var salt = RandomSalt();
        var keyfile = RandomKeyfile();
        using var keys = KeyDerivation.DeriveLayerKeys("same password", keyfile, salt);

        var plaintext = Encoding.UTF8.GetBytes("identical content");
        var ciphertext1 = CascadeCipher.Seal(plaintext, keys);
        var ciphertext2 = CascadeCipher.Seal(plaintext, keys);

        Assert.NotEqual(ciphertext1, ciphertext2);
    }

    [Fact]
    public void Open_WithWrongPassword_ReturnsNull()
    {
        var salt = RandomSalt();
        var keyfile = RandomKeyfile();
        using var correctKeys = KeyDerivation.DeriveLayerKeys("right password", keyfile, salt);
        using var wrongKeys = KeyDerivation.DeriveLayerKeys("wrong password", keyfile, salt);

        var ciphertext = CascadeCipher.Seal(Encoding.UTF8.GetBytes("payload"), correctKeys);

        using var opened = CascadeCipher.Open(ciphertext, wrongKeys);

        Assert.Null(opened);
    }

    [Fact]
    public void Open_WithWrongKeyfile_ReturnsNull()
    {
        var salt = RandomSalt();
        using var correctKeys = KeyDerivation.DeriveLayerKeys("password", RandomKeyfile(), salt);
        using var wrongKeys = KeyDerivation.DeriveLayerKeys("password", RandomKeyfile(), salt);

        var ciphertext = CascadeCipher.Seal(Encoding.UTF8.GetBytes("payload"), correctKeys);

        using var opened = CascadeCipher.Open(ciphertext, wrongKeys);

        Assert.Null(opened);
    }

    [Theory]
    [InlineData(0)]   // flip a byte in the outer XChaCha20-Poly1305 nonce
    [InlineData(30)]  // flip a byte inside the outer ciphertext/tag
    public void Open_WithTamperedCiphertext_ReturnsNull(int byteIndexToFlip)
    {
        var salt = RandomSalt();
        var keyfile = RandomKeyfile();
        using var keys = KeyDerivation.DeriveLayerKeys("password", keyfile, salt);

        var ciphertext = CascadeCipher.Seal(Encoding.UTF8.GetBytes("payload that is long enough to survive tampering checks"), keys);
        ciphertext[byteIndexToFlip] ^= 0xFF;

        using var opened = CascadeCipher.Open(ciphertext, keys);

        Assert.Null(opened);
    }

    [Fact]
    public void Open_WithTruncatedCiphertext_ReturnsNullWithoutThrowing()
    {
        var salt = RandomSalt();
        using var keys = KeyDerivation.DeriveLayerKeys("password", RandomKeyfile(), salt);

        using var opened = CascadeCipher.Open(new byte[5], keys);

        Assert.Null(opened);
    }

    [Fact]
    public void SealThenOpen_HandlesEmptyPlaintext()
    {
        var salt = RandomSalt();
        using var keys = KeyDerivation.DeriveLayerKeys("password", RandomKeyfile(), salt);

        var ciphertext = CascadeCipher.Seal(ReadOnlySpan<byte>.Empty, keys);
        using var opened = CascadeCipher.Open(ciphertext, keys);

        Assert.NotNull(opened);
        Assert.Equal(0, opened!.Length);
    }

    [Fact]
    public void DeriveLayerKeys_IsDeterministic_ForSameInputs()
    {
        var salt = RandomSalt();
        var keyfile = RandomKeyfile();

        using var keys1 = KeyDerivation.DeriveLayerKeys("password", keyfile, salt);
        using var keys2 = KeyDerivation.DeriveLayerKeys("password", keyfile, salt);

        // Encrypting with keys1 must be openable with independently-derived keys2.
        var ciphertext = CascadeCipher.Seal(Encoding.UTF8.GetBytes("deterministic"), keys1);
        using var opened = CascadeCipher.Open(ciphertext, keys2);

        Assert.NotNull(opened);
    }
}
