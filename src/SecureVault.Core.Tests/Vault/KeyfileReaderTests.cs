using SecureVault.Core.Vault;
using Xunit;

namespace SecureVault.Core.Tests.Vault;

public class KeyfileReaderTests : IDisposable
{
    private readonly string _tempDir = Directory.CreateTempSubdirectory("keyfile-reader-tests-").FullName;

    [Fact]
    public void ReadBounded_ReturnsExactBytes_ForAFileUnderTheLimit()
    {
        var path = Path.Combine(_tempDir, "small.key");
        var expected = new byte[1024];
        Random.Shared.NextBytes(expected);
        File.WriteAllBytes(path, expected);

        var actual = KeyfileReader.ReadBounded(path);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ReadBounded_ThrowsForAFileOverTheLimit()
    {
        var path = Path.Combine(_tempDir, "big.key");
        using (var stream = new FileStream(path, FileMode.Create))
        {
            stream.SetLength(KeyfileReader.MaxSizeBytes + 1);
        }

        Assert.Throws<InvalidOperationException>(() => KeyfileReader.ReadBounded(path));
    }

    [Fact]
    public void ReadBounded_AcceptsAFileExactlyAtTheLimit()
    {
        var path = Path.Combine(_tempDir, "exact.key");
        using (var stream = new FileStream(path, FileMode.Create))
        {
            stream.SetLength(KeyfileReader.MaxSizeBytes);
        }

        var bytes = KeyfileReader.ReadBounded(path);

        Assert.Equal(KeyfileReader.MaxSizeBytes, bytes.Length);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // best-effort cleanup
        }
    }
}
