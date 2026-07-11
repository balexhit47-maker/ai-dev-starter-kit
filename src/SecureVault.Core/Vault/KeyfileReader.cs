namespace SecureVault.Core.Vault;

/// <summary>
/// Reads a user-selected keyfile in streaming binary mode with a hard cap,
/// per п.3.2 of the TOR ("потоковый бинарный режим... ограничение
/// максимального объёма чтения до 10 МБ"). The cap is enforced against
/// bytes actually read, not just the reported file length, so it holds up
/// even if the file grows between the length check and the read.
/// </summary>
public static class KeyfileReader
{
    public const long MaxSizeBytes = 10 * 1024 * 1024;

    private const int ChunkSize = 64 * 1024;

    public static byte[] ReadBounded(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);

        if (stream.Length > MaxSizeBytes)
        {
            throw new InvalidOperationException(FormatLimitMessage());
        }

        using var buffer = new MemoryStream(capacity: (int)Math.Min(stream.Length, MaxSizeBytes));
        var chunk = new byte[ChunkSize];
        long totalRead = 0;
        int read;
        while ((read = stream.Read(chunk, 0, chunk.Length)) > 0)
        {
            totalRead += read;
            if (totalRead > MaxSizeBytes)
            {
                throw new InvalidOperationException(FormatLimitMessage());
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    private static string FormatLimitMessage() => $"Keyfile exceeds the {MaxSizeBytes / (1024 * 1024)} MB limit (п.3.2 ТЗ).";
}
