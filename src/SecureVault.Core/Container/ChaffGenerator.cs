using System.Security.Cryptography;

namespace SecureVault.Core.Container;

/// <summary>
/// Fills the unused tail of a container up to its bucket boundary with
/// CSPRNG bytes indistinguishable from ciphertext, per п.5 of the TOR
/// (chaffing). Streams in fixed-size chunks instead of allocating the
/// whole padding region at once.
/// </summary>
public static class ChaffGenerator
{
    private const int ChunkSize = 64 * 1024;

    public static void WriteChaff(Stream destination, long length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        Span<byte> chunk = stackalloc byte[Math.Min(ChunkSize, (int)Math.Min(length, ChunkSize))];
        long remaining = length;
        while (remaining > 0)
        {
            var take = (int)Math.Min(chunk.Length, remaining);
            var slice = chunk[..take];
            RandomNumberGenerator.Fill(slice);
            destination.Write(slice);
            remaining -= take;
        }
    }
}
