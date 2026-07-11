using System.Buffers.Binary;

namespace SecureVault.Core.Container;

/// <summary>
/// Steganographic wrapper: appends a vault container after a cover image's
/// own end-of-file marker. Every mainstream JPEG/PNG decoder stops reading
/// at its own end-of-image marker and ignores whatever bytes follow, so the
/// combined file opens as an ordinary photo in any viewer while still being
/// openable as a vault by us — we locate the hidden container via a small
/// footer at the very end of the file; we never parse the image format
/// itself, so this works for any cover image the decoder itself accepts.
///
/// This only survives a byte-exact transfer (send/copy as a file). Anything
/// that re-encodes the image — most messaging apps' "send as photo" path —
/// strips the appended bytes and destroys the hidden vault.
/// </summary>
public static class ImageCloak
{
    private static readonly byte[] FooterMagic = "CAVLTIMG"u8.ToArray();
    private const int FooterLength = 8 + 8; // 8-byte container length + 8-byte magic

    public static byte[] Cloak(ReadOnlySpan<byte> coverImageBytes, ReadOnlySpan<byte> containerBytes)
    {
        var result = new byte[coverImageBytes.Length + containerBytes.Length + FooterLength];
        var span = result.AsSpan();
        coverImageBytes.CopyTo(span);
        containerBytes.CopyTo(span[coverImageBytes.Length..]);

        var footer = span[(coverImageBytes.Length + containerBytes.Length)..];
        BinaryPrimitives.WriteUInt64LittleEndian(footer, (ulong)containerBytes.Length);
        FooterMagic.CopyTo(footer[8..]);
        return result;
    }

    /// <summary>
    /// Splits a file's bytes into (container, cover image) if it ends with
    /// our footer, or returns the whole input as the container with an
    /// empty cover image when it doesn't — i.e. an ordinary, uncloaked
    /// vault file.
    /// </summary>
    public static (ReadOnlyMemory<byte> ContainerBytes, ReadOnlyMemory<byte> CoverImageBytes) Uncloak(ReadOnlyMemory<byte> fileBytes)
    {
        if (!HasCloakedFooter(fileBytes.Span))
        {
            return (fileBytes, ReadOnlyMemory<byte>.Empty);
        }

        var footer = fileBytes.Span[^FooterLength..];
        var containerLength = BinaryPrimitives.ReadUInt64LittleEndian(footer[..8]);
        var beforeFooter = fileBytes.Length - FooterLength;

        if (containerLength > (ulong)beforeFooter)
        {
            // Implausible footer (shouldn't happen outside deliberate tampering) — treat as uncloaked.
            return (fileBytes, ReadOnlyMemory<byte>.Empty);
        }

        var containerStart = beforeFooter - (int)containerLength;
        return (fileBytes[containerStart..beforeFooter], fileBytes[..containerStart]);
    }

    /// <summary>Cheap check usable on just the last 16 bytes of a file, without reading the whole thing.</summary>
    public static bool HasCloakedFooter(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= FooterLength && bytes[^8..].SequenceEqual(FooterMagic);
}
