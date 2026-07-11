using System.Security.Cryptography;
using System.Text;
using SecureVault.Core.Abstractions;
using SecureVault.Core.Cryptography;

namespace SecureVault.Core.Vault;

/// <summary>
/// Serializes the plaintext payload of one entry before it is sealed with
/// <see cref="Cryptography.CascadeCipher"/>, and parses it back after
/// <see cref="Cryptography.CascadeCipher.Open"/>. Secret-bearing fields
/// (password, note body, file bytes) are accepted/returned as spans or
/// <see cref="SecureBytes"/>, never as <see cref="string"/>, per п.4 of the
/// TOR. Lower-sensitivity metadata (username, URL) is plain <see cref="string"/>
/// for practicality — the payload itself only exists in decrypted form for
/// as long as the caller holds the returned <c>Decoded*</c> object open.
/// </summary>
public static class EntryContentCodec
{
    public static byte[] EncodeLogin(string username, ReadOnlySpan<char> password, string url, ReadOnlySpan<char> notes)
    {
        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            bw.Write(username);
            WriteCharSpan(bw, password);
            bw.Write(url);
            WriteCharSpan(bw, notes);
        }
        return ms.ToArray();
    }

    public static DecodedLogin DecodeLogin(ReadOnlySpan<byte> data, IMemoryGuard? memoryGuard = null)
    {
        using var ms = new MemoryStream(data.ToArray());
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);
        var username = br.ReadString();
        var password = ReadCharSpanSecure(br, memoryGuard);
        var url = br.ReadString();
        var notes = ReadCharSpanSecure(br, memoryGuard);
        return new DecodedLogin(username, password, url, notes);
    }

    public static byte[] EncodeNote(ReadOnlySpan<char> body)
    {
        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            WriteCharSpan(bw, body);
        }
        return ms.ToArray();
    }

    public static DecodedNote DecodeNote(ReadOnlySpan<byte> data, IMemoryGuard? memoryGuard = null)
    {
        using var ms = new MemoryStream(data.ToArray());
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);
        var body = ReadCharSpanSecure(br, memoryGuard);
        return new DecodedNote(body);
    }

    public static byte[] EncodeFile(string fileName, ReadOnlySpan<byte> fileBytes)
    {
        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.UTF8, leaveOpen: true))
        {
            bw.Write(fileName);
            bw.Write(fileBytes.Length);
            bw.Write(fileBytes);
        }
        return ms.ToArray();
    }

    public static DecodedFile DecodeFile(ReadOnlySpan<byte> data, IMemoryGuard? memoryGuard = null)
    {
        using var ms = new MemoryStream(data.ToArray());
        using var br = new BinaryReader(ms, Encoding.UTF8, leaveOpen: true);
        var fileName = br.ReadString();
        var length = br.ReadInt32();
        var fileBytes = br.ReadBytes(length);
        var secureBytes = SecureBytes.CopyFrom(fileBytes, memoryGuard);
        CryptographicOperations.ZeroMemory(fileBytes);
        return new DecodedFile(fileName, secureBytes);
    }

    private static void WriteCharSpan(BinaryWriter writer, ReadOnlySpan<char> value)
    {
        var byteCount = Encoding.UTF8.GetByteCount(value);
        Span<byte> buffer = byteCount <= 1024 ? stackalloc byte[byteCount] : new byte[byteCount];
        try
        {
            Encoding.UTF8.GetBytes(value, buffer);
            writer.Write(byteCount);
            writer.Write(buffer);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static SecureBytes ReadCharSpanSecure(BinaryReader reader, IMemoryGuard? memoryGuard)
    {
        var byteCount = reader.ReadInt32();
        var bytes = reader.ReadBytes(byteCount);
        var secure = SecureBytes.CopyFrom(bytes, memoryGuard);
        CryptographicOperations.ZeroMemory(bytes);
        return secure;
    }
}
