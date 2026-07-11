using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using SecureVault.Core.Abstractions;

namespace SecureVault.Core.Cryptography;

/// <summary>
/// Char-array counterpart of <see cref="SecureBytes"/>, for secret text
/// that a caller (typically the UI layer) needs as characters rather than
/// raw UTF-8 bytes — per п.4 of the TOR, never a <see cref="string"/>.
/// </summary>
public sealed class SecureChars : IDisposable
{
    private readonly char[] _buffer;
    private readonly IMemoryGuard _memoryGuard;
    private bool _disposed;

    public int Length { get; }

    public SecureChars(int length, IMemoryGuard? memoryGuard = null)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        Length = length;
        _memoryGuard = memoryGuard ?? NullMemoryGuard.Instance;
        _buffer = length == 0 ? [] : GC.AllocateArray<char>(length, pinned: true);

        if (length > 0)
        {
            _memoryGuard.Lock(GetAddress(_buffer), (nuint)(length * sizeof(char)));
        }
    }

    /// <summary>Decodes UTF-8 bytes into a new <see cref="SecureChars"/> without ever allocating a string.</summary>
    public static SecureChars FromUtf8(ReadOnlySpan<byte> utf8Bytes, IMemoryGuard? memoryGuard = null)
    {
        var charCount = Encoding.UTF8.GetCharCount(utf8Bytes);
        var secure = new SecureChars(charCount, memoryGuard);
        Encoding.UTF8.GetChars(utf8Bytes, secure.Span);
        return secure;
    }

    public Span<char> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _buffer;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_buffer.AsSpan()));

        if (Length > 0)
        {
            _memoryGuard.Unlock(GetAddress(_buffer), (nuint)(Length * sizeof(char)));
        }

        GC.SuppressFinalize(this);
    }

    ~SecureChars()
    {
        CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_buffer.AsSpan()));
    }

    private static unsafe nint GetAddress(char[] buffer)
        => (nint)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(buffer));
}
