using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using SecureVault.Core.Abstractions;

namespace SecureVault.Core.Cryptography;

/// <summary>
/// Fixed-size, pinned, zero-on-dispose byte buffer for secret material
/// (derived keys, passwords, decrypted plaintext) — per п.4 of the TOR,
/// secrets are never held in a <see cref="string"/> or an ordinary
/// unpinned array. The buffer is GC-pinned so the collector cannot leave
/// stray copies behind by relocating it, optionally locked into RAM via
/// <see cref="IMemoryGuard"/> so the OS cannot page it to disk, and wiped
/// on dispose with <see cref="CryptographicOperations.ZeroMemory"/>, which
/// the JIT is guaranteed not to elide.
/// </summary>
public sealed class SecureBytes : IDisposable
{
    private readonly byte[] _buffer;
    private readonly nint _pinnedAddress;
    private readonly IMemoryGuard _memoryGuard;
    private bool _disposed;

    public int Length { get; }

    public SecureBytes(int length, IMemoryGuard? memoryGuard = null)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        Length = length;
        _memoryGuard = memoryGuard ?? NullMemoryGuard.Instance;
        _buffer = length == 0 ? [] : GC.AllocateArray<byte>(length, pinned: true);
        _pinnedAddress = length == 0 ? 0 : GetAddress(_buffer);

        if (length > 0)
        {
            _memoryGuard.Lock(_pinnedAddress, (nuint)length);
        }
    }

    public static SecureBytes CopyFrom(ReadOnlySpan<byte> source, IMemoryGuard? memoryGuard = null)
    {
        var secure = new SecureBytes(source.Length, memoryGuard);
        source.CopyTo(secure.Span);
        return secure;
    }

    public Span<byte> Span
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
        CryptographicOperations.ZeroMemory(_buffer);

        if (Length > 0)
        {
            _memoryGuard.Unlock(_pinnedAddress, (nuint)Length);
        }

        GC.SuppressFinalize(this);
    }

    ~SecureBytes()
    {
        // Defense in depth: Dispose should always be called explicitly (via
        // `using`), but if a caller forgets, this still guarantees the
        // buffer is wiped before the memory is reclaimed.
        CryptographicOperations.ZeroMemory(_buffer);
    }

    private static unsafe nint GetAddress(byte[] buffer)
        => (nint)Unsafe.AsPointer(ref MemoryMarshal.GetArrayDataReference(buffer));
}
