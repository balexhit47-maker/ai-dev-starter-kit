namespace SecureVault.Core.Abstractions;

/// <summary>
/// Platform hook for pinning secret-bearing memory pages so the OS cannot swap
/// them to disk (Windows VirtualLock, POSIX mlock). Implemented per platform;
/// <see cref="NullMemoryGuard"/> is used where no such guarantee is available.
/// </summary>
public interface IMemoryGuard
{
    void Lock(nint address, nuint length);

    void Unlock(nint address, nuint length);
}

public sealed class NullMemoryGuard : IMemoryGuard
{
    public static readonly NullMemoryGuard Instance = new();

    private NullMemoryGuard() { }

    public void Lock(nint address, nuint length) { }

    public void Unlock(nint address, nuint length) { }
}
