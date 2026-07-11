using System.Diagnostics;
using System.Runtime.InteropServices;
using SecureVault.Core.Abstractions;

namespace SecureVault.Windows.Platform;

/// <summary>
/// Windows implementation of <see cref="IPlatformSecurity"/> — п.4 and п.6
/// of the TOR: VirtualLock keeps key material out of pagefile.sys,
/// SetWindowDisplayAffinity(WDA_MONITOR) blocks screenshots/screen
/// recording/remote-desktop capture of windows showing secrets.
/// </summary>
public sealed class WindowsPlatformSecurity : IPlatformSecurity
{
    /// <summary>Window content renders as black in screenshots, screen recordings, and RDP/remote sessions.</summary>
    private const uint WdaMonitor = 0x00000001;

    public bool SupportsCaptureProtection => true;

    public void Lock(nint address, nuint length)
    {
        if (!VirtualLock(address, length))
        {
            // Not fatal: the buffer is still GC-pinned and zeroed on dispose,
            // it just might not be excluded from the pagefile (e.g. the
            // process's working-set-lock quota was exhausted). Surface it
            // for diagnostics rather than crashing the app over it.
            Debug.WriteLine($"VirtualLock failed, Win32 error {Marshal.GetLastWin32Error()}");
        }
    }

    public void Unlock(nint address, nuint length)
    {
        VirtualUnlock(address, length);
    }

    public void ProtectWindowFromCapture(nint windowHandle)
    {
        if (!SetWindowDisplayAffinity(windowHandle, WdaMonitor))
        {
            Debug.WriteLine($"SetWindowDisplayAffinity failed, Win32 error {Marshal.GetLastWin32Error()}");
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualLock(nint lpAddress, nuint dwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualUnlock(nint lpAddress, nuint dwSize);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowDisplayAffinity(nint hWnd, uint dwAffinity);
}
