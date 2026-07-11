using System.Runtime.InteropServices;
using System.Security;
using SecureVault.Core.Abstractions;
using SecureVault.Core.Cryptography;

namespace SecureVault.Windows.Platform;

/// <summary>
/// Converts a WPF <see cref="System.Windows.Controls.PasswordBox"/>'s
/// <see cref="System.Windows.Controls.PasswordBox.SecurePassword"/> into a
/// <see cref="SecureChars"/> without ever creating a managed
/// <see cref="string"/> along the way, per п.4 of the TOR.
/// </summary>
public static class SecureStringInterop
{
    public static SecureChars ToSecureChars(SecureString secureString, IMemoryGuard? memoryGuard = null)
    {
        var result = new SecureChars(secureString.Length, memoryGuard);
        var unmanagedPtr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
        try
        {
            unsafe
            {
                var source = new ReadOnlySpan<char>((char*)unmanagedPtr, secureString.Length);
                source.CopyTo(result.Span);
            }
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(unmanagedPtr);
        }

        return result;
    }
}
