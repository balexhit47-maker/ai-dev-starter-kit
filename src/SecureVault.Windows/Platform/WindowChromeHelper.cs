using System.Runtime.InteropServices;

namespace SecureVault.Windows.Platform;

/// <summary>
/// The app's content is a fixed light theme, but WPF windows don't
/// automatically follow that — under Windows dark mode the native title bar
/// stays dark by default and clashes with our light chrome. This pins it to
/// light regardless of the OS app-theme setting.
/// </summary>
internal static class WindowChromeHelper
{
    private const int DwmwaUseImmersiveDarkMode = 20;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(nint hwnd, int attribute, ref int value, int valueSize);

    public static void UseLightTitleBar(nint hwnd)
    {
        var useDark = 0;
        DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref useDark, sizeof(int));
    }
}
