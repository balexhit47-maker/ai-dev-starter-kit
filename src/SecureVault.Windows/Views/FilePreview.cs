using System.IO;
using System.Windows.Media.Imaging;

namespace SecureVault.Windows.Views;

/// <summary>
/// Best-effort thumbnail decoding for file attachments. Failures (corrupt
/// data, unsupported format) are swallowed — a missing preview is not an
/// error, the raw file is still saved/revealed either way.
/// </summary>
internal static class FilePreview
{
    private static readonly string[] ImageExtensions = [".png", ".jpg", ".jpeg", ".bmp", ".gif"];

    public static bool IsImage(string fileName) =>
        ImageExtensions.Contains(Path.GetExtension(fileName), StringComparer.OrdinalIgnoreCase);

    public static BitmapImage? TryDecode(ReadOnlySpan<byte> bytes, int decodePixelWidth)
    {
        try
        {
            var image = new BitmapImage();
            using var stream = new MemoryStream(bytes.ToArray());
            image.BeginInit();
            image.CacheOption = BitmapCacheOption.OnLoad;
            image.DecodePixelWidth = decodePixelWidth;
            image.StreamSource = stream;
            image.EndInit();
            image.Freeze();
            return image;
        }
        catch
        {
            return null;
        }
    }
}
