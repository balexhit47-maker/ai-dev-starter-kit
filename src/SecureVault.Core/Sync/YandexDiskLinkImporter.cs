using System.Text.Json;

namespace SecureVault.Core.Sync;

/// <summary>
/// Способ B (п.3.2 of the architecture addendum): import a vault shared via
/// a Yandex.Disk public link, using Yandex's public REST API, which does
/// not require authentication for public resources.
///
/// Password-protected public links are intentionally not automated here —
/// Yandex's password gate is a browser/session flow (cookies + a form post)
/// outside the stable, documented public API, and hard-coding an
/// unverified endpoint for it would be worse than not supporting it. The
/// recommended mitigation (see the addendum) is treating the link itself
/// as a secret rather than relying on Yandex's link password.
/// </summary>
public sealed class YandexDiskLinkImporter(HttpClient httpClient)
{
    private const string PublicResourcesEndpoint = "https://cloud-api.yandex.net/v1/disk/public/resources/download";

    /// <summary>Resolves a https://disk.yandex.ru/d/... or https://yadi.sk/d/... share link and downloads its bytes.</summary>
    public async Task<byte[]> DownloadFromPublicLinkAsync(Uri publicUrl, CancellationToken cancellationToken = default)
    {
        var resolveUrl = $"{PublicResourcesEndpoint}?public_key={Uri.EscapeDataString(publicUrl.ToString())}";
        using var resolveResponse = await httpClient.GetAsync(resolveUrl, cancellationToken).ConfigureAwait(false);
        resolveResponse.EnsureSuccessStatusCode();

        await using var stream = await resolveResponse.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!doc.RootElement.TryGetProperty("href", out var hrefElement) || hrefElement.GetString() is not { } directUrl)
        {
            throw new InvalidOperationException("Yandex.Disk did not return a download link for this URL — it may be private, password-protected, or invalid.");
        }

        return await DownloadFromDirectUrlAsync(new Uri(directUrl), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Downloads from an already-resolved direct HTTPS URL (e.g. one the user unlocked manually in a browser).</summary>
    public async Task<byte[]> DownloadFromDirectUrlAsync(Uri directUrl, CancellationToken cancellationToken = default)
    {
        using var response = await httpClient.GetAsync(directUrl, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
    }
}
