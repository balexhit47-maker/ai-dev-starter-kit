using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using SecureVault.Core.Cryptography;

namespace SecureVault.Core.Sync;

/// <summary>
/// PUT/GET against Yandex.Disk's WebDAV endpoint (RFC 4918), authenticated
/// with a per-app password the user generates in their Yandex ID settings —
/// per способ A (п.3.1) of the architecture addendum. No OAuth flow, and by
/// default the app password is never cached by the caller (see
/// <c>KeyDerivation</c>'s treatment of the master password for the same
/// "not written to disk" principle).
/// </summary>
public sealed class WebDavSyncClient(HttpClient httpClient)
{
    private const string BaseUrl = "https://webdav.yandex.ru/";

    public async Task UploadAsync(string login, SecureChars appPassword, string remotePath, Stream content, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, BuildUri(remotePath))
        {
            Content = new StreamContent(content),
        };
        request.Headers.Authorization = BuildBasicAuth(login, appPassword.Span);

        using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }

    public async Task<byte[]> DownloadAsync(string login, SecureChars appPassword, string remotePath, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, BuildUri(remotePath));
        request.Headers.Authorization = BuildBasicAuth(login, appPassword.Span);

        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
    }

    private static Uri BuildUri(string remotePath) => new(BaseUrl + remotePath.TrimStart('/'));

    private static AuthenticationHeaderValue BuildBasicAuth(string login, ReadOnlySpan<char> appPassword)
    {
        // HttpHeaders is string-based, so the app password is briefly
        // materialized here to build the Basic-auth token — the same
        // documented, unavoidable boundary as IClipboardService.SetText.
        var credential = $"{login}:{new string(appPassword)}";
        var credentialBytes = Encoding.UTF8.GetBytes(credential);
        try
        {
            return new AuthenticationHeaderValue("Basic", Convert.ToBase64String(credentialBytes));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(credentialBytes);
        }
    }
}
