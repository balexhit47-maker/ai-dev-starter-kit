using SecureVault.Core.Abstractions;
using SecureVault.Core.Security;
using Xunit;

namespace SecureVault.Core.Tests.Security;

file sealed class FakeClipboard : IClipboardService
{
    public string? Content { get; private set; }
    public int ClearCount { get; private set; }

    public void SetText(ReadOnlySpan<char> text) => Content = new string(text);

    public void Clear()
    {
        Content = null;
        ClearCount++;
    }
}

public class ClipboardAutoClearServiceTests
{
    [Fact]
    public void CopyWithAutoClear_SetsClipboardImmediately()
    {
        var clipboard = new FakeClipboard();
        using var service = new ClipboardAutoClearService(clipboard);

        service.CopyWithAutoClear("s3cret");

        Assert.Equal("s3cret", clipboard.Content);
    }

    [Fact]
    public async Task CopyWithAutoClear_ClearsAfterDelay()
    {
        var clipboard = new FakeClipboard();
        using var service = new ClipboardAutoClearService(clipboard);

        service.CopyWithAutoClear("s3cret", TimeSpan.FromMilliseconds(30));
        await Task.Delay(200);

        Assert.Null(clipboard.Content);
        Assert.Equal(1, clipboard.ClearCount);
    }

    [Fact]
    public void ClearNow_ClearsImmediatelyAndCancelsPendingTimer()
    {
        var clipboard = new FakeClipboard();
        using var service = new ClipboardAutoClearService(clipboard);

        service.CopyWithAutoClear("s3cret", TimeSpan.FromSeconds(15));
        service.ClearNow();

        Assert.Null(clipboard.Content);
        Assert.Equal(1, clipboard.ClearCount);
    }

    [Fact]
    public async Task NewerCopy_IsNotClobberedByOlderTimer()
    {
        var clipboard = new FakeClipboard();
        using var service = new ClipboardAutoClearService(clipboard);

        service.CopyWithAutoClear("first", TimeSpan.FromMilliseconds(30));
        await Task.Delay(10);
        service.CopyWithAutoClear("second", TimeSpan.FromSeconds(15));
        await Task.Delay(200);

        // The first timer fired but must not have cleared the second, newer copy.
        Assert.Equal("second", clipboard.Content);
    }
}
