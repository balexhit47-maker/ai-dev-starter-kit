using SecureVault.Core.Container;
using Xunit;

namespace SecureVault.Core.Tests.Container;

public class ImageCloakTests
{
    [Fact]
    public void Cloak_ThenUncloak_RecoversBothPiecesExactly()
    {
        byte[] coverImage = [0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 0xFF, 0xD9]; // fake-ish JPEG-shaped bytes
        byte[] container = [10, 20, 30, 40, 50];

        var combined = ImageCloak.Cloak(coverImage, container);
        var (recoveredContainer, recoveredCover) = ImageCloak.Uncloak(combined);

        Assert.Equal(container, recoveredContainer.ToArray());
        Assert.Equal(coverImage, recoveredCover.ToArray());
    }

    [Fact]
    public void Cloak_KeepsCoverImageBytesUnchangedAtTheStartOfTheFile()
    {
        byte[] coverImage = [0x89, 0x50, 0x4E, 0x47, 1, 2, 3, 4, 5]; // fake-ish PNG-shaped bytes
        byte[] container = [1, 2, 3];

        var combined = ImageCloak.Cloak(coverImage, container);

        Assert.Equal(coverImage, combined[..coverImage.Length]);
    }

    [Fact]
    public void Uncloak_OnPlainUncloakedBytes_ReturnsInputAsContainerWithNoCoverImage()
    {
        byte[] plain = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        var (container, cover) = ImageCloak.Uncloak(plain);

        Assert.Equal(plain, container.ToArray());
        Assert.Equal(0, cover.Length);
    }

    [Fact]
    public void HasCloakedFooter_FalseForOrdinaryImageTail()
    {
        byte[] ordinaryImageTail = new byte[16];
        Array.Fill(ordinaryImageTail, (byte)0xAB);

        Assert.False(ImageCloak.HasCloakedFooter(ordinaryImageTail));
    }

    [Fact]
    public void HasCloakedFooter_TrueOnlyOnTheLast16BytesOfACloakedFile()
    {
        byte[] coverImage = [1, 2, 3, 4, 5];
        byte[] container = [9, 8, 7];
        var combined = ImageCloak.Cloak(coverImage, container);

        Assert.True(ImageCloak.HasCloakedFooter(combined[^16..]));
    }
}
