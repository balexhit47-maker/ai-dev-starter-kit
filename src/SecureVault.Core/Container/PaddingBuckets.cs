namespace SecureVault.Core.Container;

/// <summary>
/// Adaptive size-quantization scheme (bucket/PADMÉ-style padding) per п.4
/// of the architecture addendum: the container is padded up to the next
/// bucket boundary rather than a flat 10 MB, so an observer only learns
/// "between N and 2N", not the exact content size, without wasting space
/// on small vaults.
/// </summary>
public static class PaddingBuckets
{
    private const long Kb = 1024;
    private const long Mb = 1024 * Kb;

    private static readonly long[] ExponentialBuckets =
    [
        256 * Kb, 512 * Kb,
        1 * Mb, 2 * Mb, 4 * Mb, 8 * Mb, 16 * Mb, 32 * Mb, 64 * Mb,
    ];

    /// <summary>Beyond the largest exponential bucket, growth switches to a flat step.</summary>
    private const long LinearStepAfterMax = 32 * Mb;

    public static long NextBucketSize(long usedBytes)
    {
        if (usedBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(usedBytes));
        }

        foreach (var bucket in ExponentialBuckets)
        {
            if (usedBytes <= bucket)
            {
                return bucket;
            }
        }

        var max = ExponentialBuckets[^1];
        var overflow = usedBytes - max;
        var stepsNeeded = (overflow + LinearStepAfterMax - 1) / LinearStepAfterMax;
        return max + stepsNeeded * LinearStepAfterMax;
    }
}
