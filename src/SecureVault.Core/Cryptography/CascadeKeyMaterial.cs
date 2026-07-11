namespace SecureVault.Core.Cryptography;

/// <summary>
/// The two independent per-layer keys produced from the master key by
/// HKDF-Expand, per п.3.3 of the TOR. Disposing zeroes both.
/// </summary>
public sealed class CascadeKeyMaterial : IDisposable
{
    public SecureBytes Layer1Key { get; }

    public SecureBytes Layer2Key { get; }

    internal CascadeKeyMaterial(SecureBytes layer1Key, SecureBytes layer2Key)
    {
        Layer1Key = layer1Key;
        Layer2Key = layer2Key;
    }

    public void Dispose()
    {
        Layer1Key.Dispose();
        Layer2Key.Dispose();
    }
}
