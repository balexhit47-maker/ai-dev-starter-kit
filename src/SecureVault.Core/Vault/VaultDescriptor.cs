namespace SecureVault.Core.Vault;

/// <summary>
/// One entry in the local Vaults folder listing (see п.6 of the
/// architecture addendum) — filesystem metadata only, obtained without
/// opening or decrypting anything.
/// </summary>
public sealed record VaultDescriptor(string FilePath, string FileName, long SizeBytes, DateTimeOffset LastModifiedUtc);
