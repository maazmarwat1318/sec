using System.Security.Cryptography;
using System.Text;

public interface IEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
}

public class EncryptionService : IEncryptionService
{
    private readonly byte[] _key; // In production, load this from Azure Key Vault or Environment Variables
    private const int NonceSize = 12; // AES-GCM standard
    private const int TagSize = 16;

    public EncryptionService(string base64Key)
    {
        _key = Convert.FromBase64String(base64Key);
    }

    public string Encrypt(string plainText)
    {
        using var aes = new AesGcm(_key, TagSize);
        byte[] nonce = new byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[TagSize];

        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

        // Concatenate Nonce + Tag + Ciphertext into one string for storage
        return Convert.ToBase64String(nonce.Concat(tag).Concat(ciphertext).ToArray());
    }

    public string Decrypt(string combinedBase64)
    {
        byte[] data = Convert.FromBase64String(combinedBase64);
        byte[] nonce = data.Take(NonceSize).ToArray();
        byte[] tag = data.Skip(NonceSize).Take(TagSize).ToArray();
        byte[] ciphertext = data.Skip(NonceSize + TagSize).ToArray();

        using var aes = new AesGcm(_key, TagSize);
        byte[] decryptedBytes = new byte[ciphertext.Length];

        aes.Decrypt(nonce, ciphertext, tag, decryptedBytes);
        return Encoding.UTF8.GetString(decryptedBytes);
    }
}