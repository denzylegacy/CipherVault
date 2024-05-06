using System.Security.Cryptography;

namespace CipherVault
{
    public class UnitOfDecryption
    {
        /// <summary>
        /// Decrypts a ciphertext string using AES decryption with a key derived from the provided password.
        /// </summary>
        /// <param name="cipherText">The ciphertext string to be decrypted (Base64-encoded).</param>
        /// <param name="password">The password used to derive the decryption key.</param>
        /// <returns>The decrypted plaintext string.</returns>
        public static string DecryptText(string cipherText, string password)
        {
            byte[] encryptedBytes = Convert.FromBase64String(cipherText);

            byte[] salt = encryptedBytes.Take(16).ToArray();
            byte[] iv = encryptedBytes.Skip(16).Take(16).ToArray();

            const int keySize = 256;
            byte[] key = UnitOfEncryption.DeriveKeyFromPassword(password, salt, keySize / 8);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var msDecrypt = new MemoryStream(encryptedBytes, 32, encryptedBytes.Length - 32))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
