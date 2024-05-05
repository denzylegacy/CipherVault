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

            byte[] iv = new byte[16];
            Array.Copy(encryptedBytes, iv, iv.Length);

            byte[] salt = encryptedBytes.Take(16).ToArray();
            byte[] key = UnitOfEncryption.DeriveKeyFromPassword(password, salt);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (var msDecrypt = new MemoryStream(encryptedBytes, iv.Length, encryptedBytes.Length - iv.Length))
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
