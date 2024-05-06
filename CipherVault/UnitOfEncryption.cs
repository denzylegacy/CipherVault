using System.Security.Cryptography;

namespace CipherVault
{
    public class UnitOfEncryption
    {
        /// <summary>
        /// Encrypts a plaintext string using AES encryption with a key derived from the provided password.
        /// </summary>
        /// <param name="plainText">The plaintext string to be encrypted.</param>
        /// <param name="password">The password used to derive the encryption key.</param>
        /// <returns>The encrypted text represented as a Base64-encoded string.</returns>
        public static string EncryptText(string plainText, string password)
        {
            byte[] salt = GenerateRandomSalt();

            const int keySize = 256;
            byte[] key = DeriveKeyFromPassword(password, salt, keySize / 8);
            
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.GenerateIV();

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                byte[] encryptedBytes;
                using (var msEncrypt = new MemoryStream())
                {
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);

                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    encryptedBytes = msEncrypt.ToArray();
                }

                return Convert.ToBase64String(encryptedBytes);
            }
        }

        /// <summary>
        /// This method derives a 256-bit AES cryptographic key from a password and a salt using PBKDF2 (Password-Based Key Derivation Function 2).
        /// </summary>
        /// <param name="password">The password from which the key will be derived.</param>
        /// <param name="salt">The salt (random value) used as additional input in key derivation.</param>
        /// <returns>The derived 256-bit AES cryptographic key as a byte array.</returns>
        public static byte[] DeriveKeyFromPassword(string password, byte[] salt, int keySizeInBytes)
        {
            const int iterations = 100_000;
            using (var rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, salt, iterations))
            {
                return rfc2898DeriveBytes.GetBytes(keySizeInBytes); // 256
            }
        }

        /// <summary>
        /// Generates a random salt of 32-bits
        /// </summary>
        /// <returns>A byte array containing the random salt.</returns>
        private static byte[] GenerateRandomSalt()
        {
            byte[] salt = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }
    }
}
