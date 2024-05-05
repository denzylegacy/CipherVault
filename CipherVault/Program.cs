namespace CipherVault
{
    class Program
    {
        static void Main()
        {
            string plainText = "Sensitive text that needs to be encrypted!";
            // This password'll only be used for development support purposes
            string password = "3$gjL1p$ypre!9ql/^L!wgBH%*bAe0#K*g9!0ffvFh*Dsvm2iC&HjysNtsUARyyn";


            #region Password
            var generator = new PasswordGenerator();
            string _password = generator.Generate();
            Console.WriteLine("Generated Password:");
            Console.WriteLine(_password);
            #endregion

            #region Encrypt
            string cipherText = UnitOfEncryption.EncryptText(plainText, password);
            Console.WriteLine("Encrypted Text:");
            Console.WriteLine(cipherText);

            Console.ReadLine();
            #endregion


            #region Decryption
            string decryptedText = UnitOfDecryption.DecryptText(cipherText, password);
            Console.WriteLine("Texto Descriptografado:");
            Console.WriteLine(decryptedText);

            Console.ReadLine();
            #endregion
        }
    }
}
