using System;
using System.IO;
using System.Security.Cryptography;

namespace Aes_Example
{
    class AesExample
    {
        public static void Main()
        {
	    FileDecrypt(@"/home/dan/Downloads/DCA632206690_20200309_0002_0000/DCA632206690_20200309_0002_0000.dat.aes",@"/home/dan/Downloads/DCA632206690_20200309_0002_0000/test.txt");
        }

	/// <summary>
	/// Decrypts an encrypted file with the FileEncrypt method through its path and the plain password.
	/// </summary>
	/// <param name="inputFile"></param>
	/// <param name="outputFile"></param>
	static void FileDecrypt(string inputFile, string outputFile)
	{
	    using (Aes myAes = Aes.Create())
            {

	    myAes.Key = new byte[] {0x63,0x8E,0x28,0x4D,0x21,0xEC,0x4B,0x6E,0x93,0x95,0xD6,0x41,0x3C,0x69,0x72,0x82,0x23,0x68,0x4A,0xDF,0x60,0x3C,0xBF,0xFF,0xA1,0xE4,0x70,0xCA,0x50,0x6F,0xE6,0x7B};

	    myAes.IV = new byte[] {0xD8,0xF6,0xAA,0xAC,0x63,0x60,0x5E,0xA7,0xA1,0x9D,0x76,0x77,0xA4,0xD6,0xC5,0x8C};


	    byte[] salt = new byte[32];

	    FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
	    fsCrypt.Read(salt, 0, salt.Length);

	    CryptoStream cs = new CryptoStream(fsCrypt, myAes.CreateDecryptor(), CryptoStreamMode.Read);

	    FileStream fsOut = new FileStream(outputFile, FileMode.Create);

	    int read;
	    byte[] buffer = new byte[1048576];

	    try
	    {
		while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
		{
		    fsOut.Write(buffer, 0, read);
		}
	    }
	    catch (CryptographicException ex_CryptographicException)
	    {
		Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
	    }
	    catch (Exception ex)
	    {
		Console.WriteLine("Error: " + ex.Message);
	    }

	    try
	    {
		cs.Close();
	    }
	    catch (Exception ex)
	    {
		Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
	    }
	    finally
	    {
		fsOut.Close();
		fsCrypt.Close();
	    }
	    }
	}

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}
