using System;
using System.IO;
using System.Security.Cryptography;

namespace Aes_Example
{
    class AesExample
    {
        public static int Main(string[] args)
        {

			if (args.Length == 0)
			{
				System.Console.WriteLine("Please enter a folder to parse.");
				return 1;
			}

			string[] filePaths = Directory.GetFiles(args[0], "*.aes");
			foreach (string infile in filePaths) 
			{
				string outfile = System.IO.Path.ChangeExtension(infile, null);
            	System.Console.WriteLine("Decrypting file: {0} >> {1}", infile, outfile);

				FileDecrypt(infile, outfile);
			}
			return 0;
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

	    FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);

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
    }
}
