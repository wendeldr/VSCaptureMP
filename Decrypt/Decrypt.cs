using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
namespace Aes_Example
{
    class AesExample
    {

        public static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                System.Console.WriteLine("Please enter a folder to parse and a folder to output to. If no output folder given will output to input folder");
                return 1;
            }
            // System.Console.WriteLine("Serching for folders in {0}", args[0]);

            // string[] folders = Directory.GetDirectories(args[0]);
            // //string[] folders = Directory.GetDirectories(@"D:\data\deeplab\ICU\tmp\DCA6324D35E1\DCA6324D35E1");
            // foreach (string folder in folders)
            // {


            if (args.Length == 1)
            {
                System.Console.WriteLine("Decrypting *.aes in {0}", args[0]);

                System.Console.WriteLine("Outputting to input folder.");
                string[] aesFiles = Directory.GetFiles(args[0], "*.aes", SearchOption.AllDirectories);
                string[] datFiles = Directory.GetFiles(args[0], "*.dat", SearchOption.AllDirectories);

                Parallel.For(0, aesFiles.Length, i=>{
                    try{
                        if (!Array.Exists(datFiles, element =>  Path.GetFileName(element) == Path.GetFileName(aesFiles[i]).Substring(0,Path.GetFileName(aesFiles[i]).Length - 4)) ){
                            string outfile = System.IO.Path.ChangeExtension(aesFiles[i], null);
                            System.Console.WriteLine("Decrypting file: {0} >> {1}", aesFiles[i], outfile);
                            FileDecrypt(aesFiles[i], outfile);
                        }

                    }catch (Exception ex){
                        Console.WriteLine("Error in Parfor: " + ex.Message);
                    }
                });
                
            }else{
                System.Console.WriteLine("Decrypting *.aes in {0}", args[0]);
                System.Console.WriteLine("Outputting to folder {0} orginized by date.", args[1]);
                string[] aesFiles = Directory.GetFiles(args[0], "*.aes", SearchOption.AllDirectories);
                string[] datFiles = Directory.GetFiles(args[0], "*.dat", SearchOption.AllDirectories);

                Parallel.For(0, aesFiles.Length, i=>{
                    try{

                        if (!Array.Exists(datFiles, element =>  Path.GetFileName(element) == Path.GetFileName(aesFiles[i]).Substring(0,Path.GetFileName(aesFiles[i]).Length - 4)) ){
                            string[] parts =  Path.GetFileName(aesFiles[i]).Split(new [] { '_' });
                            string folder_path = Path.Combine(args[1],parts[1],parts[0]);

                            new DirectoryInfo(folder_path).Create();

                            string outfile = Path.Combine(folder_path, System.IO.Path.ChangeExtension(Path.GetFileName(aesFiles[i]), null));
                            System.Console.WriteLine("Decrypting file: {0} >> {1}", aesFiles[i], outfile);

                            FileDecrypt(aesFiles[i], outfile);
                        }
                    }catch (Exception ex){
                        Console.WriteLine("Error in Parfor: " + ex.Message);
                    }

                });
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

        //FileStream fsOut = new FileStream(outputFile, FileMode.Create);

        int read;
        //byte[] buffer = new byte[1048576];
        byte[] buffer = new byte[1024];

        try
        {
             using (System.IO.StreamWriter file = new System.IO.StreamWriter(outputFile, true))
            {
                // bool flag = true;
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    string converted = Encoding.UTF8.GetString(buffer, 0, read);
                    converted = Regex.Replace(converted, @"\00", "");
                    // if (flag){
                    //     //System.Console.WriteLine(converted);
                    //     flag = false;
                    // }       
                    //System.Console.Write(converted);
                    file.Write(converted);
                    //fsOut.Write(buffer, 0, read);

                }
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
        //fsOut.Close();
        fsCrypt.Close();
        }
        }
    }
    }
}
