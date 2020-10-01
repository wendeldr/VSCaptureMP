from Cryptodome.Cipher import AES
import gzip

key = b'\x63\x8E\x28\x4D\x21\xEC\x4B\x6E\x93\x95\xD6\x41\x3C\x69\x72\x82\x23\x68\x4A\xDF\x60\x3C\xBF\xFF\xA1\xE4\x70\xCA\x50\x6F\xE6\x7B'
ivADL = b'\xD8\xF6\xAA\xAC\x63\x60\x5E\xA7\xA1\x9D\x76\x77\xA4\xD6\xC5\x8C'

aesFile = open(r'C:\Users\jfannon\Desktop\Customer Projects\UC-Deep-SQL\WorkspaceSQL\DCA632206690_20200927_0001_0000.dat.aes', "rb")
ciphertext = aesFile.read()
aesFile.close()
cipher = AES.new(key, AES.MODE_CBC, iv=ivADL)
decryptedData = cipher.decrypt(ciphertext)


uncompressedData = gzip.decompress(decryptedData)


# read in seperate gzip file and decompress
# data=gzip.open(r'C:\Users\jfannon\Desktop\Customer Projects\UC-Deep\VSCapture Data files\9-28-2020\DCA632206690_20200928_0001_0000.dat.gz', 'rb')