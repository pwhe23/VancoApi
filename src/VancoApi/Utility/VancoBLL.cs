
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using ComponentAce.Compression.Libs.zlib;

namespace VancoBLL
{

	public class VancoHelper
	{
		private static string VANCO_ENCRYPTION_KEY = "09KzF2qMBy58ZWg137N$I4h6UwJvp!ij";
		private static string VANCO_NVPCONTENT = "vanco_nvpcontent";
		private static string VANCO_BASE_URI = "https://www.vancodev.com/cgi-bin/wsnvptest.vps";
		private static string VANCO_RETURN_URL = "http://localhost/";

		public static string EncryptAndEncodeMessage(string message, string encryptionKey)
		{
			var inData = Encoding.ASCII.GetBytes(message);

			//1. Compress
			byte[] outData = VancoHelper.CompressData(inData);

			//2. Pad
			outData = VancoHelper.Pad(outData);

			//3. Encrypt
			outData = VancoHelper.Encrypt(outData, encryptionKey);

			//4. Base 64 Encode
			return Convert.ToBase64String(outData);
		}

		public static byte[] CompressData(byte[] inData)
		{
			using (var outMemoryStream = new MemoryStream())
			using (var outZStream = new ZOutputStream(outMemoryStream, zlibConst.Z_BEST_COMPRESSION))
			using (Stream inMemoryStream = new MemoryStream(inData))
			{
				CopyStream(inMemoryStream, outZStream);
				outZStream.finish();
				return outMemoryStream.ToArray();
			}
		}

		public static void CopyStream(System.IO.Stream input, System.IO.Stream output)
		{
			var buffer = new byte[2000];
			int len;
			while ((len = input.Read(buffer, 0, 2000)) > 0)
			{
				output.Write(buffer, 0, len);
			}
			output.Flush();
		}

		public static byte[] Encrypt(byte[] data, string encryptionKey)
		{
			byte[] encrypted;

			// Create an RijndaelManaged object 
			// with the specified key and IV. 
			using (var rijAlg = new RijndaelManaged())
			{
				rijAlg.Key = Encoding.ASCII.GetBytes(encryptionKey);
				rijAlg.Padding = PaddingMode.None;
				rijAlg.Mode = CipherMode.ECB;
				var encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
				using (var msEncrypt = new MemoryStream())
				{
					using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						csEncrypt.Write(data, 0, data.Length);
					}
					encrypted = msEncrypt.ToArray();
				}
			}

			// Return the encrypted bytes from the memory stream. 
			return encrypted;
		}

		public static byte[] Pad(byte[] input)
		{
			double roundUpLength = 16.0 * Math.Ceiling((double)input.Length / 16.0);
			var output = new byte[(int)roundUpLength];
			input.CopyTo(output, 0);
			for (var i = input.Length; i < (int)roundUpLength; i++)
			{
				output[i] = Encoding.ASCII.GetBytes(" ")[0];
			}
			return output;
		}
	}
}