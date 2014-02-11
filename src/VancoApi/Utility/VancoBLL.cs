
using System;
using System.IO;
using System.Text;

namespace VancoBLL
{

	public class VancoHelper
	{
		private static string VANCO_ENCRYPTION_KEY = "09KzF2qMBy58ZWg137N$I4h6UwJvp!ij";
		private static string VANCO_NVPCONTENT = "vanco_nvpcontent";
		private static string VANCO_BASE_URI = "https://www.vancodev.com/cgi-bin/wsnvptest.vps";
		private static string VANCO_RETURN_URL = "http://localhost/";

		public static string EncryptAndEncodeMessage(string message)
		{

			dynamic inData = Encoding.ASCII.GetBytes(message);

			//1. Compress

			byte[] outData = null;
			System.IO.MemoryStream mem = new System.IO.MemoryStream();
			System.IO.Compression.DeflateStream gz = new System.IO.Compression.DeflateStream(mem, System.IO.Compression.CompressionMode.Compress);
			System.IO.StreamWriter sw = new System.IO.StreamWriter(gz);
			sw.Write(message);
			sw.Close();
			outData = mem.ToArray();

			//2. Pad

			outData = Pad(outData);

			//3. Encrypt

			outData = Encrypt(outData);

			//4. Base 64 Encode
			return Convert.ToBase64String(outData);


		}


		public static byte[] Encrypt(byte[] data)
		{

			byte[] encrypted = null;

			// Create an RijndaelManaged object 

			// with the specified key and IV. 

			using (var rijAlg = new System.Security.Cryptography.AesManaged())
			{

				rijAlg.Key = Encoding.ASCII.GetBytes("09KzF2qMBy58ZWg137N$I4h6UwJvp!ij");

				rijAlg.Padding = System.Security.Cryptography.PaddingMode.None;

				rijAlg.Mode = System.Security.Cryptography.CipherMode.ECB;

				dynamic encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

				using (var msEncrypt = new MemoryStream())
				{

					using (var csEncrypt = new System.Security.Cryptography.CryptoStream(msEncrypt, encryptor, System.Security.Cryptography.CryptoStreamMode.Write))
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

			double roundUpLength = 16.0 * Math.Ceiling(Convert.ToDouble(input.Length) / 16.0);

			dynamic output = new byte[Convert.ToInt32(roundUpLength)];


			input.CopyTo(output, 0);

			for (int i = input.Length; i <= Convert.ToInt32(roundUpLength) - 1; i++)
			{
				output[i] = Encoding.ASCII.GetBytes(" ")[0];
			}

			return output;

		}
	}
}