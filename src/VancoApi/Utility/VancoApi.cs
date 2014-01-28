
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using ComponentAce.Compression.Libs.zlib;

namespace Site
{
	//REF: http://docs.vancodev.com/doku.php?id=nvp:examplecode#c
	public class VancoApi
	{
		private readonly string VancoClientId;
		private readonly string VancoUserId;
		private readonly string VancoEncryptionKey;
		private readonly string VancoPassword;
		private readonly string VancoUri;

		public VancoApi()
		{
			var cs = ConfigurationManager.ConnectionStrings["Vanco"].ConnectionString;
			var dict = cs.Split(';').Select(x => x.Split(new[] { '=' }, 2)).Where(x => x.Length == 2).ToDictionary(x => x[0], x => x[1]);

			VancoClientId = dict["ClientId"];
			VancoUserId = dict["UserId"];
			VancoEncryptionKey = dict["EncryptionKey"];
			VancoPassword = dict["Password"];
			VancoUri = dict["Uri"]; //"https://www.vancodev.com/cgi-bin/wsdebug.vps"
		}

		public void Login()
		{
			var qs = new Dictionary<string, object>();
			qs["nvpvar"] = string.Empty;
			qs["requesttype"] = "login";
			qs["userid"] = VancoUserId;
			qs["password"] = VancoPassword;
			qs["requestid"] = DateTime.Now.Ticks;

			//var response = HttpPost(VancoUri, qs);
			var response = "nvpvar=O41MKt44jIZo_bP73AyzuU81YDTMk9ktmDOh4UjW999ddJ1hH35exnE6f-I4aHdKht3yHotg-cqE1uh2jZhbQQgzokv1ypAmFLt8IVxANLc="; //ok

			var responseQs = HttpUtility.ParseQueryString(response);
			var nvpvar = DecodeMessage(responseQs["nvpvar"] + "=", VancoEncryptionKey);
			var resultQs = HttpUtility.ParseQueryString(nvpvar);

			var sessionId = resultQs["sessionid"];
			var requestId = resultQs["requestid"];
			//TODO: something with the sessionid
		}

		private static string HttpPost(string url, IDictionary<string, object> qs = null)
		{
			//build Uri
			var builder = new UriBuilder(url) { Port = -1 };
			var values = HttpUtility.ParseQueryString(builder.Query);

			//Populate querystring if provided
			if (qs != null)
			{
				qs.Where(x => x.Value != null)
				  .ToList()
				  .ForEach(x => values[x.Key] = x.Value.ToString());

			}
			builder.Query = values.ToString();

			//send request
			using (var client = new WebClient())
			{
				url = builder.Uri.ToString().Replace("nvpvar=&", "nvpvar="); //HACK: 
				return client.DownloadString(url); 
			}
		}

		private static string EncodeMessage(string message, string encryptionKey)
		{
			var inData = Encoding.ASCII.GetBytes(message);

			//1. Compress
			var outData = CompressData(inData);

			//2. Pad
			outData = Pad(outData, 16.0, " ");

			//3. Encrypt
			if (encryptionKey != null)
			{
				outData = Encrypt(outData, encryptionKey);
			}

			//4. Base 64 Encode
			return Convert.ToBase64String(outData);
		}

		private static string DecodeMessage(string message, string encryptionKey)
		{
			// replace invalid characters
			message = message.Replace('-', '+').Replace('_', '/');
			// Base64 decode
			var bytes = Convert.FromBase64String(message);
			// Pad length before decrypting
			bytes = Pad(bytes, 4.0, "=");
			// Decrypt Rijndael
			bytes = Decrypt(bytes, encryptionKey);
			// De-gzip
			bytes = DecompressData2(bytes);
			// Convert to Ascii
			message = Encoding.ASCII.GetString(bytes);
			return message.Trim();
		}

		private static byte[] CompressData(byte[] inData)
		{
			using (var outMemoryStream = new MemoryStream())
			using (var outZStream = new ZOutputStream(outMemoryStream, zlibConst.Z_DEFAULT_COMPRESSION))
			using (Stream inMemoryStream = new MemoryStream(inData))
			{
				CopyStream(inMemoryStream, outZStream);
				outZStream.finish();
				return outMemoryStream.ToArray();
			}
		}

		//Throws "inflating: unknown compression method"
		private static byte[] DecompressData(byte[] inData)
		{
			using (var outputStream = new MemoryStream())
			{
				using (var outZStream = new ZOutputStream(outputStream))
				{
					using (var inputStream = new MemoryStream(inData))
					{
						CopyStream(inputStream, outZStream);
						outZStream.finish();
						return outputStream.ToArray();
					}
				}
			}
		}

		//Is able to decompress about 50% of the time, other is incoherent
		private static byte[] DecompressData2(byte[] bytes)
		{
			using (var input = new MemoryStream(bytes))
			{
				using (var ds = new DeflateStream(input, CompressionMode.Decompress))
				{
					using (var output = new MemoryStream())
					{
						ds.CopyTo(output);
						return output.ToArray();
					}
				}
			}
		}

		private static byte[] Pad(byte[] input, double mod, string pad)
		{
			var roundUpLength = mod * Math.Ceiling((double)input.Length / mod);
			var output = new byte[(int)roundUpLength];
			input.CopyTo(output, 0);
			for (var i = input.Length; i < (int)roundUpLength; i++)
			{
				output[i] = Encoding.ASCII.GetBytes(pad)[0];
			}
			return output;
		}

		private static byte[] Encrypt(byte[] data, string encryptionKey)
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

		private static byte[] Decrypt(byte[] data, string encryptionKey)
		{
			byte[] decrypted;

			using (var rijAlg = new RijndaelManaged())
			{
				rijAlg.Key = Encoding.ASCII.GetBytes(encryptionKey);
				rijAlg.Padding = PaddingMode.None;
				rijAlg.Mode = CipherMode.ECB;

				var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
				using (var msEncrypt = new MemoryStream())
				{
					using (var csDecrypt = new CryptoStream(msEncrypt, decryptor, CryptoStreamMode.Write))
					{
						csDecrypt.Write(data, 0, data.Length);
					}
					decrypted = msEncrypt.ToArray();
				}
			}

			return decrypted;
		}

		private static void CopyStream(Stream input, Stream output)
		{
			var buffer = new byte[2000];
			int len;
			while ((len = input.Read(buffer, 0, buffer.Length)) > 0)
			{
				output.Write(buffer, 0, len);
			}
			output.Flush();
		}
	};
}
