
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
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
			qs["requestid"] = "635260894372186928";// DateTime.Now.Ticks;

			//var response = HttpPost(VancoUri + "?nvpvar=requesttype=login&userid=MARTSOLU&password=v@nco2oo&requestid=635260894372186927", null);
			//var response = HttpPost(VancoUri, qs);
			//var response = "nvpvar=XcQ3XCwmi9VFcZ2pkY4mmv095P0fVsmtZphjtuZWm5HyIgjiBr1fMsyEVshusQDhb1tBN4S47bAs-0hpEF4_j2HhoOHziPmQ93ttC9Ttjwc="; //not
			//var response = "nvpvar=sIWE_LEEkjz0Ab8GtWFuqZHCDHZBfLP8CzAPf63j4nHOQ6Sj_q0Ov2TmdaZBbN7p3dUT0WWPiJyoshpHwyGZQIRkldeCJb16W5Jws1qf_w0="; //not
			//var response = "nvpvar=nypmlgLdfq3fb0OrN2PrqEcy1k2jKlnXDdq-fwSwM_AfP1ahLmLmz3J0LPDQUqoBeIxNNyi4cddBx-ej8q6yAz5tWZ4TV6O5hDrLJmY0En4="; //not
			//var response = "nvpvar=W-QQ-PcAMFlp3A5anlBGsQk81oN5PEC30XKc4xwR7DWrGxtTF7guSsO1aeNrtK1btM9vXsfBE6MXtZgauC8BLH2d049-5M5SPciAH2bnVLs="; //ok
			//var response = "nvpvar=8mmbN790xCsGHRks1JbBoGAfA1uchqC4MWqoUrPnnGah-vmpJGFixsDiDyFy2banbuMGno3-vgoOD6jmoCn_NyetXxpnKQvtyrQ2t9IGgfE="; //not
			//var response = "nvpvar=H21mh8ryxYG5vY_5zE0yymxUeSsm-OS1Rs0zl2lKM6lHENL_N2VhxMdOlWTJy3qE4hd_Spmh1cyOWmBS-dWwZUjO5pBLQjCGbnj-x5PQ0uQ="; //ok
			var response = "nvpvar=O41MKt44jIZo_bP73AyzuU81YDTMk9ktmDOh4UjW999ddJ1hH35exnE6f-I4aHdKht3yHotg-cqE1uh2jZhbQQgzokv1ypAmFLt8IVxANLc="; //ok
			//var response = "nvpvar=A9cc9tnD34cs7GdVuiHSU9u1ziFbJClOEIRPY3TbYwWTCVHKwB7oAD6ZFoMXTtZqR9Xfar_RLvErLeZoxEzVr4VugAiQ9pBbHByAWFSgcJ8="; //not


			var responseQs = HttpUtility.ParseQueryString(response);
			var nvpvar = DecodeMessage(responseQs["nvpvar"] + "=", VancoEncryptionKey);
			var resultQs = HttpUtility.ParseQueryString(nvpvar);

		}

		private static string HttpPost(string url, IDictionary<string, object> qs)
		{
			//create Uri
			var builder = new UriBuilder(url) {Port = -1};
			var values = HttpUtility.ParseQueryString(builder.Query);

			//Populate querystring
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
				//client.QueryString = values;
				//return client.UploadString(url, "GET", string.Empty);
				return client.DownloadString(builder.Uri.ToString().Replace("nvpvar=&", "nvpvar="));
			}
		}

		//REF: http://stackoverflow.com/questions/566462/upload-files-with-httpwebrequest-multipart-form-data
		private static string HttpPost(string url, IDictionary<string, object> form, IEnumerable<string> files)
		{
			if (form == null) form = new Dictionary<string, object>();
			if (files == null) files = new string[0];

			var boundary = "----------------------------" + DateTime.Now.Ticks.ToString("x");

			var request = (HttpWebRequest)WebRequest.Create(url);
			request.ContentType = "multipart/form-data; boundary=" + boundary;
			request.Method = "POST";
			request.KeepAlive = true;
			request.Credentials = CredentialCache.DefaultCredentials;

			Stream memStream = new MemoryStream();
			var boundarybytes = Encoding.ASCII.GetBytes("\r\n--" + boundary + "\r\n");
			var formdataTemplate = "\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"{0}\";\r\n\r\n{1}";

			//write out name value pairs for form
			foreach (var item in form)
			{
				var formitem = string.Format(formdataTemplate, item.Key, item.Value);
				var formitembytes = Encoding.UTF8.GetBytes(formitem);
				memStream.Write(formitembytes, 0, formitembytes.Length);
			}
			memStream.Write(boundarybytes, 0, boundarybytes.Length);

			//write out the files
			const string headerTemplate = "Content-Disposition: form-data; name=\"{0}\"; filename=\"{1}\"\r\nContent-Type: application/octet-stream\r\n\r\n";
			foreach (var file in files)
			{
				var header = string.Format(headerTemplate, "upload", file);
				var headerbytes = Encoding.UTF8.GetBytes(header);
				memStream.Write(headerbytes, 0, headerbytes.Length);
				var buffer = new byte[1024];
				using (var fileStream = new FileStream(file, FileMode.Open, FileAccess.Read))
				{
					var bytesRead = 0;
					while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) != 0)
					{
						memStream.Write(buffer, 0, bytesRead);
					}
					memStream.Write(boundarybytes, 0, boundarybytes.Length);
				}
			}

			//write memory stream to request
			request.ContentLength = memStream.Length;
			memStream.Position = 0;
			using (var stream = request.GetRequestStream())
			{
				var tempBuffer = new byte[memStream.Length];
				memStream.Read(tempBuffer, 0, tempBuffer.Length);
				memStream.Close();
				stream.Write(tempBuffer, 0, tempBuffer.Length);
			}

			//get response
			using (var response = request.GetResponse())
			using (var stream = response.GetResponseStream())
			using (var reader = new StreamReader(stream))
			{
				return reader.ReadToEnd();
			}
		}

		private static string VANCO_NVPCONTENT = "vanco_nvpcontent";
		private static string VANCO_BASE_URI = "vanco_base_uri";
		private static string ADDITIONALinfo = "";
		private static string VANCO_RETURN_URL = "";

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
			//var decoded = Convert.FromBase64String(message);
			message = message.Replace('-', '+').Replace('_', '/');
			var bytes = Convert.FromBase64String(message);
			bytes = Pad(bytes, 4.0, "=");
			bytes = Decrypt(bytes, encryptionKey);
			bytes = DecompressData2(bytes);
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

		private static byte[] DecompressData(byte[] inData)
		{
			using (var outputStream = new MemoryStream())
			{
				using (var outZStream = new ZOutputStream(outputStream))
				{
					using (var inputStream = new MemoryStream(inData))
					{
						CopyStream(inputStream, outZStream);
						return outputStream.ToArray();
					}
				}
			}
		}

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
			//input.Seek(0, SeekOrigin.Begin);
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
