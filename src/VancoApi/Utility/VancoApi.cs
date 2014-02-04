
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

		public string Login()
		{
			var qs = new Dictionary<string, object>();
			qs["nvpvar"] = string.Empty;
			qs["requesttype"] = "login";
			qs["userid"] = VancoUserId;
			qs["password"] = VancoPassword;
			qs["requestid"] = Guid.NewGuid().ToString("N");

			var response = VancoHttp(qs);

			var sessionId = response["sessionid"];
			var requestId = response["requestid"];

			return sessionId;
		}

		public PaymentMethodResponse SavePaymentMethod(PaymentMethodRequest pm)
		{
			var form = new Dictionary<string, object>();
			form["requesttype"] = "eftaddeditpaymentmethod";
			form["requestid"] = Guid.NewGuid().ToString("N");
			form["clientid"] = VancoClientId;

			if (!string.IsNullOrWhiteSpace(pm.CustomerRef))
			{
				form["customerref"] = pm.CustomerRef;
			}
			else if (!string.IsNullOrWhiteSpace(pm.CustomerId))
			{
				form["customerid"] = pm.CustomerId;
			}
			else
			{
				throw new ApplicationException("Either CustomerRef or CustomerId must be supplied");
			}

			if (pm.DeletePm)
			{
				form["deletepm"] = "Yes";
			}

			if (pm.AccountType == "C")
			{
				form["accounttype"] = "C";
				form["accountnumber"] = pm.AccountNumber;
				form["routingnumber"] = pm.RoutingNumber;
			}
			else if (pm.AccountType == "S")
			{
				form["accounttype"] = "S";
				form["accountnumber"] = pm.AccountNumber;
				form["routingnumber"] = pm.RoutingNumber;
			}
			else if (pm.AccountType == "CC")
			{
				form["accounttype"] = "CC";
				form["accountnumber"] = pm.AccountNumber;
				form["cardbillingname"] = pm.CardBillingName;
				form["cardexpmonth"] = pm.CardExpMonth;
				form["cardexpyear"] = pm.CardExpYear;
				if (pm.SameCcBillingAddrAsCust)
				{
					form["sameccbillingaddrascust"] = "Yes";
				}
				else
				{
					form["sameccbillingaddrascust"] = "No";
					form["cardbillingaddr1"] = pm.CardBillingAddr1;
					form["cardbillingaddr2"] = pm.CardBillingAddr2;
					form["cardbillingcity"] = pm.CardBillingCity;
					form["cardbillingstate"] = pm.CardBillingState;
					form["cardbillingzip"] = pm.CardBillingZip;
				}
			}

			var qs = new Dictionary<string, object>();
			qs["sessionid"] = pm.SessionId;
			qs["nvpvar"] = EncodeVariables(form, VancoEncryptionKey);

			var response = VancoHttp(qs);

			return new PaymentMethodResponse
			       {
					   RequestId = response["requestid"],
					   CardType = response["cardtype"],
					   PaymentMethodRef = response["paymentmethodref"],
					   PaymentMethodDeleted = response["paymentmethoddeleted"] == "Yes",
			       };
		}

		private NameValueCollection VancoHttp(IDictionary<string, object> qs)
		{
			//build Uri
			var builder = new UriBuilder(VancoUri) { Port = -1 };
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
				var url = builder.Uri.ToString().Replace("nvpvar=&", "nvpvar="); //HACK:
				//var url = VancoUri + "?" + string.Join("&", qs.Select(x => x.Key + "=" + x.Value)).Replace("nvpvar=&", "nvpvar="); //HACK:
				var response = client.DownloadString(url);

				var responseQs = HttpUtility.ParseQueryString(response);
				var nvpvar = DecodeMessage(responseQs["nvpvar"], VancoEncryptionKey);
				var nvp = HttpUtility.ParseQueryString(nvpvar);

				if (!string.IsNullOrWhiteSpace(nvp["errorlist"]))
				{
					throw new ApplicationException("Error: " + GetErrorMessages(nvp["errorlist"]));
				}

				return nvp;
			}
		}

		private static string EncodeVariables(IDictionary<string, object> dict, string encryptionKey)
		{
			var values = HttpUtility.ParseQueryString(string.Empty);
			dict.Where(x => x.Value != null)
			    .ToList()
			    .ForEach(x => values[x.Key] = x.Value.ToString());
			//var message = values.ToString().Replace("+", "%20");
			var message = string.Join("&", dict.Select(x => x.Key + "=" + x.Value));
			return EncodeMessage(message, encryptionKey);
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
			//bytes = Pad(bytes, 4.0, "=");
			// Decrypt Rijndael
			bytes = Decrypt(bytes, encryptionKey);
			// De-gzip
			message = DecompressData(bytes);
			// Convert to Ascii
			//message = Encoding.ASCII.GetString(bytes);
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

		private static string DecompressData(byte[] inData)
		{
			using (var mem = new MemoryStream(inData))
			{
				using (var gz = new DeflateStream(mem, CompressionMode.Decompress))
				{
					using (var sw = new StreamReader(gz))
					{
						string outData = sw.ReadLine();
						sw.Close();

						return outData;
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

		public static byte[] Decrypt(byte[] data, string encryptionKey)
		{
			byte[] decrypted;
			// Create an AesManaged object 
			// with the specified key and IV. 
			using (var rijAlg = new AesManaged())
			{
				// below key used as an example, contact Vanco for your unique encryption key
				rijAlg.Key = Encoding.ASCII.GetBytes(encryptionKey);
				rijAlg.Padding = PaddingMode.None;
				rijAlg.Mode = CipherMode.ECB;
				var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
				using (var msDecrypt = new MemoryStream())
				{
					using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
					{
						csDecrypt.Write(data, 0, data.Length);
					}
					decrypted = msDecrypt.ToArray();
				}
			}

			// Return the encrypted bytes from the memory stream. 
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

		private static readonly Dictionary<string, string> _Errors = new Dictionary<string, string>
		{
			{ "495", "Field Contains Invalid Characters" },
		};

		private static string GetErrorMessages(string errorlist)
		{
			return String.Join(",", errorlist.Split(',')
			                                 .Select(x => _Errors.ContainsKey(x) ? _Errors[x] : x));
		}
	};

	public class PaymentMethodRequest
	{
		public string SessionId { get; set; }
		public string CustomerRef { get; set; }
		public string CustomerId { get; set; }
		public string PaymentMethodRef { get; set; }
		public bool DeletePm { get; set; }
		public string AccountType { get; set; }
		public string AccountNumber { get; set; }
		public string RoutingNumber { get; set; }
		public string CardBillingName { get; set; }
		public string CardExpMonth { get; set; }
		public string CardExpYear { get; set; }
		public bool SameCcBillingAddrAsCust { get; set; }
		public string CardBillingAddr1 { get; set; }
		public string CardBillingAddr2 { get; set; }
		public string CardBillingCity { get; set; }
		public string CardBillingState { get; set; }
		public string CardBillingZip { get; set; }
	};

	public class PaymentMethodResponse
	{
		public string RequestId { get; set; }
		public string CardType { get; set; }
		public string PaymentMethodRef { get; set; }
		public bool PaymentMethodDeleted { get; set; }
	};

	public class Trnx
	{
		public string SessionId { get; set; }
		public string CustomerRef { get; set; }
		public string CustomerId { get; set; }
		public string CustomerName { get; set; }
		public string CustomerAddress1 { get; set; }
		public string CustomerAddress2 { get; set; }
		public string CustomerCity { get; set; }
		public string CustomerState { get; set; }
		public string CustomerZip { get; set; }
		public string CustomePhone { get; set; }
	};
}
