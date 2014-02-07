
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Diagnostics;
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
			//var response = ParseVancoResponse("nvpvar=BPRUf4hPQGCGlw9MQN6RjyvNrYD5o15Qw-BIO6Db_xzg40ZR5KwHXbMbFa5ssu5oMUiIEODXVMgH_h1sJRzoxONt8_9fE9yqj37xFGnguPk=", VancoEncryptionKey);

			var sessionId = response["sessionid"];
			var requestId = response["requestid"];

			return sessionId;
		}

		public EftResponse Eft(EftRequest model)
		{
			if (string.IsNullOrWhiteSpace(model.SessionId)) throw new ApplicationException("SessionId is required");

			var form = new Dictionary<string, object>();
			form["requesttype"] = "efttransparentredirect";
			form["requestid"] = Guid.NewGuid().ToString("N");
			form["clientid"] = VancoClientId;
			form["urltoredirect"] = "";

			if (!string.IsNullOrWhiteSpace(model.CustomerRef))
			{
				form["customerref"] = model.CustomerRef;
			}
			else if (!string.IsNullOrWhiteSpace(model.CustomerId))
			{
				form["customerid"] = model.CustomerId;
			}
			else
			{
				throw new ApplicationException("Either CustomerRef or CustomerId must be supplied");
			}

			form["isdebitcardonly"] = model.IsDebitCardOnly ? "Yes" : "No";

			if (string.IsNullOrWhiteSpace(model.CustomerId) && string.IsNullOrWhiteSpace(model.CustomerRef) && string.IsNullOrWhiteSpace(model.Name))
				throw new ApplicationException("Name is required");

			if (string.IsNullOrWhiteSpace(model.AccountType)) throw new ApplicationException("AccountType is required");
			if (string.IsNullOrWhiteSpace(model.AccountNumber)) throw new ApplicationException("AccountNumber is required");

			if (model.AccountType == "CC")
			{
				if (string.IsNullOrWhiteSpace(model.BillingAddr1)) throw new ApplicationException("BillingAddr1 is required");
				if (string.IsNullOrWhiteSpace(model.BillingCity)) throw new ApplicationException("BillingCity is required");
				if (string.IsNullOrWhiteSpace(model.BillingState)) throw new ApplicationException("BillingState is required");
				if (string.IsNullOrWhiteSpace(model.BillingZip)) throw new ApplicationException("BillingZip is required");
				if (string.IsNullOrWhiteSpace(model.NameOnCard)) throw new ApplicationException("NameOnCard is required");
				if (string.IsNullOrWhiteSpace(model.ExpMonth)) throw new ApplicationException("ExpMonth is required");
				if (string.IsNullOrWhiteSpace(model.ExpYear)) throw new ApplicationException("ExpYear is required");
				if (model.BillingState.Length != 2) throw new ApplicationException("BillingState length must be 2 digits");
				if (model.ExpMonth.Length != 2) throw new ApplicationException("ExpMonth length must be 2 digits");
				if (model.ExpYear.Length != 2) throw new ApplicationException("ExpYear length must be 2 digits");
			}
			else if (model.AccountType == "C" || model.AccountType == "S")
			{
				if (string.IsNullOrWhiteSpace(model.RoutingNumber)) throw new ApplicationException("RoutingNumber is required");
				if (model.RoutingNumber.Length != 9) throw new ApplicationException("RoutingNumber length must be 9 digits");
			}
			else
			{
				throw new ApplicationException("AccountType is invalid");
			}

			var qs = new Dictionary<string, object>();
			qs["sessionid"] = model.SessionId;
			qs["nvpvar"] = EncodeVariables(form, VancoEncryptionKey);
			qs["newcustomer"] = model.AddNewCustomer ? "true" : "false";
			qs["name"] = model.Name;
			qs["email"] = model.Email;
			qs["billingaddr1"] = model.BillingAddr1;
			qs["billingaddr2"] = model.BillingAddr2;
			qs["billingcity"] = model.BillingCity;
			qs["billingstate"] = model.BillingState;
			qs["billingzip"] = model.BillingZip;
			qs["accounttype"] = model.AccountType;
			qs["name_on_card"] = model.NameOnCard;
			qs["accountnumber"] = model.AccountNumber;
			qs["routingnumber"] = model.RoutingNumber;
			qs["expmonth"] = model.ExpMonth;
			qs["expyear"] = model.ExpYear;

			var response = VancoHttp(qs);

			return new EftResponse
			{
				SessionId = response["sessionid"],
				RequestType = response["requesttype"],
				RequestId = response["requestid"],
				ClientId = response["clientid"],
				CustomerId = response["customerid"],
				CustomerRef = response["customerref"],
				IsDebitCardOnly = response["isdebitcardonly"] == "Yes",
				PaymentMethodRef = response["paymentmethodref"],
				ErrorList = response["errorlist"],
				Last4 = response["last4"],
				VisaMcType = response["visamctype"],
				CardType = response["cardtype"],
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
				//var url = builder.Uri.ToString();
				var url = VancoUri + "?" + string.Join("&", qs.Select(x => x.Key + "=" + x.Value));
				url = url.Replace("nvpvar=&", "nvpvar="); //.Replace("/", "_").Replace("+", "-"); //HACK:
				Debug.WriteLine("GET: " + url);
				var response = client.DownloadString(url);
				return ParseVancoResponse(response, VancoEncryptionKey);
			}
		}

		private static NameValueCollection ParseVancoResponse(string response, string vancoEncryptionKey)
		{
			Debug.WriteLine("RESPONSE: " + response);
			var responseQs = HttpUtility.ParseQueryString(response);
			var nvpvar = DecodeMessage(responseQs["nvpvar"], vancoEncryptionKey);
			Debug.WriteLine("NVPVAR: " + nvpvar);
			var nvp = HttpUtility.ParseQueryString(nvpvar);

			if (!string.IsNullOrWhiteSpace(nvp["errorlist"]))
			{
				throw new ApplicationException("Error: " + GetErrorMessages(nvp["errorlist"]));
			}

			return nvp;
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
			Debug.WriteLine("MESSAGE: " + message);
			var inData = Encoding.ASCII.GetBytes(message);

			//1. Compress
			var outData = CompressData(inData);

			//2. Pad
			outData = Pad(outData);

			//3. Encrypt
			if (encryptionKey != null)
			{
				outData = Encrypt(outData, encryptionKey);
			}

			//4. Base 64 Encode
			var encoded = Convert.ToBase64String(outData);
			return encoded; //.Replace("/", "_").Replace("+", "-");
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

		private static byte[] Pad(byte[] input)
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

	public class EftRequest
	{
		public string SessionId { get; set; }
		public string CustomerId { get; set; }
		public string CustomerRef { get; set; }
		public bool IsDebitCardOnly { get; set; }
		public bool AddNewCustomer { get; set; }
		public string Name { get; set; }
		public string Email { get; set; }
		public string BillingAddr1 { get; set; }
		public string BillingAddr2 { get; set; }
		public string BillingCity { get; set; }
		public string BillingState { get; set; }
		public string BillingZip { get; set; }
		public string AccountType { get; set; }
		public string NameOnCard { get; set; }
		public string AccountNumber { get; set; }
		public string RoutingNumber { get; set; }
		public string ExpMonth { get; set; }
		public string ExpYear { get; set; }
	};

	public class EftResponse
	{
		public string SessionId { get; set; }
		public string RequestType { get; set; }
		public string RequestId { get; set; }
		public string ClientId { get; set; }
		public string UrlToRedirect { get; set; }
		public string CustomerId { get; set; }
		public string CustomerRef { get; set; }
		public bool IsDebitCardOnly { get; set; }
		public string PaymentMethodRef { get; set; }
		public string ErrorList { get; set; }
		public string Last4 { get; set; }
		public string VisaMcType { get; set; }
		public string CardType { get; set; }
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
