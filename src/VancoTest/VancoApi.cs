
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Vanco
{
	//REF: http://docs.vancodev.com/doku.php?id=nvp:examplecode#c
	public class VancoConnection
	{
		public VancoConnection()
		{
			var cs = ConfigurationManager.ConnectionStrings["Vanco"].ConnectionString;
			var dict = cs.Split(';').Select(x => x.Split(new[] { '=' }, 2)).Where(x => x.Length == 2).ToDictionary(x => x[0], x => x[1]);

			VancoClientId = dict["ClientId"];
			VancoUserId = dict["UserId"];
			VancoEncryptionKey = dict["EncryptionKey"];
			VancoPassword = dict["Password"];
			VancoUri = dict["Uri"];
		}

		public string VancoClientId { get; set; }
		public string VancoUserId { get; set; }
		public string VancoEncryptionKey { get; set; }
		public string VancoPassword { get; set; }
		public string VancoUri { get; set; }
		public string SessionId { get; set; }
		
		public string CreateRequestId()
		{
			return Guid.NewGuid().ToString("N");
		}

		public NameValueCollection HttpGet(IDictionary<string, object> qs)
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

			using (var client = new WebClient())
			{
				var url = builder.Uri.ToString();
				url = url.Replace("nvpvar=&", "nvpvar="); //HACK:

				// send Request
				Debug.WriteLine("GET: " + url);
				var response = client.DownloadString(url);

				// process Response
				return DecodeNvpvar(response, VancoEncryptionKey);
			}
		}

		public NameValueCollection HttpPost(IDictionary<string, object> qs, IDictionary<string, object> form)
		{
			//build Uri
			var builder = new UriBuilder(VancoUri) { Port = -1 };

			//Populate querystring if provided
			var qsValues = HttpUtility.ParseQueryString(builder.Query);
			if (qs != null)
			{
				qs.Where(x => x.Value != null)
				  .ToList()
				  .ForEach(x => qsValues[x.Key] = x.Value.ToString());

			}
			builder.Query = qsValues.ToString();

			//Form
			var formValues = HttpUtility.ParseQueryString(string.Empty);
			if (form != null)
			{
				form.Where(x => x.Value != null)
					.ToList()
					.ForEach(x => formValues[x.Key] = x.Value.ToString());
			}

			using (var client = new WebClient())
			{
				var url = builder.Uri.ToString();

				// send Request
				Debug.WriteLine("POST: " + url + ", FORM: " + formValues);
				var response = Encoding.ASCII.GetString(client.UploadValues(url, "POST", formValues));

				// process Response
				return DecodeNvpvar(response, VancoEncryptionKey);
			}
		}

		private static NameValueCollection DecodeNvpvar(string response, string vancoEncryptionKey)
		{
			if (response.Contains("http-equiv"))
			{
				var start = response.IndexOf("url=http://localhost/?") + 22;
				var end = response.IndexOf("\">", start);
				response = response.Substring(start, end - start);
			} 
			else if (response.Contains("<html>"))
			{
				throw new ApplicationException("ERROR: " + response);
			}

			Debug.WriteLine("RESPONSE: " + response);
			var responseQs = HttpUtility.ParseQueryString(response);
			var nvpvar = DecodeMessage(responseQs["nvpvar"], vancoEncryptionKey);

			Debug.WriteLine("NVPVAR: " + nvpvar);
			var nvp = HttpUtility.ParseQueryString(nvpvar);

			if (!string.IsNullOrWhiteSpace(nvp["errorlist"]))
			{
				var msg = GetErrorMessages(nvp["errorlist"]);
				Debug.WriteLine("ERROR: " + msg);
				throw new ApplicationException("Error: " + msg);
			}

			return nvp;
		}

		public string EncodeNvpvar(IDictionary<string, object> dict)
		{
			var message = string.Join("&", dict.Select(x => x.Key + "=" + x.Value));

			Debug.WriteLine("MESSAGE: " + message);
			message = EncryptAndEncodeMessage(message, VancoEncryptionKey);

			return message.Replace("/", "_").Replace("+", "-").TrimEnd();
		}

		private static string EncryptAndEncodeMessage(string message, string encryptionKey)
		{
			//1. Compress
			var outData = Compress(message);

			//2. Pad
			outData = Pad(outData);

			//3. Encrypt
			outData = Encrypt(outData, encryptionKey);

			//4. Base 64 Encode
			return Convert.ToBase64String(outData);
		}

		private static byte[] Compress(string message)
		{
			using (var mem = new MemoryStream())
			using (var gz = new DeflateStream(mem, CompressionMode.Compress))
			using (var sw = new StreamWriter(gz))
			{
				sw.Write(message);
				sw.Close();
				return mem.ToArray();
			}
		}

		private static byte[] Encrypt(byte[] data, string encryptionKey)
		{
			// Create an RijndaelManaged object  with the specified key and IV. 
			using (var rijAlg = new AesManaged())
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

					// Return the encrypted bytes from the memory stream. 
					return msEncrypt.ToArray();
				}
			}
		}

		private static byte[] Pad(byte[] input)
		{
			var roundUpLength = 16.0 * Math.Ceiling(Convert.ToDouble(input.Length) / 16.0);
			var output = new byte[Convert.ToInt32(roundUpLength)];
			input.CopyTo(output, 0);

			for (var i = input.Length; i <= Convert.ToInt32(roundUpLength) - 1; i++)
			{
				output[i] = Encoding.ASCII.GetBytes(" ")[0];
			}

			return output;
		}

		private static string DecodeMessage(string message, string encryptionKey)
		{
			//1. replace invalid characters
			message = message.Replace('-', '+').Replace('_', '/');

			//2. Base64 decode
			var bytes = Convert.FromBase64String(message);

			//3. Decrypt Rijndael
			bytes = Decrypt(bytes, encryptionKey);
			
			//4. De-gzip
			message = DecompressData(bytes);

			return message.Trim();
		}

		private static string DecompressData(byte[] inData)
		{
			using (var mem = new MemoryStream(inData))
			using (var gz = new DeflateStream(mem, CompressionMode.Decompress))
			using (var sw = new StreamReader(gz))
			{
				var outData = sw.ReadLine();
				sw.Close();

				return outData;
			}
		}

		private static byte[] Decrypt(byte[] data, string encryptionKey)
		{
			// Create an AesManaged object with the specified key and IV. 
			using (var rijAlg = new AesManaged())
			{
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
					return msDecrypt.ToArray();
				}
			}
		}

		//REF: http://docs.vancodev.com/doku.php?id=errorcodes
		private static readonly Dictionary<string, string> _Errors = new Dictionary<string, string>
		{
			{ "390", "Requesttype Not Authorized For User" },
			{ "495", "Field Contains Invalid Characters" },
		};

		private static string GetErrorMessages(string errorlist)
		{
			return String.Join(",", errorlist.Split(',')
											 .Select(x => _Errors.ContainsKey(x) ? _Errors[x] : x));
		}

		public static DateTime? ParseDate(string str)
		{
			DateTime date;
			return DateTime.TryParse(str, out date) ? date : (DateTime?)null;
		}
	};

	public class LoginRequest
	{
		public string RequestId { get; set; }

		public LoginResponse Execute(VancoConnection conn)
		{
			// RequestId
			if (string.IsNullOrWhiteSpace(RequestId))
			{
				RequestId = conn.CreateRequestId();
			}

			// QueryString
			var qs = new Dictionary<string, object>();
			qs["nvpvar"] = string.Empty;
			qs["requesttype"] = "login";
			qs["userid"] = conn.VancoUserId;
			qs["password"] = conn.VancoPassword;
			qs["requestid"] = RequestId;

			// Response
			var dict = conn.HttpGet(qs);
			var response = new LoginResponse
			{
				SessionId = dict["sessionid"],
				RequestId = dict["requestid"],
			};

			// Validate
			if (response.RequestId != RequestId)
			{
				throw new ApplicationException("RequestId does not match");
			}

			// Store SessionId on connection
			conn.SessionId = response.SessionId;

			return response;
		}
	};

	public class LoginResponse
	{
		public string SessionId { get; set; }
		public string RequestId { get; set; }
	};

	public class LogoutRequest
	{
		public string RequestId { get; set; }
		public string SessionId { get; set; }

		public bool Execute(VancoConnection conn)
		{
			// RequestId
			if (string.IsNullOrWhiteSpace(RequestId))
			{
				RequestId = conn.CreateRequestId();
			}

			// SessionId
			if (string.IsNullOrWhiteSpace(SessionId))
			{
				SessionId = conn.SessionId;
			}

			// Data
			var data = new Dictionary<string, object>();
			data["requesttype"] = "logout";
			data["requestid"] = RequestId;

			// QueryString
			var qs = new Dictionary<string, object>();
			qs["sessionid"] = SessionId;
			qs["nvpvar"] = conn.EncodeNvpvar(data);

			var dict = conn.HttpGet(qs);
			if (dict["response"] != "successful")
			{
				throw new ApplicationException("ERROR logging out: " + dict);
			}

			return true;
		}
	};

	//REF: http://docs.vancodev.com/doku.php?id=nvp:efttransparentredirect
	public class EftRequest
	{
		public string RequestId { get; set; }
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
		public AccountTypes AccountType { get; set; }
		public string NameOnCard { get; set; }
		public string AccountNumber { get; set; }
		public string RoutingNumber { get; set; }
		public string ExpMonth { get; set; }
		public string ExpYear { get; set; }

		public EftResponse Execute(VancoConnection conn)
		{
			// RequestId
			if (string.IsNullOrWhiteSpace(RequestId))
			{
				RequestId = conn.CreateRequestId();
			}

			// SessionId
			if (string.IsNullOrWhiteSpace(SessionId))
			{
				SessionId = conn.SessionId;
			}

			// Validation
			if (string.IsNullOrWhiteSpace(SessionId)) throw new ApplicationException("SessionId is required");

			if (string.IsNullOrWhiteSpace(CustomerId) && string.IsNullOrWhiteSpace(CustomerRef) && string.IsNullOrWhiteSpace(Name))
				throw new ApplicationException("Name is required");

			if (string.IsNullOrWhiteSpace(AccountNumber)) throw new ApplicationException("AccountNumber is required");

			if (AccountType == AccountTypes.CC)
			{
				if (string.IsNullOrWhiteSpace(BillingAddr1)) throw new ApplicationException("BillingAddr1 is required");
				if (string.IsNullOrWhiteSpace(BillingCity)) throw new ApplicationException("BillingCity is required");
				if (string.IsNullOrWhiteSpace(BillingState)) throw new ApplicationException("BillingState is required");
				if (string.IsNullOrWhiteSpace(BillingZip)) throw new ApplicationException("BillingZip is required");
				if (string.IsNullOrWhiteSpace(NameOnCard)) throw new ApplicationException("NameOnCard is required");
				if (string.IsNullOrWhiteSpace(ExpMonth)) throw new ApplicationException("ExpMonth is required");
				if (string.IsNullOrWhiteSpace(ExpYear)) throw new ApplicationException("ExpYear is required");
				if (BillingState.Length != 2) throw new ApplicationException("BillingState length must be 2 digits");
				if (ExpMonth.Length != 2) throw new ApplicationException("ExpMonth length must be 2 digits");
				if (ExpYear.Length != 2) throw new ApplicationException("ExpYear length must be 2 digits");
			}
			else if (AccountType == AccountTypes.C || AccountType == AccountTypes.S)
			{
				if (string.IsNullOrWhiteSpace(RoutingNumber)) throw new ApplicationException("RoutingNumber is required");
				if (RoutingNumber.Length != 9) throw new ApplicationException("RoutingNumber length must be 9 digits");
			}
			else
			{
				throw new ApplicationException("AccountType is invalid");
			}

			// Data
			var data = new Dictionary<string, object>();
			data["requesttype"] = "efttransparentredirect";
			data["requestid"] = RequestId;
			data["clientid"] = conn.VancoClientId;
			data["urltoredirect"] = "http://localhost/";

			if (!string.IsNullOrWhiteSpace(CustomerRef))
			{
				data["customerref"] = CustomerRef;
			}
			else if (!string.IsNullOrWhiteSpace(CustomerId))
			{
				data["customerid"] = CustomerId;
			}
			else
			{
				throw new ApplicationException("Either CustomerRef or CustomerId must be supplied");
			}

			data["isdebitcardonly"] = IsDebitCardOnly ? "Yes" : "No";

			// QueryString
			var qs = new Dictionary<string, object>();
			qs["sessionid"] = SessionId;
			qs["newcustomer"] = AddNewCustomer ? "true" : "false";
			qs["name"] = Name;
			qs["email"] = Email;
			qs["billingaddr1"] = BillingAddr1;
			qs["billingaddr2"] = BillingAddr2;
			qs["billingcity"] = BillingCity;
			qs["billingstate"] = BillingState;
			qs["billingzip"] = BillingZip;
			qs["accounttype"] = AccountType.ToString();
			qs["name_on_card"] = NameOnCard;
			qs["accountnumber"] = AccountNumber;
			qs["routingnumber"] = RoutingNumber;
			qs["expmonth"] = ExpMonth;
			qs["expyear"] = ExpYear;

			// Form
			var form = new Dictionary<string, object>();
			form["nvpvar"] = conn.EncodeNvpvar(data);

			// Response
			var dict = conn.HttpPost(qs, form);
			var response = new EftResponse
			{
				SessionId = dict["sessionid"],
				RequestType = dict["requesttype"],
				RequestId = dict["requestid"],
				CustomerId = dict["customerid"],
				CustomerRef = dict["customerref"],
				IsDebitCardOnly = dict["isdebitcardonly"] == "Yes",
				PaymentMethodRef = dict["paymentmethodref"],
				ErrorList = dict["errorlist"],
				Last4 = dict["last4"],
				VisaMcType = (CardBrands)Enum.Parse(typeof(CardBrands), dict["visamctype"].Replace(" ", ""), true),
				CardType = (CardTypes)Enum.Parse(typeof(CardTypes), dict["cardtype"].Replace(" ", ""), true),
			};

			return response;
		}
	};

	public class EftResponse
	{
		public string SessionId { get; set; }
		public string RequestType { get; set; }
		public string RequestId { get; set; }
		public string UrlToRedirect { get; set; }
		public string CustomerId { get; set; }
		public string CustomerRef { get; set; }
		public bool IsDebitCardOnly { get; set; }
		public string PaymentMethodRef { get; set; }
		public string ErrorList { get; set; }
		public string Last4 { get; set; }
		public CardBrands VisaMcType { get; set; }
		public CardTypes CardType { get; set; }
	};

	//REF: http://docs.vancodev.com/doku.php?id=nvp:eftgetpaymentmethod
	public class PaymentMethodsRequest
	{
		public string SessionId { get; set; }
		public string RequestId { get; set; }
		public string ClientId { get; set; }
		public string CustomerRef { get; set; }
		public string CustomerId { get; set; }
		public string PaymentMethodRef { get; set; }

		public PaymentMethodResponse Execute(VancoConnection conn)
		{
			// SessionId
			if (string.IsNullOrWhiteSpace(SessionId))
			{
				SessionId = conn.SessionId;
			}

			// RequestId
			if (string.IsNullOrWhiteSpace(RequestId))
			{
				RequestId = conn.CreateRequestId();
			}

			// Validation
			if (string.IsNullOrWhiteSpace(SessionId)) throw new ApplicationException("SessionId is required");
			if (string.IsNullOrWhiteSpace(RequestId)) throw new ApplicationException("RequestId is required");
			if (string.IsNullOrWhiteSpace(conn.VancoClientId)) throw new ApplicationException("ClientId is required");

			// QueryString
			var qs = new Dictionary<string, object>();
			qs["sessionid"] = SessionId;

			// Data
			var data = new Dictionary<string, object>();
			data["requesttype"] = "eftgetpaymentmethod";
			data["requestid"] = RequestId;
			data["clientid"] = conn.VancoClientId;

			if (!string.IsNullOrWhiteSpace(CustomerRef))
			{
				data["customerref"] = CustomerRef;
			}
			else if (!string.IsNullOrWhiteSpace(CustomerId))
			{
				data["customerid"] = CustomerId;
			}
			else
			{
				throw new ApplicationException("Either CustomerRef or CustomerId must be supplied");
			}

			data["paymentmethodref"] = PaymentMethodRef;

			// Form
			var form = new Dictionary<string, object>();
			form["nvpvar"] = conn.EncodeNvpvar(data);

			// Response
			var dict = conn.HttpPost(qs, form);
			var response = new PaymentMethodResponse
			               {
							   PaymentMethodCount = int.Parse(dict["paymentmethodcount"]),
							   PaymentMethods = new List<PaymentMethod>(),
			               };

			for (var i = 0; i < response.PaymentMethodCount; i++)
			{
				response.PaymentMethods.Add(new PaymentMethod
				                            {
					                            PaymentMethodRef = dict["paymentmethodref_" + i],
					                            IsDefault = dict["isdefault_" + i] == "YES",
					                            AccountType = (AccountTypes)Enum.Parse(typeof(AccountTypes), dict["accounttype_" + i].Replace(" ", ""), true),
												CardType = (CardBrands)Enum.Parse(typeof(CardBrands), dict["cardtype_" + i].Replace(" ", ""), true),
					                            AccountNumber = dict["accountnumber_" + i],
					                            RoutingNumber = dict["routingnumber_" + i],
				                            });
			}

			return response;
		}
	};

	public class PaymentMethodResponse
	{	
		public int PaymentMethodCount { get; set; }
		public List<PaymentMethod> PaymentMethods { get; set; }
	};

	public class PaymentMethod
	{
		public string PaymentMethodRef { get; set; }
		public bool IsDefault { get; set; }
		public AccountTypes AccountType { get; set; }
		public CardBrands CardType { get; set; }
		public string AccountNumber { get; set; }
		public string RoutingNumber { get; set; }
	};

	//REF: http://docs.vancodev.com/doku.php?id=nvp:eftaddcompletetransaction
	public class TransactionRequest
	{
		public string SessionId { get; set; }
		public string RequestId { get; set; }
		public string CustomerRef { get; set; }
		public string CustomerId { get; set; }
		public string CustomerName { get; set; }
		public string CustomerAddress1 { get; set; }
		public string CustomerAddress2 { get; set; }
		public string CustomerCity { get; set; }
		public string CustomerState { get; set; }
		public string CustomerZip { get; set; }
		public string CustomerPhone { get; set; }
		public PaymentMethod PaymentMethod { get; set; }
		public bool IsDebitCardOnly { get; set; }
		public decimal Amount { get; set; }
		public DateTime? StartDate { get; set; }
		public DateTime? EndDate { get; set; }
		public Frequencies FrequencyCode { get; set; }
		public TransactionTypes? TransactionTypeCode { get; set; }

		public TransactionResponse Execute(VancoConnection conn)
		{
			// SessionId
			if (string.IsNullOrWhiteSpace(SessionId))
			{
				SessionId = conn.SessionId;
			}

			// RequestId
			if (string.IsNullOrWhiteSpace(RequestId))
			{
				RequestId = conn.CreateRequestId();
			}

			// Validation
			if (string.IsNullOrWhiteSpace(SessionId)) throw new ApplicationException("SessionId is required");
			if (string.IsNullOrWhiteSpace(RequestId)) throw new ApplicationException("RequestId is required");
			if (string.IsNullOrWhiteSpace(conn.VancoClientId)) throw new ApplicationException("ClientId is required");
			if (PaymentMethod == null) throw new ApplicationException("PaymentMethod is required");
			if (Amount == 0m) throw new ApplicationException("Amount cannot be zero");

			if (PaymentMethod.AccountType == AccountTypes.CC) //not needed if already on file
			{
				//if (string.IsNullOrWhiteSpace(CustomerName)) throw new ApplicationException("CustomerName is required");
				//if (string.IsNullOrWhiteSpace(CustomerAddress1)) throw new ApplicationException("CustomerAddress1 is required");
				//if (string.IsNullOrWhiteSpace(CustomerCity)) throw new ApplicationException("CustomerCity is required");
				//if (string.IsNullOrWhiteSpace(CustomerState)) throw new ApplicationException("CustomerState is required");
				//if (string.IsNullOrWhiteSpace(CustomerZip)) throw new ApplicationException("CustomerZip is required");
			}

			// QueryString
			var qs = new Dictionary<string, object>();
			qs["sessionid"] = SessionId;

			// Data
			var data = new Dictionary<string, object>();
			data["requesttype"] = "eftaddcompletetransaction";
			data["requestid"] = RequestId;
			data["clientid"] = conn.VancoClientId;

			if (!string.IsNullOrWhiteSpace(CustomerRef))
			{
				data["customerref"] = CustomerRef;
			}
			else if (!string.IsNullOrWhiteSpace(CustomerId))
			{
				data["customerid"] = CustomerId;
			}
			else
			{
				throw new ApplicationException("Either CustomerRef or CustomerId must be supplied");
			}

			data["customername"] = CustomerName;
			data["customeraddress1"] = CustomerAddress1;
			data["customeraddress2"] = CustomerAddress2;
			data["customercity"] = CustomerCity;
			data["customerstate"] = CustomerState;
			data["customerzip"] = CustomerZip;
			data["customerphone"] = CustomerPhone;

			data["paymentmethodref"] = PaymentMethod.PaymentMethodRef;
			data["isdebitcardonly"] = IsDebitCardOnly ? "Yes" : "No";

			data["amount"] = Amount.ToString("0.00");
			data["frequencycode"] = FrequencyCode.ToString();
			if (StartDate.HasValue) data["startdate"] = StartDate.Value.ToString("yyyy-MM-dd");
			if (EndDate.HasValue) data["enddate"] = EndDate.Value.ToString("yyyy-MM-dd");
			if (TransactionTypeCode.HasValue) data["transactiontypecode"] = TransactionTypeCode.Value.ToString();

			if (FrequencyCode == Frequencies.O)
			{
				data["startdate"] = "0000-00-00";
			}

			// Form
			var form = new Dictionary<string, object>();
			form["nvpvar"] = conn.EncodeNvpvar(data);

			// Response
			var dict = conn.HttpPost(qs, form);
			return new TransactionResponse
			       {
					   RequestId = dict["requestid"],
					   PaymentMethodRef = dict["paymentmethodref"],
					   CustomerRef = dict["customerref"],
					   TransactionRef = dict["transactionref"],
					   StartDate = VancoConnection.ParseDate(dict["startdate"]),
			       };
		}
	};

	public class TransactionResponse
	{
		public string RequestId { get; set; }
		public string PaymentMethodRef { get; set; }
		public string CustomerRef { get; set; }
		public string TransactionRef { get; set; }
		public DateTime? StartDate { get; set; }
	};

	public enum AccountTypes
	{
		C, // checking
		S, // saving
		CC, // credit-card
	};

	public enum CardTypes
	{
		Credit,
		Debit,
	}

	public enum CardBrands
	{
		Visa,
		MasterCard,
		AmericanExpress,
		Discover,
	};

	public enum Frequencies
	{
		O, // one-time
		M, // monthly
		W, // weekly
		BW, // bi-weekly
		Q, // quarterly
		A, // annual
	};

	public enum TransactionTypes
	{
		PPD, // Consumer to Business (Written authorization required)
		CCD, // Business to Business (Written authorization required)
		WEB, // Web (Customer initiated through a website)
		TEL, // Telephone (Voice recorded authorization required)
	};
}
