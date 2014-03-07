
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
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
		public VancoConnection(string connectionString)
		{
			var dict = connectionString.Split(';')
									   .Select(x => x.Split(new[] { '=' }, 2))
									   .Where(x => x.Length == 2)
									   .ToDictionary(x => x[0], x => x[1]);

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
				//throw new ApplicationException("Error: " + msg);
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
			{"10","Invalid UserID/password combination"},
			{"11","Session expired"},
			{"25","All default address fields are required"},
			{"32","Name is required"},
			{"33","Unknown bank/bankpk"},
			{"34","Valid PaymentType is required"},
			{"35","Valid Routing Number Is Required"},
			{"63","Invalid StartDate"},
			{"65","Specified fund reference is not valid."},
			{"66","Invalid End Date"},
			{"67","Transaction must have at least one transaction fund."},
			{"68","User is Inactive"},
			{"69","Expiration Date Invalid"},
			{"70","Account Type must be “C”, “S' for ACH and must be blank for Credit Card"},
			{"71","Class Code must be PPD, CCD, TEL, WEB, RCK or blank."},
			{"72","Missing Client Data: Client ID"},
			{"73","Missing Customer Data: Customer ID or Name or Last Name & First Name"},
			{"74","PaymentMethod is required."},
			{"76","Transaction Type is required"},
			{"77","Missing Credit Card Data: Card # or Expiration Date"},
			{"78","Missing ACH Data: Routing # or Account #"},
			{"79","Missing Transaction Data: Amount or Start Date"},
			{"80","Account Number has invalid characters in it"},
			{"81","Account Number has too many characters in it"},
			{"82","Customer name required"},
			{"83","Customer ID has not been set"},
			{"86","NextSettlement does not fall in today's processing dates"},
			{"87","Invalid FrequencyPK"},
			{"88","Processed yesterday"},
			{"89","Duplicate Transaction (matches another with PaymentMethod and NextSettlement)"},
			{"91","Dollar amount for transaction is over the allowed limit"},
			{"92","Invalid client reference occurred. - Transaction WILL NOT process"},
			{"94","Customer ID already exists for this client"},
			{"95","Payment Method is missing Account Number"},
			{"101","Dollar Amount for transaction cannot be negative"},
			{"102","Updated transaction's dollar amount violates amount limit"},
			{"105","PaymentMethod Date not valid yet."},
			{"125","Email Address is required."},
			{"127","User Is Not Proofed"},
			{"134","User does not have access to specified client."},
			{"157","Client ID is required"},
			{"158","Specified Client is invalid"},
			{"159","Customer ID required"},
			{"160","Customer ID is already in use"},
			{"161","Customer name required"},
			{"162","Invalid Date Format"},
			{"163","Transaction Type is required"},
			{"164","Transaction Type is invalid"},
			{"165","Fund required"},
			{"166","Customer Required"},
			{"167","Payment Method Not Found"},
			{"168","Amount Required"},
			{"169","Amount Exceeds Limit. Set up manually."},
			{"170","Start Date Required"},
			{"171","Invalid Start Date"},
			{"172","End Date earlier than Start Date"},
			{"173","Cannot Prenote a Credit Card"},
			{"174","Cannot Prenote processed account"},
			{"175","Transaction pending for Prenote account"},
			{"176","Invalid Account Type"},
			{"177","Account Number Required"},
			{"178","Invalid Routing Number"},
			{"179","Client doesn't accept Credit Card Transactions"},
			{"180","Client is in test mode for Credit Cards"},
			{"181","Client is cancelled for Credit Cards"},
			{"182","Name on Credit Card is Required"},
			{"183","Invalid Expiration Date"},
			{"184","Complete Billing Address is Required"},
			{"195","Transaction Cannot Be Deleted"},
			{"196","Recurring Telephone Entry Transaction NOT Allowed"},
			{"198","Invalid State"},
			{"199","Start Date Is Later Than Expiration date"},
			{"201","Frequency Required"},
			{"202","Account Cannot Be Deleted, Active Transaction Exists"},
			{"203","Client Does Not Accept ACH Transactions"},
			{"204","Duplicate Transaction"},
			{"210","Recurring Credits NOT Allowed"},
			{"211","ONHold/Cancelled Customer"},
			{"217","End Date Cannot Be Earlier Than The Last Settlement Date"},
			{"218","Fund ID Cannot Be W, P, T, or C"},
			{"223","Customer ID not on file"},
			{"224","Credit Card Credits NOT Allowed - Must Be Refunded"},
			{"231","Customer Not Found For Client"},
			{"232","Invalid Account Number"},
			{"233","Invalid Country Code"},
			{"234","Transactions Are Not Allow From This Country"},
			{"242","Valid State Required"},
			{"251","Transactionref Required"},
			{"284","User Has Been Deleted"},
			{"286","Client not set up for International Credit Card Processing"},
			{"296","Client Is Cancelled"},
			{"328","Credit Pending - Cancel Date cannot be earlier than Today"},
			{"329","Credit Pending - Account cannot be placed on hold until Tomorrow"},
			{"341","Cancel Date Cannot be Greater Than Today"},
			{"344","Phone Number Must be 10 Digits Long"},
			{"378","Invalid Loginkey"},
			{"379","Requesttype Unavailable"},
			{"380","Invalid Sessionid"},
			{"381","Invalid Clientid for Session"},
			{"383","Internal Handler Error. Contact Vanco Services."},
			{"384","Invalid Requestid"},
			{"385","Duplicate Requestid"},
			{"390","Requesttype Not Authorized For User"},
			{"391","Requesttype Not Authorized For Client"},
			{"392","Invalid Value Format"},
			{"393","Blocked IP"},
			{"395","Transactions cannot be processed on Weekends"},
			{"404","Invalid Date"},
			{"410","Credits Cannot Be WEB or TEL"},
			{"420","Transaction Not Found"},
			{"431","Client Does Not Accept International Credit Cards"},
			{"432","Can not process credit card"},
			{"434","Credit Card Processor Error"},
			{"445","Cancel Date Cannot Be Prior to the Last Settlement Date"},
			{"446","End Date Cannot Be In The Past"},
			{"447","Masked Account"},
			{"469","Card Number Not Allowed"},
			{"474","MasterCard Not Accepted"},
			{"475","Visa Not Accepted"},
			{"476","American Express Not Accepted"},
			{"477","Discover Not Accepted"},
			{"478","Invalid Account Number"},
			{"489","Customer ID Exceeds 15 Characters"},
			{"490","Too Many Results, Please Narrow Search"},
			{"495","Field Contains Invalid Characters"},
			{"496","Field contains Too Many Characters"},
			{"497","Invalid Zip Code"},
			{"498","Invalid City"},
			{"499","Invalid Canadian Postal Code"},
			{"500","Invalid Canadian Province"},
			{"506","User Not Found"},
			{"511","Amount Exceeds Limit"},
			{"512","Client Not Set Up For Credit Card Processing"},
			{"515","Transaction Already Refunded"},
			{"516","Can Not Refund a Refund"},
			{"517","Invalid Customer"},
			{"518","Invalid Payment Method"},
			{"519","Client Only Accepts Debit Cards"},
			{"520","Transaction Max for Account Number Reached"},
			{"521","Thirty Day Max for Client Reached"},
			{"523","Invalid Login Request"},
			{"527","Change in account/routing# or type"},
			{"535","SSN Required"},
			{"549","CVV2 Number is Required"},
			{"550","Invalid Client ID"},
			{"556","Invalid Banking Information"},
			{"569","Please Contact This Organization for Assistance with Processing This Transaction"},
			{"570","City Required"},
			{"571","Zip Code Required"},
			{"572","Canadian Provence Required"},
			{"573","Canadian Postal Code Required"},
			{"574","Country Code Required"},
			{"578","Unable to Read Card Information. Please Click “Click to Swipe” Button and Try Again."},
			{"610","Invalid Banking Information. Previous Notification of Change Received for this Account"},
			{"629","Invalid CVV2"},
			{"641","Fund ID Not Found"},
			{"642","Request Amount Exceeds Total Transaction Amount"},
			{"643","Phone Extension Required"},
			{"645","Invalid Zip Code"},
			{"652","Invalid SSN"},
			{"653","SSN Required"},
			{"657","Billing State Required"},
			{"659","Phone Number Required"},
			{"663","Version Not Supported"},
			{"665","Invalid Billing Address"},
			{"666","Customer Not On Hold"},
			{"667","Account number for fund is invalid"},
			{"678","Password Expired"},
			{"687","Fund Name is currently in use. Please choose another name. If you would like to use this Fund Name, go to the other fund and change the Fund Name to something different."},
			{"688","Fund ID is currently in use. Please choose another number. If you would like to use this Fund ID, go to the other fund and change the Fund ID to something different."},
			{"705","Please Limit Your Date Range To 30 Days"},
			{"706","Last Digits of Account Number Required"},
			{"721","MS Transaction Amount Cannot Be Greater Than $50,000."},
			{"725","User ID is for Web Services Only"},
			{"730","Start Date Required"},
			{"734","Date Range Cannot Be Greater Than One Year"},
			{"764","Start Date Cannot Occur In The Past"},
			{"800","The CustomerID Does Not Match The Given CustomerRef"},
			{"801","Default Payment Method Not Found"},
			{"838","Transaction Cannot Be Processed. Please contact your organization."},
			{"842","Invalid Pin"},
			{"844","Phone Number Must be 10 Digits Long"},
			{"850","Invalid Authentication Signature"},
			{"857","Fund Name Can Not Be Greater Than 30 Characters"},
			{"858","Fund ID Can Not Be Greater Than 20 Characters"},
			{"859","Customer Is Unproofed"},
			{"862","Invalid Start Date"},
			{"956","Amount Must Be Greater Than $0.00"},
			{"960","Date of Birth Required"},
			{"963","Missing Field"},
			{"973","No match found for these credentials."},
			{"974","Recurring Return Fee Not Allowed"},
			{"992","No Transaction Returned Within the Past 45 Days"},
			{"993","Return Fee Must Be Collected Within 45 Days"},
			{"994","Return Fee Is Greater Than the Return Fee Allowed"},
			{"1005","Phone Extension Must Be All Digits"},
			{"1008","We are sorry. This organization does not accept online credit card transactions. Please try again using a debit card."},
			{"1047","Invalid nvpvar variables"},
			{"1054","Invalid. Debit Card Only"},
			{"1067","Invalid Original Request ID"},
			{"1070","Transaction Cannot Be Voided"},
			{"1073","Transaction Processed More Than 25 Minutes Ago"},
			{"1127","Declined - Tran Not Permitted"},
			{"1128","Unable To Process, Please Try Again"},
		};

		public static string GetErrorMessages(string errorlist)
		{
			return String.Join(",", errorlist.Split(',')
											 .Select(x => _Errors.ContainsKey(x) ? _Errors[x] : x));
		}

		public static DateTime? ParseDate(string str)
		{
			DateTime date;
			return DateTime.TryParse(str, out date) ? date : (DateTime?)null;
		}

	    public static T ParseEnum<T>(string value)
	    {
	        return string.IsNullOrWhiteSpace(value)
	                   ? default(T)
	                   : (T) Enum.Parse(typeof (T), value.Replace(" ", ""), true);
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
				VisaMcType = VancoConnection.ParseEnum<CardBrands?>(dict["visamctype"]),
				CardType = VancoConnection.ParseEnum<CardTypes?>(dict["cardtype"]),
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
		public CardBrands? VisaMcType { get; set; }
		public CardTypes? CardType { get; set; }
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
		                       PaymentMethodCount = int.Parse(dict["paymentmethodcount"] ?? "0"),
		                       PaymentMethods = new List<PaymentMethod>(),
		                   };

			for (var i = 0; i < response.PaymentMethodCount; i++)
			{
				response.PaymentMethods.Add(new PaymentMethod
				{
					PaymentMethodRef = dict["paymentmethodref_" + i],
					IsDefault = dict["isdefault_" + i] == "YES",
					AccountType = VancoConnection.ParseEnum<AccountTypes>(dict["accounttype_" + i]),
					CardType = VancoConnection.ParseEnum<CardBrands>(dict["cardtype_" + i]),
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
		public AccountTypes? AccountType { get; set; }
		public CardBrands? CardType { get; set; }
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
		public string PaymentMethodRef { get; set; }
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
			if (string.IsNullOrEmpty(PaymentMethodRef)) throw new ApplicationException("PaymentMethodRef is required");
			if (Amount == 0m) throw new ApplicationException("Amount cannot be zero");

			//if (PaymentMethod.AccountType == AccountTypes.CC) //not needed if already on file
			//{
				//if (string.IsNullOrWhiteSpace(CustomerName)) throw new ApplicationException("CustomerName is required");
				//if (string.IsNullOrWhiteSpace(CustomerAddress1)) throw new ApplicationException("CustomerAddress1 is required");
				//if (string.IsNullOrWhiteSpace(CustomerCity)) throw new ApplicationException("CustomerCity is required");
				//if (string.IsNullOrWhiteSpace(CustomerState)) throw new ApplicationException("CustomerState is required");
				//if (string.IsNullOrWhiteSpace(CustomerZip)) throw new ApplicationException("CustomerZip is required");
			//}

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

			data["paymentmethodref"] = PaymentMethodRef;
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
		               CcAuthDesc = dict["ccauthdesc"],
		               ErrorList = dict["errorlist"],
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
		public string CcAuthDesc { get; set; }
		public string ErrorList { get; set; }
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
