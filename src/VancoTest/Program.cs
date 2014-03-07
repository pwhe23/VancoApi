
using System;
using System.Configuration;
using Vanco;

namespace VancoTest
{
	internal class Program
	{
		private static void Main()
		{
			var cust = new
					   {
						   Id = "3",
						   Name = "Test",
						   Email = "test@example.com",
						   Address1 = "123 Main St",
						   City = "Charlotte",
						   State = "NC",
						   Zip = "29028",
					   };

			var card = new
					   {
						   AccountType = AccountTypes.C,
						   NameOnCard = "Test",
						   AccountNumber = "4012000033330026",
						   RoutingNumber = "123456780",
						   ExpMonth = (string)null,
						   ExpYear = (string)null,
					   };

			var trnx = new
					   {
						   Amount = 1234.56m,
					   };

			var conn = new VancoConnection(ConfigurationManager.ConnectionStrings["Vanco"].ConnectionString);

			// Login
			var loginRequest = new LoginRequest();
			var loginResponse = loginRequest.Execute(conn);
			Console.WriteLine("SessionId: " + loginResponse.SessionId);

			// Add Payment method
			var eftRequest = new EftRequest
							 {
								 CustomerId = cust.Id,
								 AddNewCustomer = true,
								 Name = cust.Name,
								 Email = cust.Email,
								 BillingAddr1 = cust.Address1,
								 BillingCity = cust.City,
								 BillingState = cust.State,
								 BillingZip = cust.Zip,
								 AccountType = card.AccountType,
								 NameOnCard = card.NameOnCard,
								 AccountNumber = card.AccountNumber,
								 RoutingNumber = card.RoutingNumber,
								 ExpMonth = card.ExpMonth,
								 ExpYear = card.ExpYear,
							 };
			var eftResponse = eftRequest.Execute(conn);
			Console.WriteLine("PaymentMethodRef: " + eftResponse.PaymentMethodRef);

			// Get Payment Methods
			var methodsRequest = new PaymentMethodsRequest
						  {
							  CustomerId = cust.Id,
						  };
			var methodsResponse = methodsRequest.Execute(conn);
			Console.WriteLine("PaymentMethods: " + methodsResponse.PaymentMethodCount);

			// Transaction
			var trnxRequest = new TransactionRequest
					   {
						   CustomerId = cust.Id,
						   PaymentMethodRef = methodsResponse.PaymentMethods[methodsResponse.PaymentMethods.Count - 1].PaymentMethodRef,
						   Amount = trnx.Amount,
						   FrequencyCode = Frequencies.O,
					   };
			var trnxResponse = trnxRequest.Execute(conn);
			if (!string.IsNullOrWhiteSpace(trnxResponse.ErrorList))
			{
				Console.WriteLine("Error: " + VancoConnection.GetErrorMessages(trnxResponse.ErrorList));
			}
			Console.WriteLine("TrnxId: " + trnxResponse.TransactionRef);

			// Logout
			var logout = new LogoutRequest().Execute(conn);
			Console.WriteLine("Logout: " + logout);

			Console.ReadKey();
		}
	};
}
