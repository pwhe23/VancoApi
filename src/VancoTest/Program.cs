
using System;
using Vanco;

namespace VancoTest
{
	internal class Program
	{
		private static void Main()
		{
			var cust = new
			           {
				           Id = "1",
				           Name = "Test",
				           Email = "test@example.com",
				           Address1 = "123 Main St",
						   City = "Charlotte",
						   State = "NC",
						   Zip = "29028",
			           };

			var card = new
			           {
						   AccountType = AccountTypes.CC,
				           NameOnCard = "Test",
				           AccountNumber = "36555500001111",
				           ExpMonth = "12",
				           ExpYear = "14",
			           };

			var trnx = new
			           {
				           Amount = 1234.56m,
			           };

			var conn = new VancoConnection();

			// Login
			var loginRequest = new LoginRequest();
			var loginResponse = loginRequest.Execute(conn);
			Console.WriteLine("SessionId: " + loginResponse.SessionId);

			// Add Payment method
			var eftRequest = new EftRequest
			                 {
				                 CustomerId = cust.Id,
				                 Name = cust.Name,
				                 Email = cust.Email,
				                 BillingAddr1 = cust.Address1,
				                 BillingCity = cust.City,
				                 BillingState = cust.State,
				                 BillingZip = cust.Zip,
								 AccountType = card.AccountType,
				                 NameOnCard = card.NameOnCard,
				                 AccountNumber = card.AccountNumber,
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
						   PaymentMethod = methodsResponse.PaymentMethods[0],
						   Amount = trnx.Amount,
						   FrequencyCode = Frequencies.O,
					   };
			var trnxResponse = trnxRequest.Execute(conn);
			Console.WriteLine("TrnxId: " + trnxResponse.TransactionRef);

			// Logout
			var logout = new LogoutRequest().Execute(conn);
			Console.WriteLine("Logout: " + logout);

			Console.ReadKey();
		}
	};
}
