
using System;
using Vanco;

namespace VancoTest
{
	internal class Program
	{
		private static void Main()
		{
			var vanco = new VancoConnection();

			var login = new LoginRequest().Execute(vanco);
			Console.WriteLine("SessionId: " + login.SessionId);

			var response = new EftRequest
						   {
							   SessionId = login.SessionId,
							   CustomerId = "1",
							   IsDebitCardOnly = false,
							   AddNewCustomer = true,
							   Name = "Test",
							   Email = "test@example.com",
							   BillingAddr1 = "123 Main St",
							   BillingCity = "Charlotte",
							   BillingState = "NC",
							   BillingZip = "29028",
							   AccountType = "CC",
							   NameOnCard = "Test",
							   AccountNumber = "36555500001111",
							   //RoutingNumber = 
							   ExpMonth = "12",
							   ExpYear = "14",

						   }.Execute(vanco);
			Console.WriteLine("PaymentMethodRef: " + response.PaymentMethodRef);

			var logout = new LogoutRequest().Execute(vanco);
			Console.WriteLine("Logout: " + logout);

			Console.ReadKey();
		}
	};
}
