<%@ Page Language="C#" %>
<%@ Import Namespace="Site" %>

<script runat="server">
	void Button_Click(object sender, EventArgs args)
	{
		var vanco = new VancoApi();
		var sessionid = vanco.Login();
		Response.Write("SessionId: " + sessionid);
		var response = vanco.Eft(new EftRequest
								 {
									 SessionId = sessionid,
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

								 });
		Response.Write("PaymentMethodRef: " + response.PaymentMethodRef);
	}
</script>

<html lang="en">
<head id="Head1" runat="server">
	<title />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
</head>
<body>
	<form id='aspnetForm' name='aspnetForm' runat='server'>
		<asp:Button ID="Button1" Text="Run" OnClick="Button_Click" runat="server" />
	</form>
</body>
</html>
