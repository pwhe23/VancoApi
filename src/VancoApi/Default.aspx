<%@ Page Language="C#" %>
<%@ Import Namespace="Site" %>

<script runat="server">
	void Button_Click(object sender, EventArgs args)
	{
		var vanco = new VancoApi();
		var sessionid = vanco.Login();
		Response.Write("SessionId: " + sessionid);
		var response = vanco.SavePaymentMethod(new PaymentMethodRequest
		                                       {
			                                       SessionId = sessionid,
												   CustomerId = "1",
												   AccountType = "CC",
												   AccountNumber = "36555500001111",
												   CardBillingName = "Test",
												   CardExpMonth = "12",
												   CardExpYear = "14",
												   CardBillingAddr1 = "123 Main St",
												   CardBillingCity = "Charlotte",
												   CardBillingState = "NC",
												   CardBillingZip = "29028",
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
