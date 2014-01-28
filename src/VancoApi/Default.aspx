<%@ Page Language="C#" %>
<%@ Import Namespace="Site" %>

<script runat="server">
	void Button_Click(object sender, EventArgs args)
	{
		var vanco = new VancoApi();
		vanco.Login();
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
