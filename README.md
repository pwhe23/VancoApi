VancoApi
========

C# Api for interfacing with Vanco payments

Currently Implemented:
* Login
* Create a Payment Method for a customer
* Retrieve all Payment Methods for a customer
* Create a transaction with a given customer Payment method
* Logout

Implementation of additional Api calls should be very simple, feel free to submit pull requests

To get started you need to enter the values into connectionStrings.config which you can get from Vanco:
* ClientId
* UserId
* Password
* EncryptionKey

To include this code into your project you only need the VancoApi.cs file, which is self-contained. The project itself is
just a console app that demonstrates how to use the Api. I plan on keeping this project up-to-date with what I need to 
interact with Vanco, but don't plan on attempting a full implementation (though pull requests are welcome).
