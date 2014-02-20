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
