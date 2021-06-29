This project contain four java files
1 - AES.java
2 - RSA.java
3 - client.java
4 - server.java



1 - AES.java 
	- This is the main file for all the execution of AES algorithm.
	- this contains encrypt() and decrypt() function.
		both takes key and text as an argument and return the corresponding string.
	- Operation envolves.
		- shiftrow()
			left cyclic shift the hexadecimal size words.
		- multiply()
			multiply two hexadecimal words under GF(2^4).
		- mixColumn()
			multiply the matrix of word with the mixColumn matrix.

2 - RSA.java
	- This file contain the algorithm to run rsa algorithm.
	- takes the key generation parameters.
	- encrypt()
		-takes the string with the keys to encrypt.
	- decrypt()
		-takes the string with the keys to decrypt.
		

3- client.java
	- this class creates a Connection between client and server.
	- Request for the server public key.
	- Takes the plain Message, secretKey and input for key generation as input from the user.
	- Secretkey is encrypted using server public key .
	- Message is encrypted with the secretKey.
	- Message is hashed using sha-256 algorithm and then passed to rsa encrypt method with the private key of client.
	- all these value send to the server.
	
4 - server.java	
	- this takes the rsa key parameters and generates public as well the private key.
	- decrypt the secret key by using server private key.
	- decrypt the message by using secret key.
	- hashed the message.
	- decrypt the signature .
	- for authentication it compares the decrypted signature and hased message.
		


Proper java jdk must be properly installed.

command to compile java file.
javac <FILENAME>.java
command to run 
java <FILENAME>

firstly server must run after that client must run

