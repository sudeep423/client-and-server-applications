import java.io.*;
import java.math.*;
import java.security.*;
import java.text.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import java.math.BigInteger; 
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;
import java.net.*;
import java.util.Scanner;

class client{
	
	public static byte[] getSHA(String input) throws NoSuchAlgorithmException
    { 
        // Static getInstance method is called with hashing SHA 
        MessageDigest md = MessageDigest.getInstance("SHA-256"); 
  
        // digest() method called 
        // to calculate message digest of an input 
        // and return array of byte
        return md.digest(input.getBytes(StandardCharsets.UTF_8)); 
    }
	
	public static String toHexString(byte[] hash)
    {
        // Convert byte array into signum representation 
        BigInteger number = new BigInteger(1, hash); 
  
        // Convert message digest into hex value 
        StringBuilder hexString = new StringBuilder(number.toString(16)); 
  
        // Pad with leading zeros
        while (hexString.length() < 32) 
        { 
            hexString.insert(0, '0'); 
        } 
  
        return hexString.toString(); 
    }
	
	
	public static String getBufHexStr(byte[] raw){	 	// Convert hext into thier corresponding String
    String HEXES = "0123456789ABCDEF";		
    if ( raw == null ) {
      return null;
    }
    final StringBuilder hex = new StringBuilder( 2 * raw.length );
    for ( final byte b : raw ) {
      hex.append(HEXES.charAt((b & 0xF0) >> 4))
        .append(HEXES.charAt((b & 0x0F)));
    }
    return hex.toString();
  }
  
 
	
  public static void main(String args[])throws Exception{
		System.out.println("Assignment Created by Sudeep Kumar Gupta (2018379)");
		BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in)); // Buffer Reader for taking input from user
		DatagramSocket clientSocket = new DatagramSocket();	//Datagramsocket created
		InetAddress IPAddress = InetAddress.getByName("127.0.0.1");
		String s = "Request for Server Public key";
		byte[] sendRequest = s.getBytes();
		DatagramPacket sendPacket = new DatagramPacket(sendRequest, sendRequest.length,IPAddress, 9876);
		clientSocket.send(sendPacket);
		
		String recvdString="";
		
		int MESSAGE_LEN = 60;
		byte[ ] recvBuffer = new byte[MESSAGE_LEN];
		DatagramPacket datagram = new DatagramPacket(recvBuffer, MESSAGE_LEN);
		clientSocket.receive(datagram);											// Receive Server Public key 
		
		recvdString = new String(recvBuffer);
		int[] serverPublicKey = new int[2];
		
		String[] ReceiveKey = recvdString.split("-");
		for(int i=0;i<2;i++){
			serverPublicKey[i]= Integer.parseInt(ReceiveKey[i].trim()); 		// convert String into Integer
		}
		System.out.println("Message");
		String message = inFromUser.readLine();									// Message input from the client
		System.out.println("Enter key of 2 bytes only ");
		String secretKey = inFromUser.readLine();								// Input secret key from client for AES algorithm
	
		AES aes = new AES();													// instance of AES class
		byte[] sendKey = secretKey.getBytes();
		
		RSA rsa = new RSA();
		int[] k = rsa.keyGeneration();											// generate key for RSA algorithm
		
		String encrypteSecretKey = rsa.encrypt(secretKey,serverPublicKey[0],serverPublicKey[1]); 
																				// rsa encrypt secret key of AES algorithm
		System.out.println("encrypted Secret Key  : " + encrypteSecretKey);

		StringBuilder plainText = new StringBuilder(message);
		if(message.length()%2==1)						// Add a space if length of plain text is not a multiple of 2
			plainText.append(' ');
		String sentence = plainText.toString();
		//System.out.println(message);
		StringBuilder cypherText = new StringBuilder();
		for(int i=0;i<sentence.length();i=i+2){
			cypherText.append(aes.encrypt(sentence.substring(i,i+2),secretKey));	// encrypt the substring one by one
		}

		System.out.println("cypher Text  : "+ cypherText);

		byte[] cypherString = cypherText.toString().getBytes();
		String clientSignature = "";
		String hashedMessage = "";
		try 
        {	
			hashedMessage = toHexString(getSHA(message));							// Hashed the message using SHA-256
			
		}
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        } 
		System.out.println("Digest  : " + hashedMessage);
		clientSignature = rsa.encrypt(hashedMessage,rsa.getPrivateKey()[0],rsa.getPrivateKey()[1]);
																					// RSA encryption using client private key
		System.out.println("Signature  : " + clientSignature);
		//System.out.println(rsa.getPrivateKey()[0] + " " + rsa.getPrivateKey()[0]);
		String publicKey = Integer.toString(rsa.getPublicKey()[0])+"-"+Integer.toString(rsa.getPublicKey()[1]);
		
		String completeMessage = cypherText + " " + encrypteSecretKey + " " + clientSignature + " " + publicKey;
																					// Complete message for transfer
		byte[] finalString = completeMessage.getBytes();
		DatagramPacket sendCypherText = new DatagramPacket(finalString, finalString.length,IPAddress, 9876); 	
		clientSocket.send(sendCypherText);											// sending Complete Message
	
    try{
		clientSocket.close();
		inFromUser.close();
    }
    catch(Exception e){
		e.printStackTrace();
    }
  }
}
