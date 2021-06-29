/////////////////////////////////////////////ASSIGNMENT DONE BY SUDEEP KUMAR GUPT ////////////////////////////////////////
//////////////////////////////////////////////////////////2018379/////////////////////////////////////////////////////////

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

class server{
	
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
	
	
	public static String getBufHexStr(byte[] raw){
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
  
  // The hexadecimal string converted into an array of characters
  public static int[] getHexBytes(String str){
    int[] bytes = new int[str.length() / 2];
    for(int i = 0; i < str.length() / 2; i++) {
      String subStr = str.substring(i * 2, i * 2 + 2);
      bytes[i] = Integer.parseInt(subStr, 16);
    }
    return bytes;
  }
	
	
	
  public static void main(String args[])throws Exception{
    try{
		
		System.out.println("Assignment Created by Sudeep Kumar Gupta (2018379)");
		RSA rsa = new RSA();
		int a[] = rsa.keyGeneration();																// RSA key generation
		DatagramSocket serverSocket = new DatagramSocket(9876);
        byte[] buf= new byte[1024];
		DatagramPacket requestReceive = new DatagramPacket(buf,buf.length);
		serverSocket.receive(requestReceive);														// Received request
		
		String request = new String(requestReceive.getData());
		
		InetAddress senderAddress = requestReceive.getAddress( );
		
		int senderPort = requestReceive.getPort( );
		
		String publicKeyToSend = Integer.toString(rsa.getPublicKey()[0])+"-"+Integer.toString(rsa.getPublicKey()[1]);
																									// Converting server public into string 
		byte[ ] sendBuffer = publicKeyToSend.getBytes();
		
		DatagramPacket datagram = new DatagramPacket(sendBuffer, sendBuffer.length,senderAddress, senderPort);
		serverSocket.send(datagram);																// sending the server public key
		
		byte[] completeMessage = new byte[2048];
        DatagramPacket receiveMessage = new DatagramPacket(completeMessage, completeMessage.length);
        serverSocket.receive(receiveMessage);														// Received the whole content from the client
		
		String Message = new String(receiveMessage.getData()).trim();
		System.out.println("Complete Content Came from the Server " +Message);		
		
		String[] totalMessage = Message.split(" ");													// spliting the whole content
		
		for(int i=0;i<4;i++){
			totalMessage[i]=totalMessage[i].trim();
		}
		
		String publicSecretKey = rsa.decrypt(totalMessage[1],rsa.getPrivateKey()[0],rsa.getPrivateKey()[1]);
																									// decrypting the secret key
																									// by the help of server private key
		
		System.out.println("Decrypted Secret key  : " + publicSecretKey);
		
		
		int[] sentence = getHexBytes(totalMessage[0]);												// Merge Two hexadecimal to make 1 Byte decimal
		AES aes = new AES();																		// instance of AES class
		StringBuilder plainText = new StringBuilder();
		int[] part = new int[2];
		for(int i=0;i<sentence.length;i=i+2){														// Applying decryption function over two byte at a time
			part[0]=sentence[i];
			part[1]=sentence[i+1];
			plainText.append(aes.decrypt(part,publicSecretKey));									// decrypt function of AES class is calles
		}	
		
		System.out.println("Decrypted Message  : " + plainText.toString());													// Message found
		
		
		int[] clientPublicKey = new int[2];
		
		String[] ReceiveKey = totalMessage[3].split("-");
		
		for(int i=0;i<2;i++){
			//System.out.println(ReceiveKey[i].trim());
			clientPublicKey[i]= Integer.parseInt(ReceiveKey[i].trim());								// fetching client public key 
		}
		
		String hashedMessage = "";
		try 
        {	
			hashedMessage = toHexString(getSHA(plainText.toString().trim()));						// hashing the Message found 
        }
        catch (NoSuchAlgorithmException e) { 
            System.out.println("Exception thrown for incorrect algorithm: " + e); 
        }
		System.out.println("Message Digest  : "+hashedMessage);															
		
		String signaturedMessage = rsa.decrypt(totalMessage[2],clientPublicKey[0],clientPublicKey[1]); 
																									// Decrypting the client signature  
		
		System.out.println("Intermediate verification code  : "+signaturedMessage);														
		//String plainText = aes.decrypt(cipherContent,key);
		System.out.println("Authenticated " + signaturedMessage.equals(hashedMessage));				// Comparing the decrypted client signature and hash of Message
    }
    catch(Exception e){
      e.printStackTrace();
    }
  }
}
