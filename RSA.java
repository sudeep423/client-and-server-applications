import java.io.*;
import java.math.*;
import java.security.*;
import java.text.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

public class RSA{
	private static int[] p = new int[2];
	private static int d;
	private static int e;
	public static boolean isPrime(double f){
		if(f==1)
			return false;
		for(int i=2;i<=Math.sqrt(f);i++){
			if(f%i==0)
				return false;
		}
		return true;
	}
	public static int gcd(int a, int b)
    {
      if (b == 0)
        return a;
      return gcd(b, a % b);
    }
	public static int[] getPublicKey(){
		int[] a = new int[2];
		a[0]=e;
		a[1]=p[0]*p[1];
		return a;
	}
	
	public static int[] getPrivateKey(){
		int[] a = new int[2];
		a[0]=d;
		a[1]=p[0]*p[1];
		return a;
	}
	
	static String decimalToHexString(int m){
		String s = Integer.toHexString(m);
		int k = 8 - s.length();
		String text = "";
		for(int i=0;i<k;i++){
			text=text+'0';
		}
		return text+s;
	}
	
	static int power(long x, long y, long m)
    {
        if (y == 0)
            return 1;
        long p = power(x, y / 2, m) % m;
        p = ((p * (long)p) % m);
        if (y % 2 == 0)
            return (int)p;
        else
            return (int)((x * (long)p) % m);
    }
	
	static int modInverse(int a, int m)
    {
        int m0 = m;
        int y = 0, x = 1;
 
        if (m == 1)
            return 0;
 
        while (a > 1) {
            // q is quotient
            int q = a / m;
 
            int t = m;
 
            // m is remainder now, process
            // same as Euclid's algo
            m = a % m;
            a = t;
            t = y;
 
            // Update x and y
            y = x - q * y;
            x = t;
        }
 
        // Make x positive
        if (x < 0)
            x += m0;
 
        return x;
    }
	
	public static int[] keyGeneration(){
		Scanner input = new Scanner(System.in);
		System.out.println("Enter two distinct prime number and the product of both must be greater then 200 for public key");
		while(true){
			for(int i=0;i<2;i++){
				p[i] = input.nextInt();
			}
			if(isPrime(p[0]) && isPrime(p[1]) && p[0]!=p[1])
				break;
			System.out.println("Enter valid distinct two prime numbers");
		}
		int phi = (p[0]-1)*(p[1]-1);
		for(int i=2;i<phi;i++){
			if(gcd(i,phi)==1){
				e = i;
				break;
			}
		}
		d = modInverse(e,phi);
		int[] b = new int[2];
		b[0]=e;
		b[1]=d;
		return b;
	}
	
	public static String encrypt(String s,int d,int n){
		int len = s.length(),temp;
		String encrypted_text = "";
		for(int i=0;i<len;i++){
			Character c = s.charAt(i);
			temp = power((int)c,d,n);
			encrypted_text = encrypted_text + decimalToHexString(temp);
		}
		return encrypted_text;
	}
	
	
	
	public static String decrypt(String s,int d,int n){
		int len = s.length(),temp;
		String decrypted_text = "";
		for(int i=0;i<len;i=i+8){
			
			temp = Integer.parseInt(s.substring(i,i+8),16);
			temp = power(temp,d,n);
			decrypted_text = decrypted_text + (char)temp;
		}
		return decrypted_text;
	}
}
