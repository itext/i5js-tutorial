/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 * 
 * For more info, go to: http://itextpdf.com/learn
 */
package signatures.chapter1;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

public class C1_01_DigestDefault {

	protected byte[] digest;
	protected MessageDigest md;
	
	protected C1_01_DigestDefault(String password, String algorithm, String provider) throws GeneralSecurityException {
		if (provider == null)
			md = MessageDigest.getInstance(algorithm);
		else
			md = MessageDigest.getInstance(algorithm, provider);
		digest = md.digest(password.getBytes());
	}
	
	public static C1_01_DigestDefault getInstance(String password, String algorithm) throws GeneralSecurityException {
		return new C1_01_DigestDefault(password, algorithm, null);
	}
	
	public int getDigestSize() {
		return digest.length;
	}
	
	public String getDigestAsHexString() {
	    return new BigInteger(1, digest).toString(16);
	}

	
	public boolean checkPassword(String password) {
		return Arrays.equals(digest, md.digest(password.getBytes()));
	}
	
	public static void showTest(String algorithm) {
		try {
			C1_01_DigestDefault app = getInstance("password", algorithm);
			System.out.println("Digest using " + algorithm + ": " + app.getDigestSize());
			System.out.println("Digest: " + app.getDigestAsHexString());
			System.out.println("Is the password 'password'? " + app.checkPassword("password"));
			System.out.println("Is the password 'secret'? " + app.checkPassword("secret"));
		} catch (GeneralSecurityException e) {
			System.out.println(e.getMessage());
		}
	}
	
	public static void testAll() {
		showTest("MD5");
		showTest("SHA-1");
		showTest("SHA-224");
		showTest("SHA-256");
		showTest("SHA-384");
		showTest("SHA-512");
		showTest("RIPEMD128");
		showTest("RIPEMD160");
		showTest("RIPEMD256");
	}
	
	public static void main(String[] args) {
		testAll();
	}
}
