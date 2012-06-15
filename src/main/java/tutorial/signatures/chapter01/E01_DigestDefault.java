package tutorial.signatures.chapter01;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

public class E01_DigestDefault {

	protected byte[] digest;
	protected MessageDigest md;
	
	public E01_DigestDefault(String password, String algorithm) throws NoSuchAlgorithmException {
		md = MessageDigest.getInstance(algorithm);
		digest = md.digest(password.getBytes());
	}
	
	public E01_DigestDefault(String password, String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
		md = MessageDigest.getInstance(algorithm, provider);
		digest = md.digest(password.getBytes());
	}
	
	public int getDigestSize() {
		return digest.length;
	}
	
	public String getDigestAsHexString() {
	    StringBuffer hex = new StringBuffer();
	    for (int i = 0; i < digest.length; i++) {
	        hex.append(Integer.toHexString(digest[i] & 0xFF));
	    }
	    return hex.toString();
	}

	
	public boolean checkPassword(String password) {
		return Arrays.equals(digest, md.digest(password.getBytes()));
	}
	
	public static void showTest(String algorithm) {
		try {
			E01_DigestDefault app = new E01_DigestDefault("secret", algorithm);
			System.out.println("Digest using " + algorithm + ": " + app.getDigestSize());
			System.out.println("Digest: " + app.getDigestAsHexString());
			System.out.println("Is the password 'password'? " + app.checkPassword("password"));
			System.out.println("Is the password 'secret'? " + app.checkPassword("secret"));
		} catch (NoSuchAlgorithmException e) {
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
