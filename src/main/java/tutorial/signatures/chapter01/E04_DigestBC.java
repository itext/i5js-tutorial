package tutorial.signatures.chapter01;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class E04_DigestBC extends E03_DigestDefault {

	public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
	static {
		Security.addProvider(PROVIDER);
	}
	
	public E04_DigestBC(String password, String algorithm)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		super(password, algorithm, PROVIDER.getName());
		System.out.println(PROVIDER.getName());
	}
	
	public static void showTest(String algorithm) {
		try {
			E04_DigestBC app = new E04_DigestBC("secret", algorithm);
			System.out.println("Digest using " + algorithm + ": " + app.getDigestSize());
			System.out.println("Digest: " + app.getDigestAsHexString());
			System.out.println("Is the password 'password'? " + app.checkPassword("password"));
			System.out.println("Is the password 'secret'? " + app.checkPassword("secret"));
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		} catch (NoSuchProviderException e) {
			System.out.println(e.getMessage());
		}
	}

	public static void main(String[] args) {
		testAll();
	}
}
