package tutorial.signatures;

import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class E02_DigestBC extends E01_DigestDefault {

	public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
	static {
		Security.addProvider(PROVIDER);
	}
	
	protected E02_DigestBC(String password, String algorithm)
			throws GeneralSecurityException {
		super(password, algorithm, PROVIDER.getName());
	}
	
	public static E01_DigestDefault getInstance(String password, String algorithm) throws GeneralSecurityException {
		return new E02_DigestBC(password, algorithm);
	}

	public static void main(String[] args) {
		testAll();
	}
}
