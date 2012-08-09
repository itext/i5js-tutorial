package signatures.chapter02;

import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C2_02_DigestBC extends C2_01_DigestDefault {

	public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
	static {
		Security.addProvider(PROVIDER);
	}
	
	protected C2_02_DigestBC(String password, String algorithm)
			throws GeneralSecurityException {
		super(password, algorithm, PROVIDER.getName());
	}
	
	public static C2_01_DigestDefault getInstance(String password, String algorithm) throws GeneralSecurityException {
		return new C2_02_DigestBC(password, algorithm);
	}

	public static void main(String[] args) {
		testAll();
	}
}
