/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 * 
 * For more info, go to: http://itextpdf.com/learn
 */
package signatures.chapter1;

import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class C1_02_DigestBC extends C1_01_DigestDefault {

	public static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();
	static {
		Security.addProvider(PROVIDER);
	}
	
	protected C1_02_DigestBC(String password, String algorithm)
			throws GeneralSecurityException {
		super(password, algorithm, PROVIDER.getName());
	}
	
	public static C1_01_DigestDefault getInstance(String password, String algorithm) throws GeneralSecurityException {
		return new C1_02_DigestBC(password, algorithm);
	}

	public static void main(String[] args) {
		testAll();
	}
}
