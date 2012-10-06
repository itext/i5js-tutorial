package signatures.chapter5;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateVerifier;
import com.itextpdf.text.pdf.security.LtvVerifier;
import com.itextpdf.text.pdf.security.LtvVerification.CertificateOption;

public class C5_06_ValidateLTV {
	public static final String ADOBE = "src/main/resources/adobeRootCA.cer";
	public static final String EXAMPLE1 = "results/chapter5/ltv_1.pdf";
	public static final String EXAMPLE2 = "results/chapter5/ltv_2.pdf";
	public static final String EXAMPLE3 = "results/chapter5/ltv_3.pdf";
	public static final String EXAMPLE4 = "results/chapter5/ltv_4.pdf";
	
	public static void main(String[] args) throws IOException, GeneralSecurityException, OCSPException, OperatorCreationException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C5_06_ValidateLTV app = new C5_06_ValidateLTV();
		System.out.println(EXAMPLE1);
		app.validate(new PdfReader(EXAMPLE1));
		System.out.println();
		System.out.println(EXAMPLE2);
		app.validate(new PdfReader(EXAMPLE2));
		System.out.println();
		System.out.println(EXAMPLE3);
		app.validate(new PdfReader(EXAMPLE3));
		System.out.println();
		System.out.println(EXAMPLE4);
		app.validate(new PdfReader(EXAMPLE4));
	}
	
	public void validate(PdfReader reader) throws IOException, GeneralSecurityException, OCSPException, OperatorCreationException {
		
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(null, null);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		ks.setCertificateEntry("adobe",
				cf.generateCertificate(new FileInputStream(ADOBE)));
		
		CertificateVerifier custom = new CertificateVerifier(null) {
			public boolean verify(X509Certificate signCert,
					X509Certificate issuerCert, Date signDate)
					throws GeneralSecurityException, IOException {
				System.out.println("ALL VERIFICATIONS DONE");
				return false;
			}
		};
		
 		LtvVerifier data = new LtvVerifier(reader);
 		data.setCertificateOption(CertificateOption.WHOLE_CHAIN);
 		data.setVerifier(custom);
 		data.setVerifyRootCertificate(false);
 		data.setOnlineCheckingAllowed(false);
 		data.setKeyStore(ks);
		data.verify();
	}
}
