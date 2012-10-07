package signatures.chapter5;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.security.CRLVerifier;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.OCSPVerifier;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.VerificationException;
import com.itextpdf.text.pdf.security.VerificationOK;

public class C5_03_CertificateValidation extends C5_01_SignatureIntegrity {
	public static final String ADOBE = "src/main/resources/adobeRootCA.cer";
	public static final String CACERT = "src/main/resources/CACertSigningAuthority.crt";
	public static final String BRUNO = "src/main/resources/bruno.crt";

	public static final String EXAMPLE1 = "results/chapter3/hello_cacert_ocsp_ts.pdf";
	public static final String EXAMPLE2 = "results/chapter3/hello_token.pdf";
	public static final String EXAMPLE3 = "results/chapter2/hello_signed1.pdf";
	public static final String EXAMPLE4 = "results/chapter4/hello_smartcard_Signature.pdf";

	KeyStore ks;

	public PdfPKCS7 verifySignature(AcroFields fields, String name)
			throws GeneralSecurityException, IOException {
		PdfPKCS7 pkcs7 = super.verifySignature(fields, name);
		Certificate[] certs = pkcs7.getSignCertificateChain();
		Calendar cal = pkcs7.getSignDate();
		List<VerificationException> errors = CertificateVerification.verifyCertificates(certs, ks, cal);
		if (errors.size() == 0)
			System.out.println("Certificates verified against the KeyStore");
		else
			System.out.println(errors);
		for (int i = 0; i < certs.length; i++) {
			X509Certificate cert = (X509Certificate) certs[i];
			System.out.println("=== Certificate " + i + " ===");
			showCertificateInfo(cert, cal.getTime());
		}
		X509Certificate signCert = (X509Certificate)certs[0];
		X509Certificate issuerCert = (certs.length > 1 ? (X509Certificate)certs[1] : null);
		System.out.println("=== Checking validity of the document at the time of signing ===");
		checkRevocation(pkcs7, signCert, issuerCert, cal.getTime());
		System.out.println("=== Checking validity of the document today ===");
		checkRevocation(pkcs7, signCert, issuerCert, new Date());
		return pkcs7;
	}
	
	public void checkRevocation(PdfPKCS7 pkcs7, X509Certificate signCert, X509Certificate issuerCert, Date date) throws GeneralSecurityException, IOException {
		List<BasicOCSPResp> ocsps = new ArrayList<BasicOCSPResp>();
		if (pkcs7.getOcsp() != null)
			ocsps.add(pkcs7.getOcsp());
		OCSPVerifier ocspVerifier = new OCSPVerifier(null, ocsps);
		List<VerificationOK> verification =
			ocspVerifier.verify(signCert, issuerCert, date);
		if (verification.size() == 0) {
			List<X509CRL> crls = new ArrayList<X509CRL>();
			if (pkcs7.getCRLs() != null) {
				for (CRL crl : pkcs7.getCRLs())
					crls.add((X509CRL)crl);
			}
			CRLVerifier crlVerifier = new CRLVerifier(null, crls);
			verification.addAll(crlVerifier.verify(signCert, issuerCert, date));
		}
		if (verification.size() == 0) {
			System.out.println("The signing certificate couldn't be verified");
		}
		else {
			for (VerificationOK v : verification)
				System.out.println(v);
		}
	}

	public void showCertificateInfo(X509Certificate cert, Date signDate) {
		System.out.println("Issuer: " + cert.getIssuerDN());
		System.out.println("Subject: " + cert.getSubjectDN());
		SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
		System.out.println("Valid from: " + date_format.format(cert.getNotBefore()));
		System.out.println("Valid to: " + date_format.format(cert.getNotAfter()));
		try {
			cert.checkValidity(signDate);
			System.out
					.println("The certificate was valid at the time of signing.");
		} catch (CertificateExpiredException e) {
			System.out
					.println("The certificate was expired at the time of signing.");
		} catch (CertificateNotYetValidException e) {
			System.out
					.println("The certificate wasn't valid yet at the time of signing.");
		}
		try {
			cert.checkValidity();
			System.out.println("The certificate is still valid.");
		} catch (CertificateExpiredException e) {
			System.out.println("The certificate has expired.");
		} catch (CertificateNotYetValidException e) {
			System.out.println("The certificate isn't valid yet.");
		}
	}
	
	private void setKeyStore(KeyStore ks) {
		this.ks = ks;
	}

	public static void main(String[] args) throws IOException,
			GeneralSecurityException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C5_03_CertificateValidation app = new C5_03_CertificateValidation();
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

		ks.load(null, null);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		ks.setCertificateEntry("adobe",
				cf.generateCertificate(new FileInputStream(ADOBE)));
		ks.setCertificateEntry("cacert",
				cf.generateCertificate(new FileInputStream(CACERT)));
		ks.setCertificateEntry("bruno",
				cf.generateCertificate(new FileInputStream(BRUNO)));
		app.setKeyStore(ks);
		app.verifySignatures(EXAMPLE1);
		app.verifySignatures(EXAMPLE2);
		app.verifySignatures(EXAMPLE3);
		app.verifySignatures(EXAMPLE4);
	}
}
