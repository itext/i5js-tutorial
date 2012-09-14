package signatures.chapter5;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PdfPKCS7;

public class C5_03_CertificateValidation extends C5_01_SignatureIntegrity {
	public static final String ADOBE = "src/main/resources/adobeRootCA.cer";
	public static final String CACERT = "src/main/resources/CACertSigningAuthority.crt";
	public static final String BRUNO = "src/main/resources/bruno.crt";
	public static final String EXAMPLE1 = "results/chapter3/hello_cacert_ocsp_ts.pdf";
	public static final String EXAMPLE2 = "results/chapter3/hello_token.pdf";
	public static final String EXAMPLE3 = "results/chapter4/hello_smartcard_Signature.pdf";
	public static final String EXAMPLE4 = "results/chapter2/hello_signed1.pdf";
	
	KeyStore ks;

	public PdfPKCS7 verifySignature(AcroFields fields, String name) throws GeneralSecurityException, IOException {
        PdfPKCS7 pkcs7 = super.verifySignature(fields, name);
        Certificate[] certs = pkcs7.getSignCertificateChain();
        for (int i = 0; i < certs.length; i++) {
        	X509Certificate cert = (X509Certificate)certs[i];
        	System.out.println("=== Certificate " + i + " ===");
        	showCertificateInfo(cert);
        }
        Calendar cal = pkcs7.getSignDate();
        Object fails[] = CertificateVerification.verifyCertificates(certs, ks, null, cal);
        if (fails == null)
            System.out.println("Certificates verified against the KeyStore");
        else
        	System.out.println("Certificate failed: " + fails[1]);  
        if (certs.length > 1) {
        	OcspClientBouncyCastle ocsp = new OcspClientBouncyCastle();
        	BasicOCSPResp ocspResp = ocsp.getBasicOCSPResp((X509Certificate)certs[0], (X509Certificate)certs[1], null);
        	if (ocspResp == null) {
        		System.out.println("NO OCSP");
        	}
        	else {
        		SingleResp[] resp = ocspResp.getResponses();
        		for (int i = 0; i < resp.length; i++) {
        			Object status = resp[i].getCertStatus();
                    if (status == CertificateStatus.GOOD) {
                    	System.out.println("OCSP Status: GOOD");
                    }
                    else if (status instanceof org.bouncycastle.ocsp.RevokedStatus) {
                    	System.out.println("OCSP Status: REVOKED");
                    }
                    else {
                    	System.out.println("OCSP Status: UNKNOWN");
                    }
        		}
        	}
        }
        return pkcs7;
	}
	
	public void showCertificateInfo(X509Certificate cert) {
    	System.out.println("Issuer: " + cert.getIssuerDN());
    	System.out.println("Subject: " + cert.getSubjectDN());
	}
	
	private void setKeyStore(KeyStore ks) {
		this.ks = ks;
	}
	
	public static void main(String[] args) throws IOException, GeneralSecurityException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C5_03_CertificateValidation app = new C5_03_CertificateValidation();
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        
        ks.load(null, null);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
    	ks.setCertificateEntry("adobe", cf.generateCertificate(new FileInputStream(ADOBE)));
    	ks.setCertificateEntry("cacert", cf.generateCertificate(new FileInputStream(CACERT)));
    	ks.setCertificateEntry("bruno", cf.generateCertificate(new FileInputStream(BRUNO)));
        app.setKeyStore(ks);
		app.verifySignatures(EXAMPLE1);
		app.verifySignatures(EXAMPLE2);
		app.verifySignatures(EXAMPLE3);
		app.verifySignatures(EXAMPLE4);
	}
}
