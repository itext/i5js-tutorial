package signatures.chapter5;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.CertificateVerification;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PdfPKCS7;

public class C5_03_SignatureValidation {
	public static final String EXAMPLE1 = "results/chapter2/step_4_signed_by_alice_bob_carol_and_dave.pdf";
	public static final String EXAMPLE2 = "results/chapter2/hello_level_1_annotated_wrong.pdf";
	public static final String EXAMPLE3 = "results/chapter2/step_5_signed_by_alice_and_bob_broken_by_chuck.pdf";
	public static final String EXAMPLE4 = "results/chapter2/step_6_signed_by_dave_broken_by_chuck.pdf";
	public static final String EXAMPLE5 = "results/chapter3/hello_cacert_ocsp_ts.pdf";
	public static final String EXAMPLE6 = "results/chapter3/hello_token.pdf";
	public static final String EXAMPLE7 = "results/chapter4/hello_smartcard_Authentication.pdf";
	public static final String EXAMPLE8 = "results/chapter4/hello_smartcard_Signature.pdf";

	public void verifySignature(AcroFields fields, String name) throws GeneralSecurityException, IOException {
		System.out.println("Signature covers whole document: " + fields.signatureCoversWholeDocument(name));
		System.out.println("Document revision: " + fields.getRevision(name) + " of " + fields.getTotalRevisions());
        PdfPKCS7 pkcs7 = fields.verifySignature(name);
        System.out.println("Subject: " + CertificateInfo.getSubjectFields(pkcs7.getSigningCertificate()));
        System.out.println("Revision modified: " + !pkcs7.verify());
        Certificate[] certs = pkcs7.getSignCertificateChain();
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        for (int i = 0; i < certs.length; i++) {
        	X509Certificate cert = (X509Certificate)certs[i];
        	System.out.println("=== Certificate " + i + " ===");
        	showCertificateInfo(cert);
        	ks.setCertificateEntry("cert" + i, cert);
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
	}
	
	public void showCertificateInfo(X509Certificate cert) {
    	System.out.println("Issuer: " + cert.getIssuerDN());
    	System.out.println("Subject: " + cert.getSubjectDN());
	}
	
	public void verifySignatures(String path) throws IOException, GeneralSecurityException {
		System.out.println(path);
        PdfReader reader = new PdfReader(path);
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
		for (String name : names) {
			System.out.println("===== " + name + " =====");
			verifySignature(fields, name);
		}
		System.out.println();
	}
	
	public static void main(String[] args) throws IOException, GeneralSecurityException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C5_03_SignatureValidation app = new C5_03_SignatureValidation();
		app.verifySignatures(EXAMPLE1);
		app.verifySignatures(EXAMPLE2);
		app.verifySignatures(EXAMPLE3);
		app.verifySignatures(EXAMPLE4);
		app.verifySignatures(EXAMPLE5);
		app.verifySignatures(EXAMPLE6);
		app.verifySignatures(EXAMPLE7);
		app.verifySignatures(EXAMPLE8);
	}
}
