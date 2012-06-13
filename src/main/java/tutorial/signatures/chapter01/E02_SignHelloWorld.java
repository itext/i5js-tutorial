package tutorial.signatures.chapter01;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;

public class E02_SignHelloWorld {

    public void sign(File src, File keyStore, String alias, char[] password, File dest)
            throws IOException, DocumentException, GeneralSecurityException {
    	
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(new FileInputStream(keyStore), password);
            PrivateKey key = (PrivateKey) ks.getKey(alias, password);
            Certificate[] chain = ks.getCertificateChain(alias);
            
            PdfReader reader = new PdfReader(src.getAbsolutePath());
            FileOutputStream os = new FileOutputStream(dest);
            PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setCrypto(key, chain, null, PdfSignatureAppearance.SELF_SIGNED);
            appearance.setReason("Demo purposes.");
            appearance.setLocation("Ghent");
            appearance.setVisibleSignature(new Rectangle(0, 0, 0, 0), 1, "signature");
            stamper.close();
        }
	
	public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException {
		File results = new File("results/signatures");
		results.mkdir();
		File src = new File(results, "hello.pdf");
		File dest = new File(results, "hello_signed.pdf");
		File keyStore = new File("src/main/resources/signatures/ks");
		String alias = "demo";
		char[] password = new char[]{'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
		if (src.exists()) {
			E02_SignHelloWorld app = new E02_SignHelloWorld();
			app.sign(src, keyStore, alias, password, dest);
		}
	}
}
