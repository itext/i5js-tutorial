/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 * 
 * For more info, go to: http://itextpdf.com/sales
 */
package signatures.chapter2;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class C2_03_SignEmptyField {

	public static final String KEYSTORE = "src/main/resources/ks";
	public static final char[] PASSWORD = "password".toCharArray();
	public static final String SRC = "src/main/resources/hello_to_sign.pdf";
	public static final String DEST = "results/chapter2/field_signed%s.pdf";
	
	public void sign(PrivateKey pk, Certificate[] chain,
			String src, String name, String dest, String provider,
			String reason, String location,
			String digestAlgorithm, CryptoStandard subfilter)
					throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(name);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, subfilter);
	}
	
	public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
		C2_03_SignEmptyField app = new C2_03_SignEmptyField();
		app.sign(pk, chain, SRC, "Signature1", String.format(DEST, 1), provider.getName(), "Test 1", "Ghent", DigestAlgorithms.SHA256, CryptoStandard.CMS);
		app.sign(pk, chain, SRC, "Signature1", String.format(DEST, 2), provider.getName(), "Test 2", "Ghent", DigestAlgorithms.SHA512, CryptoStandard.CMS);
		app.sign(pk, chain, SRC, "Signature1", String.format(DEST, 3), provider.getName(), "Test 3", "Ghent", DigestAlgorithms.SHA256, CryptoStandard.CADES);
		app.sign(pk, chain, SRC, "Signature1", String.format(DEST, 4), provider.getName(), "Test 4", "Ghent", DigestAlgorithms.RIPEMD160, CryptoStandard.CADES);
	}
}
