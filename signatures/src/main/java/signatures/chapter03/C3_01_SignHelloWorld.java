package signatures.chapter03;

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
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class C3_01_SignHelloWorld {

	public static final String KEYSTORE = "src/main/resources/ks";
	public static final String PASSWORD = "password";
	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String DEST = "results/hello_signed%s.pdf";
	
	public void sign(PrivateKey pk, Certificate[] chain,
			String src, String dest, String provider,
			String reason, String location,
			String digestAlgorithm, boolean subfilter)
					throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        MakeSignature.signDetached(appearance, pks, chain, null, null, null, provider, 0, subfilter);
	}
	
	public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(KEYSTORE), PASSWORD.toCharArray());
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
		C3_01_SignHelloWorld app = new C3_01_SignHelloWorld();
		app.sign(pk, chain, SRC, String.format(DEST, 1), provider.getName(), "Test 1", "Ghent", DigestAlgorithms.SHA256, MakeSignature.CMS);
		app.sign(pk, chain, SRC, String.format(DEST, 2), provider.getName(), "Test 2", "Ghent", DigestAlgorithms.SHA512, MakeSignature.CMS);
		app.sign(pk, chain, SRC, String.format(DEST, 3), provider.getName(), "Test 3", "Ghent", DigestAlgorithms.SHA256, MakeSignature.CADES);
		app.sign(pk, chain, SRC, String.format(DEST, 4), provider.getName(), "Test 4", "Ghent", DigestAlgorithms.RIPEMD160, MakeSignature.CADES);
	}
}
