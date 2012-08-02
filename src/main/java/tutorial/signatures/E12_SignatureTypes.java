package tutorial.signatures;

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
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class E12_SignatureTypes {

	public static final String KEYSTORE = "src/main/resources/signatures/ks";
	public static final String PASSWORD = "password";
	public static final String SRC = "src/main/resources/signatures/hello.pdf";
	public static final String DEST = "results/signatures/hello_level_%s.pdf";
	
	public void sign(PrivateKey pk, Certificate[] chain,
			String src, String dest, String provider,
			String reason, String location, int certificationLevel,
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
        appearance.setCertificationLevel(certificationLevel);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        MakeSignature.signDetached(appearance, pks, chain, null, null, null, provider, 0, subfilter);
	}
	
	public void addSomething(String src, String dest) throws IOException, DocumentException {
		PdfReader reader = new PdfReader(src);
		PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest), '\0', true);
		PdfAnnotation comment = PdfAnnotation.createText(stamper.getWriter(),
				new Rectangle(200, 800, 250, 820), "Finally Signed!",
				"Bruno Specimen has finally signed the document", true, "Comment");
		stamper.addAnnotation(comment, 1);
		stamper.close();
	}
	
	public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(KEYSTORE), PASSWORD.toCharArray());
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
		E12_SignatureTypes app = new E12_SignatureTypes();
		app.sign(pk, chain, SRC, String.format(DEST, 1), provider.getName(), "Test 1", "Ghent", PdfSignatureAppearance.NOT_CERTIFIED, DigestAlgorithms.SHA256, MakeSignature.CMS);
		app.sign(pk, chain, SRC, String.format(DEST, 2), provider.getName(), "Test 2", "Ghent", PdfSignatureAppearance.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS, DigestAlgorithms.SHA256, MakeSignature.CMS);
		app.sign(pk, chain, SRC, String.format(DEST, 3), provider.getName(), "Test 2", "Ghent", PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED, DigestAlgorithms.SHA256, MakeSignature.CMS);
		app.addSomething(String.format(DEST, 1), String.format(DEST, "1_annotated"));
		app.addSomething(String.format(DEST, 2), String.format(DEST, "2_annotated"));
		app.addSomething(String.format(DEST, 3), String.format(DEST, "3_annotated"));
	}
}
