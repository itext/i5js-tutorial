/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 * 
 * For more info, go to: http://itextpdf.com/learn
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
import com.itextpdf.text.Element;
import com.itextpdf.text.Phrase;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.ColumnText;
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class C2_09_SignatureTypes {

	public static final String KEYSTORE = "src/main/resources/ks";
	public static final char[] PASSWORD = "password".toCharArray();
	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String DEST = "results/chapter2/hello_level_%s.pdf";
	
	public void sign(String src, String dest,
			Certificate[] chain, PrivateKey pk,
			String digestAlgorithm, String provider,
			CryptoStandard subfilter, int certificationLevel,
			String reason, String location)
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
        ExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, subfilter);
	}
	
	public void addText(String src, String dest) throws IOException, DocumentException {
		PdfReader reader = new PdfReader(src);
		PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest), '\0', true);
		ColumnText.showTextAligned(stamper.getOverContent(1), Element.ALIGN_LEFT, new Phrase("TOP SECRET"), 36, 820, 0);
		stamper.close();
	}
	
	public void addAnnotation(String src, String dest) throws IOException, DocumentException {
		PdfReader reader = new PdfReader(src);
		PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest), '\0', true);
		PdfAnnotation comment = PdfAnnotation.createText(stamper.getWriter(),
				new Rectangle(200, 800, 250, 820), "Finally Signed!",
				"Bruno Specimen has finally signed the document", true, "Comment");
		stamper.addAnnotation(comment, 1);
		stamper.close();
	}
	
	public void addWrongAnnotation(String src, String dest) throws IOException, DocumentException {
		PdfReader reader = new PdfReader(src);
		PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest));
		PdfAnnotation comment = PdfAnnotation.createText(stamper.getWriter(),
				new Rectangle(200, 800, 250, 820), "Finally Signed!",
				"Bruno Specimen has finally signed the document", true, "Comment");
		stamper.addAnnotation(comment, 1);
		stamper.close();
	}
	
	public void signAgain(String src, String dest, Certificate[] chain, PrivateKey pk,
			String digestAlgorithm, String provider,
			CryptoStandard subfilter,
			String reason, String location)
					throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(new Rectangle(36, 700, 144, 732), 1, "Signature2");
        // Creating the signature
        ExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
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
		C2_09_SignatureTypes app = new C2_09_SignatureTypes();
		app.sign(SRC, String.format(DEST, 1), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, PdfSignatureAppearance.NOT_CERTIFIED, "Test 1", "Ghent");
		app.sign(SRC, String.format(DEST, 2), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, PdfSignatureAppearance.CERTIFIED_FORM_FILLING_AND_ANNOTATIONS, "Test 1", "Ghent");
		app.sign(SRC, String.format(DEST, 3), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, PdfSignatureAppearance.CERTIFIED_FORM_FILLING, "Test 1", "Ghent");
		app.sign(SRC, String.format(DEST, 4), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED, "Test 1", "Ghent");
		app.addWrongAnnotation(String.format(DEST, 1), String.format(DEST, "1_annotated_wrong"));
		app.addAnnotation(String.format(DEST, 1), String.format(DEST, "1_annotated"));
		app.addAnnotation(String.format(DEST, 2), String.format(DEST, "2_annotated"));
		app.addAnnotation(String.format(DEST, 3), String.format(DEST, "3_annotated"));
		app.addAnnotation(String.format(DEST, 4), String.format(DEST, "4_annotated"));
		app.addText(String.format(DEST, 1), String.format(DEST, "1_text"));
		app.signAgain(String.format(DEST, 1), String.format(DEST, "1_double"), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, "Second signature test", "Gent");
		app.signAgain(String.format(DEST, 2), String.format(DEST, "2_double"), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, "Second signature test", "Gent");
		app.signAgain(String.format(DEST, 3), String.format(DEST, "3_double"), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, "Second signature test", "Gent");
		app.signAgain(String.format(DEST, 4), String.format(DEST, "4_double"), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, "Second signature test", "Gent");
	}
}
