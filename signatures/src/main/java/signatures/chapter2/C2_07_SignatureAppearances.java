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
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfSignatureAppearance.RenderingMode;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class C2_07_SignatureAppearances {

	public static final String KEYSTORE = "src/main/resources/ks";
	public static final char[] PASSWORD = "password".toCharArray();
	public static final String IMG = "src/main/resources/1t3xt.gif";
	public static final String SRC = "src/main/resources/hello_to_sign.pdf";
	public static final String DEST = "results/chapter2/signature_appearance_%s.pdf";
	
	public void sign(String src, String name, String dest,
			Certificate[] chain, PrivateKey pk,
			String digestAlgorithm, String provider,
			CryptoStandard subfilter,
			String reason, String location, RenderingMode renderingMode,
			Image image)
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
        appearance.setLayer2Text("Signed on " + new Date().toString());
        appearance.setRenderingMode(renderingMode);
        appearance.setSignatureGraphic(image);
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
        Image image = Image.getInstance(IMG);
        C2_07_SignatureAppearances app = new C2_07_SignatureAppearances();
        app.sign(SRC, "Signature1", String.format(DEST, 1), chain, pk,
        		DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS,
        		"Appearance 1", "Ghent", RenderingMode.DESCRIPTION, null);
        app.sign(SRC, "Signature1", String.format(DEST, 2), chain, pk,
        		DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS,
        		"Appearance 2", "Ghent", RenderingMode.NAME_AND_DESCRIPTION, null);
        app.sign(SRC, "Signature1", String.format(DEST, 3), chain, pk,
        		DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS,
        		"Appearance 3", "Ghent", RenderingMode.GRAPHIC_AND_DESCRIPTION, image);
        app.sign(SRC, "Signature1", String.format(DEST, 4), chain, pk,
        		DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS,
        		"Appearance 4", "Ghent", RenderingMode.GRAPHIC, image);
	}
}
