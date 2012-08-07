package tutorial.signatures;

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
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class E10_SignatureAppearances {

	public static final String KEYSTORE = "src/main/resources/signatures/ks";
	public static final String PASSWORD = "password";
	public static final String IMG = "src/main/resources/signatures/1t3xt.gif";
	public static final String SRC = "src/main/resources/signatures/hello_to_sign.pdf";
	public static final String DEST = "results/signatures/signature_appearance_%s.pdf";
	
	public void sign(PrivateKey pk, Certificate[] chain,
			String src, String name, String dest, String provider,
			String reason, String location, RenderingMode renderingMode,
			Image image, String digestAlgorithm, boolean subfilter)
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
        Image image = Image.getInstance(IMG);
        E10_SignatureAppearances app = new E10_SignatureAppearances();
        app.sign(pk, chain, SRC, "Signature1", String.format(DEST, 1), provider.getName(),
        		"Appearance 1", "Ghent", RenderingMode.DESCRIPTION, null,
        		DigestAlgorithms.SHA256, MakeSignature.CMS);
        app.sign(pk, chain, SRC, "Signature1", String.format(DEST, 2), provider.getName(),
        		"Appearance 2", "Ghent", RenderingMode.NAME_AND_DESCRIPTION, null,
        		DigestAlgorithms.SHA256, MakeSignature.CMS);
        app.sign(pk, chain, SRC, "Signature1", String.format(DEST, 3), provider.getName(),
        		"Appearance 3", "Ghent", RenderingMode.GRAPHIC_AND_DESCRIPTION, image,
        		DigestAlgorithms.SHA256, MakeSignature.CMS);
        app.sign(pk, chain, SRC, "Signature1", String.format(DEST, 4), provider.getName(),
        		"Appearance 4", "Ghent", RenderingMode.GRAPHIC, image,
        		DigestAlgorithms.SHA256, MakeSignature.CMS);
	}
}
