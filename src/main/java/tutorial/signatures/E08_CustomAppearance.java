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

import com.itextpdf.text.BaseColor;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.ColumnText;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfTemplate;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class E08_CustomAppearance {

	public static final String KEYSTORE = "src/main/resources/signatures/ks";
	public static final String PASSWORD = "password";
	public static final String SRC = "src/main/resources/signatures/hello_to_sign.pdf";
	public static final String DEST = "results/signatures/signature_custom.pdf";
	
	public void sign(PrivateKey pk, Certificate[] chain,
			String src, String name, String dest, String provider,
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
        appearance.setVisibleSignature(name);
        // Creating the appearance for layer 0
        PdfTemplate n0 = appearance.getLayer(0);
        float x = n0.getBoundingBox().getLeft();
        float y = n0.getBoundingBox().getBottom();
        float width = n0.getBoundingBox().getWidth();
        float height = n0.getBoundingBox().getHeight();
        n0.setColorFill(BaseColor.LIGHT_GRAY);
        n0.rectangle(x, y, width, height);
        n0.fill();
        // Creating the appearance for layer 2
        PdfTemplate n2 = appearance.getLayer(2);
        ColumnText ct = new ColumnText(n2);
        ct.setSimpleColumn(n2.getBoundingBox());
        Paragraph p = new Paragraph("This document was signed by Bruno Specimen.");
        ct.addElement(p);
        ct.go();
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
        E08_CustomAppearance app = new E08_CustomAppearance();
        app.sign(pk, chain, SRC, "Signature1", DEST, provider.getName(),
        		"Custom appearance example", "Ghent",
        		DigestAlgorithms.SHA256, MakeSignature.CMS);
	}
}
