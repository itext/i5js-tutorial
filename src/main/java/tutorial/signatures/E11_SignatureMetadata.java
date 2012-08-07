package tutorial.signatures;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfSignatureAppearance.SignatureEvent;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class E11_SignatureMetadata {

	public static final String KEYSTORE = "src/main/resources/signatures/ks";
	public static final String PASSWORD = "password";
	public static final String SRC = "src/main/resources/signatures/hello_to_sign.pdf";
	public static final String DEST = "results/signatures/field_metadata.pdf";
	
	public void sign(PrivateKey pk, Certificate[] chain,
			String src, String name, String dest, String provider,
			String reason, String location, String contact, Calendar signDate,
			final String fullName, String digestAlgorithm, boolean subfilter)
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
        appearance.setContact(contact);
        appearance.setSignDate(signDate);
        appearance.setSignatureEvent(
        	new SignatureEvent(){
        		public void getSignatureDictionary(PdfDictionary sig) {
        			sig.put(PdfName.NAME, new PdfString(fullName));
        		}
        	}
        );
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
		E11_SignatureMetadata app = new E11_SignatureMetadata();
		app.sign(pk, chain, SRC, "Signature1", String.format(DEST, 1), provider.getName(), "Test metadata", "Ghent", "555 123 456", new GregorianCalendar(2012, GregorianCalendar.AUGUST, 5), "Bruno L. Specimen", DigestAlgorithms.SHA256, MakeSignature.CMS);
	}
}
