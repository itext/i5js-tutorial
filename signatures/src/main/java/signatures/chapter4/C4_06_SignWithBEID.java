package signatures.chapter4;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;

import javax.smartcardio.CardException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.smartcard.CardReaders;
import com.itextpdf.smartcard.EidSignature;
import com.itextpdf.smartcard.SmartCardWithKey;
import com.itextpdf.smartcard.beid.BeIDCard;
import com.itextpdf.smartcard.beid.BeIDCertificates;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;

public class C4_06_SignWithBEID {

	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String DEST = "results/chapter4/hello_beid.pdf";

	public void sign(String src, String dest,
			SmartCardWithKey card, Certificate[] chain,
			CryptoStandard subfilter,
			String reason, String location,
			Collection<CrlClient> crlList,
			OcspClient ocspClient,
			TSAClient tsaClient,
			int estimatedSize)
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
        ExternalSignature eid = new EidSignature(card, "SHA256", "BC");
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, eid, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
	}
	
	public static void main(String[] args) throws CardException, GeneralSecurityException, IOException, DocumentException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		
		CardReaders readers = new CardReaders();
		SmartCardWithKey card = new BeIDCard(readers.getReadersWithCard().get(0));
		card.setSecure(true);
		Certificate[] chain = BeIDCertificates.getSignCertificateChain(card);
		Collection<CrlClient> crlList = new ArrayList<CrlClient>();
		crlList.add(new CrlClientOnline(chain));
        OcspClient ocspClient = new OcspClientBouncyCastle();
		C4_06_SignWithBEID app = new C4_06_SignWithBEID();
		app.sign(SRC, DEST, card, chain, CryptoStandard.CMS,
				"Test", "Ghent", crlList, ocspClient, null, 0);
	}
}
