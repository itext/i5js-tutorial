/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 * 
 * For more info, go to: http://itextpdf.com/sales
 */
package signatures.chapter3;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.security.mscapi.SunMSCAPI;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

public class C3_10_SignWithToken extends C3_01_SignWithCAcert {
	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String DEST = "results/chapter3/hello_token.pdf";
	
	public void sign(PrivateKey pk, Certificate[] chain,
			String src, String dest, String provider,
			String reason, String location,
			String digestAlgorithm, CryptoStandard subfilter,
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
        ExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        ExternalDigest da = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, da, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
	}
	
	public static void main(String[] args) throws IOException, GeneralSecurityException, DocumentException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		
		BouncyCastleProvider providerBC = new BouncyCastleProvider();
		Security.addProvider(providerBC);
		SunMSCAPI providerMSCAPI = new SunMSCAPI();
		Security.addProvider(providerMSCAPI);
        KeyStore ks = KeyStore.getInstance("Windows-MY");
		ks.load(null, null);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey)ks.getKey(alias, null);
        Certificate[] chain = ks.getCertificateChain(alias);
        OcspClient ocspClient = new OcspClientBouncyCastle();
        TSAClient tsaClient = null;
        for (int i = 0; i < chain.length; i++) {
        	X509Certificate cert = (X509Certificate)chain[i];
        	String tsaUrl = CertificateUtil.getTSAURL(cert);
        	if (tsaUrl != null) {
        		tsaClient = new TSAClientBouncyCastle(tsaUrl);
        		break;
        	}
        }
        List<CrlClient> crlList = new ArrayList<CrlClient>();
        crlList.add(new CrlClientOnline(chain));
        C3_10_SignWithToken app = new C3_10_SignWithToken();
		app.sign(pk, chain, SRC, DEST, providerMSCAPI.getName(), "Test", "Ghent",
				DigestAlgorithms.SHA256, CryptoStandard.CMS,
				crlList, ocspClient, tsaClient, 0);
	}
}
