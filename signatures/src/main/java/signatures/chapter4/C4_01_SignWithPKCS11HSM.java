package signatures.chapter4;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.security.pkcs11.SunPKCS11;

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
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;

public class C4_01_SignWithPKCS11HSM {
	
	public static final String SRC = "/home/itext/hello.pdf";
	public static final String PROPS = "/home/itext/key.properties";
	public static final String DEST = "/home/itext/hello_hsm.pdf";

	public void sign(String src, String dest,
			Certificate[] chain, PrivateKey pk,
			String digestAlgorithm, String provider, CryptoStandard subfilter,
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
        ExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
	}
	
	public static void main(String[] args) throws IOException, GeneralSecurityException, DocumentException {

		LoggerFactory.getInstance().setLogger(new SysoLogger());
		
		Properties properties = new Properties();
		properties.load(new FileInputStream(PROPS));
        char[] pass = properties.getProperty("PASSWORD").toCharArray();
        String pkcs11cfg = properties.getProperty("PKCS11CFG");

		BouncyCastleProvider providerBC = new BouncyCastleProvider();
		Security.addProvider(providerBC);
		FileInputStream fis = new FileInputStream(pkcs11cfg);
		Provider providerPKCS11 = new SunPKCS11(fis);
        Security.addProvider(providerPKCS11);
        
        KeyStore ks = KeyStore.getInstance("PKCS11");
		ks.load(null, pass);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey)ks.getKey(alias, pass);
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
        C4_01_SignWithPKCS11HSM app = new C4_01_SignWithPKCS11HSM();
		app.sign(SRC, DEST, chain, pk, DigestAlgorithms.SHA256, providerPKCS11.getName(), CryptoStandard.CMS,
				"HSM test", "Ghent", crlList, ocspClient, tsaClient, 0);
	}
}
