package signatures.chapter04;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

public class C4_10_SignWithToken extends C4_01_SignWithCAcert {
	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String DEST = "results/hello_token.pdf";

	public static void main(String[] args) throws IOException, GeneralSecurityException, DocumentException {

		LoggerFactory.getInstance().setLogger(new SysoLogger());
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
        C4_10_SignWithToken app = new C4_10_SignWithToken();
		app.sign(pk, chain, SRC, DEST, null, "Test", "Ghent",
				DigestAlgorithms.SHA256, CryptoStandard.CMS,
				crlList, ocspClient, tsaClient, 0);
	}
}
