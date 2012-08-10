package signatures.chapter04;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

public class C4_08_SignWithToken extends C4_01_SignWithCAcert {
	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String DEST = "results/hello_token.pdf";

	public static void main(String[] args) throws IOException, GeneralSecurityException, DocumentException {

        KeyStore ks = KeyStore.getInstance("Windows-MY");
		ks.load(null, null);
        String alias = "Bruno Lowagie";
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
        C4_08_SignWithToken app = new C4_08_SignWithToken();
		app.sign(pk, chain, SRC, DEST, null, "Test", "Ghent",
				DigestAlgorithms.SHA256, MakeSignature.CMS,
				null, ocspClient, tsaClient, 0);
	}
}
