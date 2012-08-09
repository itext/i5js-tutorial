package signatures.chapter04;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOffline;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;

public class C4_04_SignWithCRLOffline extends C4_01_SignWithCAcert {
	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String CRL = "src/main/resources/revoke.crl";
	public static final String DEST = "results/hello_cacert_crl_offline.pdf";
	
	public static void main(String[] args) throws IOException, GeneralSecurityException, DocumentException {
		Properties properties = new Properties();
		properties.load(new FileInputStream("c:/home/blowagie/key.properties"));
    	String path = properties.getProperty("PRIVATE");
        String pass = properties.getProperty("PASSWORD");

		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance("pkcs12", provider.getName());
		ks.load(new FileInputStream(path), pass.toCharArray());
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, pass.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
		CRL crl = (CRL)cf.generateCRL(new FileInputStream(CRL));
        CrlClient crlClient = new CrlClientOffline(crl);
        List<CrlClient> crlList = new ArrayList<CrlClient>();
        crlList.add(crlClient);
        C4_04_SignWithCRLOffline app = new C4_04_SignWithCRLOffline();
		app.sign(pk, chain, SRC, DEST, provider.getName(), "Test", "Ghent", DigestAlgorithms.SHA256, MakeSignature.CMS,
				crlList, null, null, 0);
	}
  
}
