package signatures.chapter04;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

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

public class C4_11_SignWithPKCS11 extends C4_01_SignWithCAcert {
	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String DEST = "results/hello_token2.pdf";

	public static void main(String[] args) throws IOException, GeneralSecurityException, DocumentException {

		LoggerFactory.getInstance().setLogger(new SysoLogger());
		
		Properties properties = new Properties();
		properties.load(new FileInputStream("c:/home/blowagie/key.properties"));
        String pass = properties.getProperty("PASSWORD");

		String config = "name=Safenetikey2032\n" +
				"library=c:/windows/system32/dkck201.dll\n" +
				"slotListIndex = " + getSlotsWithTokens()[0];
		ByteArrayInputStream bais = new ByteArrayInputStream(config.getBytes());
		Provider provider = new SunPKCS11(bais);
        Security.addProvider(provider);
        
        KeyStore ks = KeyStore.getInstance("PKCS11");
		ks.load(null, pass.toCharArray());
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey)ks.getKey(alias, pass.toCharArray());
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
        C4_11_SignWithPKCS11 app = new C4_11_SignWithPKCS11();
		app.sign(pk, chain, SRC, DEST, provider.getName(), "Test", "Ghent",
				DigestAlgorithms.SHA256, CryptoStandard.CMS,
				crlList, ocspClient, tsaClient, 0);
	}
	
	
	public static long[] getSlotsWithTokens() throws IOException{
		String libraryPath = "c:/windows/system32/dkck201.dll";
        CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
        String functionList = "C_GetFunctionList";
 
        initArgs.flags = 0;
        PKCS11 tmpPKCS11 = null;
        long[] slotList = null;
        try {
            try {
                tmpPKCS11 = PKCS11.getInstance(libraryPath, functionList, initArgs, false);
            } catch (IOException ex) {
                ex.printStackTrace();
                throw ex;
            }
        } catch (PKCS11Exception e) {
            try {
                initArgs = null;
                tmpPKCS11 = PKCS11.getInstance(libraryPath, functionList, initArgs, true);
            } catch (IOException ex) {
               ex.printStackTrace();
            } catch (PKCS11Exception ex) {
               ex.printStackTrace();
            }
        }
 
        try {
            slotList = tmpPKCS11.C_GetSlotList(true);
 
            for (long slot : slotList){
                CK_TOKEN_INFO tokenInfo = tmpPKCS11.C_GetTokenInfo(slot);
                System.out.println("slot: "+slot+"\nmanufacturerID: "
                        + String.valueOf(tokenInfo.manufacturerID) + "\nmodel: "
                        + String.valueOf(tokenInfo.model));
            }
        } catch (PKCS11Exception ex) {
                ex.printStackTrace();
        } catch (Throwable t) {
            t.printStackTrace();
        }
 
        return slotList;
 
    }
}
