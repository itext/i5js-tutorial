package signatures.chapter4;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.ExceptionConverter;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalBlankSignatureContainer;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class C4_09_DeferredSigning {
	public static final String CERT = "src/main/resources/bruno.crt";
	public static final String KEYSTORE = "src/main/resources/ks";
	public static final char[] PASSWORD = "password".toCharArray();
	
	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String TEMP = "results/chapter4/hello_empty_sig.pdf";
	public static final String DEST = "results/chapter4/hello_sig_ok.pdf";

	class MyExternalSignatureContainer implements ExternalSignatureContainer {

		protected PrivateKey pk;
		protected Certificate[] chain;
		
		public MyExternalSignatureContainer(PrivateKey pk, Certificate[] chain) {
			this.pk = pk;
			this.chain = chain;
		}
		
		public byte[] sign(InputStream is) throws GeneralSecurityException {
			try {
				PrivateKeySignature signature = new PrivateKeySignature(pk, "SHA256", "BC");
				String hashAlgorithm = signature.getHashAlgorithm();
				BouncyCastleDigest digest = new BouncyCastleDigest();
				PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, null, digest, false);
		        byte hash[] = DigestAlgorithms.digest(is, digest.getMessageDigest(hashAlgorithm));
				Calendar cal = Calendar.getInstance();
		        byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, cal, null, null, CryptoStandard.CMS);
		        byte[] extSignature = signature.sign(sh);
		        sgn.setExternalDigest(extSignature, null, signature.getEncryptionAlgorithm());
				return sgn.getEncodedPKCS7(hash, cal, null, null, null, CryptoStandard.CMS);
			}
			catch (IOException ioe) {
				throw new ExceptionConverter(ioe);
			}
		}

		public void modifySigningDictionary(PdfDictionary signDic) {
		}
		
	}
	
	public void emptySignature(String src, String dest, String fieldname, Certificate[] chain) throws IOException, DocumentException, GeneralSecurityException {
		PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, fieldname);
        appearance.setCertificate(chain[0]);
		ExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
		MakeSignature.signExternalContainer(appearance, external, 8192);
	}
	
	public void createSignature(String src, String dest, String fieldname, PrivateKey pk, Certificate[] chain) throws IOException, DocumentException, GeneralSecurityException {
        
		PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        ExternalSignatureContainer external = new MyExternalSignatureContainer(pk, chain);
        MakeSignature.signDeferred(reader, fieldname, os, external);
	}
	
	public static void main(String[] args) throws IOException, GeneralSecurityException, DocumentException {
		BouncyCastleProvider providerBC = new BouncyCastleProvider();
		Security.addProvider(providerBC);

	    // we load our private key from the key store
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = (String)ks.aliases().nextElement();
        Certificate[] chain = ks.getCertificateChain(alias);
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
		
		C4_09_DeferredSigning app = new C4_09_DeferredSigning();
		app.emptySignature(SRC, TEMP, "sig", chain);
		app.createSignature(TEMP, DEST, "sig", pk, chain);
	}
}
