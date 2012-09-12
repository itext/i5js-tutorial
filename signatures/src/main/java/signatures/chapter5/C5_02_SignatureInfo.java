package signatures.chapter5;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfNumber;
import com.itextpdf.text.pdf.security.PdfPKCS7;

public class C5_02_SignatureInfo extends C5_01_SignatureIntegrity {
	public static final String EXAMPLE1 = "results/chapter2/step_4_signed_by_alice_bob_carol_and_dave.pdf";
	public static final String EXAMPLE2 = "results/chapter3/hello_cacert_ocsp_ts.pdf";
	public static final String EXAMPLE3 = "results/chapter3/hello_token.pdf";
	public static final String EXAMPLE4 = "results/chapter2/hello_signed4.pdf";
	public static final String EXAMPLE5 = "results/chapter4/hello_smartcard_Signature.pdf";

	public PdfPKCS7 verifySignature(AcroFields fields, String name) throws GeneralSecurityException, IOException {
		PdfPKCS7 pkcs7 = super.verifySignature(fields, name);
		System.out.println("Digest algorithm: " + pkcs7.getHashAlgorithm());
		System.out.println("Encryption algorithm: " + pkcs7.getEncryptionAlgorithm());
		System.out.println("Filter subtype: " + pkcs7.getFilterSubtype());
		PdfDictionary sigDict = fields.getSignatureDictionary(name);
		PdfArray ref = sigDict.getAsArray(PdfName.REFERENCE);
		if (ref == null) {
			System.out.println("Signature type: approval");
		}
		else {
			boolean certification = false;
			boolean fillInAllowed = true;
			boolean annotationsAllowed = true;
			PdfName action = null;
			PdfArray fieldlocks = null;
			for (int i = 0; i < ref.size(); i++) {
				PdfDictionary dict = ref.getAsDict(i);
				PdfDictionary params = dict.getAsDict(PdfName.TRANSFORMPARAMS);
				if (PdfName.DOCMDP.equals(dict.getAsName(PdfName.TRANSFORMMETHOD))) {
					certification = true;
				}
				if (action == null)
					action = params.getAsName(PdfName.ACTION);
				if (fieldlocks == null)
					fieldlocks = params.getAsArray(PdfName.FIELDS);
				PdfNumber p = params.getAsNumber(PdfName.P);
				if (p == null)
					continue;
				switch (p.intValue()) {
				default:
					break;
				case 1:
					fillInAllowed &= false;
				case 2:
					annotationsAllowed &= false;
				}
			}
			if (certification) {
				System.out.println("Signature type: certification");
			}
			else {
				System.out.println("Signature type: approval");
			}
			System.out.println("Form filling allowed: " + fillInAllowed);
			System.out.println("Annotations allowed: " + annotationsAllowed);
			if (action != null) {
				System.out.print("Field locks: " + action);
				if (fieldlocks != null) {
					System.out.print(fieldlocks);
				}
				System.out.println();
			}
		}
        return pkcs7;
	}
	
	public static void main(String[] args) throws IOException, GeneralSecurityException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C5_02_SignatureInfo app = new C5_02_SignatureInfo();
		app.verifySignatures(EXAMPLE1);
		app.verifySignatures(EXAMPLE2);
		app.verifySignatures(EXAMPLE3);
		app.verifySignatures(EXAMPLE4);
		app.verifySignatures(EXAMPLE5);
	}
}
