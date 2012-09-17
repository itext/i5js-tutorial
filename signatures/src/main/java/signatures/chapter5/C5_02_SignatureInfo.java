package signatures.chapter5;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampToken;

import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.AcroFields.FieldPosition;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.security.CertificateInfo;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.SignaturePermissions;
import com.itextpdf.text.pdf.security.SignaturePermissions.FieldLock;

public class C5_02_SignatureInfo extends C5_01_SignatureIntegrity {
	public static final String EXAMPLE1 = "results/chapter2/step_4_signed_by_alice_bob_carol_and_dave.pdf";
	public static final String EXAMPLE2 = "results/chapter3/hello_cacert_ocsp_ts.pdf";
	public static final String EXAMPLE3 = "results/chapter3/hello_token.pdf";
	public static final String EXAMPLE4 = "results/chapter2/hello_signed4.pdf";
	public static final String EXAMPLE5 = "results/chapter4/hello_smartcard_Signature.pdf";
	public static final String EXAMPLE6 = "results/chapter2/field_metadata.pdf";

	public SignaturePermissions inspectSignature(AcroFields fields, String name, SignaturePermissions perms) throws GeneralSecurityException, IOException {
		List<FieldPosition> fps = fields.getFieldPositions(name);
		if (fps == null || fps.size() == 0) {
			System.out.println("Invisible signature");
		}
		else {
			FieldPosition fp = fps.get(0);
			System.out.println(String.format("Field on page %s; llx: %s, lly: %s, urx: %s; ury: %s",
					fp.page, fp.position.getLeft(), fp.position.getBottom(), fp.position.getRight(), fp.position.getTop()));
		}
		
		PdfPKCS7 pkcs7 = super.verifySignature(fields, name);
		System.out.println("Digest algorithm: " + pkcs7.getHashAlgorithm());
		System.out.println("Encryption algorithm: " + pkcs7.getEncryptionAlgorithm());
		System.out.println("Filter subtype: " + pkcs7.getFilterSubtype());
		X509Certificate cert = (X509Certificate) pkcs7.getSigningCertificate();
			System.out.println("Name of the signer: " + CertificateInfo.getSubjectFields(cert).getField("CN"));
		if (pkcs7.getSignName() != null)
			System.out.println("Alternative name of the signer: " + pkcs7.getSignName());
		SimpleDateFormat date_format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SS");
		System.out.println("Signed on: " + date_format.format(pkcs7.getSignDate().getTime()));
		if (pkcs7.getTimeStampDate() != null) {
			System.out.println("TimeStamp: " + date_format.format(pkcs7.getTimeStampDate().getTime()));
			TimeStampToken ts = pkcs7.getTimeStampToken();
			System.out.println("TimeStamp service: " + ts.getTimeStampInfo().getTsa());
		}
		System.out.println("Location: " + pkcs7.getLocation());
		System.out.println("Reason: " + pkcs7.getReason());
		PdfDictionary sigDict = fields.getSignatureDictionary(name);
		PdfString contact = sigDict.getAsString(PdfName.CONTACTINFO);
		if (contact != null)
			System.out.println("Contact info: " + contact);
		perms = new SignaturePermissions(sigDict, perms);
		System.out.println("Signature type: " + (perms.isCertification() ? "certification" : "approval"));
		System.out.println("Filling out fields allowed: " + perms.isFillInAllowed());
		System.out.println("Adding annotations allowed: " + perms.isAnnotationsAllowed());
		for (FieldLock lock : perms.getFieldLocks()) {
			System.out.println("Lock: " + lock.toString());
		}
        return perms;
	}
	
	public void inspectSignatures(String path) throws IOException, GeneralSecurityException {
		System.out.println(path);
        PdfReader reader = new PdfReader(path);
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
        SignaturePermissions perms = null;
		for (String name : names) {
			System.out.println("===== " + name + " =====");
			perms = inspectSignature(fields, name, perms);
		}
		System.out.println();
	}
	
	public static void main(String[] args) throws IOException, GeneralSecurityException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C5_02_SignatureInfo app = new C5_02_SignatureInfo();
		app.inspectSignatures(EXAMPLE1);
		app.inspectSignatures(EXAMPLE2);
		app.inspectSignatures(EXAMPLE3);
		app.inspectSignatures(EXAMPLE4);
		app.inspectSignatures(EXAMPLE5);
		app.inspectSignatures(EXAMPLE6);
	}
}
