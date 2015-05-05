package signatures.chapter5;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.List;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.CrlClient;
import com.itextpdf.text.pdf.security.CrlClientOnline;
import com.itextpdf.text.pdf.security.LtvTimestamp;
import com.itextpdf.text.pdf.security.LtvVerification;
import com.itextpdf.text.pdf.security.OcspClient;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;

public class C5_04_LTV {

	public static final String EXAMPLE1 = "results/chapter3/hello_token.pdf";
	public static final String EXAMPLE2 = "results/chapter4/hello_smartcard_Signature.pdf";
	public static final String EXAMPLE3 = "results/chapter3/hello_cacert_ocsp_ts.pdf";
	public static final String DEST = "results/chapter5/ltv_%s.pdf";
	
	public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException {
		Security.addProvider(new BouncyCastleProvider());
        LoggerFactory.getInstance().setLogger(new SysoLogger());
		Properties properties = new Properties();
		properties.load(new FileInputStream("c:/home/blowagie/key.properties"));
        String tsaUrl = properties.getProperty("TSAURL");
        String tsaUser = properties.getProperty("TSAUSERNAME");
        String tsaPass = properties.getProperty("TSAPASSWORD");
        C5_04_LTV app = new C5_04_LTV();
        TSAClient tsa = new TSAClientBouncyCastle(tsaUrl, tsaUser, tsaPass, 6500, "SHA512");
        OcspClient ocsp = new OcspClientBouncyCastle();
        app.addLtv(EXAMPLE1, String.format(DEST, 1), ocsp, new CrlClientOnline(), tsa);
        System.out.println();
        app.addLtv(EXAMPLE2, String.format(DEST, 2), ocsp, new CrlClientOnline(), tsa);
        System.out.println();
        app.addLtv(EXAMPLE3, String.format(DEST, 3), ocsp, new CrlClientOnline(), tsa);
        System.out.println();
        app.addLtv(String.format(DEST, 1), String.format(DEST, 4), null, new CrlClientOnline(), tsa);
	}
	
	public void addLtv(String src, String dest, OcspClient ocsp, CrlClient crl, TSAClient tsa) throws IOException, DocumentException, GeneralSecurityException {
        PdfReader r = new PdfReader(src);
        FileOutputStream fos = new FileOutputStream(dest);
        PdfStamper stp = PdfStamper.createSignature(r, fos, '\0', null, true);
        LtvVerification v = stp.getLtvVerification();
        AcroFields fields = stp.getAcroFields();
		List<String> names = fields.getSignatureNames();
        String sigName = names.get(names.size() - 1);
		PdfPKCS7 pkcs7 = fields.verifySignature(sigName);
		if (pkcs7.isTsp())
			System.out.println("TIMESTAMP!");
		for (String name : names) {
			v.addVerification(name, ocsp, crl, LtvVerification.CertificateOption.WHOLE_CHAIN, LtvVerification.Level.OCSP_CRL, LtvVerification.CertificateInclusion.NO);
        }
        PdfSignatureAppearance sap = stp.getSignatureAppearance();
        LtvTimestamp.timestamp(sap, tsa, null); 
	}
}
