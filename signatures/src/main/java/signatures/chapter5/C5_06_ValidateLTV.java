package signatures.chapter5;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import com.itextpdf.text.log.Logger;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PRStream;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.LtvValidation;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PdfPKCS7;

public class C5_06_ValidateLTV {
	public static final String EXAMPLE1 = "results/chapter5/ltv_1.pdf";
	public static final String EXAMPLE2 = "results/chapter5/ltv_2.pdf";
	public static final String EXAMPLE3 = "results/chapter5/ltv_3.pdf";
	public static final String EXAMPLE4 = "results/chapter5/ltv_4.pdf";
	
	public static void main(String[] args) throws IOException, GeneralSecurityException, OCSPException, OperatorCreationException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C5_06_ValidateLTV app = new C5_06_ValidateLTV();
		System.out.println(EXAMPLE1);
		app.validate(new PdfReader(EXAMPLE1));
		System.out.println();
		System.out.println(EXAMPLE2);
		app.validate(new PdfReader(EXAMPLE2));
		System.out.println();
		System.out.println(EXAMPLE3);
		app.validate(new PdfReader(EXAMPLE3));
		System.out.println();
		System.out.println(EXAMPLE4);
		app.validate(new PdfReader(EXAMPLE4));
	}
	
	public void validate(PdfReader reader) throws IOException, GeneralSecurityException, OCSPException, OperatorCreationException {
 		LtvValidation data = new LtvValidation(reader);
		data.verify();
	}
}
