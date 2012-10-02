package signatures.chapter5;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
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

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PRStream;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.PdfPKCS7;

public class C5_06_ValidateLTV {
	public static final String EXAMPLE = "results/chapter5/ltv_4.pdf";
	public static final String REV = "results/chapter5/rev_%s.pdf";

	
	public static void main(String[] args) throws IOException, GeneralSecurityException, OCSPException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		
		String path = EXAMPLE;
		Date checkDate = new Date();
		List<X509CRL> crls = null;
		List<BasicOCSPResp> ocsps = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
		while (true) {
			PdfReader reader = new PdfReader(path);
			AcroFields fields = reader.getAcroFields();
			List<String> names = fields.getSignatureNames();
			String lastSig = names.remove(names.size() - 1);
			PdfPKCS7 pkcs7 = fields.verifySignature(lastSig);
			System.out.println("Signature: " + lastSig);
			if (fields.signatureCoversWholeDocument(lastSig)) {
				System.out.println("Signature covers whole document");
			}
			else {
				throw new GeneralSecurityException("Signature doesn't cover whole document.");
			}
			if (pkcs7.verify()) {
				System.out.println("Integrity OK!");
			}
			else {
				throw new GeneralSecurityException("The document was altered after the final signature was applied.");
			}
			X509Certificate signCert = pkcs7.getSigningCertificate();
			Certificate[] certs = pkcs7.getSignCertificateChain();
			for (int i = 0; i < certs.length; i++) {
				X509Certificate cert = (X509Certificate) certs[i];
				cert.checkValidity(checkDate);
			}
			System.out.println("All certificates are valid on " + checkDate.toString());
			if (pkcs7.isTsp()) {
				System.out.println("The signature is a document-level timestamp");
				if (crls == null) {
					String crlurl = CertificateUtil.getCRLURL(signCert);
			        X509CRL crl = (X509CRL)cf.generateCRL(new URL(crlurl).openStream());
			        crls = new ArrayList<X509CRL>();
			        crls.add(crl);
				}
				boolean crlFound = false;
				for (X509CRL crl : crls) {
					System.out.println("Check crl " + crl.getIssuerDN());
					if (crl.getIssuerX500Principal().equals(signCert.getIssuerX500Principal())) {
						System.out.println("Found corresponding CRL!");
						crlFound = true;
					}
 					if (crl.isRevoked(signCert)) {
						throw new GeneralSecurityException("The certificate of the final document-level timestamp has been revoked.");
		        	}
				}
				if (crlFound) {
					System.out.println("CRLs OK!");
				}
				else {
					throw new GeneralSecurityException("CRL corresponding with the signing certificate not found");
				}
				crls = new ArrayList<X509CRL>();
				PdfDictionary dss = reader.getCatalog().getAsDict(PdfName.DSS);
				PdfArray crlarray = dss.getAsArray(PdfName.CRLS);
				if (crlarray != null) {
					for (int i = 0; i < crlarray.size(); i++) {
						PRStream stream = (PRStream) crlarray.getAsStream(i);
						X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(PdfReader.getStreamBytes(stream)));
						crls.add(crl);
					}
				}
				ocsps = new ArrayList<BasicOCSPResp>();
				PdfArray ocsparray = dss.getAsArray(PdfName.OCSPS);
				if (ocsparray != null) {
					for (int i = 0; i < ocsparray.size(); i++) {
						PRStream stream = (PRStream) ocsparray.getAsStream(i);
						OCSPResp ocspResponse = new OCSPResp(PdfReader.getStreamBytes(stream));
						if (ocspResponse.getStatus() == 0)
							ocsps.add((BasicOCSPResp) ocspResponse.getResponseObject());
					}
				}
				lastSig = names.remove(names.size() - 1);
				path = String.format(REV, fields.getRevision(lastSig));
			    FileOutputStream fos = new FileOutputStream(path);
			    InputStream is = fields.extractRevision(lastSig);
			    byte[] b = new byte[1028];
			    int n = 0;
			    while ((n = is.read(b)) > 0) {
			        fos.write(b, 0, n);
			    }
			    fos.close();
			    is.close();
				checkDate = pkcs7.getTimeStampDate().getTime();
			}
			else {
				for (String name : fields.getSignatureNames()) {
					System.out.println("Signature: " + name);
					pkcs7 = fields.verifySignature(name);
					signCert = pkcs7.getSigningCertificate();
					certs = pkcs7.getSignCertificateChain();
					if (pkcs7.verify()) {
						System.out.println("Integrity OK!");
						boolean crlFound = false;
						for (X509CRL crl : crls) {
							System.out.println("Check crl " + crl.getIssuerDN());
							if (crl.getIssuerX500Principal().equals(signCert.getIssuerX500Principal())) {
								System.out.println("Found corresponding CRL!");
								crlFound = true;
							}
							if (crl.isRevoked(signCert)) {
								throw new GeneralSecurityException("The certificate of the final document-level timestamp has been revoked.");
							}
						}
						if (crlFound) {
							System.out.println("CRLs OK!");
						}
						boolean ocspFound = false;
						if (ocsps != null) {
							for (BasicOCSPResp ocspResp : ocsps) {
								try {
									if (ocspResp.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(certs[1].getPublicKey()))) {
										ocspFound = true;
										break;
									}
								} catch (OperatorCreationException e) {
									e.printStackTrace();
								}
							}
						}
						if (ocspFound) {
							System.out.println("OSCP Found!");
						}
						if (!ocspFound && !crlFound)
							throw new GeneralSecurityException("NO OCSP, NO CRL found.");
					}
					else {
						throw new GeneralSecurityException("The document was altered after the final signature was applied.");
					}
				}
				break;
			}
		}
	}

}
