package signatures.chapter5;

import java.io.ByteArrayInputStream;
import java.io.IOException;
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
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

	protected AcroFields fields;
	
	public class VerificationData {
		protected PdfReader reader;
		protected PdfDictionary dss;
		protected Date signDate;
	}
	
	public static void main(String[] args) throws IOException, GeneralSecurityException, OCSPException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		
		C5_06_ValidateLTV app = new C5_06_ValidateLTV();
		VerificationData data = app.new VerificationData();
		data.reader = new PdfReader(EXAMPLE);
		data.signDate = new Date();
		
		while (data != null) {
			data = app.verifySignatures(data);
		}
	}
	

	
	public VerificationData verifySignatures(VerificationData data) throws IOException, GeneralSecurityException, OCSPException {
		fields = data.reader.getAcroFields();
		List<String> names = fields.getSignatureNames();
		String lastSig = names.get(names.size() - 1);
		PdfPKCS7 pkcs7 = checkIntegrity(lastSig);
		VerificationData newData = null;
		if (pkcs7.isTsp()) {
			System.out.println("Document-level timestamp: " + lastSig);
			newData = checkDocumentLevelTimestamp(names.get(names.size() - 2), pkcs7, data);
		}
		else {
			checkRemainingSignatures(names, data);
		}
		return newData;
	}
	
	public PdfPKCS7 checkIntegrity(String lastSig) throws GeneralSecurityException {
		PdfPKCS7 pkcs7 = fields.verifySignature(lastSig);
		if (fields.signatureCoversWholeDocument(lastSig)) {
			System.out.println("Signature covers whole document");
		}
		else {
			throw new GeneralSecurityException("Signature doesn't cover whole document.");
		}
		if (pkcs7.verify()) {
			System.out.println("Integrity OK!");
			return pkcs7;
		}
		else {
			throw new GeneralSecurityException("The document was altered after the final signature was applied.");
		}
	}

	public boolean checkCertificateValidity(Certificate[] certs, Date date) throws GeneralSecurityException {
		if (date == null)
			date = new Date();
		for (int i = 0; i < certs.length; i++) {
			X509Certificate cert = (X509Certificate) certs[i];
			cert.checkValidity(date);
		}
		System.out.println("All certificates are valid on " + date.toString());
		return true;
	}
	
	public VerificationData checkDocumentLevelTimestamp(String sig, PdfPKCS7 pkcs7, VerificationData data) throws GeneralSecurityException, IOException, OCSPException {
        Certificate[] certs = pkcs7.getSignCertificateChain();
		checkCertificateValidity(certs, data.signDate);
		if (certs.length < 2)
        	throw new GeneralSecurityException("Self-signed TSA certificates can't be checked");
		X509Certificate signCert = (X509Certificate) certs[0];
		
		// Checking CRLs
		List<X509CRL> crls;
		if (data.dss == null) {
			String crlurl = CertificateUtil.getCRLURL(signCert);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
	        X509CRL crl = (X509CRL) cf.generateCRL(new URL(crlurl).openStream());
	        crls = new ArrayList<X509CRL>();
	        crls.add(crl);
		}
		else {
			crls = getCRLsFromDSS(data.dss);
		}
		boolean crlFound = checkCrls(signCert, data.signDate, crls);
		
		// Checking OCSP
		List<BasicOCSPResp> ocsps;
		if (data.dss == null) {
			ocsps = new ArrayList<BasicOCSPResp>();
			// TODO try to fetch OCSP online
		}
		else {
			ocsps = getOCSPResponsesFromDSS(data.dss);
		}
		boolean ocspFound = checkOCSPs(signCert, data.signDate, ocsps);
		if (!crlFound && !ocspFound)
			throw new GeneralSecurityException("Couldn't verify with CRL or OCSP");
		
		VerificationData res = new VerificationData();
		res.dss = data.reader.getCatalog().getAsDict(PdfName.DSS);
	    res.reader = new PdfReader(fields.extractRevision(sig));
		res.signDate = pkcs7.getTimeStampDate().getTime();
		return res;
	}
	
	public void checkRemainingSignatures(List<String> names, VerificationData data) throws GeneralSecurityException, IOException, OCSPException {
		PdfPKCS7 pkcs7;
		for (String name : names) {
			System.out.println("Signature: " + name);
			pkcs7 = fields.verifySignature(name);
			X509Certificate signCert = pkcs7.getSigningCertificate();
			if (pkcs7.verify()) {
				System.out.println("Integrity OK!");
				List<X509CRL> crls = getCRLsFromDSS(data.dss);
				boolean crlFound = checkCrls(signCert, data.signDate, crls);
				List<BasicOCSPResp> ocsps = getOCSPResponsesFromDSS(data.dss);
				boolean ocspFound = checkOCSPs(signCert, data.signDate, ocsps);
				if (!crlFound && !ocspFound)
					throw new GeneralSecurityException("Couldn't verify with CRL or OCSP");
			}
			else {
				throw new GeneralSecurityException("The document was altered after the final signature was applied.");
			}
		} 
	}
	
	public List<X509CRL> getCRLsFromDSS(PdfDictionary dss) throws GeneralSecurityException, IOException {
		List<X509CRL> crls = new ArrayList<X509CRL>();
		PdfArray crlarray = dss.getAsArray(PdfName.CRLS);
		if (crlarray != null) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			for (int i = 0; i < crlarray.size(); i++) {
				PRStream stream = (PRStream) crlarray.getAsStream(i);
				X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(PdfReader.getStreamBytes(stream)));
				crls.add(crl);
			}
		}
		return crls;
	}
	
	public boolean checkCrls(X509Certificate cert, Date date, List<X509CRL> crls) throws GeneralSecurityException {
		int validCrlsFound = 0;
		for (X509CRL crl : crls) {
			// TODO: check if the CRL corresponds with cert and date; we need at least one match!
			validCrlsFound++;
			if (crl.isRevoked(cert)) {
				throw new GeneralSecurityException("The certificate of the final document-level timestamp has been revoked.");
			}
		}
		return validCrlsFound > 0;
	}
	
	public List<BasicOCSPResp> getOCSPResponsesFromDSS(PdfDictionary dss) throws IOException, OCSPException {
		List<BasicOCSPResp> ocsps = new ArrayList<BasicOCSPResp>();
		PdfArray ocsparray = dss.getAsArray(PdfName.OCSPS);
		if (ocsparray != null) {
			for (int i = 0; i < ocsparray.size(); i++) {
				PRStream stream = (PRStream) ocsparray.getAsStream(i);
				OCSPResp ocspResponse = new OCSPResp(PdfReader.getStreamBytes(stream));
				if (ocspResponse.getStatus() == 0)
					ocsps.add((BasicOCSPResp) ocspResponse.getResponseObject());
			}
		}
		return ocsps;
	}
	
	public boolean checkOCSPs(X509Certificate cert, Date date, List<BasicOCSPResp> ocsps) {
		int validOCSPsFound = 0;
		for (BasicOCSPResp ocspResp : ocsps) {
			// TODO: check if the OCSP response corresponds with cert and date; we need at least one match!
			SingleResp[] resp = ocspResp.getResponses();
			for (int i = 0; i < resp.length; i++) {
				Object status = resp[i].getCertStatus();
				if (status == CertificateStatus.GOOD) {
					validOCSPsFound++;
				}
			}
		}
		return validOCSPsFound > 0;
	}
}
