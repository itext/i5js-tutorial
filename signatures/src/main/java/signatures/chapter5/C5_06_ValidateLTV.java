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

import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PRStream;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.OcspClientBouncyCastle;
import com.itextpdf.text.pdf.security.PdfPKCS7;

public class C5_06_ValidateLTV {
	public static final String EXAMPLE1 = "results/chapter5/ltv_1.pdf";
	public static final String EXAMPLE2 = "results/chapter5/ltv_2.pdf";
	public static final String EXAMPLE3 = "results/chapter5/ltv_3.pdf";
	public static final String EXAMPLE4 = "results/chapter5/ltv_4.pdf";

	protected AcroFields fields;
	
	public class VerificationData {
		protected PdfReader reader;
		protected PdfDictionary dss;
		protected Date signDate;
	}
	
	public static void main(String[] args) throws IOException, GeneralSecurityException, OCSPException, OperatorCreationException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C5_06_ValidateLTV app = new C5_06_ValidateLTV();
		System.out.println(EXAMPLE1);
		app.validate(EXAMPLE1);
		System.out.println();
		System.out.println(EXAMPLE2);
		app.validate(EXAMPLE2);
		System.out.println();
		System.out.println(EXAMPLE3);
		app.validate(EXAMPLE3);
		System.out.println();
		System.out.println(EXAMPLE4);
		app.validate(EXAMPLE4);
	}
	
	public void validate(String path) throws IOException, GeneralSecurityException, OCSPException, OperatorCreationException {
 		VerificationData data = new VerificationData();
		data.reader = new PdfReader(path);
		data.signDate = new Date();
		while (data != null) {
			data = verifySignatures(data);
		}
	}
	

	
	public VerificationData verifySignatures(VerificationData data) throws IOException, GeneralSecurityException, OCSPException, OperatorCreationException {
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
	
	public VerificationData checkDocumentLevelTimestamp(String sig, PdfPKCS7 pkcs7, VerificationData data) throws GeneralSecurityException, IOException, OCSPException, OperatorCreationException {
        Certificate[] certs = pkcs7.getSignCertificateChain();
		checkCertificateValidity(certs, data.signDate);
		if (certs.length < 2)
        	throw new GeneralSecurityException("Self-signed TSA certificates can't be checked");
		X509Certificate signCert = (X509Certificate) certs[0];
		X509Certificate issuerCert = (X509Certificate) certs[1];
		
		// Checking CRLs
		List<X509CRL> crls;
		if (data.dss == null) {
			String crlurl = CertificateUtil.getCRLURL(signCert);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
	        X509CRL crl = (X509CRL) cf.generateCRL(new URL(crlurl).openStream());
	        crl.verify(issuerCert.getPublicKey());
	        crls = new ArrayList<X509CRL>();
	        crls.add(crl);
		}
		else {
			crls = getCRLsFromDSS(data.dss);
		}
		boolean crlFound = checkCrls(signCert, issuerCert, data.signDate, crls);
		
		// Checking OCSP
		List<BasicOCSPResp> ocsps;
		if (data.dss == null) {
			ocsps = new ArrayList<BasicOCSPResp>();
			BasicOCSPResp ocsp = getOcspResponse(signCert, issuerCert);
			if (ocsp != null)
				ocsps.add(ocsp);
		}
		else {
			ocsps = getOCSPResponsesFromDSS(data.dss);
		}
		boolean ocspFound = checkOCSPs(signCert, issuerCert, data.signDate, ocsps);
		if (!crlFound && !ocspFound)
			throw new GeneralSecurityException("Couldn't verify with CRL or OCSP");
		if (crlFound)
			System.out.println("CRL found!");
		if (ocspFound)
			System.out.println("OCSP found!");
		VerificationData res = new VerificationData();
		res.dss = data.reader.getCatalog().getAsDict(PdfName.DSS);
	    res.reader = new PdfReader(fields.extractRevision(sig));
		res.signDate = pkcs7.getTimeStampDate().getTime();
		return res;
	}
	
	public void checkRemainingSignatures(List<String> names, VerificationData data) throws GeneralSecurityException, IOException, OCSPException, OperatorCreationException {
		PdfPKCS7 pkcs7;
		for (String name : names) {
			System.out.println("Signature: " + name);
			pkcs7 = fields.verifySignature(name);        
			Certificate[] certs = pkcs7.getSignCertificateChain();
			checkCertificateValidity(certs, data.signDate);
			if (certs.length < 2)
	        	throw new GeneralSecurityException("Self-signed TSA certificates can't be checked");
			X509Certificate signCert = (X509Certificate) certs[0];
			X509Certificate issuerCert = (X509Certificate) certs[1];
			signCert.verify(issuerCert.getPublicKey());
			if (pkcs7.verify()) {
				System.out.println("Integrity OK!");
				List<X509CRL> crls = getCRLsFromDSS(data.dss);
				boolean crlFound = checkCrls(signCert, issuerCert, data.signDate, crls);
				List<BasicOCSPResp> ocsps = getOCSPResponsesFromDSS(data.dss);
				boolean ocspFound = checkOCSPs(signCert, issuerCert, data.signDate, ocsps);
				if (!crlFound && !ocspFound)
					throw new GeneralSecurityException("Couldn't verify with CRL or OCSP");
				if (crlFound)
					System.out.println("CRL found!");
				if (ocspFound)
					System.out.println("OCSP found!");
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
	
	public boolean checkCrls(X509Certificate signCert, X509Certificate issuerCert, Date date, List<X509CRL> crls) throws GeneralSecurityException {
		int validCrlsFound = 0;
		for (X509CRL crl : crls) {
			if (crl.getIssuerX500Principal().equals(signCert.getIssuerX500Principal())
				&& date.after(crl.getThisUpdate()) && date.before(crl.getNextUpdate())) {
				try {
					crl.verify(issuerCert.getPublicKey());
				} catch (GeneralSecurityException e) {
					continue;
				}
				if (crl.isRevoked(signCert)) {
					throw new GeneralSecurityException("The certificate has been revoked.");
				}
				validCrlsFound++;
			}
		}
		return validCrlsFound > 0;
	}
	
	public BasicOCSPResp getOcspResponse(X509Certificate signCert, X509Certificate issuerCert) {
		if (signCert == null && issuerCert == null) {
			return null;
		}
		OcspClientBouncyCastle ocsp = new OcspClientBouncyCastle();
		BasicOCSPResp ocspResp = ocsp.getBasicOCSPResp(
				(X509Certificate) signCert, issuerCert, null);
		if (ocspResp == null) {
			return null;
		}
		SingleResp[] resp = ocspResp.getResponses();
		for (int i = 0; i < resp.length; i++) {
			Object status = resp[i].getCertStatus();
			if (status == CertificateStatus.GOOD) {
				return ocspResp;
			}
		}
		return null;
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
	
	public boolean checkOCSPs(X509Certificate signCert, X509Certificate issuerCert, Date date, List<BasicOCSPResp> ocsps) throws GeneralSecurityException, OCSPException, IOException, OperatorCreationException {
		int validOCSPsFound = 0;
		BigInteger serialNumber = signCert.getSerialNumber();
		for (BasicOCSPResp ocspResp : ocsps) {
			X509CertificateHolder[] certHolders = ocspResp.getCerts();
			Certificate certif = new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( certHolders[0] );
			certif.verify(issuerCert.getPublicKey());
			ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder().setProvider("BC").build(certif.getPublicKey());
			if (!ocspResp.isSignatureValid(verifierProvider)) {
				throw new GeneralSecurityException("OCSP response could not be verified");
			}
			SingleResp[] resp = ocspResp.getResponses();
			for (int i = 0; i < resp.length; i++) {
				if (date.after(resp[i].getNextUpdate())) {
					System.out.println(String.format("OCSP no longer valid: %s after %s", date, resp[i].getThisUpdate(), resp[i].getNextUpdate()));
					continue;
				}
				if (!resp[i].getCertID().matchesIssuer(new X509CertificateHolder(issuerCert.getEncoded()), new BcDigestCalculatorProvider())) {
					System.out.println("OCSP: Issuer doesn't match.");
					continue;
				}
				if (!serialNumber.equals(resp[i].getCertID().getSerialNumber())) {
					System.out.println("OCSP: Serial number doesn't match");
					continue;
				}
				Object status = resp[i].getCertStatus();
				if (status == CertificateStatus.GOOD) {
					validOCSPsFound++;
				}
			}
		}
		return validOCSPsFound > 0;
	}
}
