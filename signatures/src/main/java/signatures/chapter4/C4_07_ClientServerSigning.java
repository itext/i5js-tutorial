package signatures.chapter4;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.ExceptionConverter;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;

public class C4_07_ClientServerSigning {

	public static final String SRC = "src/main/resources/hello.pdf";
	public static final String DEST = "results/chapter4/hello_server.pdf";

	public static final String CERT = "http://demo.itextsupport.com/SigningApp/itextpdf.cer";
	
	public class ServerSignature implements ExternalSignature {
		public static final String SIGN = "http://demo.itextsupport.com/SigningApp/signbytes";
		
		public String getHashAlgorithm() {
			return DigestAlgorithms.SHA256;
		}

		public String getEncryptionAlgorithm() {
			return "RSA";
		}

		public byte[] sign(byte[] message) throws GeneralSecurityException {
			try {
				URL url = new URL(SIGN);
				HttpURLConnection conn = (HttpURLConnection)url.openConnection();
			    conn.setDoOutput(true);
			    conn.setRequestMethod("POST"); 
			    conn.connect();
			    OutputStream os = conn.getOutputStream();
			    os.write(message);
			    os.flush();
			    os.close();
			    InputStream is = conn.getInputStream();
			    ByteArrayOutputStream baos = new ByteArrayOutputStream();
		        byte[] b = new byte[1];  
		        int read;  
		        while ((read = is.read(b)) != -1) {  
		            baos.write(b, 0, read);  
		        }
			    is.close();
				return baos.toByteArray();
			} catch (IOException e) {
				throw new ExceptionConverter(e);
			}
		}
		
	}
	
	public void sign(String src, String dest,
			Certificate[] chain,
			CryptoStandard subfilter,
			String reason, String location)
					throws GeneralSecurityException, IOException, DocumentException {
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
        // Creating the signature
        ExternalDigest digest = new BouncyCastleDigest();
        ExternalSignature signature = new ServerSignature();
        MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, subfilter);
	}
	
	public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
		CertificateFactory factory = CertificateFactory.getInstance("X.509");
		URL certUrl = new URL(CERT);
		Certificate[] chain = new Certificate[1];
		chain[0] = factory.generateCertificate(certUrl.openStream());
		C4_07_ClientServerSigning app = new C4_07_ClientServerSigning();
		app.sign(SRC, DEST, chain, CryptoStandard.CMS, "Test", "Ghent");
	}
}