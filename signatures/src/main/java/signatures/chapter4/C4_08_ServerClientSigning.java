package signatures.chapter4;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.List;

public class C4_08_ServerClientSigning {

	public static final String CERT = "src/main/resources/bruno.crt";
	public static final String KEYSTORE = "src/main/resources/ks";
	public static final char[] PASSWORD = "password".toCharArray();
	public static final String DEST = "results/chapter4/hello_server2.pdf";

	public static final String PRE = "http://demo.itextsupport.com/SigningApp/presign";
	public static final String POST = "http://demo.itextsupport.com/SigningApp/postsign";
	
	public static void main(String[] args) throws IOException, GeneralSecurityException {
		// we make a connection to a PreSign servlet
		URL url = new URL(PRE);
		HttpURLConnection conn = (HttpURLConnection)url.openConnection();
	    conn.setDoOutput(true);
	    conn.setRequestMethod("POST"); 
	    conn.connect();
	    // we upload our self-signed certificate
	    OutputStream os = conn.getOutputStream();
	    FileInputStream fis = new FileInputStream(CERT);
		int read;
		byte[] data = new byte[256];
		while ((read = fis.read(data, 0, data.length)) != -1) {
			os.write(data, 0, read);
		}
	    os.flush();
	    os.close();
	    // we use cookies to maintain a session
		List<String> cookies = conn.getHeaderFields().get("Set-Cookie");
	    // we receive a hash that needs to be signed
	    InputStream is = conn.getInputStream();
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    data = new byte[256];
        while ((read = is.read(data)) != -1) {  
            baos.write(data, 0, read);  
        }
	    is.close();
	    byte[] hash = baos.toByteArray();
	    
	    // we load our private key from the key store
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(KEYSTORE), PASSWORD);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        // we sign the hash received from the server
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(pk);
		sig.update(hash);
		data = sig.sign();
		
		// we make a connection to the PostSign Servlet
		url = new URL(POST);
		conn = (HttpURLConnection)url.openConnection();
		for (String cookie : cookies) {
		    conn.addRequestProperty("Cookie", cookie.split(";", 2)[0]);
		}
	    conn.setDoOutput(true);
	    conn.setRequestMethod("POST"); 
	    conn.connect();
	    // we upload the signed bytes
	    os = conn.getOutputStream();
	    os.write(data);
	    os.flush();
	    os.close();
	    // we receive the signed document
	    is = conn.getInputStream();
	    FileOutputStream fos = new FileOutputStream(DEST);
	    data = new byte[256];
        while ((read = is.read(data)) != -1) {  
            fos.write(data, 0, read);  
        }
	    is.close();
	    fos.flush();
	    fos.close();
	}
}