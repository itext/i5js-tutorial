package tutorial.signatures;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.util.Properties;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class E0X_EncryptDecryptCA extends E03_EncryptDecrypt {
	
	public E0X_EncryptDecryptCA(String keystore, String ks_pass) throws GeneralSecurityException, IOException {
		super(keystore, ks_pass);
	}

	public void initKeyStore(String keystore, String ks_pass) throws GeneralSecurityException, IOException {
        ks = KeyStore.getInstance("pkcs12", "BC");
		ks.load(new FileInputStream(keystore), ks_pass.toCharArray());
	}
	
	public String getAlias() throws GeneralSecurityException {
		return (String)ks.aliases().nextElement();
	}

	public static void main(String[] args) throws GeneralSecurityException, IOException {
        Security.addProvider(new BouncyCastleProvider());
		Properties properties = new Properties();
		properties.load(new FileInputStream("c:/home/blowagie/key.properties"));
    	String path = properties.getProperty("PRIVATE");
        String ks_pass = properties.getProperty("PASSWORD");
        String pk_pass = properties.getProperty("PASSWORD");
        
		E0X_EncryptDecryptCA app = new E0X_EncryptDecryptCA(path, ks_pass);
        String alias = app.getAlias();
		Key publicKey = app.getPublicKey(alias);
		Key privateKey = app.getPrivateKey(alias, pk_pass);
		
		System.out.println("Let's encrypt 'secret message' with a public key");
		byte[] encrypted = app.encrypt(publicKey, "secret message");
		System.out.println("Encrypted message: " + new BigInteger(1, encrypted).toString(16));
		System.out.println("Let's decrypt it with the corresponding private key");
		String decrypted = app.decrypt(privateKey, encrypted);
		System.out.println(decrypted);
		
		System.out.println("You can also encrypt the message with a private key");
		encrypted = app.encrypt(privateKey, "secret message");
		System.out.println("Encrypted message: " + new BigInteger(1, encrypted).toString(16));
		System.out.println("Now you need the public key to decrypt it");
		decrypted = app.decrypt(publicKey, encrypted);
		System.out.println(decrypted);
	}
	
}
