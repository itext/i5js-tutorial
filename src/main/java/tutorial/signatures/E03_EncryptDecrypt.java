package tutorial.signatures;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

public class E03_EncryptDecrypt {

	protected KeyStore ks;
	
	public E03_EncryptDecrypt(String keystore, String ks_pass) throws GeneralSecurityException, IOException {
		initKeyStore(keystore, ks_pass);
	}
	
	public void initKeyStore(String keystore, String ks_pass) throws GeneralSecurityException, IOException {
		ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(keystore), ks_pass.toCharArray());
	}
	
	public Key getPublicKey(String alias) throws GeneralSecurityException, IOException {
		X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
		return certificate.getPublicKey();
	}
	
	public Key getPrivateKey(String alias, String pk_pass) throws GeneralSecurityException, IOException {
		return ks.getKey(alias, pk_pass.toCharArray());
	}
	
	public byte[] encrypt(Key key, String message) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherData = cipher.doFinal(message.getBytes());
		return cipherData;
	}
	
	public String decrypt(Key key, byte[] message) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] cipherData = cipher.doFinal(message);
		return new String(cipherData);
	}
	
	public static void main(String[] args) throws GeneralSecurityException, IOException {
		E03_EncryptDecrypt app = new E03_EncryptDecrypt("src/main/resources/signatures/ks", "password");
		Key publicKey = app.getPublicKey("demo");
		Key privateKey = app.getPrivateKey("demo", "password");
		
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
