package signatures.chapter4;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

import com.itextpdf.smartcard.CardReaders;
import com.itextpdf.smartcard.PinDialog;
import com.itextpdf.smartcard.SmartCardWithKey;
import com.itextpdf.smartcard.beid.BeIDCertificates;

public class C4_05_SignWithBEID {

	public static void main(String[] args) throws CardException, IOException, GeneralSecurityException {
		CardReaders readers = new CardReaders();
		for (CardTerminal terminal : readers.getReadersWithCard()) {
			SmartCardWithKey card = new SmartCardWithKey(terminal, BeIDCertificates.AUTHENTICATION_KEY_ID, "RSA");
			card.setPinProvider(new PinDialog(4));
			byte[] signed = card.sign("ABCD".getBytes(), "SHA-256");
			System.out.println(new String(signed));
			X509Certificate cert = card.readCertificate(BeIDCertificates.AUTHN_CERT_FILE_ID);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, cert.getPublicKey());
			System.out.println(new String(cipher.doFinal(signed)));
		}
	} 
}
