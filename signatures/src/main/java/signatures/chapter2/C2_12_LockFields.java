/*
 * This class is part of the white paper entitled
 * "Digital Signatures for PDF documents"
 * written by Bruno Lowagie
 * 
 * For more info, go to: http://itextpdf.com/learn
 */
package signatures.chapter2;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.ExceptionConverter;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPCellEvent;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSigLockDictionary;
import com.itextpdf.text.pdf.PdfSigLockDictionary.LockAction;
import com.itextpdf.text.pdf.PdfSigLockDictionary.LockPermissions;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.TextField;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class C2_12_LockFields {
	public static final String FORM = "results/chapter2/form_lock.pdf";
	public static final String ALICE = "src/main/resources/alice";
	public static final String BOB = "src/main/resources/bob";
	public static final String CAROL = "src/main/resources/carol";
	public static final String DAVE = "src/main/resources/dave";
	public static final char[] PASSWORD = "password".toCharArray();
	public static final String DEST = "results/chapter2/step_%s_signed_by_%s.pdf";
	
	public class MyTextFieldEvent implements PdfPCellEvent {

		public String name;
		
		public MyTextFieldEvent(String name) {
			this.name = name;
		}

		public void cellLayout(PdfPCell cell, Rectangle position,
				PdfContentByte[] canvases) {
			PdfWriter writer = canvases[0].getPdfWriter();
			TextField text = new TextField(writer, position, name);
			try {
				writer.addAnnotation(text.getTextField());
			} catch (IOException e) {
				throw new ExceptionConverter(e);
			} catch (DocumentException e) {
				throw new ExceptionConverter(e);
			}
		}
	}
	
	public class MySignatureFieldEvent implements PdfPCellEvent {

		public PdfFormField field;
		
		public MySignatureFieldEvent(PdfFormField field) {
			this.field = field;
		}
		
		public void cellLayout(PdfPCell cell, Rectangle position,
				PdfContentByte[] canvases) {
			PdfWriter writer = canvases[0].getPdfWriter();
			field.setPage();
			field.setWidget(position, PdfAnnotation.HIGHLIGHT_INVERT);
			writer.addAnnotation(field);
		}
		
	}
	
	public void createForm() throws IOException, DocumentException {
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(FORM));
		document.open();
		PdfPTable table = new PdfPTable(1);
		table.setWidthPercentage(100);
		table.addCell("Written by Alice");
		table.addCell(createSignatureFieldCell(writer, "sig1", null));
		table.addCell("For approval by Bob");
		table.addCell(createTextFieldCell("approved_bob"));
		PdfSigLockDictionary lock = new PdfSigLockDictionary(LockAction.INCLUDE, "sig1", "approved_bob", "sig2");
		table.addCell(createSignatureFieldCell(writer, "sig2", lock));
		table.addCell("For approval by Carol");
		table.addCell(createTextFieldCell("approved_carol"));
		lock = new PdfSigLockDictionary(LockAction.EXCLUDE, "approved_dave", "sig4");
		table.addCell(createSignatureFieldCell(writer, "sig3", lock));
		table.addCell("For approval by Dave");
		table.addCell(createTextFieldCell("approved_dave"));
		lock = new PdfSigLockDictionary(LockPermissions.NO_CHANGES_ALLOWED);
		table.addCell(createSignatureFieldCell(writer, "sig4", lock));
		document.add(table);
		document.close();
	}
	
	protected PdfPCell createTextFieldCell(String name) {
		PdfPCell cell = new PdfPCell();
		cell.setMinimumHeight(20);
		cell.setCellEvent(new MyTextFieldEvent(name));
		return cell;
	}
	
	protected PdfPCell createSignatureFieldCell(PdfWriter writer, String name, PdfDictionary lock) throws IOException {
		PdfPCell cell = new PdfPCell();
		cell.setMinimumHeight(50);
		PdfFormField field = PdfFormField.createSignature(writer);
        field.setFieldName(name);
        if (lock != null)
        	field.put(PdfName.LOCK, writer.addToBody(lock).getIndirectReference());
        field.setFlags(PdfAnnotation.FLAGS_PRINT);
        cell.setCellEvent(new MySignatureFieldEvent(field));
		return cell;
	}
	
	public void certify(String keystore,
			String src, String name, String dest)
					throws GeneralSecurityException, IOException, DocumentException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setVisibleSignature(name);
        appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_FORM_FILLING);
		AcroFields form = stamper.getAcroFields();
		form.setFieldProperty(name, "setfflags", PdfFormField.FF_READ_ONLY, null);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, "BC");
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, CryptoStandard.CMS);
	}
	
	public void fillOutAndSign(String keystore,
			String src, String name, String fname, String value, String dest)
					throws GeneralSecurityException, IOException, DocumentException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
		AcroFields form = stamper.getAcroFields();
		form.setField(fname, value);
		form.setFieldProperty(name, "setfflags", PdfFormField.FF_READ_ONLY, null);
		form.setFieldProperty(fname, "setfflags", PdfFormField.FF_READ_ONLY, null);
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setVisibleSignature(name);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, "BC");
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, CryptoStandard.CMS);
	}
	
	public void fillOut(String src, String dest, String name, String value) throws IOException, DocumentException {
		PdfReader reader = new PdfReader(src);
		PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest), '\0', true);
		AcroFields form = stamper.getAcroFields();
		form.setField(name, value);
		stamper.close();
	}
	
	public void sign(String keystore,
			String src, String name, String dest)
					throws GeneralSecurityException, IOException, DocumentException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(keystore), PASSWORD);
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setVisibleSignature(name);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, "BC");
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, CryptoStandard.CMS);
	}
	
	public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C2_12_LockFields app = new C2_12_LockFields();
		app.createForm();
		app.certify(ALICE, FORM, "sig1", String.format(DEST, 1, "alice"));
		app.fillOutAndSign(BOB, String.format(DEST, 1, "alice"), "sig2", "approved_bob", "Read and Approved by Bob", String.format(DEST, 2, "alice_and_bob"));
		app.fillOutAndSign(CAROL, String.format(DEST, 2, "alice_and_bob"), "sig3", "approved_carol", "Read and Approved by Carol", String.format(DEST, 3, "alice_bob_and_carol"));
		app.fillOutAndSign(DAVE, String.format(DEST, 3, "alice_bob_and_carol"), "sig4", "approved_dave", "Read and Approved by Dave", String.format(DEST, 4, "alice_bob_carol_and_dave"));
		app.fillOut(String.format(DEST, 2, "alice_and_bob"), String.format(DEST, 5, "alice_and_bob_broken_by_chuck"), "approved_bob", "Changed by Chuck");
		app.fillOut(String.format(DEST, 4, "alice_bob_carol_and_dave"), String.format(DEST, 6, "dave_broken_by_chuck"), "approved_carol", "Changed by Chuck");
	}
}
