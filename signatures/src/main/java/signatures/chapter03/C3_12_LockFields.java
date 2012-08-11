package signatures.chapter03;

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
import com.itextpdf.text.pdf.PdfSigLockDictionary.LockPermissions;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.TextField;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class C3_12_LockFields {
	public static final String FORM = "results/form.pdf";
	public static final String ALICE = "src/main/resources/alice";
	public static final String BOB = "src/main/resources/bob";
	public static final String CAROL = "src/main/resources/carol";
	public static final String DAVE = "src/main/resources/dave";
	public static final String PASSWORD = "password";
	public static final String DEST = "results/step_%s_signed_by_%s.pdf";
	
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
		table.addCell(createSignatureFieldCell(writer, "sig2", null));
		table.addCell("For approval by Carol");
		table.addCell(createTextFieldCell("approved_carol"));
		table.addCell(createSignatureFieldCell(writer, "sig3", null));
		table.addCell("For approval by Dave");
		table.addCell(createTextFieldCell("approved_dave"));
		PdfSigLockDictionary lock = new PdfSigLockDictionary(LockPermissions.NO_CHANGES_ALLOWED);
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
		ks.load(new FileInputStream(keystore), PASSWORD.toCharArray());
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setVisibleSignature(name);
        appearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_FORM_FILLING);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, "BC");
        MakeSignature.signDetached(appearance, pks, chain, null, null, null, "BC", 0, MakeSignature.CMS);
	}
	
	public void fillOutAndSign(String keystore,
			String src, String name, String fname, String value, String dest)
					throws GeneralSecurityException, IOException, DocumentException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(keystore), PASSWORD.toCharArray());
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        // Creating the reader and the stamper
        PdfReader reader = new PdfReader(src);
        FileOutputStream os = new FileOutputStream(dest);
        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);
		AcroFields form = stamper.getAcroFields();
		form.setField(fname, value);
		form.setFieldProperty(fname, "setfflags", PdfFormField.FF_READ_ONLY, null);
        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setVisibleSignature(name);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, "BC");
        MakeSignature.signDetached(appearance, pks, chain, null, null, null, "BC", 0, MakeSignature.CMS);
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
		ks.load(new FileInputStream(keystore), PASSWORD.toCharArray());
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD.toCharArray());
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
        MakeSignature.signDetached(appearance, pks, chain, null, null, null, "BC", 0, MakeSignature.CMS);
	}
	
	public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C3_12_LockFields app = new C3_12_LockFields();
		app.createForm();
		app.certify(ALICE, FORM, "sig1", String.format(DEST, 1, "alice"));
		app.fillOutAndSign(BOB, String.format(DEST, 1, "alice"), "sig2", "approved_bob", "Read and Approved by Bob", String.format(DEST, 2, "alice_and_bob"));
		app.fillOutAndSign(CAROL, String.format(DEST, 2, "alice_and_bob"), "sig3", "approved_carol", "Read and Approved by Carol", String.format(DEST, 3, "alice_bob_and_carol"));
		app.fillOutAndSign(DAVE, String.format(DEST, 3, "alice_bob_and_carol"), "sig4", "approved_dave", "Read and Approved by Dave", String.format(DEST, 4, "alice_bob_carol_and_dave"));
	}
}
