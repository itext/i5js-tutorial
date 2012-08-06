package tutorial.signatures;

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
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPCellEvent;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class E13_SequentialSignatures {
	public static final String FORM = "results/signatures/multiple_signatures.pdf";
	public static final String ALICE = "src/main/resources/signatures/alice";
	public static final String BOB = "src/main/resources/signatures/bob";
	public static final String CAROL = "src/main/resources/signatures/carol";
	public static final String PASSWORD = "password";
	public static final String DEST = "results/signatures/signed_by_%s.pdf";
	
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
		table.addCell("Signer 1: Alice");
		table.addCell(createSignatureFieldCell(writer, "sig1"));
		table.addCell("Signer 2: Bob");
		table.addCell(createSignatureFieldCell(writer, "sig2"));
		table.addCell("Signer 3: Carol");
		table.addCell(createSignatureFieldCell(writer, "sig3"));
		document.add(table);
		document.close();
	}
	
	protected PdfPCell createSignatureFieldCell(PdfWriter writer, String name) {
		PdfPCell cell = new PdfPCell();
		cell.setMinimumHeight(50);
		PdfFormField field = PdfFormField.createSignature(writer);
        field.setFieldName(name);
        field.setFlags(PdfAnnotation.FLAGS_PRINT);
        cell.setCellEvent(new MySignatureFieldEvent(field));
		return cell;
	}
	
	public void sign(String keystore, int level,
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
        appearance.setCertificationLevel(level);
        // Creating the signature
        PrivateKeySignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, "BC");
        MakeSignature.signDetached(appearance, pks, chain, null, null, null, "BC", 0, MakeSignature.CMS);
	}
	
	public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		E13_SequentialSignatures app = new E13_SequentialSignatures();
		app.createForm();
		
		app.sign(ALICE, PdfSignatureAppearance.CERTIFIED_FORM_FILLING, FORM, "sig1", String.format(DEST, "alice"));
		app.sign(BOB, PdfSignatureAppearance.NOT_CERTIFIED, String.format(DEST, "alice"), "sig2", String.format(DEST, "bob"));
		app.sign(CAROL, PdfSignatureAppearance.NOT_CERTIFIED, String.format(DEST, "bob"), "sig3", String.format(DEST, "carol"));

		app.sign(ALICE, PdfSignatureAppearance.NOT_CERTIFIED, FORM, "sig1", String.format(DEST, "alice2"));
		app.sign(BOB, PdfSignatureAppearance.NOT_CERTIFIED, String.format(DEST, "alice2"), "sig2", String.format(DEST, "bob2"));
		app.sign(CAROL, PdfSignatureAppearance.CERTIFIED_FORM_FILLING, String.format(DEST, "bob2"), "sig3", String.format(DEST, "carol2"));
	}
}
