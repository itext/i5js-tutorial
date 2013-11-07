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
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class C2_10_SequentialSignatures {
	public static final String FORM = "results/chapter2/multiple_signatures.pdf";
	public static final String ALICE = "src/main/resources/alice";
	public static final String BOB = "src/main/resources/bob";
	public static final String CAROL = "src/main/resources/carol";
	public static final char[] PASSWORD = "password".toCharArray();
	public static final String DEST = "results/chapter2/signed_by_%s.pdf";
	
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
	
	public void sign(String keystore, int level,
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
        appearance.setCertificationLevel(level);
        // Creating the signature
        ExternalSignature pks = new PrivateKeySignature(pk, "SHA-256", "BC");
        ExternalDigest digest = new BouncyCastleDigest();
        MakeSignature.signDetached(appearance, digest, pks, chain, null, null, null, 0, CryptoStandard.CMS);
	}
	
	public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException {
		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		C2_10_SequentialSignatures app = new C2_10_SequentialSignatures();
		app.createForm();
		
		app.sign(ALICE, PdfSignatureAppearance.CERTIFIED_FORM_FILLING, FORM, "sig1", String.format(DEST, "alice"));
		app.sign(BOB, PdfSignatureAppearance.NOT_CERTIFIED, String.format(DEST, "alice"), "sig2", String.format(DEST, "bob"));
		app.sign(CAROL, PdfSignatureAppearance.NOT_CERTIFIED, String.format(DEST, "bob"), "sig3", String.format(DEST, "carol"));

		app.sign(ALICE, PdfSignatureAppearance.NOT_CERTIFIED, FORM, "sig1", String.format(DEST, "alice2"));
		app.sign(BOB, PdfSignatureAppearance.NOT_CERTIFIED, String.format(DEST, "alice2"), "sig2", String.format(DEST, "bob2"));
		app.sign(CAROL, PdfSignatureAppearance.CERTIFIED_FORM_FILLING, String.format(DEST, "bob2"), "sig3", String.format(DEST, "carol2"));

		app.sign(ALICE, PdfSignatureAppearance.NOT_CERTIFIED, FORM, "sig1", String.format(DEST, "alice3"));
		app.sign(BOB, PdfSignatureAppearance.NOT_CERTIFIED, String.format(DEST, "alice3"), "sig2", String.format(DEST, "bob3"));
		app.sign(CAROL, PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED, String.format(DEST, "bob3"), "sig3", String.format(DEST, "carol3"));
		
		app.sign(ALICE, PdfSignatureAppearance.CERTIFIED_FORM_FILLING, FORM, "sig1", String.format(DEST, "alice4"));
		app.sign(BOB, PdfSignatureAppearance.NOT_CERTIFIED, String.format(DEST, "alice4"), "sig2", String.format(DEST, "bob4"));
		app.sign(CAROL, PdfSignatureAppearance.CERTIFIED_FORM_FILLING, String.format(DEST, "bob4"), "sig3", String.format(DEST, "carol4"));
	}
}
