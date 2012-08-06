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

import com.itextpdf.text.BaseColor;
import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Element;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.Phrase;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.ColumnText;
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfAppearance;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;

public class E07_CreateEmptyField {

	public static final String KEYSTORE = "src/main/resources/signatures/ks";
	public static final String PASSWORD = "password";
	public static final String UNSIGNED = "results/signatures/hello_empty.pdf";
	public static final String SIGNAME = "Signature1";
	public static final String DEST = "results/signatures/field_signed.pdf";

	public static final String SRC = "src/main/resources/signatures/hello.pdf";
	public static final String UNSIGNED2 = "results/signatures/hello_empty2.pdf";
	
    public void createPdf(String filename) throws IOException, DocumentException {
    	// step 1: Create a Document
        Document document = new Document();
        // step 2: Create a PdfWriter
        PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(filename));
        // step 3: Open the Document
        document.open();
        // step 4: Add content
        document.add(new Paragraph("Hello World!"));
        // create a signature form field
        PdfFormField field = PdfFormField.createSignature(writer);
        field.setFieldName(SIGNAME);
        // set the widget properties
        field.setPage();
        field.setWidget(new Rectangle(72, 732, 144, 780), PdfAnnotation.HIGHLIGHT_INVERT);
        field.setFlags(PdfAnnotation.FLAGS_PRINT);
        // add it as an annotation
        writer.addAnnotation(field);
        // maybe you want to define an appearance
        PdfAppearance tp = PdfAppearance.createAppearance(writer, 72, 48);
        tp.setColorStroke(BaseColor.BLUE);
        tp.setColorFill(BaseColor.LIGHT_GRAY);
        tp.rectangle(0.5f, 0.5f, 71.5f, 47.5f);
        tp.fillStroke();
        tp.setColorFill(BaseColor.BLUE);
        ColumnText.showTextAligned(tp, Element.ALIGN_CENTER, new Phrase("SIGN HERE"), 36, 24, 25);
        field.setAppearance(PdfAnnotation.APPEARANCE_NORMAL, tp);
        // step 5: Close the Document
        document.close();
    }
    
    public void addField(String src, String dest) throws IOException, DocumentException {
    	PdfReader reader = new PdfReader(src);
    	PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest));
        // create a signature form field
        PdfFormField field = PdfFormField.createSignature(stamper.getWriter());
        field.setFieldName(SIGNAME);
        // set the widget properties
        field.setWidget(new Rectangle(72, 732, 144, 780), PdfAnnotation.HIGHLIGHT_OUTLINE);
        field.setFlags(PdfAnnotation.FLAGS_PRINT);
        // add the annotation
        stamper.addAnnotation(field, 1);
        // close the stamper
    	stamper.close();
    }
    
    public static void main(String[] args) throws IOException, DocumentException, GeneralSecurityException {
    	E07_CreateEmptyField appCreate = new E07_CreateEmptyField();
    	appCreate.createPdf(UNSIGNED);
    	appCreate.addField(SRC, UNSIGNED2);

		BouncyCastleProvider provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(new FileInputStream(KEYSTORE), PASSWORD.toCharArray());
        String alias = (String)ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD.toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
    	E06_SignEmptyField appSign = new E06_SignEmptyField();
        appSign.sign(pk, chain, UNSIGNED, SIGNAME, DEST, provider.getName(), "Test", "Ghent", DigestAlgorithms.SHA256, MakeSignature.CMS);
    }
}