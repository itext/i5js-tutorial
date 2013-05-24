package basics.chapter01;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;

public class HelloWorld {

	public static void main(String[] args) throws IOException, DocumentException {
		createPdf1();
		createPdf2();
		createPdf3();
		createPdf4();
	}
	
	public static void createPdf1() throws IOException, DocumentException {
		Document document = new Document();
		PdfWriter.getInstance(document, new FileOutputStream("hello1.pdf"));
		document.open();
		document.add(new Paragraph("Hello World"));
		document.close();
	}
	
	public static void createPdf2() throws IOException, DocumentException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		Document document = new Document();
		PdfWriter.getInstance(document, baos);
		document.open();
		document.add(new Paragraph("Hello World"));
		document.close();
		PdfReader reader = new PdfReader(baos.toByteArray());
		PdfStamper stamper = new PdfStamper(reader, new FileOutputStream("hello2.pdf"), '\0', true);
		stamper.close();
	}
	
	public static void createPdf3() throws IOException, DocumentException {
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream("hello3.pdf"));
		writer.setFullCompression();
		document.open();
		document.add(new Paragraph("Hello World"));
		document.close();
	}
	
	public static void createPdf4() throws IOException, DocumentException {
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream("hello4.pdf"));
		writer.createXmpMetadata();
		document.open();
		document.add(new Paragraph("Hello World"));
		document.close();
	}
}
