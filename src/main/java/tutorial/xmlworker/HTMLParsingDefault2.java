package tutorial.xmlworker;

import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.FontFactory;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.tool.xml.XMLWorkerHelper;

public class HTMLParsingDefault2 {

	public static void main(String[] args) throws IOException, DocumentException {
		FontFactory.registerDirectories();
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream("results/walden2.pdf"));
		writer.setInitialLeading(12.5f);
		document.open();
		XMLWorkerHelper.getInstance().parseXHtml(writer, document,
				HTMLParsingDefault2.class.getResourceAsStream("/html/walden.html"));
		document.close();
	}
}
