package tutorial.xmlworker;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.tool.xml.XMLWorkerHelper;

public class HTMLParsingDefault {

	public static void main(String[] args) throws IOException, DocumentException {
		File results = new File("results");
		results.mkdir();
		new File(results, "xmlworker").mkdir();
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document,
				new FileOutputStream("results/xmlworker/walden1.pdf"));
		document.open();
		XMLWorkerHelper.getInstance().parseXHtml(writer, document,
				HTMLParsingDefault.class.getResourceAsStream("/html/walden.html"), null);
		document.close();
	}
}
