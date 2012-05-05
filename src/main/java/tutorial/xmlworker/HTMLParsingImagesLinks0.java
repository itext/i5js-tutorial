package tutorial.xmlworker;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.tool.xml.XMLWorkerHelper;

public class HTMLParsingImagesLinks0 {

	public static void main(String[] args) throws IOException, DocumentException {
		File results = new File("results");
		results.mkdir();
		new File(results, "xmlworker").mkdir();
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document,
				new FileOutputStream("results/xmlworker/thoreau0.pdf"));
		document.open();
		XMLWorkerHelper.getInstance().parseXHtml(writer, document,
				HTMLParsingImagesLinks0.class.getResourceAsStream("/html/thoreau.html"));
		document.close();
	}
}
