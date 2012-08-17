package signatures.chapterA;

import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;

public class A1_01_Replace1500by1500 {
	
	public static final String SCROOGE = "src/main/resources/ebenezer.pdf";
	public static final String SCROOGED = "results/chapterA/ebenezer.pdf";
	
	public static void main(String[] args) throws IOException, DocumentException {
		PdfReader reader = new PdfReader(SCROOGE);
		replace(reader, "$1,500", "$15,000");
		PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(SCROOGED));
		stamper.close();
	}
	
	public static void replace(PdfReader reader, String original, String fake) throws IOException {
		String content = new String(reader.getPageContent(1));
		reader.setPageContent(1, content.replace(original, fake).getBytes());
	}
}
