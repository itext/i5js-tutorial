package signatures.chapterA;

import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfRectangle;
import com.itextpdf.text.pdf.PdfWriter;

public class A1_02_ForgeTestament {
	public static final String SCROOGE = "src/main/resources/ebenezer.pdf";
	public static final String SCROOGED = "results/chapterA/scrooge.pdf";
	
	public static String TEXT = "To whom it may concern,\n\n" +
			"I, Enenezer Scrooge, being of sound mind and body, " +
			"hereby declare this to be my Last Will and Testament." +
			" I hereby revoke all previous wills and codicils.\n" +
			"Should he survive me, all my belongings should be given" +
			" to Bruno, because he writes such excellent software," +
			" and because he's a real expert in digital signatures.\n" +
			"I hereby affix my signature to this, my Last Will and Testament," +
			" on the 24th day of December, 2012, at London,\n\n";
	
	public static void addSignature(PdfWriter writer) throws IOException {
		float pos = writer.getVerticalPosition(true);
		PdfReader reader = new PdfReader(SCROOGE);
		PdfDictionary pageDict = reader.getPageN(1);
		PdfArray annots = pageDict.getAsArray(PdfName.ANNOTS);
		PdfAnnotation stamp = new PdfAnnotation(writer, null);
		PdfAnnotation popup = new PdfAnnotation(writer, null);
		for (int i = 0; i < annots.size(); i++) {
			PdfDictionary dict = annots.getAsDict(i);
			if (PdfName.POPUP.equals(dict.getAsName(PdfName.SUBTYPE))) {
				popup.putAll(dict);
			}
			else {
				stamp.putAll(dict);
				stamp.remove(PdfName.POPUP);
				PdfArray position = stamp.getAsArray(PdfName.RECT);
				PdfRectangle rect = new PdfRectangle(position.getAsNumber(0).floatValue(),
						pos,
						position.getAsNumber(2).floatValue(),
						pos - Math.abs(position.getAsNumber(1).floatValue() - position.getAsNumber(3).floatValue())
						);
				stamp.put(PdfName.RECT, rect);
			}
		}
		popup.put(PdfName.PARENT, stamp.getIndirectReference());
		stamp.put(PdfName.POPUP, popup.getIndirectReference());
		writer.addAnnotation(stamp);
		writer.addAnnotation(popup);
	}

	public static void main(String[] args) throws IOException, DocumentException {
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(SCROOGED));
		document.open();
		document.add(new Paragraph(TEXT));
		addSignature(writer);
		document.close();
	}
}
