package tutorial.attachments;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PRStream;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfFileSpecification;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.PdfWriter;

public class Attachments {
	
	public static void main(String[] args) throws IOException, DocumentException {
		Attachments app = new Attachments();
		String originalFile = "src/main/resources/attachments/KS-EI-11-001-EN.pdf";
		String fileWithAttachments = "results/KS-EI-11-001-EN.pdf";
		String[] attachments = {
				"src/main/resources/attachments/tec00001.xml",
				"src/main/resources/attachments/tec00033.xml",
				"src/main/resources/attachments/tec00097.xml",
				"src/main/resources/attachments/tsieb090.xml",
				"src/main/resources/attachments/prc_hicp_aind_Label.csv",
				"src/main/resources/attachments/prc_hicp_aind_1_Data.csv"
		};
		String destFolder = "results/attachments";
		app.addAttachments(originalFile, fileWithAttachments, attachments);
		app.extractAttachments(fileWithAttachments, destFolder);
	}

	public void addAttachments(String src, String dest, String[] attachments) throws IOException, DocumentException {
		PdfReader reader = new PdfReader(src);
		PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(dest));
		for (int i = 0; i < attachments.length; i++) {
			addAttachment(stamper.getWriter(), new File(attachments[i]));
		}
		stamper.close();
	}

	protected void addAttachment(PdfWriter writer, File src) throws IOException {
		PdfFileSpecification fs = PdfFileSpecification.fileEmbedded(writer, src.getAbsolutePath(), src.getName(), null);
		writer.addFileAttachment(src.getName().substring(0, src.getName().indexOf('.')), fs);
	}
	
	public void extractAttachments(String src, String dir) throws IOException {
		File folder = new File(dir);
		folder.mkdirs();
		PdfReader reader = new PdfReader(src);
		PdfDictionary root = reader.getCatalog();
		PdfDictionary names = root.getAsDict(PdfName.NAMES);
		PdfDictionary embedded = names.getAsDict(PdfName.EMBEDDEDFILES);
		PdfArray filespecs = embedded.getAsArray(PdfName.NAMES);
		for (int i = 0; i < filespecs.size(); ) {
			extractAttachment(reader, folder, filespecs.getAsString(i++), filespecs.getAsDict(i++));
		}
	}
	
	protected void extractAttachment(PdfReader reader, File dir, PdfString name, PdfDictionary filespec) throws IOException {
		PRStream stream;
		FileOutputStream fos;
		String filename;
		PdfDictionary refs = filespec.getAsDict(PdfName.EF);
		for (PdfName key : refs.getKeys()) {
			stream = (PRStream)PdfReader.getPdfObject(refs.getAsIndirectObject(key));
			filename = filespec.getAsString(key).toString();
			fos = new FileOutputStream(new File(dir, filename));
			fos.write(PdfReader.getStreamBytes(stream));
			fos.flush();
			fos.close();
		}
	}
}
