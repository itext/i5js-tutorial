package basics.chapter03;

import java.io.IOException;

import com.itextpdf.text.io.RandomAccessSource;
import com.itextpdf.text.io.RandomAccessSourceFactory;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfIndirectReference;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;

public class C0302_PageTree {

	public static void main(String[] args) throws IOException {
		RandomAccessSourceFactory rasf = new RandomAccessSourceFactory();
		RandomAccessSource ras = rasf.createBestSource("src/main/resources/primes.pdf");
		PdfReader reader = new PdfReader(ras);
		PdfDictionary dict = reader.getCatalog();
		PdfDictionary pageroot = dict.getAsDict(PdfName.PAGES);
		new C0302_PageTree().expand(pageroot);
	}

	private int page = 1;
	
	public void expand(PdfDictionary dict) {
		if (dict == null)
			return;
		PdfIndirectReference ref = dict.getAsIndirectObject(PdfName.PARENT);
		if (dict.isPage()) {
			System.out.println("Child of " + ref + ": PAGE " + (page++));
		}
		else if (dict.isPages()) {
			if (ref ==  null)
				System.out.println("PAGES ROOT");
			else
				System.out.println("Child of " + ref + ": PAGES");
			PdfArray kids = dict.getAsArray(PdfName.KIDS);
			System.out.println(kids);
			if (kids != null) {
				for (int i = 0; i < kids.size(); i++) {
					expand(kids.getAsDict(i));
				}
			}
		}
	}
}
