package basics.chapter03;

import java.io.IOException;

import com.itextpdf.text.io.RandomAccessSource;
import com.itextpdf.text.io.RandomAccessSourceFactory;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfIndirectReference;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfNumber;
import com.itextpdf.text.pdf.PdfObject;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfString;

public class C0201_CatalogInfo {

	public static void main(String[] args) throws IOException {
		RandomAccessSourceFactory rasf = new RandomAccessSourceFactory();
		RandomAccessSource ras = rasf.createBestSource("src/main/resources/primes.pdf");
		PdfReader reader = new PdfReader(ras);
		PdfDictionary trailer = reader.getTrailer();
		showEntries(trailer);
		PdfNumber size = (PdfNumber)trailer.get(PdfName.SIZE);
		showObject(size);
		size = trailer.getAsNumber(PdfName.SIZE);
		showObject(size);
		PdfArray ids = trailer.getAsArray(PdfName.ID);
		PdfString id1 = ids.getAsString(0);
		showObject(id1);
		PdfString id2 = ids.getAsString(1);
		showObject(id2);
		PdfObject object = trailer.get(PdfName.INFO);
		showObject(object);
		PdfIndirectReference ref = trailer.getAsIndirectObject(PdfName.INFO);
		object = reader.getPdfObject(ref.getNumber());
		showObject(object);
		showObject(trailer.getAsDict(PdfName.INFO));
	}
	
	public static void showEntries(PdfDictionary dict) {
		for (PdfName key : dict.getKeys()) {
			System.out.print(" " + key + ": ");
			System.out.println(dict.get(key));
		}
	}
	
	public static void showObject(PdfObject obj) {
		System.out.println(obj.getClass().getName() + ":");
		System.out.println("-> type: " + obj.type());
		System.out.println("-> toString: " + obj.toString());
	}
}
