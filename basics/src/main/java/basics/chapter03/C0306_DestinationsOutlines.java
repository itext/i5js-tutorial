package basics.chapter03;

import java.io.IOException;
import java.util.Map;

import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.SimpleNamedDestination;

public class C0306_DestinationsOutlines {

	public static void main(String[] args) throws IOException {
		PdfReader reader = new PdfReader("src/main/resources/primes.pdf");
		PdfDictionary catalog = reader.getCatalog();
		PdfDictionary names = catalog.getAsDict(PdfName.NAMES);
		PdfDictionary dests = names.getAsDict(PdfName.DESTS);
		PdfArray array = dests.getAsArray(PdfName.NAMES);
		System.out.println(array.getAsString(0));
		System.out.println(array.getAsArray(1));
		
		Map<String, String> map = SimpleNamedDestination.getNamedDestination(reader, false);
		System.out.println(map.get("Prime101"));
		
		reader.close();
	}
}
