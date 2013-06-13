package basics.chapter03;

import java.io.IOException;

import com.itextpdf.text.io.RandomAccessSource;
import com.itextpdf.text.io.RandomAccessSourceFactory;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfReader;

public class C0303_PageNumbers {
	public static void main(String[] args) throws IOException {
		RandomAccessSourceFactory rasf = new RandomAccessSourceFactory();
		RandomAccessSource ras = rasf.createBestSource("src/main/resources/primes.pdf");
		PdfReader reader = new PdfReader(ras);
		int n = reader.getNumberOfPages();
		PdfDictionary page;
		for (int i = 1; i <= n; i++) {
			page = reader.getPageN(i);
			System.out.println(page);
		}
	}
}
