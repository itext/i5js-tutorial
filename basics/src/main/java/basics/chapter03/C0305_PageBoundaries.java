package basics.chapter03;

import java.io.IOException;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;

public class C0305_PageBoundaries {

	public static void main(String[] args) throws IOException {
		PdfReader reader = new PdfReader("src/main/resources/pages.pdf");

		show(reader.getPageSize(1));
		show(reader.getPageSize(3));
		show(reader.getPageSizeWithRotation(3));
		show(reader.getPageSize(4));
		show(reader.getPageSizeWithRotation(4));
		
		show(reader.getPageSize(5));
		show(reader.getCropBox(5));
		
		show(reader.getPageSize(7));
		show(reader.getBoxSize(7, "art"));
		
		PdfDictionary page6 = reader.getPageN(6);
		System.out.println(page6.getAsNumber(PdfName.USERUNIT));
	}
	
	public static void show(Rectangle rect) {
		System.out.print("llx: ");
		System.out.print(rect.getLeft());
		System.out.print(", lly: ");
		System.out.print(rect.getBottom());
		System.out.print(", urx: ");
		System.out.print(rect.getRight());
		System.out.print(", lly: ");
		System.out.print(rect.getTop());
		System.out.print(", rotation: ");
		System.out.println(rect.getRotation());
	}
}
