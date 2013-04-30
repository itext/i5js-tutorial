package basics.chapter01;

import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfBoolean;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfNumber;
import com.itextpdf.text.pdf.PdfStream;
import com.itextpdf.text.pdf.PdfString;

public class PdfObjects {

	public static void main(String[] args) {

		PdfStream stream = new PdfStream("Long stream of data stored in a FlateDecode compressed stream object".getBytes());
		stream.flateCompress();
		
		PdfArray array = new PdfArray();
		array.add(PdfName.FIRST);
		array.add(new PdfString("Second"));
		array.add(new PdfNumber(3));
		array.add(PdfBoolean.PDFFALSE);
		
		PdfDictionary dict = new PdfDictionary();
		dict.put(new PdfName("Entry1"), PdfName.FIRST);
		dict.put(new PdfName("Entry2"), new PdfString("Second"));
		dict.put(new PdfName("3rd"), new PdfNumber(3));
		dict.put(new PdfName("Fourth"), PdfBoolean.PDFFALSE);
		dict.put(new PdfName("Fifth"), array);
		dict.put(new PdfName("6th"), stream);
		
		array.add(dict);
		
		PdfBoolean b2 = dict.getAsBoolean(new PdfName("Entry2"));
		if (b2 != null)
			C0101_BooleanObject.showObject(b2);
		PdfNumber number = array.getAsNumber(2);
		if (number != null)
			C0102_NumberObject.showObject(number);
		PdfString string = dict.getAsString(new PdfName("Entry2"));
		if (string != null)
			C0103_StringObject.showObject(string);
		PdfName first = array.getAsName(0);
		if (first != null)
			C0104_NameObject.showObject(first);
		PdfArray arr = dict.getAsArray(new PdfName("Fifth"));
		if (arr != null)
			C0105_ArrayObject.showObject(arr);
		PdfDictionary d = array.getAsDict(4);
		if (d != null)
			C0106_DictionaryObject.showObject(d);
		PdfStream s = dict.getAsStream(new PdfName("6th"));
		if (s != null)
			C0107_StreamObject.showObject(s);
	}
}
