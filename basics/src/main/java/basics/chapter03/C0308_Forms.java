package basics.chapter03;

import java.io.File;
import java.io.IOException;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.XfaForm;

public class C0308_Forms {
	
	public static void main(String[] args) throws IOException {
		inspectForm(new File("src/main/resources/pages.pdf"));
		inspectForm(new File("src/main/resources/datasheet.pdf"));
		inspectForm(new File("src/main/resources/xfa_movies.pdf"));
		inspectForm(new File("src/main/resources/xfa_movie.pdf"));
	}
	
    public static void inspectForm(File file) throws IOException {
    	System.out.print(file.getName());
    	System.out.print(": ");
        PdfReader reader = new PdfReader(file.getAbsolutePath());
        AcroFields form = reader.getAcroFields();
        XfaForm xfa = form.getXfa();
        System.out.println(
        	xfa.isXfaPresent() ?
        		  form.getFields().size() == 0 ? "XFA form" : "Hybrid form"
        		: form.getFields().size() == 0 ? "not a form" : "AcroForm");
        reader.close();
    }
}
