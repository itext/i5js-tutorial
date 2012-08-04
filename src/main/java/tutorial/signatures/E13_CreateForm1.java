package tutorial.signatures;

import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.ExceptionConverter;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfAnnotation;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfFormField;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPCellEvent;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.TextField;

public class E13_CreateForm1 {
	public class MyTextFieldEvent implements PdfPCellEvent {

		public String name;
		
		public MyTextFieldEvent(String name) {
			this.name = name;
		}

		public void cellLayout(PdfPCell cell, Rectangle position,
				PdfContentByte[] canvases) {
			PdfWriter writer = canvases[0].getPdfWriter();
			TextField text = new TextField(writer, position, name);
			try {
				writer.addAnnotation(text.getTextField());
			} catch (IOException e) {
				throw new ExceptionConverter(e);
			} catch (DocumentException e) {
				throw new ExceptionConverter(e);
			}
		}
	}
	
	public class MySignatureFieldEvent implements PdfPCellEvent {

		public PdfFormField field;
		
		public MySignatureFieldEvent(PdfFormField field) {
			this.field = field;
		}
		
		public void cellLayout(PdfPCell cell, Rectangle position,
				PdfContentByte[] canvases) {
			PdfWriter writer = canvases[0].getPdfWriter();
			field.setPage();
			field.setWidget(position, PdfAnnotation.HIGHLIGHT_INVERT);
			writer.addAnnotation(field);
		}
		
	}

	public static final String FORM = "results/signatures/form1.pdf";
	
	public void createForm() throws IOException, DocumentException {
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document, new FileOutputStream(FORM));
		document.open();
		PdfPTable table = new PdfPTable(1);
		table.setWidthPercentage(100);
		table.addCell("Signer 1");
		table.addCell(createTextFieldCell("field1"));
		table.addCell(createSignatureFieldCell(writer, "sig1"));
		table.addCell("Signer 2");
		table.addCell(createTextFieldCell("field2"));
		table.addCell(createSignatureFieldCell(writer, "sig2"));
		table.addCell("Signer 3");
		table.addCell(createTextFieldCell("field3"));
		table.addCell(createSignatureFieldCell(writer, "sig3"));
		document.add(table);
		document.close();
	}
	
	protected PdfPCell createTextFieldCell(String name) {
		PdfPCell cell = new PdfPCell();
		cell.setMinimumHeight(20);
		cell.setCellEvent(new MyTextFieldEvent(name));
		return cell;
	}
	
	protected PdfPCell createSignatureFieldCell(PdfWriter writer, String name) {
		PdfPCell cell = new PdfPCell();
		cell.setMinimumHeight(50);
		PdfFormField field = PdfFormField.createSignature(writer);
        field.setFieldName(name);
        field.setFlags(PdfAnnotation.FLAGS_PRINT);
        cell.setCellEvent(new MySignatureFieldEvent(field));
		return cell;
	}
	
	public static void main(String[] args) throws IOException, DocumentException {
		E13_CreateForm1 app = new E13_CreateForm1();
		app.createForm();
	}
}
