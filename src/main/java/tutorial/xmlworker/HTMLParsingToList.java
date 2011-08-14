package tutorial.xmlworker;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

import com.itextpdf.text.Element;
import com.itextpdf.text.ExceptionConverter;
import com.itextpdf.tool.xml.ElementHandler;
import com.itextpdf.tool.xml.Writable;
import com.itextpdf.tool.xml.XMLWorkerHelper;
import com.itextpdf.tool.xml.pipeline.WritableElement;

public class HTMLParsingToList {

	public static void main(String[] args) throws IOException {
		File results = new File("results");
		results.mkdir();
		new File(results, "xmlworker").mkdir();
		final BufferedWriter writer = new BufferedWriter(new FileWriter("results/xmlworker/objects.txt"));
		XMLWorkerHelper.getInstance().parseXHtml(new ElementHandler() {
			public void add(final Writable w) {
				if (w instanceof WritableElement) {
					List<Element> elements = ((WritableElement)w).elements();
					for (Element element : elements) {
						try {
							writer.write(element.getClass().getName());
							writer.newLine();
						} catch (IOException e) {
							throw new ExceptionConverter(e);
						}
					}
				}

			}
		}, HTMLParsingToList.class.getResourceAsStream("/html/walden.html"), null);
	}
}
