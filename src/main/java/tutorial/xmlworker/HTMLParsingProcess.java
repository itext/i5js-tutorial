package tutorial.xmlworker;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.tool.xml.Pipeline;
import com.itextpdf.tool.xml.XMLWorker;
import com.itextpdf.tool.xml.XMLWorkerHelper;
import com.itextpdf.tool.xml.html.Tags;
import com.itextpdf.tool.xml.parser.XMLParser;
import com.itextpdf.tool.xml.pipeline.css.CSSResolver;
import com.itextpdf.tool.xml.pipeline.css.CssResolverPipeline;
import com.itextpdf.tool.xml.pipeline.end.PdfWriterPipeline;
import com.itextpdf.tool.xml.pipeline.html.HtmlPipeline;
import com.itextpdf.tool.xml.pipeline.html.HtmlPipelineContext;

public class HTMLParsingProcess {

	public static void main(String[] args) throws IOException, DocumentException {
		File results = new File("results");
		results.mkdir();
		new File(results, "xmlworker").mkdir();
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document,
				new FileOutputStream(new File("results/xmlworker/walden3.pdf")));
		writer.setInitialLeading(12.5f);
		document.open();
		HtmlPipelineContext htmlContext = new HtmlPipelineContext();
		htmlContext.setTagFactory(Tags.getHtmlTagProcessorFactory());
		CSSResolver cssResolver = XMLWorkerHelper.getInstance().getDefaultCssResolver(true);
		Pipeline<?> pipeline = new CssResolverPipeline(cssResolver, new HtmlPipeline(htmlContext,
				new PdfWriterPipeline(document, writer)));
		XMLWorker worker = new XMLWorker(pipeline, true);
		XMLParser p = new XMLParser(worker);
		p.parse(HTMLParsingProcess.class.getResourceAsStream("/html/walden.html"));
		document.close();
	}
}
