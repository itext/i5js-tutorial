package tutorial.xmlworker;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.FontFactory;
import com.itextpdf.text.log.LoggerFactory;
import com.itextpdf.text.log.SysoLogger;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.tool.xml.Pipeline;
import com.itextpdf.tool.xml.XMLWorker;
import com.itextpdf.tool.xml.XMLWorkerHelper;
import com.itextpdf.tool.xml.html.Tags;
import com.itextpdf.tool.xml.parser.XMLParser;
import com.itextpdf.tool.xml.pipeline.css.CSSResolver;
import com.itextpdf.tool.xml.pipeline.css.CssResolverPipeline;
import com.itextpdf.tool.xml.pipeline.end.PdfWriterPipeline;
import com.itextpdf.tool.xml.pipeline.html.AbstractImageProvider;
import com.itextpdf.tool.xml.pipeline.html.HtmlPipeline;
import com.itextpdf.tool.xml.pipeline.html.HtmlPipelineContext;
import com.itextpdf.tool.xml.pipeline.html.LinkProvider;

public class HTMLParsingImagesLinks1 {

	public static void main(String[] args) throws IOException, DocumentException {
		LoggerFactory.getInstance().setLogger(new SysoLogger());
		File results = new File("results");
		results.mkdir();
		new File(results, "xmlworker").mkdir();
		FontFactory.registerDirectories();
		Document document = new Document();
		PdfWriter writer = PdfWriter.getInstance(document,
				new FileOutputStream("results/xmlworker/thoreau1.pdf"));
		document.open();
		HtmlPipelineContext htmlContext = new HtmlPipelineContext();
		htmlContext.setTagFactory(Tags.getHtmlTagProcessorFactory());
		htmlContext.setImageProvider(new AbstractImageProvider() {
			public String getImageRootPath() {
				return "src/main/resources/html/";
			}
		});
		htmlContext.setLinkProvider(new LinkProvider() {

			public String getLinkRoot() {
				return "http://tutorial.itextpdf.com/src/main/resources/html/";
			}
		});
		CSSResolver cssResolver =
			XMLWorkerHelper.getInstance().getDefaultCssResolver(true);
		Pipeline<?> pipeline =
			new CssResolverPipeline(cssResolver,
				new HtmlPipeline(htmlContext,
						new PdfWriterPipeline(document, writer)));
		XMLWorker worker = new XMLWorker(pipeline, true);
		XMLParser p = new XMLParser(worker);
		p.parse(HTMLParsingProcess.class.getResourceAsStream("/html/thoreau.html"));
		document.close();
	}
}
