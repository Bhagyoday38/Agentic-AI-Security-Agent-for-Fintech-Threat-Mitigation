# app/services/reporting.py
import logging
import base64
import io
from xhtml2pdf import pisa  # Import pisa
from datetime import datetime
from typing import Dict, List, Any
import traceback
import re
from fpdf import FPDF  # Keep FPDF *only* for the error fallback

logger = logging.getLogger("Runner." + __name__)


def build_report_html(
    llm_text_report: str,
    analytics_data: Dict[str, Any],
    trend_chart_b64: str,
    severity_chart_b64: str
) -> str:
    """
    Generates a full HTML document string for the PDF report,
    including embedded base64 images.
    """

    # --- 1. Build Analytics Table HTML ---
    analytics_html = ""
    try:
        analytics_html += "<tr><td class='key'>Total Threat Events</td><td class='value'>{val}</td></tr>".format(
            val=analytics_data.get("total_threat_events", 0))
        analytics_html += "<tr><td class='key'>Total Website Incidents</td><td class='value'>{val}</td></tr>".format(
            val=analytics_data.get("total_website_incidents", 0))
        analytics_html += "<tr><td class='key'>Rate-Limited IPs (Current)</td><td class='value'>{val}</td></tr>".format(
            val=analytics_data.get("rate_limited_ip_count", 0))

        attack_counts = analytics_data.get("attack_type_counts", {})
        if attack_counts:
            analytics_html += "<tr><td colspan='2' class='subkey'>Attack Type Counts:</td></tr>"
            for key, value in sorted(attack_counts.items(), key=lambda item: item[1], reverse=True):
                analytics_html += "<tr><td class='key indented'>{k}</td><td class='value'>{v}</td></tr>".format(
                    k=key, v=value)

        website_incidents = analytics_data.get("website_incident_counts", {})
        if website_incidents:
            analytics_html += "<tr><td colspan='2' class='subkey'>Website Incidents:</td></tr>"
            for key, value in sorted(website_incidents.items(), key=lambda item: item[1], reverse=True):
                analytics_html += "<tr><td class='key indented'>{k}</td><td class='value'>{v}</td></tr>".format(
                    k=key, v=value)

    except Exception as e:
        logger.error(f"Error building analytics HTML: {e}")
        analytics_html = "<tr><td colspan='2'>Error building analytics table.</td></tr>"

    # --- 2. Format LLM Report Text ---
    try:
        # Convert markdown-like text from LLM to basic HTML
        llm_html = llm_text_report.replace("\n\n", "<p>")  # Paragraphs
        llm_html = llm_html.replace("\n", "<br />")  # Newlines
        llm_html = re.sub(r'# (.*?)(<br />|$)', r'<h1>\1</h1>',
                          llm_html, flags=re.MULTILINE)
        llm_html = re.sub(r'## (.*?)(<br />|$)', r'<h2>\1</h2>',
                          llm_html, flags=re.MULTILINE)
        llm_html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', llm_html)
        llm_html = re.sub(r'^- (.*?)(<br />|$)', r'<li>\1</li>',
                          llm_html, flags=re.MULTILINE)
        # Fix for multiple <li> being wrapped in individual <ul>
        llm_html = re.sub(r'(<ul>.*?</ul>)', r'\1', llm_html,
                          flags=re.DOTALL)  # Remove existing
        llm_html = re.sub(r'(<li>.*?</li>)', r'<ul>\1</ul>',
                          llm_html, flags=re.DOTALL)  # Wrap all <li>
    except Exception as e:
        logger.error(f"Error formatting LLM text to HTML: {e}")
        # Fallback to preformatted text
        llm_html = f"<h3>LLM Report Error</h3><pre>{llm_text_report}</pre>"

    # --- 3. Assemble Full HTML Document ---
    html_template = f"""
    <html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
        <style>
            /* Define print layout */
            @page {{
                size: a4 portrait;
                margin: 1.5cm; /* Simple margins */
                
                @frame header {{
                    -pdf-frame-content: header_content;
                    top: 1cm;
                    left: 1.5cm;
                    right: 1.5cm;
                    height: 1.5cm;
                }}
                
                @frame footer {{
                    -pdf-frame-content: footer_content;
                    bottom: 1cm;
                    left: 1.5cm;
                    right: 1.5cm;
                    height: 1cm;
                }}
            }}
            
            body {{ font-family: "Helvetica", "Arial", sans-serif; font-size: 10pt; color: #333; }}
            h1 {{ font-size: 18pt; font-weight: bold; color: #111; margin-top: 0; margin-bottom: 5pt; page-break-after: avoid; }}
            h2 {{ font-size: 14pt; font-weight: bold; color: #222; margin-top: 15pt; border-bottom: 1px solid #888; padding-bottom: 2px; page-break-after: avoid; }}
            h3 {{ font-size: 12pt; font-weight: bold; color: #333; margin-top: 10pt; page-break-after: avoid; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10pt; margin-bottom: 10pt; page-break-inside: avoid; }}
            th, td {{ border: 1px solid #ddd; padding: 6px; text-align: left; word-wrap: break-word; }}
            td.key {{ font-weight: bold; width: 40%; background-color: #f9f9f9; }}
            td.value {{ width: 60%; }}
            td.subkey {{ font-weight: bold; background-color: #f0f0f0; padding-left: 10px;}}
            td.indented {{ padding-left: 20px; }}
            ul {{ margin-top: 5pt; margin-bottom: 10pt; padding-left: 20px; }}
            li {{ margin-bottom: 4pt; }}
            p, pre {{ margin-top: 5pt; margin-bottom: 5pt; white-space: pre-wrap; word-wrap: break-word; }}
            img.chart {{ max-width: 100%; height: auto; margin-top: 10px; page-break-inside: avoid; }}
            
            /* Header and Footer content */
            #header_content {{
                text-align: left;
                font-size: 10pt;
                font-weight: bold;
                color: #555;
            }}
            #footer_content {{
                text-align: right;
                font-size: 9pt;
                color: #888;
            }}
            
            .page-break {{
                page-break-before: always;
            }}
        </style>
    </head>
    <body>
        <div id="header_content">
            AI Security Agent - Executive Report
        </div>

        <div id="footer_content">
            Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")} | Page <pdf:pagecount />
        </div>

        {llm_html}

        <h2>Key Metrics</h2>
        <table>
            {analytics_html}
        </table>

        <div class="page-break">
            <h2>Visual Dashboards</h2>
            
            <h3>Event Trend Chart</h3>
            <p>This chart shows the volume of detected security events over time.</p>
            <img src="{trend_chart_b64}" class="chart" />
            
            <br />
            
            <h3>Severity Distribution</h3>
            <p>This chart shows the breakdown of all detected events by severity.</p>
            <img src="{severity_chart_b64}" class="chart" style="width: 70%; margin-left: auto; margin-right: auto;" />
        </div>
        
    </body>
    </html>
    """
    return html_template


def create_pdf_report(
    llm_text_report: str,
    analytics_data: Dict[str, Any],
    trend_chart_b64: str,
    severity_chart_b64: str
) -> bytes:
    """
    Generates a PDF report from an HTML string using xhtml2pdf.
    This is a blocking function.
    """
    result = io.BytesIO()  # In-memory PDF file

    try:
        # 1. Build the HTML string
        html_content = build_report_html(
            llm_text_report,
            analytics_data,
            trend_chart_b64,
            severity_chart_b64
        )

        # 2. Convert HTML to PDF
        pisa_status = pisa.CreatePDF(
            html_content,    # The HTML to convert
            dest=result,     # File handle to receive result
            encoding='utf-8'  # Ensure UTF-8
        )

        # 3. Check for errors
        if pisa_status.err:
            logger.error(f"PDF creation error: {pisa_status.err}")
            # Try to create a fallback error PDF
            raise Exception(f"PISA PDF creation error: {pisa_status.err}")

        # 4. Return PDF bytes
        pdf_bytes = result.getvalue()
        if not pdf_bytes:
            raise Exception("PDF generation resulted in an empty file.")
        logger.info("xhtml2pdf conversion successful.")
        return pdf_bytes

    except Exception as e:
        logger.error(f"Failed to generate PDF: {e}", exc_info=True)
        # Create a simple fallback PDF *using FPDF*
        pdf_error = FPDF()
        pdf_error.add_page()
        pdf_error.set_font('Arial', 'B', 16)
        pdf_error.cell(0, 20, 'PDF Generation Failed', 0, 1, 'C')
        pdf_error.set_font('Arial', '', 10)
        pdf_error.multi_cell(
            0, 5, f"An error occurred: {e}\n\n{traceback.format_exc()}")
        return pdf_error.output(dest='S')  # Returns bytes
    finally:
        result.close()
