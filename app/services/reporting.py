# app/services/reporting.py
import io
import re
from xhtml2pdf import pisa
from datetime import datetime
from typing import Dict, Any


def build_report_html(ai_text: str, stats: Dict[str, Any], trend_b64: str, sev_b64: str) -> str:
    # Convert Markdown-style headers and bolding to HTML
    body = ai_text.replace("\n", "<br/>")
    body = re.sub(r'### (.*?)(<br/>|$)', r'<h3>\1</h3>', body)
    body = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', body)

    return f"""
    <html>
    <head>
        <style>
            @page {{ size: a4; margin: 1cm; }}
            body {{ font-family: Helvetica, Arial, sans-serif; color: #333; line-height: 1.4; font-size: 10pt; }}
            .header {{ border-bottom: 2px solid #2d3748; padding-bottom: 10px; margin-bottom: 20px; }}
            h1 {{ color: #1a202c; font-size: 22pt; margin: 0; }}
            h2 {{ color: #2d3748; border-bottom: 1px solid #e2e8f0; margin-top: 20px; }}
            h3 {{ color: #3182ce; background: #f7fafc; padding: 5px; margin-top: 15px; border-left: 4px solid #3182ce; }}
            .stats-box {{ background: #f8fafc; border: 1px solid #edf2f7; padding: 10px; margin-bottom: 20px; }}
            .chart-container {{ text-align: center; margin-top: 20px; }}
            /* FIX: Use fixed widths (pt) instead of percentages to avoid getSize errors */
            .chart-img {{ width: 450pt; border: 1px solid #eee; }}
            .footer {{ text-align: center; font-size: 8pt; color: #a0aec0; margin-top: 30px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Security Intelligence Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        
        <div class="stats-box">
            <strong>Threat Intelligence Overview:</strong><br/>
            - Total Threat Events Detected: {stats.get('total_threat_events', 0)}<br/>
            - Active Network Blocks: {stats.get('active_blocks', 0)}
        </div>

        {body}

        <pdf:nextpage />
        <h2>Visual Analytics</h2>
        <div class="chart-container">
            <p><strong>Threat Velocity (Over Time)</strong></p>
            <img src="{trend_b64}" class="chart-img" />
            
            <p style="margin-top: 30px;"><strong>Severity Distribution</strong></p>
            <img src="{sev_b64}" style="width: 300pt;" />
        </div>

        <div class="footer">Confidential Intelligence Data | AI Security Agent v2.0</div>
    </body>
    </html>
    """


def create_pdf_report(ai_text, stats, trend_b64, sev_b64) -> bytes:
    result = io.BytesIO()
    html = build_report_html(ai_text, stats, trend_b64, sev_b64)
    pisa.CreatePDF(html, dest=result, encoding='utf-8')
    return result.getvalue()
