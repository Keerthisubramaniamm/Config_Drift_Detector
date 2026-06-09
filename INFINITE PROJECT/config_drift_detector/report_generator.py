import os
import datetime
from typing import Any, Dict, List
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Custom canvas that performs a two-pass render to draw dynamic headers and footers.
    
    This ensures we know the total page count when printing 'Page X of Y'.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        # Save page state for the second pass
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_header_footer(self, page_count: int):
        self.saveState()
        
        # Colors
        slate_gray = colors.HexColor("#64748B")
        border_gray = colors.HexColor("#E2E8F0")
        
        # Don't draw headers/footers on page 1 (acting as a cover page)
        if self._pageNumber > 1:
            # Header
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(slate_gray)
            self.drawString(54, 750, "CONFIG DRIFT ANALYSIS REPORT")
            self.setFont("Helvetica", 8)
            self.drawRightString(558, 750, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            # Header line
            self.setStrokeColor(border_gray)
            self.setLineWidth(0.75)
            self.line(54, 742, 558, 742)
            
            # Footer line
            self.line(54, 52, 558, 52)
            
            # Footer
            self.setFont("Helvetica", 8)
            self.drawString(54, 40, "Confidential - IT Infrastructure Audit Logs")
            page_text = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(558, 40, page_text)
            
        else:
            # Simple footer for cover/page 1
            self.setStrokeColor(border_gray)
            self.setLineWidth(0.75)
            self.line(54, 52, 558, 52)
            self.setFont("Helvetica", 8)
            self.setFillColor(slate_gray)
            self.drawString(54, 40, "Confidential - Config Drift Detector")
            self.drawRightString(558, 40, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d')}")
            
        self.restoreState()

def get_severity_color(severity: str) -> str:
    """Returns HSL-matched color strings for severity tags."""
    colors_map = {
        "Critical": "#EF4444", # Red
        "High": "#F97316",     # Orange
        "Medium": "#F59E0B",   # Amber/Yellow
        "Low": "#10B981"       # Green
    }
    return colors_map.get(severity, "#64748B")

def generate_pdf_report(drifts_data: List[Dict[str, Any]], output_path: str) -> str:
    """Generates a professional PDF document from drift history results.
    
    Args:
        drifts_data: List of drift items with matched AI Analysis.
        output_path: Target write path.
        
    Returns:
        The generated PDF path.
    """
    # 1. Document Configuration
    # Page height is 792 pt, width 612 pt. Margins 0.75 in (54 pt)
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=72,
        bottomMargin=72
    )
    
    # 2. Styling System
    styles = getSampleStyleSheet()
    
    # Add unique custom paragraph styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=8
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=20
    )
    
    section_h1 = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=16,
        spaceAfter=10,
        keepWithNext=True
    )
    
    sub_h2 = ParagraphStyle(
        'SubH2',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )
    
    body_p = ParagraphStyle(
        'BodyP',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155'),
        spaceAfter=5
    )
    
    code_p = ParagraphStyle(
        'CodeP',
        parent=styles['Code'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1E293B')
    )
    
    # 3. Content Story Builder
    story = []
    
    # ------------------- PAGE 1: COVER & EXECUTIVE SUMMARY -------------------
    story.append(Spacer(1, 40))
    story.append(Paragraph("Config Drift Analysis Report", title_style))
    story.append(Paragraph("Automated DevOps Compliance & Risk Assessment", subtitle_style))
    story.append(Spacer(1, 15))
    
    # Statistics Computations
    total_drifts = len(drifts_data)
    unique_files = list(set([d["file_name"] for d in drifts_data]))
    files_count = len(unique_files)
    
    critical_count = sum(1 for d in drifts_data if d["severity"] == "Critical")
    high_count = sum(1 for d in drifts_data if d["severity"] == "High")
    medium_count = sum(1 for d in drifts_data if d["severity"] == "Medium")
    low_count = sum(1 for d in drifts_data if d["severity"] == "Low")
    
    scan_timestamp = drifts_data[0]["timestamp"] if drifts_data else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Summary Table Box (KPI Panel)
    summary_data = [
        [
            Paragraph("<b>Scan Timestamp</b>", body_p), 
            Paragraph(f"{scan_timestamp}", body_p)
        ],
        [
            Paragraph("<b>Total Config Files Evaluated</b>", body_p), 
            Paragraph(f"{files_count} ({', '.join(unique_files)})", body_p)
        ],
        [
            Paragraph("<b>Total Anomalies Detected</b>", body_p), 
            Paragraph(f"<b>{total_drifts}</b> issues", body_p)
        ],
        [
            Paragraph("<b>Risk Severity Profile</b>", body_p),
            Paragraph(
                f"<font color='#EF4444'><b>Critical: {critical_count}</b></font> | "
                f"<font color='#F97316'><b>High: {high_count}</b></font> | "
                f"<font color='#F59E0B'><b>Medium: {medium_count}</b></font> | "
                f"<font color='#10B981'><b>Low: {low_count}</b></font>", 
                body_p
            )
        ]
    ]
    
    kpi_table = Table(summary_data, colWidths=[180, 324])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    
    story.append(kpi_table)
    story.append(Spacer(1, 20))
    
    # Executive Summary Paragraph
    story.append(Paragraph("Executive Summary", section_h1))
    summary_text = (
        "This configuration compliance audit reports drifts identified between intended configuration layouts "
        "and actual parameters retrieved from live production nodes. Discrepancies are categorized "
        "according to logical keyword threat scores (e.g., firewall parameters raise Critical ratings). "
        "Each active drift has been run through an AI impact analysis engine powered by Groq LLM. "
        "Engineering and Operations staff should review security-impacting modifications immediately to "
        "mitigate environment breaches, service outages, or compliance regressions."
    )
    story.append(Paragraph(summary_text, body_p))
    story.append(Spacer(1, 25))
    
    # ------------------- PAGE 2+: DETAILED DRIFTS TABLE -------------------
    story.append(PageBreak())
    story.append(Paragraph("Detailed Drift Registry", section_h1))
    story.append(Paragraph("The table below lists every individual structural or parameter difference found during execution.", body_p))
    story.append(Spacer(1, 8))
    
    # Table headers
    headers = [
        Paragraph("<b>File Name</b>", body_p),
        Paragraph("<b>Config Path</b>", body_p),
        Paragraph("<b>Expected</b>", body_p),
        Paragraph("<b>Actual</b>", body_p),
        Paragraph("<b>Severity</b>", body_p)
    ]
    
    table_rows = [headers]
    for d in drifts_data:
        sev = d["severity"]
        sev_color = get_severity_color(sev)
        
        # Clean values to avoid breaking ReportLab layout (e.g. escaping '<' or '>')
        expected_cleaned = d["intended_value"].replace("<", "&lt;").replace(">", "&gt;")
        actual_cleaned = d["actual_value"].replace("<", "&lt;").replace(">", "&gt;")
        
        table_rows.append([
            Paragraph(d["file_name"], body_p),
            Paragraph(d["config_path"], body_p),
            Paragraph(expected_cleaned, code_p),
            Paragraph(actual_cleaned, code_p),
            Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_p)
        ])
        
    # Column widths out of total printable 504 points
    drift_table = Table(table_rows, colWidths=[70, 110, 122, 122, 80])
    drift_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#FFFFFF')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#FFFFFF'), colors.HexColor('#F8FAFC')]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    
    # Re-apply text color overrides to headers
    for i in range(len(headers)):
        drift_table.setStyle(TableStyle([
            ('TEXTCOLOR', (i,0), (i,0), colors.white)
        ]))
        
    story.append(drift_table)
    story.append(Spacer(1, 20))
    
    # ------------------- SECTION 3: AI ANALYSIS CARDS -------------------
    story.append(PageBreak())
    story.append(Paragraph("AI-Powered Impact & Remediation Review", section_h1))
    story.append(Paragraph("Detailed technical audits and fix playbooks generated by Groq LLM for each configuration drift.", body_p))
    story.append(Spacer(1, 10))
    
    for idx, d in enumerate(drifts_data):
        sev = d["severity"]
        sev_color = get_severity_color(sev)
        
        # Prepare card elements
        card_story = []
        card_story.append(Paragraph(f"<b>Issue #{idx+1}: {d['file_name']} &rarr; {d['config_path']}</b>", sub_h2))
        
        # Details Table
        details_txt = (
            f"<b>Drift Type:</b> {d['drift_type']} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Severity:</b> <font color='{sev_color}'><b>{sev}</b></font> &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Expected:</b> {d['intended_value']} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"<b>Deployed:</b> {d['actual_value']}"
        )
        card_story.append(Paragraph(details_txt, body_p))
        card_story.append(Spacer(1, 5))
        
        # Impact text formatting
        tech_impact = d.get("technical_impact") or "No technical impact assessed."
        biz_impact = d.get("business_impact") or "No business impact assessed."
        sec_impact = d.get("security_impact") or "No security impact assessed."
        recommendation = d.get("recommendation") or "1. Revert to the expected config value."
        
        card_story.append(Paragraph(f"<b>Technical Impact:</b> {tech_impact}", body_p))
        card_story.append(Paragraph(f"<b>Business Impact:</b> {biz_impact}", body_p))
        card_story.append(Paragraph(f"<b>Security Impact:</b> {sec_impact}", body_p))
        
        # Format recommendations (split into paragraphs or lists if multiline)
        card_story.append(Spacer(1, 4))
        card_story.append(Paragraph("<b>Remediation Plan:</b>", body_p))
        rec_lines = recommendation.split("\n")
        for line in rec_lines:
            if line.strip():
                card_story.append(Paragraph(line.strip(), body_p))
                
        card_story.append(Spacer(1, 10))
        
        # Draw a horizontal line inside the card block
        line_table = Table([[""]], colWidths=[504])
        line_table.setStyle(TableStyle([
            ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
        ]))
        card_story.append(line_table)
        card_story.append(Spacer(1, 10))
        
        # Keep each issue analysis block together so it doesn't break awkwardly across pages
        story.append(KeepTogether(card_story))
        
    # 4. Build Document with Two-Pass Page Numbering
    doc.build(story, canvasmaker=NumberedCanvas)
    
    return output_path
