import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def generate_pdf(scan):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    styles = getSampleStyleSheet()
    normal = styles['Normal']
    heading1 = styles['Heading1']
    heading2 = styles['Heading2']
    heading3 = styles['Heading3']
    
    elements = []
    
    elements.append(Paragraph("WEBGUARD", heading1))
    elements.append(Paragraph("Web Application Security Assessment Report", heading2))
    elements.append(Spacer(1, 12))
    
    s = scan['summary']
    data = [
        ["Target", scan['target_url']],
        ["Final URL", scan['final_url']],
        ["Assessment date", scan['scan_date']],
        ["HTTP status", str(scan['status_code'])],
        ["HTTPS status", "Yes" if scan['https'] else "No"],
        ["Response time", f"{scan['response_time_ms']} ms"],
        ["Security Score", str(s['score'])],
        ["Configuration rating", s.get('rating', '')],
        ["Risk Score", str(s.get('risk_score', ''))],
        ["Risk Level", s.get('risk_level', '')],
        ["Severity summary", f"Critical: {s['critical']}, High: {s['high']}, Medium: {s['medium']}, Low: {s['low']}, Passed: {s['passed']}"]
    ]
    t = Table(data, colWidths=[150, 350])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.lightgrey),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6)
    ]))
    elements.append(t)
    elements.append(Spacer(1, 20))
    
    categories = [
        ("headers", "Security Header Analysis"),
        ("cookies", "Cookie Security Analysis"),
        ("tls", "HTTPS/TLS Analysis"),
        ("exposure", "Information Exposure"),
        ("html", "HTML Security Analysis")
    ]
    
    elements.append(Paragraph("Detailed Findings", heading2))
    
    for cat_id, cat_name in categories:
        cat_findings = [f for f in scan['findings'] if f['category'] == cat_id]
        if not cat_findings:
            continue
        elements.append(Paragraph(cat_name, heading3))
        for f in cat_findings:
            elements.append(Paragraph(f"<b>{f['name']} ({f['status']})</b>", normal))
            elements.append(Paragraph(f"<b>Severity:</b> {f['severity']}", normal))
            elements.append(Paragraph(f"<b>Description:</b> {f['description']}", normal))
            if f.get('why'):
                elements.append(Paragraph(f"<b>Potential Impact:</b> {f['why']}", normal))
            if f.get('recommendation'):
                elements.append(Paragraph(f"<b>Recommended Remediation:</b> {f['recommendation']}", normal))
            if f.get('evidence'):
                elements.append(Paragraph(f"<b>Evidence:</b> {f['evidence'][:200]}", normal))
            if f.get('owasp'):
                elements.append(Paragraph(f"<b>OWASP Mapping:</b> {f['owasp']}", normal))
            elements.append(Spacer(1, 10))
            
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("Assessment Limitations & Authorized Use Disclaimer", heading2))
    elements.append(Paragraph("This report represents only the configuration checks performed by WebGuard and is not proof that the application is completely secure or insecure. The Risk Score represents the severity-weighted configuration issues detected by WebGuard. It is not a probability of compromise and does not replace a complete penetration test. It is an educational tool for authorized use only.", normal))

    doc.build(elements)
    buffer.seek(0)
    return buffer.read()
