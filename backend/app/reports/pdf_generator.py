"""Generate a PDF scan report using ReportLab."""
import io
from collections import Counter
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from app.models.scan import Scan
from app.models.vulnerability import SEVERITY_SCORE, Severity


SEVERITY_COLORS = {
    Severity.CRITICAL: colors.HexColor("#7f1d1d"),
    Severity.HIGH: colors.HexColor("#b91c1c"),
    Severity.MEDIUM: colors.HexColor("#ca8a04"),
    Severity.LOW: colors.HexColor("#1d4ed8"),
    Severity.INFO: colors.HexColor("#374151"),
}


def generate_scan_pdf(scan: Scan) -> io.BytesIO:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"SecScan Report - {scan.target_host}",
        author="SecScan",
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], textColor=colors.HexColor("#111827"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#1f2937"))
    body = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        alignment=TA_LEFT,
        spaceAfter=6,
    )
    mono = ParagraphStyle(
        "Mono",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1f2937"),
    )

    story = []
    story.append(Paragraph("SecScan Security Audit Report", h1))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"<b>Target:</b> {scan.target_url}", body))
    story.append(Paragraph(f"<b>Host:</b> {scan.target_host}", body))
    story.append(Paragraph(f"<b>Scan ID:</b> {scan.id}", body))
    story.append(
        Paragraph(
            f"<b>Generated:</b> {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
            body,
        )
    )
    if scan.finished_at:
        story.append(
            Paragraph(f"<b>Scan completed:</b> {scan.finished_at.isoformat(timespec='seconds')}", body)
        )
    story.append(Paragraph(f"<b>Modules:</b> {', '.join(scan.modules)}", body))
    story.append(Paragraph(f"<b>Depth:</b> {scan.depth}", body))
    if scan.risk_score is not None:
        story.append(
            Paragraph(
                f"<b>Overall risk score:</b> {scan.risk_score:.2f} / "
                f"{max(SEVERITY_SCORE.values()):.1f}",
                body,
            )
        )

    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph("Summary by severity", h2))
    counts = Counter(v.severity for v in scan.vulnerabilities)
    table_data = [["Severity", "Count"]]
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        table_data.append([sev.value.upper(), counts.get(sev, 0)])

    t = Table(table_data, colWidths=[60 * mm, 30 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f9fafb"), colors.white]),
            ]
        )
    )
    story.append(t)

    story.append(PageBreak())
    story.append(Paragraph("Findings", h1))
    story.append(Spacer(1, 4 * mm))

    sorted_vulns = sorted(
        scan.vulnerabilities,
        key=lambda v: SEVERITY_SCORE.get(v.severity, 0.0),
        reverse=True,
    )

    if not sorted_vulns:
        story.append(Paragraph("No findings reported.", body))
    for v in sorted_vulns:
        sev_color = SEVERITY_COLORS.get(v.severity, colors.black)
        story.append(
            Paragraph(
                f'<b><font color="{sev_color.hexval()}">[{v.severity.value.upper()}]</font> '
                f"{_escape(v.title)}</b>",
                h2,
            )
        )
        story.append(Paragraph(f"<b>Module:</b> {v.module}", body))
        story.append(Paragraph(f"<b>OWASP:</b> {v.owasp_category.value}", body))
        story.append(Paragraph(f"<b>Description:</b> {_escape(v.description)}", body))
        if v.remediation:
            story.append(Paragraph(f"<b>Remediation:</b> {_escape(v.remediation)}", body))
        if v.reference_url:
            story.append(Paragraph(f"<b>Reference:</b> {_escape(v.reference_url)}", body))
        if v.evidence:
            ev_str = _format_evidence(v.evidence)
            story.append(Paragraph("<b>Evidence:</b>", body))
            story.append(Paragraph(ev_str, mono))
        story.append(Spacer(1, 3 * mm))

    doc.build(story)
    buf.seek(0)
    return buf


def _escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _format_evidence(evidence: dict) -> str:
    import json

    try:
        text = json.dumps(evidence, indent=2, default=str)
    except Exception:
        text = str(evidence)
    return _escape(text).replace("\n", "<br/>").replace(" ", "&nbsp;")
