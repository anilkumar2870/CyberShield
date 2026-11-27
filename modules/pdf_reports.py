"""
CyberShield - Automated PDF Report Generator

Generates downloadable security assessment reports
using historical network monitoring scan records.
"""

import json
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether
)


NAVY = colors.HexColor("#14243B")
BLUE = colors.HexColor("#078BC9")
LIGHT_BLUE = colors.HexColor("#EAF2FA")
BORDER = colors.HexColor("#D5DEE8")
DARK = colors.HexColor("#26384D")
GREEN = colors.HexColor("#168653")


def safe_text(value):
    """Safely format dynamic values for PDF paragraphs."""
    return escape(str(value if value is not None else "Not available"))


def generate_security_report(scan):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="CyberShield Security Assessment Report",
        author="CyberShield"
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontSize=21,
        leading=26,
        textColor=NAVY,
        alignment=TA_CENTER,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        textColor=NAVY,
        spaceBefore=10,
        spaceAfter=8
    ))

    styles.add(ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        textColor=DARK
    ))

    styles.add(ParagraphStyle(
        name="TableText",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        textColor=DARK
    ))

    def paragraph(value):
        return Paragraph(safe_text(value), styles["TableText"])

    # Recover the complete historical scan result.
    try:
        payload = json.loads(scan.get("result_json") or "{}")
    except (json.JSONDecodeError, TypeError):
        payload = {}

    devices = scan.get("devices") or payload.get("devices", [])
    events = payload.get("events", [])

    scan_id = scan.get("id", "N/A")
    network = scan.get("network", "Not available")
    total = scan.get("total", len(devices))
    event_count = scan.get("event_count", len(events))
    scanner = scan.get("scanner", "Not available")
    scan_time = scan.get("monitoring_time", "Not available")

    story = []

    # Report heading
    story.append(Paragraph(
        "CYBERSHIELD",
        ParagraphStyle(
            "Brand",
            parent=styles["ReportTitle"],
            fontSize=12,
            textColor=BLUE,
            spaceAfter=5
        )
    ))

    story.append(Paragraph(
        "Security Assessment Report",
        styles["ReportTitle"]
    ))

    story.append(Paragraph(
        "Historical Network Monitoring Assessment",
        ParagraphStyle(
            "Subtitle",
            parent=styles["ReportBody"],
            alignment=TA_CENTER,
            spaceAfter=15
        )
    ))

    # Report summary
    story.append(Paragraph("1. Report Summary",
                           styles["SectionHeading"]))

    summary_data = [
        ["Report ID", f"#{safe_text(scan_id)}"],
        ["Network", safe_text(network)],
        ["Devices Discovered", safe_text(total)],
        ["Security Events", safe_text(event_count)],
        ["Scanner", safe_text(scanner)],
        ["Scan Time", safe_text(scan_time)]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[48 * mm, 115 * mm]
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BLUE),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
        ("TEXTCOLOR", (1, 0), (1, -1), DARK),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8)
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 12))

    # Discovered devices
    story.append(Paragraph(
        "2. Discovered Network Devices",
        styles["SectionHeading"]
    ))

    device_data = [[
        "IP Address",
        "MAC Address",
        "Status"
    ]]

    for device in devices:
        device_data.append([
            paragraph(device.get("ip", "Not available")),
            paragraph(device.get("mac", "Not available")),
            paragraph(device.get("status", "Not available"))
        ])

    if not devices:
        device_data.append([
            "No device information available.",
            "",
            ""
        ])

    device_table = Table(
        device_data,
        colWidths=[53 * mm, 65 * mm, 45 * mm],
        repeatRows=1
    )

    device_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, LIGHT_BLUE]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8)
    ]))

    story.append(device_table)
    story.append(Spacer(1, 12))

    # Security events
    story.append(Paragraph(
        "3. Security Event Summary",
        styles["SectionHeading"]
    ))

    story.append(Paragraph(
        f"Total security events detected: <b>{safe_text(event_count)}</b>",
        styles["ReportBody"]
    ))

    if events:

        event_data = [[
            "Type",
            "Severity",
            "IP Address",
            "Message"
        ]]

        for event in events:
            event_data.append([
                paragraph(event.get("type", "Not available")),
                paragraph(event.get("severity", "Not available")),
                paragraph(event.get("ip", "Not available")),
                paragraph(event.get("message", "Not available"))
            ])

        event_table = Table(
            event_data,
            colWidths=[30 * mm, 28 * mm, 35 * mm, 70 * mm],
            repeatRows=1
        )

        event_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7)
        ]))

        story.append(Spacer(1, 8))
        story.append(event_table)

    else:
        story.append(Paragraph(
            "No security events were recorded during this "
            "monitoring scan.",
            styles["ReportBody"]
        ))

    story.append(Spacer(1, 12))

    # Assessment conclusion
    conclusion = [
        Paragraph(
            "4. Assessment Conclusion",
            styles["SectionHeading"]
        ),
        Paragraph(
            "This report summarizes the network devices and "
            "security event information recorded during the "
            "selected monitoring scan.",
            styles["ReportBody"]
        ),
        Spacer(1, 6),
        Paragraph(
            "This is a historical monitoring summary and should "
            "not be interpreted as a guarantee that the network "
            "is free from security vulnerabilities.",
            styles["ReportBody"]
        )
    ]

    story.append(KeepTogether(conclusion))

    def add_page_number(canvas, doc):
        canvas.saveState()

        canvas.setStrokeColor(BORDER)
        canvas.line(
            18 * mm,
            13 * mm,
            A4[0] - 18 * mm,
            13 * mm
        )

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(DARK)

        canvas.drawString(
            18 * mm,
            8 * mm,
            "CyberShield | Security Assessment Report"
        )

        canvas.drawRightString(
            A4[0] - 18 * mm,
            8 * mm,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    document.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )

    buffer.seek(0)

    return buffer
