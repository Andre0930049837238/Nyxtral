# -*- coding: utf-8 -*-
"""
report.py
Generates the PDF report (reportlab, a pure-Python library: no external
program needs to be installed to build the exe). It replaces the old HTML
version on explicit request: same content, designed to be read, printed or
attached to an email without depending on a browser.
"""

import io
import logging
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from quality_engine import quality_score as _quality_score
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether, PageBreak,
)

log = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#c62828"),
    "HIGH": colors.HexColor("#ef6c00"),
    "MEDIUM": colors.HexColor("#b8860b"),
    "LOW": colors.HexColor("#2e7d32"),
    "INFO": colors.HexColor("#1565c0"),
}
SEVERITY_LABELS = {
    "CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
    "LOW": "Low", "INFO": "Informational",
}
CONFIDENCE_LABELS = {
    "confirmed": "Confirmed", "unknown": "Potential", "safe": "Info",
}

TEXT_DARK = colors.HexColor("#1c1f2b")
TEXT_GRAY = colors.HexColor("#5a6072")
BORDER_GRAY = colors.HexColor("#d8dbe4")
BG_LIGHT = colors.HexColor("#f5f6fa")
BG_CODE = colors.HexColor("#282c3a")
CODE_TEXT = colors.HexColor("#e6e8ef")
ACCENT = colors.HexColor("#4a5fd6")


def _styles():
    ss = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("title", parent=ss["Title"], fontSize=20, textColor=TEXT_DARK,
                                 spaceAfter=4, alignment=TA_LEFT),
        "subtitle": ParagraphStyle("subtitle", parent=ss["Normal"], fontSize=9.5, textColor=TEXT_GRAY,
                                    spaceAfter=14),
        "intro_heading": ParagraphStyle("intro_heading", parent=ss["Normal"], fontSize=11,
                                         textColor=TEXT_DARK, fontName="Helvetica-Bold", spaceAfter=4),
        "intro_body": ParagraphStyle("intro_body", parent=ss["Normal"], fontSize=9.5, textColor=TEXT_DARK,
                                      leading=13.5),
        "score_number": ParagraphStyle("score_number", parent=ss["Normal"], fontSize=30, alignment=TA_CENTER,
                                        fontName="Helvetica-Bold"),
        "score_caption": ParagraphStyle("score_caption", parent=ss["Normal"], fontSize=8, alignment=TA_CENTER,
                                         textColor=TEXT_GRAY),
        "section_heading": ParagraphStyle("section_heading", parent=ss["Heading2"], fontSize=13,
                                           spaceBefore=16, spaceAfter=8),
        "finding_title": ParagraphStyle("finding_title", parent=ss["Normal"], fontSize=11,
                                         fontName="Helvetica-Bold", textColor=TEXT_DARK),
        "badge": ParagraphStyle("badge", parent=ss["Normal"], fontSize=8, textColor=TEXT_GRAY, alignment=TA_LEFT),
        "location": ParagraphStyle("location", parent=ss["Normal"], fontSize=8.5, textColor=TEXT_GRAY,
                                    spaceAfter=4),
        "code": ParagraphStyle("code", parent=ss["Normal"], fontName="Courier", fontSize=8.3,
                                textColor=CODE_TEXT, leading=11),
        "label": ParagraphStyle("label", parent=ss["Normal"], fontSize=9.3, fontName="Helvetica-Bold",
                                 textColor=TEXT_DARK, spaceBefore=5),
        "body": ParagraphStyle("body", parent=ss["Normal"], fontSize=9.3, textColor=TEXT_DARK, leading=13),
        "impact_body": ParagraphStyle("impact_body", parent=ss["Normal"], fontSize=9.3,
                                       textColor=colors.HexColor("#8a4b00"), leading=13),
        "rec_body": ParagraphStyle("rec_body", parent=ss["Normal"], fontSize=9.3,
                                    textColor=colors.HexColor("#1e6b3a"), leading=13),
        "footer": ParagraphStyle("footer", parent=ss["Normal"], fontSize=7.5, textColor=TEXT_GRAY,
                                  alignment=TA_CENTER),
        "suppressed_row": ParagraphStyle("suppressed_row", parent=ss["Normal"], fontSize=8.5, textColor=TEXT_GRAY),
    }
    return styles


def _score_color(score):
    if score >= 80:
        return colors.HexColor("#2e7d32")
    if score >= 60:
        return colors.HexColor("#b8860b")
    if score >= 40:
        return colors.HexColor("#ef6c00")
    return colors.HexColor("#c62828")


def _finding_flowable(f, styles, dim=False):
    sev = f["severity"]
    sev_color = SEVERITY_COLORS.get(sev, TEXT_GRAY)
    name = escape(f["name"])
    conf_label = CONFIDENCE_LABELS.get(f.get("confidence", "unknown"), "")
    location = escape(f["file"]) + (f":{f['line']}" if f["line"] else "")

    header = Paragraph(
        f'<font color="{sev_color.hexval()}">●</font> <b>{name}</b> '
        f'<font size="8" color="{TEXT_GRAY.hexval()}">[{escape(f["id"])}]</font>',
        styles["finding_title"],
    )
    badge = Paragraph(
        f'Severity: <b>{SEVERITY_LABELS.get(sev, sev)}</b> &nbsp;·&nbsp; '
        f'Confidence: <b>{conf_label}</b>',
        styles["badge"],
    )
    loc = Paragraph(f"File: {location}", styles["location"])

    snippet = escape(f.get("snippet", "")).replace("&#10;", "<br/>")
    code_table = Table(
        [[Paragraph(snippet or " ", styles["code"])]],
        colWidths=[16.5 * cm],
    )
    code_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_CODE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    meaning = Paragraph(f"<b>What it means:</b> {escape(f['description'])}", styles["body"])
    impact = Paragraph(f"<b>What you risk in practice:</b> {escape(f.get('impact', ''))}", styles["impact_body"])
    fix = Paragraph(f"<b>How to fix it:</b> {escape(f['recommendation'])}", styles["rec_body"])

    block = [header, badge, loc, Spacer(1, 3), code_table, Spacer(1, 4), meaning, impact, fix]

    block.append(Spacer(1, 12))

    wrapper = Table([[block]], colWidths=[17 * cm])
    wrapper.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER_GRAY),
        ("LINEBEFORE", (0, 0), (0, -1), 3, sev_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (-1, -1), colors.white if not dim else BG_LIGHT),
    ]))
    return KeepTogether([wrapper, Spacer(1, 8)])


def render_report(root_dir, findings, files_scanned, score, files_from_cache=0):
    """Generate the report and return the PDF bytes (to be written to a file in 'wb' mode)."""
    styles = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=1.6 * cm, rightMargin=1.6 * cm, topMargin=1.6 * cm, bottomMargin=1.6 * cm,
        title="Code Security Report",
    )

    all_active = [f for f in findings if not f.get("suppressed")]
    active = [f for f in all_active if f.get("category") != "quality"]       # security
    quality_active = [f for f in all_active if f.get("category") == "quality"]
    suppressed = [f for f in findings if f.get("suppressed")]
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story = []

    story.append(Paragraph("Code Security Analysis Report", styles["title"]))
    cache_note = f" · {files_from_cache} reused from cache" if files_from_cache else ""
    story.append(Paragraph(
        f"Analyzed folder: {escape(root_dir)}<br/>Generated on {generated_at} · "
        f"{files_scanned} files analyzed{cache_note}",
        styles["subtitle"],
    ))

    # --- "How to read this report" box -----------------------------------
    intro_text = (
        "<b>The score</b> ranges from 0 to 100 and drops according to how many problems there are and how "
        "severe they are: the higher, the better. <b>Severity</b> (Critical/High/Medium/Low) indicates how "
        "much damage a problem can do if exploited. <b>Confidence</b> indicates how sure the scanner is that "
        "it is a real problem: <b>Confirmed</b> means it traced the dangerous data back to its external "
        "origin; <b>Potential</b> means the situation is suspicious but must be checked manually, because it "
        "could be a false alarm."
    )
    intro_table = Table([[Paragraph(intro_text, styles["intro_body"])]], colWidths=[17 * cm])
    intro_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER_GRAY),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(Paragraph("How to read this report", styles["intro_heading"]))
    story.append(intro_table)
    story.append(Spacer(1, 14))

    # --- Score + summary by severity ------------------------------------
    counts = {sev: 0 for sev in SEVERITY_COLORS}
    for f in active:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    score_cell = Table(
        [[Paragraph(str(score), ParagraphStyle("scorenum", parent=styles["score_number"],
                                                textColor=_score_color(score)))],
         [Spacer(1, 4)],
         [Paragraph("SCORE OUT OF 100", styles["score_caption"])]],
        colWidths=[4 * cm],
    )
    score_cell.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 1.2, _score_color(score)),
        ("TOPPADDING", (0, 0), (-1, 0), 12), ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))

    summary_rows = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        summary_rows.append([
            Paragraph(f'<font color="{SEVERITY_COLORS[sev].hexval()}">●</font> {SEVERITY_LABELS[sev]}',
                      styles["body"]),
            Paragraph(f"<b>{counts.get(sev, 0)}</b>", styles["body"]),
        ])
    summary_table = Table(summary_rows, colWidths=[4 * cm, 1.5 * cm])
    summary_table.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, BORDER_GRAY),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))

    top_row = Table([[score_cell, summary_table, ""]], colWidths=[4 * cm, 6 * cm, 7 * cm])
    top_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(top_row)
    story.append(Paragraph(
        f"{len(active)} active problems, {len(suppressed)} already reviewed and ignored (baseline). "
        f"The score only counts active problems.",
        styles["subtitle"],
    ))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", color=BORDER_GRAY, thickness=0.7))

    # --- Details by severity -------------------------------------------------
    if not active:
        story.append(Spacer(1, 14))
        story.append(Paragraph("✅ No active problems were detected by the current rules. Remember: automated "
                                "analysis is an aid, not a substitute for a manual code review or a "
                                "penetration test.", styles["body"]))
    else:
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_findings = [f for f in active if f["severity"] == sev]
            if not sev_findings:
                continue
            heading_style = ParagraphStyle("sevheading", parent=styles["section_heading"],
                                            textColor=SEVERITY_COLORS[sev])
            story.append(Paragraph(f"{SEVERITY_LABELS[sev]} ({len(sev_findings)})", heading_style))
            for f in sev_findings:
                story.append(_finding_flowable(f, styles))

    # --- Code quality -------------------------------------------------------
    if quality_active:
        q_score = _quality_score(findings)
        story.append(PageBreak())
        story.append(Paragraph("Code quality", styles["section_heading"]))
        story.append(Paragraph(
            f"Quality score: <b>{q_score}/100</b> · {len(quality_active)} findings. "
            "These are maintainability and best-practice hints (functions that are too long or complex, "
            "ignored errors, leftover debug statements...), not security vulnerabilities: "
            "they do not affect the security score.", styles["body"]))
        story.append(Spacer(1, 8))

        detailed = [f for f in quality_active if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
        compact = [f for f in quality_active if f["severity"] not in ("CRITICAL", "HIGH", "MEDIUM")]
        for f in detailed:
            story.append(_finding_flowable(f, styles))

        if compact:
            story.append(Paragraph(f"Other minor hints ({len(compact)})", styles["section_heading"]))
            rows = [["Severity", "Location", "Finding"]]
            for f in compact[:300]:
                rows.append([SEVERITY_LABELS.get(f["severity"], f["severity"]),
                             f["file"] + (f":{f['line']}" if f["line"] else ""),
                             f["name"]])
            q_table = Table(rows, colWidths=[2.3 * cm, 7 * cm, 7.7 * cm], repeatRows=1)
            q_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), BG_LIGHT),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, BORDER_GRAY),
                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(q_table)
            if len(compact) > 300:
                story.append(Paragraph(f"... and {len(compact) - 300} more hints (see the application).",
                                       styles["subtitle"]))

    # --- Suppressed section (compact summary) ---------------------------------
    if suppressed:
        story.append(PageBreak())
        story.append(Paragraph(f"Already reviewed and ignored problems ({len(suppressed)})", styles["section_heading"]))
        story.append(Paragraph(
            "These problems were marked as already evaluated (baseline) and do not count toward the score. "
            "Condensed list, without the full details:", styles["subtitle"]))
        rows = [["Severity", "File", "Problem"]]
        for f in suppressed:
            rows.append([SEVERITY_LABELS.get(f["severity"], f["severity"]),
                         f["file"] + (f":{f['line']}" if f["line"] else ""), f["name"]])
        sup_table = Table(rows, colWidths=[2.3 * cm, 6 * cm, 8.7 * cm], repeatRows=1)
        sup_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BG_LIGHT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, BORDER_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(sup_table)

    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", color=BORDER_GRAY, thickness=0.7))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Generated by Nyxtral — AST engine (Python) + pattern matching (other languages) + "
        "quality checks (JS/TS, Java, C#, Go, PHP, Rust, Kotlin, Swift, SQL).<br/>"
        "It does not replace a manual code review, a full "
        "SAST/DAST analysis or a professional penetration test.",
        styles["footer"],
    ))

    try:
        doc.build(story)
    except Exception as exc:
        log.error(
            "PDF generation failed while building the report for '%s' (%s: %s). "
            "Possible causes: unsupported characters in a snippet, a corrupted finding record, or "
            "insufficient memory for a very large report. Try suppressing or excluding the offending "
            "file and generate the report again.", root_dir, type(exc).__name__, exc)
        raise
    return buffer.getvalue()
