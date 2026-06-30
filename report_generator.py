"""
report_generator.py — PDF Security Report Generator

Generates a professional, branded PDF report from enriched scan data.
Uses ReportLab for PDF composition and Matplotlib for charts.
"""

import os
import io
import json
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch, mm
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches


# =============================================================================
# BRAND COLORS
# =============================================================================

VULNERA_NAVY = "#3D5A80"
COLOR_BLACK = "#000000"
COLOR_WHITE = "#FFFFFF"
COLOR_LIGHT_BG = "#F5F5F5"

# Severity colors
SEVERITY_COLORS = {
    "CRITICAL": "#DC3545",
    "HIGH": "#FD7E14",
    "MEDIUM": "#FFC107",
    "LOW": "#28A745",
    "INFORMATIONAL": "#6C757D",
}


# =============================================================================
# FONT REGISTRATION
# =============================================================================

def _register_fonts():
    """Register Times New Roman. Falls back to built-in Times if TTF not found."""
    font_paths = [
        ("TimesNewRoman", "C:/Windows/Fonts/times.ttf"),
        ("TimesNewRoman-Bold", "C:/Windows/Fonts/timesbd.ttf"),
        ("TimesNewRoman-Italic", "C:/Windows/Fonts/timesi.ttf"),
        ("TimesNewRoman-BoldItalic", "C:/Windows/Fonts/timesbi.ttf"),
    ]
    registered = False
    for name, path in font_paths:
        try:
            if os.path.exists(path):
                pdfmetrics.registerFont(TTFont(name, path))
                registered = True
        except Exception:
            pass

    if registered:
        return "TimesNewRoman", "TimesNewRoman-Bold", "TimesNewRoman-Italic"
    else:
        # Fallback to ReportLab built-in Times
        return "Times-Roman", "Times-Bold", "Times-Italic"


FONT_REGULAR, FONT_BOLD, FONT_ITALIC = _register_fonts()


# =============================================================================
# CHART GENERATORS
# =============================================================================

def _generate_pie_chart(severity_counts: dict, overall_score: int) -> io.BytesIO:
    """
    Generate a donut-style pie chart of severity distribution
    with the overall score displayed in the center.
    """
    labels = []
    sizes = []
    colors = []

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    for sev in severity_order:
        count = severity_counts.get(sev, 0)
        if count > 0:
            labels.append(sev)
            sizes.append(count)
            colors.append(SEVERITY_COLORS.get(sev, "#6C757D"))

    if not sizes:
        sizes = [1]
        labels = ["NO FINDINGS"]
        colors = ["#28A745"]

    fig, ax = plt.subplots(figsize=(4, 4), dpi=150)
    fig.patch.set_alpha(0)

    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=None,
        colors=colors,
        autopct=lambda pct: f"{int(round(pct / 100. * sum(sizes)))}",
        startangle=90,
        pctdistance=0.8,
        wedgeprops=dict(width=0.35, edgecolor="white", linewidth=2),
    )

    for autotext in autotexts:
        autotext.set_fontsize(9)
        autotext.set_color("white")
        autotext.set_fontweight("bold")

    # Center score
    ax.text(0, 0.05, str(overall_score), ha="center", va="center",
            fontsize=36, fontweight="bold", color=VULNERA_NAVY)
    ax.text(0, -0.18, "/ 100", ha="center", va="center",
            fontsize=12, color="#666666")

    # Legend
    legend_patches = [
        mpatches.Patch(color=SEVERITY_COLORS.get(l, "#6C757D"), label=l)
        for l in labels
    ]
    ax.legend(handles=legend_patches, loc="lower center",
              bbox_to_anchor=(0.5, -0.15), ncol=min(len(labels), 3),
              fontsize=8, frameon=False)

    ax.set_aspect("equal")
    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", transparent=True)
    plt.close(fig)
    buf.seek(0)
    return buf


def _generate_bar_chart(type_counts: dict) -> io.BytesIO:
    """
    Generate a horizontal bar chart of the top vulnerability categories.
    """
    # Sort and take top 10
    sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    if not sorted_types:
        sorted_types = [("No findings", 0)]

    labels = [t[0].replace("_", " ").title() for t in sorted_types]
    values = [t[1] for t in sorted_types]

    # Reverse for horizontal bar (top item at top)
    labels.reverse()
    values.reverse()

    fig, ax = plt.subplots(figsize=(7, max(2.5, len(labels) * 0.4)), dpi=150)
    fig.patch.set_alpha(0)

    bars = ax.barh(labels, values, color=VULNERA_NAVY, height=0.6, edgecolor="white")

    # Add count labels
    for bar, val in zip(bars, values):
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=9, color=COLOR_BLACK)

    ax.set_xlabel("Count", fontsize=10, color="#333333")
    ax.set_title("Top Vulnerability Categories", fontsize=12,
                 fontweight="bold", color=VULNERA_NAVY, pad=10)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_color("#CCCCCC")
    ax.spines["left"].set_color("#CCCCCC")
    ax.tick_params(axis="both", colors="#333333", labelsize=9)

    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", transparent=True)
    plt.close(fig)
    buf.seek(0)
    return buf


# =============================================================================
# REPORT GENERATOR
# =============================================================================

class ReportGenerator:
    """Generates branded PDF security reports from enriched scan data."""

    def __init__(self, logo_path: str = None):
        if logo_path is None:
            base_dir = os.path.dirname(__file__)
            self.logo_path = os.path.join(base_dir, "vulneralogo.png")
        else:
            self.logo_path = logo_path

    def _build_styles(self):
        """Create custom paragraph styles using Times New Roman."""
        styles = {}

        styles["title"] = ParagraphStyle(
            "Title",
            fontName=FONT_BOLD,
            fontSize=22,
            textColor=HexColor(VULNERA_NAVY),
            spaceAfter=4,
            leading=26,
        )
        styles["subtitle"] = ParagraphStyle(
            "Subtitle",
            fontName=FONT_REGULAR,
            fontSize=11,
            textColor=HexColor("#555555"),
            spaceAfter=12,
            leading=14,
        )
        styles["heading"] = ParagraphStyle(
            "Heading",
            fontName=FONT_BOLD,
            fontSize=14,
            textColor=HexColor(VULNERA_NAVY),
            spaceBefore=16,
            spaceAfter=8,
            leading=18,
        )
        styles["subheading"] = ParagraphStyle(
            "SubHeading",
            fontName=FONT_BOLD,
            fontSize=11,
            textColor=HexColor(COLOR_BLACK),
            spaceBefore=6,
            spaceAfter=4,
            leading=14,
        )
        styles["body"] = ParagraphStyle(
            "Body",
            fontName=FONT_REGULAR,
            fontSize=10,
            textColor=HexColor(COLOR_BLACK),
            spaceAfter=6,
            leading=14,
        )
        styles["body_small"] = ParagraphStyle(
            "BodySmall",
            fontName=FONT_REGULAR,
            fontSize=8,
            textColor=HexColor("#444444"),
            spaceAfter=4,
            leading=11,
        )
        styles["footer"] = ParagraphStyle(
            "Footer",
            fontName=FONT_ITALIC,
            fontSize=8,
            textColor=HexColor("#888888"),
            alignment=TA_CENTER,
        )
        styles["score_label"] = ParagraphStyle(
            "ScoreLabel",
            fontName=FONT_BOLD,
            fontSize=11,
            textColor=HexColor(COLOR_BLACK),
            spaceAfter=2,
            leading=14,
        )
        return styles

    def _calculate_overall_score(self, severity_counts: dict) -> int:
        """
        Calculate an overall security score from 0-100.
        A perfect site with zero vulnerabilities scores 100.
        """
        penalty = (
            severity_counts.get("CRITICAL", 0) * 15 +
            severity_counts.get("HIGH", 0) * 8 +
            severity_counts.get("MEDIUM", 0) * 3 +
            severity_counts.get("LOW", 0) * 1
        )
        return max(0, min(100, 100 - penalty))

    def _get_severity_counts(self, alerts: list) -> dict:
        """Count alerts by severity level."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for alert in alerts:
            level = alert.get("risk_level", "LOW").upper()
            if level in counts:
                counts[level] += 1
            else:
                counts["INFORMATIONAL"] += 1
        return counts

    def _get_type_counts(self, alerts: list) -> dict:
        """Count alerts by vulnerability type."""
        counts = {}
        for alert in alerts:
            vtype = alert.get("type", "unknown")
            counts[vtype] = counts.get(vtype, 0) + 1
        return counts

    def _build_executive_summary(self, scan_data: dict, alerts: list, styles: dict) -> list:
        """Build the first page: logo, title, pie chart, severity table, bar chart."""
        elements = []

        # --- Logo ---
        if os.path.exists(self.logo_path):
            logo = Image(self.logo_path, width=1.8 * inch, height=0.7 * inch)
            logo.hAlign = "LEFT"
            elements.append(logo)
            elements.append(Spacer(1, 8))

        # --- Title ---
        elements.append(Paragraph("Security Assessment Report", styles["title"]))

        # --- Metadata line ---
        target = scan_data.get("target", "Unknown")
        scan_date = datetime.utcnow().strftime("%d %B %Y, %H:%M UTC")
        app_type = scan_data.get("app_type", "General")
        scan_duration = scan_data.get("results", {}).get("timing", {}).get("total_duration_seconds", 0)
        duration_str = f"{int(scan_duration // 60)}m {int(scan_duration % 60)}s" if scan_duration else "N/A"

        meta_text = (
            f"Target: <b>{target}</b>  |  "
            f"Date: <b>{scan_date}</b>  |  "
            f"App Type: <b>{app_type or 'General'}</b>  |  "
            f"Duration: <b>{duration_str}</b>"
        )
        elements.append(Paragraph(meta_text, styles["subtitle"]))

        # --- Divider ---
        elements.append(HRFlowable(
            width="100%", thickness=1.5,
            color=HexColor(VULNERA_NAVY), spaceBefore=4, spaceAfter=16
        ))

        # --- Severity counts and Pie Chart side by side ---
        severity_counts = self._get_severity_counts(alerts)
        overall_score = self._calculate_overall_score(severity_counts)
        total_alerts = sum(severity_counts.values())

        # Generate pie chart
        pie_buf = _generate_pie_chart(severity_counts, overall_score)
        pie_img = Image(pie_buf, width=2.8 * inch, height=2.8 * inch)

        # Build severity count table
        severity_table_data = [
            [Paragraph("<b>Severity</b>", styles["score_label"]),
             Paragraph("<b>Count</b>", styles["score_label"])],
        ]

        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            count = severity_counts.get(level, 0)
            color = SEVERITY_COLORS.get(level, "#6C757D")
            level_para = Paragraph(
                f'<font color="{color}"><b>{level}</b></font>',
                styles["body"]
            )
            count_para = Paragraph(f"<b>{count}</b>", styles["body"])
            severity_table_data.append([level_para, count_para])

        # Total row
        severity_table_data.append([
            Paragraph("<b>TOTAL</b>", styles["score_label"]),
            Paragraph(f"<b>{total_alerts}</b>", styles["score_label"]),
        ])

        sev_table = Table(severity_table_data, colWidths=[1.8 * inch, 0.8 * inch])
        sev_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, 0), 1, HexColor(VULNERA_NAVY)),
            ("LINEBELOW", (0, -1), (-1, -1), 1, HexColor(VULNERA_NAVY)),
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#E8EEF4")),
        ]))

        # Combine pie chart and severity table in a side-by-side layout
        layout_table = Table(
            [[pie_img, sev_table]],
            colWidths=[3.2 * inch, 3.0 * inch],
        )
        layout_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (0, 0), (0, 0), "CENTER"),
            ("ALIGN", (1, 0), (1, 0), "LEFT"),
        ]))
        elements.append(layout_table)
        elements.append(Spacer(1, 20))

        # --- Bar Chart ---
        type_counts = self._get_type_counts(alerts)
        bar_buf = _generate_bar_chart(type_counts)
        bar_img = Image(bar_buf, width=6.5 * inch, height=max(2.0 * inch, len(type_counts) * 0.28 * inch))
        bar_img.hAlign = "CENTER"
        elements.append(bar_img)

        return elements

    def _build_findings_pages(self, alerts: list, styles: dict) -> list:
        """Build detailed finding cards for each alert, sorted by risk score."""
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Findings", styles["title"]))
        elements.append(HRFlowable(
            width="100%", thickness=1.5,
            color=HexColor(VULNERA_NAVY), spaceBefore=4, spaceAfter=12
        ))

        # Sort by risk_score descending
        sorted_alerts = sorted(alerts, key=lambda a: a.get("risk_score", 0), reverse=True)

        for i, alert in enumerate(sorted_alerts):
            risk_level = alert.get("risk_level", "LOW").upper()
            risk_score = alert.get("risk_score", 0)
            color = SEVERITY_COLORS.get(risk_level, "#6C757D")

            # --- Finding Header ---
            source = alert.get("source", "unknown").upper()
            alert_type = alert.get("type", "unknown").replace("_", " ").title()

            header_text = (
                f'<font color="{color}"><b>[{risk_level}]</b></font>  '
                f'<font color="{VULNERA_NAVY}"><b>{alert_type}</b></font>  '
                f'<font color="#666666">(Score: {risk_score:.2f} | Source: {source})</font>'
            )
            elements.append(Paragraph(header_text, styles["heading"]))

            # --- URL ---
            url = alert.get("url", "N/A")
            elements.append(Paragraph(f"<b>URL:</b> {url}", styles["body"]))

            # --- CWE Info ---
            cwe_id = alert.get("cwe_id")
            if cwe_id:
                elements.append(Paragraph(f"<b>CWE:</b> {cwe_id}", styles["body"]))

            # --- Plain English sections ---
            plain = alert.get("plain_english", {})
            if plain:
                title = plain.get("title", "")
                if title and title != "Security Vulnerability Detected":
                    elements.append(Paragraph(f"<b>Vulnerability:</b> {title}", styles["body"]))

                description = plain.get("plain_english", "")
                if description:
                    elements.append(Paragraph("<b>What happened:</b>", styles["subheading"]))
                    elements.append(Paragraph(description, styles["body"]))

                impact = plain.get("impact", "")
                if impact:
                    elements.append(Paragraph("<b>Impact:</b>", styles["subheading"]))
                    elements.append(Paragraph(impact, styles["body"]))

                fix = plain.get("fix", "")
                if fix:
                    elements.append(Paragraph("<b>How to fix:</b>", styles["subheading"]))
                    elements.append(Paragraph(fix, styles["body"]))

            # --- Fallback description from raw alert ---
            elif alert.get("description"):
                elements.append(Paragraph("<b>Description:</b>", styles["subheading"]))
                elements.append(Paragraph(alert["description"], styles["body"]))

                if alert.get("solution"):
                    elements.append(Paragraph("<b>Solution:</b>", styles["subheading"]))
                    elements.append(Paragraph(alert["solution"], styles["body"]))

            # --- Score Components ---
            components = alert.get("components", {})
            if components:
                comp_text = (
                    f"CVSS: {components.get('cvss_raw', 'N/A')} | "
                    f"EPSS: {components.get('epss', 'N/A')} | "
                    f"Endpoint: {components.get('endpoint_criticality', 'N/A')} | "
                    f"Confidence: {components.get('tool_confidence', 'N/A')} | "
                    f"Amplification: {components.get('amplification', 1.0)}x"
                )
                elements.append(Paragraph(comp_text, styles["body_small"]))

            # --- Divider between findings ---
            elements.append(Spacer(1, 6))
            elements.append(HRFlowable(
                width="100%", thickness=0.5,
                color=HexColor("#CCCCCC"), spaceBefore=2, spaceAfter=10
            ))

        return elements

    def generate_report(self, scan_data: dict, output_path: str = None) -> str:
        """
        Generate a complete PDF report from enriched scan data.

        Args:
            scan_data: The full scan status dict (with results.alerts)
            output_path: Where to save the PDF. Auto-generated if None.

        Returns:
            Path to the generated PDF file.
        """
        if output_path is None:
            scan_id = scan_data.get("scan_id", "report")
            os.makedirs("reports", exist_ok=True)
            output_path = os.path.join("reports", f"{scan_id}_report.pdf")

        alerts = scan_data.get("results", {}).get("alerts", [])
        styles = self._build_styles()

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            topMargin=0.6 * inch,
            bottomMargin=0.6 * inch,
            leftMargin=0.7 * inch,
            rightMargin=0.7 * inch,
            title="Vulnera Security Assessment Report",
            author="Vulnera",
        )

        # Build all elements
        story = []
        story.extend(self._build_executive_summary(scan_data, alerts, styles))
        if alerts:
            story.extend(self._build_findings_pages(alerts, styles))

        # Add footer
        story.append(Spacer(1, 20))
        footer_style = styles["footer"]
        story.append(Paragraph(
            "Generated by Vulnera  |  Confidential  |  "
            f"{datetime.utcnow().strftime('%d %B %Y')}",
            footer_style
        ))

        doc.build(story)
        print(f"[+] PDF report generated: {output_path}")
        return output_path
