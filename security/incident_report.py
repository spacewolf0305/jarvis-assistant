"""
J.A.R.V.I.S — Incident Report Generator
Turns the security event log into a professional PDF incident report:
executive summary, severity breakdown, a detailed event timeline with
MITRE ATT&CK mapping, and recommended mitigations.

Used by the voice command "generate a security report".
"""

from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from security.event_store import get_store, Severity, mitre_label


# Severity → colour for the report
SEV_COLORS = {
    "Critical": colors.HexColor("#c0392b") if REPORTLAB_AVAILABLE else None,
    "High": colors.HexColor("#e67e22") if REPORTLAB_AVAILABLE else None,
    "Medium": colors.HexColor("#f1c40f") if REPORTLAB_AVAILABLE else None,
    "Low": colors.HexColor("#3498db") if REPORTLAB_AVAILABLE else None,
    "Info": colors.HexColor("#7f8c8d") if REPORTLAB_AVAILABLE else None,
}


class IncidentReport:
    """Generates PDF incident reports from the event store."""

    def __init__(self, output_dir=None):
        self.store = get_store()
        self.output_dir = Path(output_dir) if output_dir else \
            (Path(__file__).parent.parent / "reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, hours=24, filename=None):
        """Build a PDF covering the last `hours`. Returns the file path."""
        if not REPORTLAB_AVAILABLE:
            return None, "Sir, I require the 'reportlab' library to produce PDF reports."

        events = self.store.get_events(limit=500)
        summary = self.store.get_summary(hours=hours)

        if filename is None:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"JARVIS_Incident_Report_{stamp}.pdf"
        path = self.output_dir / filename

        doc = SimpleDocTemplate(
            str(path), pagesize=letter,
            topMargin=0.7 * inch, bottomMargin=0.7 * inch,
            leftMargin=0.8 * inch, rightMargin=0.8 * inch,
        )
        styles = self._styles()
        story = []

        # ── Header ──
        story.append(Paragraph("J.A.R.V.I.S.", styles["BrandTitle"]))
        story.append(Paragraph("Security Incident Report", styles["Subtitle"]))
        story.append(Paragraph(
            f"Generated {datetime.now().strftime('%A, %B %d, %Y at %H:%M:%S')}"
            f" &nbsp;|&nbsp; Reporting window: last {hours} hours",
            styles["Meta"]))
        story.append(Spacer(1, 0.25 * inch))

        # ── Executive summary ──
        story.append(Paragraph("Executive Summary", styles["H1"]))
        total = summary.get("Total", 0)
        crit = summary.get("Critical", 0)
        high = summary.get("High", 0)
        if total == 0:
            verdict = ("No security events were recorded in the reporting "
                       "window. All monitored systems appear nominal.")
        elif crit or high:
            verdict = (f"{total} security events were recorded, including "
                       f"{crit} critical and {high} high-severity detections "
                       f"that require immediate attention.")
        else:
            verdict = (f"{total} security events were recorded. None reached "
                       f"high severity; routine review is advised.")
        story.append(Paragraph(verdict, styles["Body"]))
        story.append(Spacer(1, 0.15 * inch))

        # ── Severity breakdown table ──
        story.append(Paragraph("Severity Breakdown", styles["H2"]))
        sev_rows = [["Severity", "Count"]]
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            sev_rows.append([sev, str(summary.get(sev, 0))])
        sev_table = Table(sev_rows, colWidths=[2.5 * inch, 1.5 * inch])
        sev_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f4f4f8")]),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]
        for i, sev in enumerate(["Critical", "High", "Medium", "Low", "Info"], start=1):
            sev_style.append(("TEXTCOLOR", (0, i), (0, i), SEV_COLORS[sev]))
            sev_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
        sev_table.setStyle(TableStyle(sev_style))
        story.append(sev_table)
        story.append(Spacer(1, 0.25 * inch))

        # ── Detailed event timeline ──
        story.append(Paragraph("Event Timeline & Details", styles["H1"]))
        if not events:
            story.append(Paragraph("No events to detail.", styles["Body"]))
        else:
            for e in events:
                sev_label = Severity(e["severity"]).label
                color = SEV_COLORS.get(sev_label, colors.black)
                hexcol = "#" + color.hexval()[2:] if color else "#000000"
                heading = (f'<font color="{hexcol}">'
                           f'[{sev_label}]</font> {e["threat_type"]}')
                story.append(Paragraph(heading, styles["EventH"]))

                mitre = ""
                if e.get("mitre_id"):
                    mitre = f' &nbsp;|&nbsp; MITRE {e["mitre_id"]}: {mitre_label(e["mitre_id"])}'
                story.append(Paragraph(
                    f'<b>{e["timestamp"]}</b> &nbsp;|&nbsp; source: {e["source"]}{mitre}',
                    styles["EventMeta"]))
                story.append(Paragraph(e["message"], styles["Body"]))
                if e.get("details"):
                    story.append(Paragraph(f'<i>Details:</i> {e["details"]}', styles["Small"]))
                if e.get("mitigation"):
                    story.append(Paragraph(
                        f'<b>Recommended mitigation:</b> {e["mitigation"]}',
                        styles["Mitigation"]))
                story.append(Spacer(1, 0.12 * inch))

        # ── Footer note ──
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph(
            "This report was generated automatically by the JARVIS security "
            "subsystem. Mitigations are advisory; verify before acting on "
            "production systems.", styles["Footer"]))

        doc.build(story)
        return str(path), f"Incident report generated, sir. Saved to {path.name}."

    def _styles(self):
        s = getSampleStyleSheet()
        navy = colors.HexColor("#1a1a2e")
        accent = colors.HexColor("#0f9ed5")
        s.add(ParagraphStyle("BrandTitle", parent=s["Title"], fontSize=26,
                             textColor=accent, spaceAfter=2, leading=28))
        s.add(ParagraphStyle("Subtitle", parent=s["Title"], fontSize=15,
                             textColor=navy, spaceAfter=2, leading=18))
        s.add(ParagraphStyle("Meta", parent=s["Normal"], fontSize=8,
                             textColor=colors.grey))
        s.add(ParagraphStyle("H1", parent=s["Heading1"], fontSize=15,
                             textColor=navy, spaceBefore=10, spaceAfter=6))
        s.add(ParagraphStyle("H2", parent=s["Heading2"], fontSize=12,
                             textColor=navy, spaceBefore=6, spaceAfter=4))
        s.add(ParagraphStyle("Body", parent=s["Normal"], fontSize=10,
                             leading=14, spaceAfter=2))
        s.add(ParagraphStyle("Small", parent=s["Normal"], fontSize=8.5,
                             textColor=colors.HexColor("#555555"), leading=11))
        s.add(ParagraphStyle("EventH", parent=s["Heading3"], fontSize=11,
                             spaceBefore=6, spaceAfter=1))
        s.add(ParagraphStyle("EventMeta", parent=s["Normal"], fontSize=8,
                             textColor=colors.grey, spaceAfter=2))
        s.add(ParagraphStyle("Mitigation", parent=s["Normal"], fontSize=9,
                             leading=12, textColor=colors.HexColor("#1e6b2e"),
                             backColor=colors.HexColor("#eafaef"),
                             borderPadding=4, spaceBefore=2))
        s.add(ParagraphStyle("Footer", parent=s["Normal"], fontSize=7.5,
                             textColor=colors.grey, leading=10))
        return s


if __name__ == "__main__":
    # Seed a few events and generate a sample report
    store = get_store()
    store.log_event("crypto_monitor", Severity.HIGH, "Cryptojacking",
                    "Possible miner: xmrig.exe (PID 4821)", mitre_id="T1496",
                    details="97% sustained CPU, connection to mining-pool port",
                    mitigation="Terminate PID 4821; block pool IP at firewall.")
    store.log_event("ransomware_monitor", Severity.CRITICAL, "Ransomware",
                    "42 files modified in 2 seconds", mitre_id="T1486",
                    details="Suspicious extension .locked observed",
                    mitigation="Disconnect from network; do not pay; restore from backup.")
    store.log_event("process_monitor", Severity.HIGH, "Fileless / Suspicious Process",
                    "powershell.exe (PID 101): obfuscated/encoded command",
                    mitre_id="T1059.001",
                    details="Command line: powershell -nop -w hidden -enc SQBFAFgA...",
                    mitigation="Investigate parent process; terminate; full scan.")
    report = IncidentReport(output_dir="/tmp/jarvis_reports")
    path, msg = report.generate(hours=24)
    print(msg)
    print("Path:", path)
