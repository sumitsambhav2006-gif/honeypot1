import io
import csv
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from config.database import SessionLocal
from backend.models import AttackEvent, Attacker, Command, Alert
from backend.services.attack_service import AttackService

class ReportService:
    """Enterprise Incident & Threat Intelligence Reporting Engine."""

    @staticmethod
    def generate_csv_report(data_type: str = "attacks") -> str:
        """Generates standard CSV content for export."""
        output = io.StringIO()
        writer = csv.writer(output)
        db = SessionLocal()

        try:
            if data_type == "attackers":
                writer.writerow(["ID", "Source IP", "Country", "City", "ASN", "ISP", "Reputation", "Total Attacks", "First Seen", "Last Seen"])
                attackers = db.query(Attacker).order_by(Attacker.total_attacks.desc()).all()
                for a in attackers:
                    writer.writerow([a.id, a.source_ip, a.country, a.city, a.asn, a.isp, a.reputation, a.total_attacks, a.first_seen, a.last_seen])

            elif data_type == "commands":
                writer.writerow(["ID", "Session ID", "Command", "Category", "Risk Points", "Timestamp"])
                commands = db.query(Command).order_by(Command.timestamp.desc()).all()
                for c in commands:
                    writer.writerow([c.id, c.session_id, c.command, c.category, c.risk_points, c.timestamp])

            elif data_type == "alerts":
                writer.writerow(["ID", "Severity", "Risk Score", "Title", "Status", "Attacker IP", "Timestamp"])
                alerts = db.query(Alert).order_by(Alert.timestamp.desc()).all()
                for al in alerts:
                    writer.writerow([al.id, al.severity, al.risk_score, al.title, al.status, al.attacker.source_ip if al.attacker else "N/A", al.timestamp])

            else:  # attacks
                writer.writerow(["ID", "Source IP", "Event Type", "Username", "Password Masked", "Timestamp", "Session ID"])
                events = db.query(AttackEvent).order_by(AttackEvent.timestamp.desc()).limit(1000).all()
                for e in events:
                    writer.writerow([e.id, e.attacker.source_ip if e.attacker else "N/A", e.event_type, e.username, e.password_masked, e.timestamp, e.session_id])

            return output.getvalue()
        finally:
            db.close()

    @staticmethod
    def generate_pdf_report() -> io.BytesIO:
        """Generates a professional SOC Threat Intelligence Briefing PDF."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        elements = []

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0a192f"),
            fontName="Helvetica-Bold",
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            textColor=colors.HexColor("#4a5568"),
            fontName="Helvetica",
            spaceAfter=14
        )
        heading2_style = ParagraphStyle(
            "Heading2Custom",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1a202c"),
            fontName="Helvetica-Bold",
            spaceBefore=12,
            spaceAfter=8
        )

        # Header Title
        elements.append(Paragraph("IHTIP - Executive Threat Intelligence Briefing", title_style))
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        elements.append(Paragraph(f"Generated: {now_str} | Classification: TLP:AMBER | Operations: SOC / Blue Team", subtitle_style))
        elements.append(Spacer(1, 10))

        # KPI Summary Table
        kpis = AttackService.get_dashboard_kpis()
        kpi_data = [
            ["Metric", "Value", "Metric", "Value"],
            ["Total Attacks Ingested", str(kpis["total_attacks"]), "Unique Source IPs", str(kpis["unique_ips"])],
            ["SSH Login Attempts", str(kpis["login_attempts"]), "Critical/High Alerts", str(kpis["critical_alerts"])],
            ["Active Sessions", str(kpis["active_sessions"]), "Deployment Status", "ONLINE (Active)"]
        ]
        kpi_table = Table(kpi_data, colWidths=[150, 100, 150, 100])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(Paragraph("Key SOC Threat Metrics", heading2_style))
        elements.append(kpi_table)
        elements.append(Spacer(1, 15))

        # Top Threat Actors Table
        db = SessionLocal()
        try:
            top_attackers = db.query(Attacker).order_by(Attacker.total_attacks.desc()).limit(8).all()
            atk_data = [["Source IP", "Country", "ASN / Provider", "Reputation", "Attacks"]]
            for a in top_attackers:
                atk_data.append([
                    a.source_ip,
                    a.country[:16],
                    (a.asn or a.isp or "Unknown")[:24],
                    f"{a.reputation}/100",
                    str(a.total_attacks)
                ])

            atk_table = Table(atk_data, colWidths=[90, 80, 170, 70, 60])
            atk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ]))
            elements.append(Paragraph("Top Malicious Threat Actors", heading2_style))
            elements.append(atk_table)
            elements.append(Spacer(1, 15))

            # Recent Critical Alerts
            recent_alerts = db.query(Alert).filter(Alert.severity.in_(["Critical", "High"])).order_by(Alert.timestamp.desc()).limit(6).all()
            alert_data = [["Severity", "Score", "Title", "Target", "Timestamp"]]
            for al in recent_alerts:
                alert_data.append([
                    al.severity,
                    f"{al.risk_score}",
                    al.title[:35],
                    al.attacker.source_ip if al.attacker else "Unknown",
                    al.timestamp.strftime("%Y-%m-%d %H:%M") if al.timestamp else ""
                ])

            alert_table = Table(alert_data, colWidths=[60, 45, 195, 90, 80])
            alert_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#b91c1c")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#fecaca")),
            ]))
            elements.append(Paragraph("Recent Critical & High Severity Alerts", heading2_style))
            elements.append(alert_table)

        finally:
            db.close()

        doc.build(elements)
        buffer.seek(0)
        return buffer

