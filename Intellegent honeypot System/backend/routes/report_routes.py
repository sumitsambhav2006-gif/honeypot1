import datetime
from flask import Blueprint, request, Response, render_template, send_file
from backend.services.report_service import ReportService

report_bp = Blueprint("report_bp", __name__)

@report_bp.route("/reports")
def reports_page():
    return render_template("reports.html")

@report_bp.route("/api/reports/export", methods=["GET"])
def api_export_report():
    export_format = request.args.get("format", "csv").lower()
    data_type = request.args.get("type", "attacks").lower()

    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if export_format == "pdf":
        pdf_buffer = ReportService.generate_pdf_report()
        filename = f"IHTIP_Threat_Briefing_{timestamp_str}.pdf"
        return send_file(
            pdf_buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename
        )

    # Default CSV
    csv_data = ReportService.generate_csv_report(data_type=data_type)
    filename = f"IHTIP_Export_{data_type}_{timestamp_str}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

