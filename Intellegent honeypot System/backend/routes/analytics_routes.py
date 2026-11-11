from flask import Blueprint, request, jsonify, render_template
from sqlalchemy import func, desc
from config.database import SessionLocal
from backend.models import Command, AttackEvent, Session
from backend.services.alert_service import AlertService

analytics_bp = Blueprint("analytics_bp", __name__)

@analytics_bp.route("/threat-intel")
def threat_intel_page():
    return render_template("threat_intelligence.html")

@analytics_bp.route("/alerts")
def alerts_page():
    return render_template("alerts.html")

@analytics_bp.route("/api/analytics/overview", methods=["GET"])
def api_get_analytics_overview():
    db = SessionLocal()
    try:
        # 1. Command Categories Distribution
        cat_counts = db.query(
            Command.category,
            func.count(Command.id).label("cnt")
        ).group_by(Command.category).order_by(desc("cnt")).all()

        command_breakdown = [{"category": cat, "count": cnt} for cat, cnt in cat_counts]

        # 2. Risk Distribution (Low, Medium, High, Critical)
        sessions = db.query(Session.risk_score).all()
        risk_dist = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for (score,) in sessions:
            if score >= 80:
                risk_dist["Critical"] += 1
            elif score >= 60:
                risk_dist["High"] += 1
            elif score >= 30:
                risk_dist["Medium"] += 1
            else:
                risk_dist["Low"] += 1

        # 3. Attack Event Types
        event_types = db.query(
            AttackEvent.event_type,
            func.count(AttackEvent.id).label("cnt")
        ).group_by(AttackEvent.event_type).order_by(desc("cnt")).all()
        event_type_breakdown = [{"type": et, "count": cnt} for et, cnt in event_types]

        return jsonify({
            "command_categories": command_breakdown,
            "risk_distribution": risk_dist,
            "event_types": event_type_breakdown
        }), 200
    finally:
        db.close()

@analytics_bp.route("/api/alerts", methods=["GET"])
def api_get_alerts():
    severity = request.args.get("severity")
    status = request.args.get("status")
    alerts = AlertService.get_alerts(severity=severity, status=status)
    return jsonify({"total": len(alerts), "alerts": alerts}), 200

@analytics_bp.route("/api/alerts/<int:alert_id>", methods=["PATCH"])
def api_update_alert_status(alert_id: int):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status")
    if not new_status or new_status not in ["open", "investigating", "resolved", "dismissed"]:
        return jsonify({"error": "Bad Request", "message": "Invalid status value"}), 400

    updated = AlertService.update_status(alert_id, new_status)
    if not updated:
        return jsonify({"error": "Not Found", "message": "Alert not found"}), 404

    return jsonify({"message": "Alert status updated", "alert": updated}), 200

