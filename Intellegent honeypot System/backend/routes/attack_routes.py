from flask import Blueprint, request, jsonify, render_template
from config.database import SessionLocal
from backend.models import AttackEvent, Attacker

attack_bp = Blueprint("attack_bp", __name__)

@attack_bp.route("/attacks")
def attacks_page():
    return render_template("attack_details.html")

@attack_bp.route("/api/attacks", methods=["GET"])
def api_get_attacks():
    event_type = request.args.get("event_type")
    source_ip = request.args.get("source_ip")
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))

    db = SessionLocal()
    try:
        query = db.query(AttackEvent).join(Attacker)

        if event_type:
            query = query.filter(AttackEvent.event_type == event_type)
        if source_ip:
            query = query.filter(Attacker.source_ip == source_ip)

        total = query.count()
        events = query.order_by(AttackEvent.timestamp.desc()).offset(offset).limit(limit).all()

        return jsonify({
            "total": total,
            "limit": limit,
            "offset": offset,
            "attacks": [e.to_dict() for e in events]
        }), 200
    finally:
        db.close()

@attack_bp.route("/api/attacks/<int:event_id>", methods=["GET"])
def api_get_attack_detail(event_id: int):
    db = SessionLocal()
    try:
        event = db.query(AttackEvent).filter(AttackEvent.id == event_id).first()
        if not event:
            return jsonify({"error": "Not Found", "message": f"Event {event_id} not found"}), 404

        return jsonify(event.to_dict()), 200
    finally:
        db.close()

