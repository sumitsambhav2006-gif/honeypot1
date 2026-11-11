from flask import Blueprint, request, jsonify, render_template
from config.database import SessionLocal
from backend.models import Attacker, Session, AttackEvent

attacker_bp = Blueprint("attacker_bp", __name__)

@attacker_bp.route("/attackers")
def attackers_page():
    return render_template("attackers.html")

@attacker_bp.route("/api/attackers", methods=["GET"])
def api_get_attackers():
    limit = min(int(request.args.get("limit", 50)), 500)
    country = request.args.get("country")
    min_rep = request.args.get("min_reputation", type=int)

    db = SessionLocal()
    try:
        query = db.query(Attacker)
        if country:
            query = query.filter(Attacker.country == country)
        if min_rep is not None:
            query = query.filter(Attacker.reputation >= min_rep)

        total = query.count()
        attackers = query.order_by(Attacker.total_attacks.desc()).limit(limit).all()

        return jsonify({
            "total": total,
            "attackers": [a.to_dict() for a in attackers]
        }), 200
    finally:
        db.close()

@attacker_bp.route("/api/attackers/<int:attacker_id>", methods=["GET"])
def api_get_attacker_detail(attacker_id: int):
    db = SessionLocal()
    try:
        attacker = db.query(Attacker).filter(Attacker.id == attacker_id).first()
        if not attacker:
            return jsonify({"error": "Not Found", "message": "Attacker not found"}), 404

        sessions = db.query(Session).filter(Session.attacker_id == attacker_id).order_by(Session.start_time.desc()).limit(10).all()
        recent_events = db.query(AttackEvent).filter(AttackEvent.attacker_id == attacker_id).order_by(AttackEvent.timestamp.desc()).limit(20).all()

        data = attacker.to_dict()
        data["sessions"] = [s.to_dict() for s in sessions]
        data["recent_events"] = [e.to_dict() for e in recent_events]

        return jsonify(data), 200
    finally:
        db.close()

