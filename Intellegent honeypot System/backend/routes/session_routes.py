from flask import Blueprint, request, jsonify, render_template
from config.database import SessionLocal
from backend.models import Session, Command

session_bp = Blueprint("session_bp", __name__)

@session_bp.route("/sessions")
def sessions_page():
    return render_template("sessions.html")

@session_bp.route("/commands")
def commands_page():
    return render_template("command_analysis.html")

@session_bp.route("/api/sessions", methods=["GET"])
def api_get_sessions():
    status = request.args.get("status")
    limit = min(int(request.args.get("limit", 50)), 200)

    db = SessionLocal()
    try:
        query = db.query(Session)
        if status:
            query = query.filter(Session.status == status)

        sessions = query.order_by(Session.start_time.desc()).limit(limit).all()
        return jsonify({
            "total": len(sessions),
            "sessions": [s.to_dict() for s in sessions]
        }), 200
    finally:
        db.close()

@session_bp.route("/api/sessions/<string:session_uuid>", methods=["GET"])
def api_get_session_by_uuid(session_uuid: str):
    db = SessionLocal()
    try:
        session = db.query(Session).filter(Session.session_id == session_uuid).first()
        if not session:
            # Try integer id
            if session_uuid.isdigit():
                session = db.query(Session).filter(Session.id == int(session_uuid)).first()

        if not session:
            return jsonify({"error": "Not Found", "message": "Session not found"}), 404

        return jsonify(session.to_dict(include_commands=True)), 200
    finally:
        db.close()

@session_bp.route("/api/sessions/<string:session_uuid>/commands", methods=["GET"])
def api_get_session_commands(session_uuid: str):
    db = SessionLocal()
    try:
        session = db.query(Session).filter(Session.session_id == session_uuid).first()
        if not session and session_uuid.isdigit():
            session = db.query(Session).filter(Session.id == int(session_uuid)).first()

        if not session:
            return jsonify({"error": "Not Found", "message": "Session not found"}), 404

        commands = db.query(Command).filter(Command.session_id == session.id).order_by(Command.timestamp.asc()).all()
        return jsonify({
            "session_id": session.session_id,
            "commands": [c.to_dict() for c in commands]
        }), 200
    finally:
        db.close()

@session_bp.route("/api/commands", methods=["GET"])
def api_get_all_commands():
    category = request.args.get("category")
    limit = min(int(request.args.get("limit", 100)), 500)

    db = SessionLocal()
    try:
        query = db.query(Command)
        if category:
            query = query.filter(Command.category == category)

        commands = query.order_by(Command.timestamp.desc()).limit(limit).all()
        return jsonify({
            "total": len(commands),
            "commands": [c.to_dict() for c in commands]
        }), 200
    finally:
        db.close()

