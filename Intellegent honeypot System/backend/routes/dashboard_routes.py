import json
import time
import socket
import threading
from flask import Blueprint, jsonify, render_template, Response, request
from backend.services.attack_service import AttackService
from backend.middleware.authentication import login_required
from config.database import SessionLocal
from config.settings import settings
from backend.models import Honeypot, AttackEvent

dashboard_bp = Blueprint("dashboard_bp", __name__)


def _get_lan_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _is_honeypot_open() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", settings.HONEYPOT_PORT), timeout=0.5):
            return True
    except OSError:
        return False


@dashboard_bp.route("/")
def index():
    return render_template("dashboard.html")

@dashboard_bp.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")

@dashboard_bp.route("/live")
def live_monitor_page():
    return render_template(
        "live_monitor.html",
        honeypot_port=settings.HONEYPOT_PORT,
        lan_ip=_get_lan_ip(),
        honeypot_online=_is_honeypot_open()
    )

@dashboard_bp.route("/settings")
@login_required
def settings_page():
    db = SessionLocal()
    try:
        honeypots = db.query(Honeypot).all()
        return render_template("settings.html", honeypots=[hp.to_dict() for hp in honeypots])
    finally:
        db.close()

@dashboard_bp.route("/api/dashboard/stats", methods=["GET"])
def api_dashboard_stats():
    """Returns core statistics and timeseries charts for SOC Dashboard."""
    kpis = AttackService.get_dashboard_kpis()
    trends = AttackService.get_attack_trends(days=7)
    top_usernames = AttackService.get_top_attacked_usernames(limit=6)
    country_dist = AttackService.get_country_distribution(limit=8)
    recent_events = AttackService.get_recent_events(limit=10)

    return jsonify({
        "kpis": kpis,
        "trends": trends,
        "top_usernames": top_usernames,
        "country_distribution": country_dist,
        "recent_events": recent_events,
        "honeypot_online": _is_honeypot_open(),
        "honeypot_port": settings.HONEYPOT_PORT
    }), 200

@dashboard_bp.route("/api/simulate", methods=["POST"])
def api_trigger_simulation():
    """Triggers a live real TCP/SSH attack (if honeypot open) or simulated log attack."""
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "auto")

    def _run_attack():
        if mode == "real" or (mode == "auto" and _is_honeypot_open()):
            from honeypot.simulator.real_attack_demo import run_real_ssh_attack
            run_real_ssh_attack("127.0.0.1", settings.HONEYPOT_PORT, delay=0.25)
        else:
            from honeypot.simulator.attack_simulator import simulate_single_attack
            simulate_single_attack(delay_between_steps=0.25)

    t = threading.Thread(target=_run_attack, daemon=True)
    t.start()
    return jsonify({
        "status": "started",
        "mode": "real-ssh" if (_is_honeypot_open() and mode != "botnet") else "log-sim",
        "message": "Live attack sequence initiated."
    }), 202

@dashboard_bp.route("/api/dashboard/live-stream")
def api_live_stream():
    """Server-Sent Events (SSE) endpoint providing streaming events to SOC live feed."""
    def event_stream():
        last_id = 0
        db = SessionLocal()
        try:
            latest = db.query(AttackEvent).order_by(AttackEvent.id.desc()).first()
            if latest:
                last_id = max(0, latest.id - 6)
        finally:
            db.close()

        ticks = 0
        while True:
            db = SessionLocal()
            try:
                new_events = db.query(AttackEvent).filter(AttackEvent.id > last_id).order_by(AttackEvent.id.asc()).limit(20).all()
                for evt in new_events:
                    last_id = evt.id
                    payload = json.dumps(evt.to_dict())
                    yield f"data: {payload}\n\n"
            except Exception:
                pass
            finally:
                db.close()

            ticks += 1
            if ticks % 20 == 0:
                yield ": keepalive\n\n"
            time.sleep(0.5)

    return Response(event_stream(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

