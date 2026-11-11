import datetime
from sqlalchemy import func, desc
from config.database import SessionLocal
from backend.models import AttackEvent, Attacker, Session, Alert

class AttackService:
    """Provides high-performance aggregation and querying of honeypot threat data."""

    @staticmethod
    def get_dashboard_kpis():
        """Returns the primary KPI metrics for the executive SOC overview."""
        db = SessionLocal()
        try:
            total_attacks = db.query(func.count(AttackEvent.id)).scalar() or 0
            unique_ips = db.query(func.count(Attacker.id)).scalar() or 0
            total_logins = db.query(func.count(AttackEvent.id)).filter(
                AttackEvent.event_type.in_(["cowrie.login.failed", "cowrie.login.success"])
            ).scalar() or 0
            critical_alerts = db.query(func.count(Alert.id)).filter(
                Alert.severity.in_(["Critical", "High"]),
                Alert.status == "open"
            ).scalar() or 0
            active_sessions = db.query(func.count(Session.id)).filter(
                Session.status == "active"
            ).scalar() or 0

            return {
                "total_attacks": total_attacks,
                "unique_ips": unique_ips,
                "login_attempts": total_logins,
                "critical_alerts": critical_alerts,
                "active_sessions": active_sessions
            }
        finally:
            db.close()

    @staticmethod
    def get_attack_trends(days: int = 7):
        """Returns daily attack timeline data for Chart.js."""
        db = SessionLocal()
        try:
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            start_date = now - datetime.timedelta(days=days)

            # Query events grouped by day
            events = db.query(
                func.date(AttackEvent.timestamp).label("day"),
                func.count(AttackEvent.id).label("count")
            ).filter(AttackEvent.timestamp >= start_date)\
             .group_by(func.date(AttackEvent.timestamp))\
             .order_by(func.date(AttackEvent.timestamp)).all()

            labels = []
            counts = []
            for day, count in events:
                labels.append(str(day))
                counts.append(count)

            if not labels:
                labels = [(now - datetime.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days, -1, -1)]
                counts = [0] * len(labels)

            return {"labels": labels, "counts": counts}
        finally:
            db.close()

    @staticmethod
    def get_top_attacked_usernames(limit: int = 6):
        """Returns top targeted usernames (root, admin, etc.) and their frequency."""
        db = SessionLocal()
        try:
            results = db.query(
                AttackEvent.username,
                func.count(AttackEvent.id).label("freq")
            ).filter(
                AttackEvent.username.isnot(None),
                AttackEvent.event_type.in_(["cowrie.login.failed", "cowrie.login.success"])
            ).group_by(AttackEvent.username)\
             .order_by(desc("freq")).limit(limit).all()

            return [{"username": u, "count": f} for u, f in results if u]
        finally:
            db.close()

    @staticmethod
    def get_country_distribution(limit: int = 8):
        """Returns geographic distribution of threat origin countries."""
        db = SessionLocal()
        try:
            results = db.query(
                Attacker.country,
                func.count(Attacker.id).label("ip_count"),
                func.sum(Attacker.total_attacks).label("attack_sum")
            ).group_by(Attacker.country)\
             .order_by(desc("attack_sum")).limit(limit).all()

            return [
                {
                    "country": c or "Unknown",
                    "ip_count": ipc,
                    "attack_count": int(atk_sum or 0)
                } for c, ipc, atk_sum in results
            ]
        finally:
            db.close()

    @staticmethod
    def get_recent_events(limit: int = 15):
        """Returns the most recent security events with attacker details."""
        db = SessionLocal()
        try:
            events = db.query(AttackEvent).order_by(desc(AttackEvent.timestamp)).limit(limit).all()
            return [e.to_dict() for e in events]
        finally:
            db.close()

