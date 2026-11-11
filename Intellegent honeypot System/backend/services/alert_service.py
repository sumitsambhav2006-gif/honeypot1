from sqlalchemy import desc
from config.database import SessionLocal
from backend.models import Alert

class AlertService:
    """Manages Security Operations Center (SOC) Alert Lifecycle."""

    @staticmethod
    def get_alerts(severity: str = None, status: str = None, limit: int = 50):
        db = SessionLocal()
        try:
            query = db.query(Alert)
            if severity:
                query = query.filter(Alert.severity == severity)
            if status:
                query = query.filter(Alert.status == status)

            alerts = query.order_by(desc(Alert.timestamp)).limit(limit).all()
            return [a.to_dict() for a in alerts]
        finally:
            db.close()

    @staticmethod
    def update_status(alert_id: int, new_status: str):
        db = SessionLocal()
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                return None
            alert.status = new_status
            db.commit()
            return alert.to_dict()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

