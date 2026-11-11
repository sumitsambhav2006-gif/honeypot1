import json
import logging
from typing import Dict, Any, Optional

from config.database import SessionLocal
from backend.models import Honeypot, Attacker, Session, AttackEvent, Command, Alert
from threat_intelligence.intelligence_service import intelligence_service
from analytics.attack_detector import AttackDetector

logger = logging.getLogger(__name__)

class EventCollector:
    """Core Event Ingestion and Database Synchronization Service."""

    def __init__(self):
        self.detector = AttackDetector()

    def process_normalized_event(self, event_data: Dict[str, Any]) -> Optional[int]:
        """
        Takes a normalized event, coordinates threat intelligence enrichment,
        runs analytics detection, updates database models, and generates alerts.
        """
        if not event_data:
            return None

        src_ip = event_data.get("source_ip")
        if not src_ip:
            return None

        db = SessionLocal()
        try:
            # 1. Resolve or Create Honeypot Node
            hp_name = event_data.get("honeypot_name", "SSH-HONEYPOT-PROD-01")
            honeypot = db.query(Honeypot).filter(Honeypot.name == hp_name).first()
            if not honeypot:
                honeypot = Honeypot(name=hp_name, type="cowrie-ssh", port=event_data.get("dest_port", 2222), status="active")
                db.add(honeypot)
                db.flush()

            # 2. Resolve or Create Attacker
            attacker = db.query(Attacker).filter(Attacker.source_ip == src_ip).first()
            if not attacker:
                # Enrich with Threat Intelligence
                intel = intelligence_service.get_ip_intel(src_ip)
                attacker = Attacker(
                    source_ip=src_ip,
                    country=intel.get("country", "Unknown"),
                    country_code=intel.get("country_code", "XX"),
                    city=intel.get("city", "Unknown"),
                    latitude=intel.get("latitude"),
                    longitude=intel.get("longitude"),
                    asn=intel.get("asn", "Unknown ASN"),
                    isp=intel.get("isp", "Unknown ISP"),
                    reputation=intel.get("reputation", 50),
                    total_attacks=1,
                    first_seen=event_data["timestamp"],
                    last_seen=event_data["timestamp"]
                )
                db.add(attacker)
                db.flush()
            else:
                attacker.total_attacks += 1
                attacker.last_seen = event_data["timestamp"]

            # 3. Resolve or Create Attacker Session
            session_uuid = event_data.get("session_id")
            session = None
            if session_uuid and session_uuid != "unknown_session":
                session = db.query(Session).filter(Session.session_id == session_uuid).first()
                if not session:
                    session = Session(
                        session_id=session_uuid,
                        attacker_id=attacker.id,
                        honeypot_id=honeypot.id,
                        start_time=event_data["timestamp"],
                        status="active",
                        command_count=0,
                        risk_score=10
                    )
                    db.add(session)
                    db.flush()

            # 4. Create AttackEvent Record
            raw_payload_str = json.dumps(event_data.get("raw_payload", {}))
            attack_evt = AttackEvent(
                attacker_id=attacker.id,
                honeypot_id=honeypot.id,
                session_id=session_uuid,
                event_type=event_data["event_type"],
                username=event_data.get("username"),
                password_masked=event_data.get("password_masked"),
                raw_payload=raw_payload_str,
                timestamp=event_data["timestamp"]
            )
            db.add(attack_evt)
            db.flush()

            # 5. Run Analytics Detector
            detection = self.detector.process_event(event_data)

            # 6. Handle Command Input specifics
            if event_data["event_type"] == "cowrie.command.input" and session and event_data.get("command"):
                cmd_meta = detection.get("command_meta", {})
                category = cmd_meta.get("category", "General")
                risk_pts = cmd_meta.get("risk_points", 5)

                cmd_obj = Command(
                    session_id=session.id,
                    command=event_data["command"],
                    category=category,
                    risk_points=risk_pts,
                    timestamp=event_data["timestamp"]
                )
                db.add(cmd_obj)

                session.command_count += 1
                session.risk_score = min(100, session.risk_score + risk_pts)

            # 7. Handle Session Close
            if event_data["event_type"] == "cowrie.session.closed" and session:
                session.status = "closed"
                session.end_time = event_data["timestamp"]
                duration = event_data.get("duration", 0)
                if duration:
                    session.duration_seconds = int(duration)
                elif session.start_time:
                    delta = (session.end_time - session.start_time).total_seconds()
                    session.duration_seconds = max(0, int(delta))

            # 8. Create Alert if triggered
            if detection.get("trigger_alert") and detection.get("alert_data"):
                adata = detection["alert_data"]
                alert = Alert(
                    event_id=attack_evt.id,
                    attacker_id=attacker.id,
                    severity=adata["severity"],
                    risk_score=adata["risk_score"],
                    title=adata["title"],
                    description=adata["description"],
                    status="open",
                    timestamp=event_data["timestamp"]
                )
                db.add(alert)

            db.commit()
            return attack_evt.id

        except Exception as e:
            db.rollback()
            logger.error(f"Error persisting attack event: {e}", exc_info=True)
            return None
        finally:
            db.close()

