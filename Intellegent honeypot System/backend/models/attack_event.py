import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from config.database import Base

class AttackEvent(Base):
    __tablename__ = "attack_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id", ondelete="CASCADE"), nullable=False, index=True)
    honeypot_id = Column(Integer, ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=True, index=True)
    session_id = Column(String(64), nullable=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    username = Column(String(100), nullable=True, index=True)
    password_masked = Column(String(100), nullable=True)
    raw_payload = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    # Relationships
    attacker = relationship("Attacker", back_populates="events")
    honeypot = relationship("Honeypot", back_populates="events")
    alerts = relationship("Alert", back_populates="event", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "attacker_id": self.attacker_id,
            "source_ip": self.attacker.source_ip if self.attacker else "Unknown",
            "country": self.attacker.country if self.attacker else "Unknown",
            "country_code": self.attacker.country_code if self.attacker else "XX",
            "honeypot_id": self.honeypot_id,
            "honeypot_name": self.honeypot.name if self.honeypot else "Default-SSH",
            "session_id": self.session_id,
            "event_type": self.event_type,
            "username": self.username,
            "password_masked": self.password_masked,
            "raw_payload": self.raw_payload,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }

