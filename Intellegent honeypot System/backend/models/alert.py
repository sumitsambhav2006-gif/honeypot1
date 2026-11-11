import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from config.database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("attack_events.id", ondelete="SET NULL"), nullable=True, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id", ondelete="CASCADE"), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # Low, Medium, High, Critical
    risk_score = Column(Integer, default=0, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), default="open", index=True)  # open, investigating, resolved, dismissed
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    # Relationships
    event = relationship("AttackEvent", back_populates="alerts")
    attacker = relationship("Attacker", back_populates="alerts")

    def to_dict(self):
        return {
            "id": self.id,
            "event_id": self.event_id,
            "attacker_id": self.attacker_id,
            "source_ip": self.attacker.source_ip if self.attacker else "Unknown",
            "country": self.attacker.country if self.attacker else "Unknown",
            "severity": self.severity,
            "risk_score": self.risk_score,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }

