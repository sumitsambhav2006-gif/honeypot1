import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from config.database import Base

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    attacker_id = Column(Integer, ForeignKey("attackers.id", ondelete="CASCADE"), nullable=False, index=True)
    honeypot_id = Column(Integer, ForeignKey("honeypots.id", ondelete="CASCADE"), nullable=True, index=True)
    start_time = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, default=0)
    command_count = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    status = Column(String(20), default="active")  # active, closed, timed_out

    # Relationships
    attacker = relationship("Attacker", back_populates="sessions")
    honeypot = relationship("Honeypot", back_populates="sessions")
    commands = relationship("Command", back_populates="session", cascade="all, delete-orphan", order_by="Command.timestamp.asc()")

    def to_dict(self, include_commands=False):
        data = {
            "id": self.id,
            "session_id": self.session_id,
            "attacker_id": self.attacker_id,
            "source_ip": self.attacker.source_ip if self.attacker else "Unknown",
            "country": self.attacker.country if self.attacker else "Unknown",
            "honeypot_id": self.honeypot_id,
            "honeypot_name": self.honeypot.name if self.honeypot else "Default-SSH",
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "command_count": self.command_count,
            "risk_score": self.risk_score,
            "status": self.status
        }
        if include_commands:
            data["commands"] = [cmd.to_dict() for cmd in self.commands]
        return data

