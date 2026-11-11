import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from config.database import Base

class Command(Base):
    __tablename__ = "commands"

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(Integer, ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    command = Column(Text, nullable=False)
    category = Column(String(50), default="General", index=True)
    risk_points = Column(Integer, default=5)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    # Relationships
    session = relationship("Session", back_populates="commands")

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "session_uuid": self.session.session_id if self.session else None,
            "command": self.command,
            "category": self.category,
            "risk_points": self.risk_points,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }

