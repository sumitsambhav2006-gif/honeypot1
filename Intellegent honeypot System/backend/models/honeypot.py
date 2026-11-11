import datetime
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.orm import relationship
from config.database import Base

class Honeypot(Base):
    __tablename__ = "honeypots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    type = Column(String(50), nullable=False, default="cowrie-ssh")
    ip_address = Column(String(45), nullable=True, default="127.0.0.1")
    port = Column(Integer, default=2222)
    status = Column(String(20), default="active")  # active, degraded, offline
    last_heartbeat = Column(DateTime, default=datetime.datetime.utcnow)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Relationships
    sessions = relationship("Session", back_populates="honeypot", cascade="all, delete-orphan")
    events = relationship("AttackEvent", back_populates="honeypot", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "ip_address": self.ip_address,
            "port": self.port,
            "status": self.status,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

