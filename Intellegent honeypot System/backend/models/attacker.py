import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.orm import relationship
from config.database import Base

class Attacker(Base):
    __tablename__ = "attackers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ip = Column(String(45), unique=True, nullable=False, index=True)
    country = Column(String(100), default="Unknown")
    country_code = Column(String(10), default="XX")
    city = Column(String(100), default="Unknown")
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(String(100), default="Unknown ASN")
    isp = Column(String(150), default="Unknown ISP")
    reputation = Column(Integer, default=50)  # 0 (clean) to 100 (malicious reputation)
    total_attacks = Column(Integer, default=0)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow, index=True)

    # Relationships
    sessions = relationship("Session", back_populates="attacker", cascade="all, delete-orphan")
    events = relationship("AttackEvent", back_populates="attacker", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="attacker", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "asn": self.asn,
            "isp": self.isp,
            "reputation": self.reputation,
            "total_attacks": self.total_attacks,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None
        }

