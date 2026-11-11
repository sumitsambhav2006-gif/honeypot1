from config.database import SessionLocal, init_db
from backend.models import User, Attacker, Honeypot

def test_database_models():
    init_db()
    db = SessionLocal()
    try:
        # Verify Honeypots
        hp = db.query(Honeypot).first()
        assert hp is not None
        assert hp.name is not None

        # Verify Attackers
        attacker = db.query(Attacker).first()
        assert attacker is not None
        assert attacker.source_ip is not None

        # Verify User auth check
        user = db.query(User).filter(User.username == "admin").first()
        assert user is not None
        assert user.check_password("admin123") is True
        assert user.check_password("wrongpassword") is False
    finally:
        db.close()

