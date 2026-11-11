import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session
from config.settings import settings

logger = logging.getLogger(__name__)

Base = declarative_base()

# Connection pool & engine creation
engine_args = {
    "echo": False,
    "future": True
}

if settings.DB_TYPE == "sqlite":
    engine_args["connect_args"] = {"check_same_thread": False}
else:
    engine_args["pool_size"] = 10
    engine_args["max_overflow"] = 20
    engine_args["pool_recycle"] = 3600
    engine_args["pool_pre_ping"] = True

try:
    engine = create_engine(settings.DATABASE_URI, **engine_args)
except Exception as e:
    logger.warning(f"Could not initialize primary database ({settings.DB_TYPE}): {e}. Falling back to SQLite.")
    fallback_uri = f"sqlite:///{settings.BASE_DIR / 'data' / 'honeypot.db'}"
    engine = create_engine(fallback_uri, connect_args={"check_same_thread": False}, echo=False, future=True)

SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

def get_db():
    """Dependency helper to yield database session and ensure clean closure."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database tables according to defined SQLAlchemy metadata."""
    import backend.models  # Ensure all models are imported before creating tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema synchronized successfully.")

