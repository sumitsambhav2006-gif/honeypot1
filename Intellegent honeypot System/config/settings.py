import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file
load_dotenv(BASE_DIR / ".env")

class Config:
    BASE_DIR = BASE_DIR
    PROJECT_NAME = "Intelligent Honeypot & Threat Intelligence Platform"
    PROJECT_SHORT = "IHTIP"
    VERSION = "1.0.0"

    # Flask Settings
    SECRET_KEY = os.getenv("SECRET_KEY", "soc-super-secret-key-change-in-production")
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = os.getenv("FLASK_DEBUG", "1") == "1"
    PORT = int(os.getenv("PORT", 5000))
    HOST = os.getenv("HOST", "0.0.0.0")

    # Database Settings
    DB_TYPE = os.getenv("DB_TYPE", "sqlite").lower()
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = os.getenv("DB_PORT", "3306")
    DB_NAME = os.getenv("DB_NAME", "honeypot_db")
    SQLITE_PATH = os.getenv("SQLITE_PATH", "data/honeypot.db")

    @property
    def DATABASE_URI(self) -> str:
        if self.DB_TYPE == "mysql":
            return f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}?charset=utf8mb4"
        else:
            db_path = BASE_DIR / self.SQLITE_PATH
            db_path.parent.mkdir(parents=True, exist_ok=True)
            return f"sqlite:///{db_path}"

    # Honeypot & Collector Logs
    HONEYPOT_HOST = os.getenv("HONEYPOT_HOST", "0.0.0.0")
    HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", 2222))
    HONEYPOT_NODE_NAME = os.getenv("HONEYPOT_NODE_NAME", "SSH-HONEYPOT-PROD-01")
    SSH_HOST_KEY_PATH = BASE_DIR / "data" / "ssh_host_rsa.key"
    COWRIE_LOG_PATH = BASE_DIR / os.getenv("COWRIE_LOG_PATH", "logs/cowrie.json")
    APP_LOG_PATH = BASE_DIR / "logs" / "app.log"
    ARCHIVE_LOG_PATH = BASE_DIR / "logs" / "archive"

    # Threat Intelligence APIs
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

    # Risk Scoring Thresholds
    MAX_FAILED_LOGINS_THRESHOLD = int(os.getenv("MAX_FAILED_LOGINS_THRESHOLD", 5))
    HIGH_RISK_THRESHOLD = int(os.getenv("HIGH_RISK_THRESHOLD", 60))
    CRITICAL_RISK_THRESHOLD = int(os.getenv("CRITICAL_RISK_THRESHOLD", 80))

settings = Config()
