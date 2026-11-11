import sys
import logging
from logging.handlers import RotatingFileHandler
from config.settings import settings

def setup_logging(name: str = "ihtip") -> logging.Logger:
    """Configures structured enterprise-grade logging with rotating file handlers and colored console output."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)

    if logger.handlers:
        return logger

    # Formatters
    file_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_formatter = logging.Formatter(
        "[%(asctime)s] \033[1;36m[%(levelname)s]\033[0m [%(name)s]: %(message)s",
        datefmt="%H:%M:%S"
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Ensure logs folder exists
    log_dir = settings.BASE_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    # Rotating File Handler
    file_handler = RotatingFileHandler(
        settings.APP_LOG_PATH,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger

