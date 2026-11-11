import sys
from pathlib import Path
from flask import Flask, jsonify, render_template, session
from flask_cors import CORS

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import settings
from config.database import init_db
from config.security_config import SecurityConfig
from config.logging_config import setup_logging

logger = setup_logging("ihtip-backend")

def create_app(config_object=None) -> Flask:
    """Application factory for IHTIP SOC Backend."""
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "frontend" / "templates"),
        static_folder=str(BASE_DIR / "frontend" / "static")
    )

    # Configuration
    app.config["SECRET_KEY"] = settings.SECRET_KEY
    app.config["JSON_SORT_KEYS"] = False

    # Enable Cross-Origin Resource Sharing
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Synchronize database tables
    try:
        init_db()
    except Exception as e:
        logger.warning(f"Database init check warning: {e}")

    # Register Blueprints
    from backend.routes.auth_routes import auth_bp
    from backend.routes.dashboard_routes import dashboard_bp
    from backend.routes.attack_routes import attack_bp
    from backend.routes.attacker_routes import attacker_bp
    from backend.routes.session_routes import session_bp
    from backend.routes.analytics_routes import analytics_bp
    from backend.routes.report_routes import report_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(attack_bp)
    app.register_blueprint(attacker_bp)
    app.register_blueprint(session_bp)
    app.register_blueprint(analytics_bp)
    app.register_blueprint(report_bp)

    # Global Template Context
    @app.context_processor
    def inject_global_vars():
        return {
            "current_user": session.get("username"),
            "current_role": session.get("user_role", "analyst"),
            "is_authenticated": "user_id" in session,
            "project_name": settings.PROJECT_SHORT,
            "project_title": settings.PROJECT_NAME,
            "version": settings.VERSION
        }

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        for header, val in SecurityConfig.get_security_headers().items():
            response.headers[header] = val
        return response

    # Error Handlers
    @app.errorhandler(404)
    def not_found(e):
        return render_template("base.html", error_msg="404 - Requested Threat Intelligence Resource Not Found"), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"error": "Internal Server Error", "message": "An unexpected exception occurred."}), 500

    return app

if __name__ == "__main__":
    app = create_app()
    logger.info(f"[*] Starting IHTIP Server on http://{settings.HOST}:{settings.PORT}")
    app.run(host=settings.HOST, port=settings.PORT, debug=settings.DEBUG)

