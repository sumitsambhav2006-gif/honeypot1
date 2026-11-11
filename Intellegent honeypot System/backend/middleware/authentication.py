from functools import wraps
from flask import session, jsonify, request, redirect, url_for

def login_required(f):
    """Requires active user session in Flask session store."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            # If API request, return 401 JSON
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
            # If Web Browser page request, redirect to login page
            return redirect(url_for("auth_bp.login_page"))
        return f(*args, **kwargs)
    return decorated_function

