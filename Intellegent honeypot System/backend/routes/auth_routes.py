import datetime
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session
from config.database import SessionLocal
from backend.models import User

auth_bp = Blueprint("auth_bp", __name__)

@auth_bp.route("/login", methods=["GET"])
def login_page():
    if "user_id" in session:
        return redirect(url_for("dashboard_bp.dashboard_page"))
    return render_template("login.html")

@auth_bp.route("/logout", methods=["GET"])
def logout_page():
    session.clear()
    return redirect(url_for("auth_bp.login_page"))

@auth_bp.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Bad Request", "message": "Username and password required"}), 400

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not user.check_password(password):
            return jsonify({"error": "Unauthorized", "message": "Invalid username or password"}), 401

        user.last_login = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        db.commit()

        # Set Flask session
        session["user_id"] = user.id
        session["username"] = user.username
        session["user_role"] = user.role

        return jsonify({
            "message": "Login successful",
            "user": user.to_dict()
        }), 200
    finally:
        db.close()

@auth_bp.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Successfully logged out"}), 200

@auth_bp.route("/api/auth/me", methods=["GET"])
def api_me():
    if "user_id" not in session:
        return jsonify({"authenticated": False}), 200

    return jsonify({
        "authenticated": True,
        "user_id": session.get("user_id"),
        "username": session.get("username"),
        "role": session.get("user_role")
    }), 200

