"""
blueprints/auth.py

Routes:
    GET  /login          → render login page
    POST /login          → authenticate user, set session
    GET  /logout         → clear session, redirect
    GET  /api/me         → current user info (JSON)
    GET  /health         → liveness probe (no auth)
"""
import logging

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash

from db.pool import get_local_conn, release_local_conn
from blueprints.utils import login_required

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if "user_id" in session:
            return redirect(url_for("dashboard.index"))
        return render_template("login.html")

    # POST — JSON body
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"success": False, "error": "Username and password required"}), 400

    conn = get_local_conn()
    if not conn:
        logger.error("Local DB unavailable during login")
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "SELECT id, username, password_hash, full_name, role, is_active "
            "FROM users WHERE username = %s",
            (username,),
        )
        user = cur.fetchone()

        if user and user["is_active"] and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"] or user["username"]
            session["role"] = user["role"]
            logger.info("Login OK: %s", username)
            return jsonify({"success": True, "redirect": url_for("dashboard.index")})

        logger.warning("Login failed: %s", username)
        return jsonify({"success": False, "error": "Invalid credentials or inactive account"}), 401

    except Exception:
        logger.exception("Login error for %s", username)
        return jsonify({"success": False, "error": "Server error"}), 500
    finally:
        if cur:
            cur.close()
        release_local_conn(conn)


@auth_bp.route("/logout")
def logout():
    username = session.get("username", "?")
    session.clear()
    logger.info("Logout: %s", username)
    return redirect(url_for("auth.login"))


@auth_bp.route("/api/me")
@login_required
def me():
    return jsonify({
        "success": True,
        "user": {
            "user_id":   session.get("user_id"),
            "username":  session.get("username"),
            "full_name": session.get("full_name"),
            "role":      session.get("role"),
        },
    })