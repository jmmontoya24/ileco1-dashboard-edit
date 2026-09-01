"""
blueprints/admin.py

Routes (superadmin only):
    GET    /user_management
    GET    /api/admin/users
    POST   /api/admin/users
    DELETE /api/admin/users/<id>
    POST   /api/admin/users/<id>/toggle
    POST   /api/admin/reset-password
"""
import logging
import re

from flask import Blueprint, jsonify, render_template, request, session
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash

from blueprints.utils import login_required, superadmin_required, isoformat_safe, validate_password_strength
from db.pool import get_local_conn, release_local_conn

logger = logging.getLogger(__name__)
admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/user_management")
@superadmin_required
def user_management_page():
    return render_template("user_management.html")


@admin_bp.route("/api/admin/users")
@superadmin_required
def list_users():
    conn = get_local_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, username, full_name, role, is_active, created_at,
                   NULL::timestamptz AS last_login_at
            FROM users ORDER BY created_at DESC
        """)
        users = []
        for u in cur.fetchall():
            d = dict(u)
            d["created_at"]    = isoformat_safe(d.get("created_at"))
            d["last_login_at"] = isoformat_safe(d.get("last_login_at"))
            d["updated_at"]    = None
            users.append(d)
        return jsonify({"success": True, "users": users})
    except Exception:
        logger.exception("list_users error")
        return jsonify({"success": False, "error": "Failed to list users"}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@admin_bp.route("/api/admin/users", methods=["POST"])
@superadmin_required
def create_user():
    data      = request.get_json() or {}
    username  = (data.get("username") or "").strip().lower()
    full_name = (data.get("full_name") or "").strip()
    password  = data.get("password") or ""
    role      = data.get("role", "staff")

    if not username:
        return jsonify({"success": False, "error": "Username is required"}), 400
    if not re.match(r"^[a-z0-9_.]+$", username):
        return jsonify({"success": False, "error": "Username: lowercase, numbers, underscores, dots only"}), 400
    if len(username) < 3 or len(username) > 50:
        return jsonify({"success": False, "error": "Username must be 3-50 characters"}), 400

    pw_err = validate_password_strength(password)
    if pw_err:
        return jsonify({"success": False, "error": pw_err}), 400

    if role not in ("staff", "admin", "superadmin"):
        return jsonify({"success": False, "error": "Invalid role"}), 400

    conn = get_local_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        if cur.fetchone():
            return jsonify({"success": False, "error": f'Username "{username}" already taken'}), 409

        cur.execute("""
            INSERT INTO users (username, full_name, password_hash, role, is_active, created_at)
            VALUES (%s,%s,%s,%s,TRUE,TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP))
            RETURNING id, username, full_name, role, is_active, created_at
        """, (username, full_name or username, generate_password_hash(password), role))
        new_user = cur.fetchone()
        conn.commit()
        d = dict(new_user)
        d["created_at"] = isoformat_safe(d.get("created_at"))
        logger.info("User '%s' (role=%s) created by '%s'", username, role, session.get("username"))
        return jsonify({"success": True, "user": d}), 201
    except Exception:
        conn.rollback()
        logger.exception("create_user error")
        return jsonify({"success": False, "error": "Create failed"}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@admin_bp.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@superadmin_required
def delete_user(user_id):
    if session.get("user_id") == user_id:
        return jsonify({"success": False, "error": "Cannot delete your own account"}), 400

    conn = get_local_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, username, role FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        if user["role"] == "superadmin":
            cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role='superadmin' AND is_active=TRUE")
            if cur.fetchone()["cnt"] <= 1:
                return jsonify({"success": False,
                                "error": "Cannot delete the last active superadmin"}), 400

        cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
        logger.info("User '%s' deleted by '%s'", user["username"], session.get("username"))
        return jsonify({"success": True, "message": f"User {user['username']} deleted"})
    except Exception:
        conn.rollback()
        logger.exception("delete_user error")
        return jsonify({"success": False, "error": "Delete failed"}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@admin_bp.route("/api/admin/users/<int:user_id>/toggle", methods=["POST"])
@superadmin_required
def toggle_user(user_id):
    conn = get_local_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT username, is_active FROM users WHERE id=%s", (user_id,))
        user = cur.fetchone()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        new_state = not user["is_active"]
        cur.execute("UPDATE users SET is_active=%s WHERE id=%s RETURNING is_active", (new_state, user_id))
        result = cur.fetchone()
        conn.commit()
        return jsonify({"success": True, "is_active": result["is_active"],
                        "message": f"User {'enabled' if new_state else 'disabled'}"})
    except Exception:
        conn.rollback()
        logger.exception("toggle_user error")
        return jsonify({"success": False, "error": "Toggle failed"}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@admin_bp.route("/api/admin/reset-password", methods=["POST"])
@superadmin_required
def reset_password():
    data     = request.get_json() or {}
    username = (data.get("username") or "").strip()
    new_pw   = data.get("new_password") or ""

    if not username:
        return jsonify({"success": False, "error": "Username required"}), 400
    pw_err = validate_password_strength(new_pw)
    if pw_err:
        return jsonify({"success": False, "error": pw_err}), 400

    conn = get_local_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        if not cur.fetchone():
            return jsonify({"success": False, "error": f'User "{username}" not found'}), 404
        cur.execute("UPDATE users SET password_hash=%s WHERE username=%s",
                    (generate_password_hash(new_pw), username))
        conn.commit()
        logger.info("Password reset for '%s' by '%s'", username, session.get("username"))
        return jsonify({"success": True, "message": f"Password reset for {username}"})
    except Exception:
        conn.rollback()
        logger.exception("reset_password error")
        return jsonify({"success": False, "error": "Reset failed"}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)