"""
blueprints/utils.py

Shared decorators and helpers used across all blueprints.
"""
import logging
import re
from datetime import datetime, timezone
from functools import wraps

from flask import jsonify, redirect, request, session, url_for

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# AUTH DECORATORS
# ─────────────────────────────────────────────────────────────────────────────

def login_required(f):
    """Redirect to login if user has no active session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Authentication required"}), 401
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def superadmin_required(f):
    """Allow only superadmin role. Returns 403 for everyone else."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Authentication required"}), 401
            return redirect(url_for("auth.login"))
        if session.get("role") != "superadmin":
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Superadmin access required"}), 403
            return jsonify({"success": False, "error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return decorated


def internal_only(f):
    """Allow only requests from localhost (Rasa action server, etc.)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        remote = request.remote_addr or ""
        if remote not in ("127.0.0.1", "::1", "localhost"):
            logger.warning("internal_only blocked request from %s", remote)
            return jsonify({"success": False, "error": "Internal access only"}), 403
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# DATE / TIME HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def isoformat_safe(value):
    """
    Convert a datetime (or None) to an ISO-8601 string safely.
    Naive datetimes are treated as UTC.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    # Already a string (e.g. from some drivers)
    return str(value)


# ─────────────────────────────────────────────────────────────────────────────
# PRIORITY CLASSIFICATION
# ─────────────────────────────────────────────────────────────────────────────

_CRITICAL_KEYWORDS = {
    "fire", "burning", "burnt", "smoke", "explosion", "electrocution",
    "sparking", "spark", "fallen wire", "downed wire", "electric shock",
    "transformer explode", "pole down", "fallen pole",
}
_HIGH_KEYWORDS = {
    "hospital", "school", "clinic", "emergency", "whole barangay",
    "entire street", "no power", "blackout", "transformer",
}


def classify_priority(details: str) -> str:
    """
    Derive CRITICAL / HIGH / MEDIUM / LOW from free-text complaint details.
    Falls back to MEDIUM when no keywords match.
    """
    if not details:
        return "MEDIUM"
    lower = details.lower()
    if any(k in lower for k in _CRITICAL_KEYWORDS):
        return "CRITICAL"
    if any(k in lower for k in _HIGH_KEYWORDS):
        return "HIGH"
    return "MEDIUM"


# ─────────────────────────────────────────────────────────────────────────────
# PASSWORD VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def validate_password_strength(password: str):
    """
    Returns an error string if the password is too weak, otherwise None.
    Rules: 8+ chars, at least one uppercase, one digit, one special char.
    """
    if not password:
        return "Password is required"
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r"\d", password):
        return "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
        return "Password must contain at least one special character"
    return None