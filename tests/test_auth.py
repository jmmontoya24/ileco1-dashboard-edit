"""
tests/test_auth.py

Tests for:
  POST /login
  GET  /logout
  GET  /api/me
"""
import pytest
from unittest.mock import MagicMock, patch
from werkzeug.security import generate_password_hash

from tests.conftest import ADMIN_USER, STAFF_USER, ADMIN_PASSWORD, _login


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN
# ─────────────────────────────────────────────────────────────────────────────

class TestLogin:

    def test_login_page_renders(self, client):
        """GET /login should render without redirect."""
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_login_success_admin(self, client, mock_local_conn):
        """Correct credentials for superadmin should return success JSON."""
        cur = MagicMock()
        cur.fetchone.return_value = ADMIN_USER
        mock_local_conn.cursor.return_value = cur

        resp = _login(client, "admin", ADMIN_PASSWORD)
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        assert "redirect" in data
        client.get("/logout")

    def test_login_wrong_password(self, client, mock_local_conn):
        """Wrong password should return 401."""
        cur = MagicMock()
        cur.fetchone.return_value = ADMIN_USER   # user exists
        mock_local_conn.cursor.return_value = cur

        resp = _login(client, "admin", "WrongPassword123")
        data = resp.get_json()

        assert resp.status_code == 401
        assert data["success"] is False
        assert "error" in data

    def test_login_unknown_user(self, client, mock_local_conn):
        """Non-existent user should return 401."""
        cur = MagicMock()
        cur.fetchone.return_value = None   # user not found
        mock_local_conn.cursor.return_value = cur

        resp = _login(client, "nobody", "Whatever1")
        data = resp.get_json()

        assert resp.status_code == 401
        assert data["success"] is False

    def test_login_inactive_user(self, client, mock_local_conn):
        """Inactive account should be rejected even with correct password."""
        inactive = dict(STAFF_USER, is_active=False)
        cur = MagicMock()
        cur.fetchone.return_value = inactive
        mock_local_conn.cursor.return_value = cur

        resp = _login(client, "juana", "Staff@1234")
        data = resp.get_json()

        assert resp.status_code == 401
        assert data["success"] is False

    def test_login_missing_fields(self, client):
        """Empty body should return 400."""
        resp = client.post(
            "/login",
            json={"username": "", "password": ""},
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code == 400
        assert data["success"] is False

    def test_login_db_unavailable(self, client):
        """If local DB is down, return 503."""
        with patch("db.pool.get_local_conn", return_value=None):
            resp = _login(client, "admin", ADMIN_PASSWORD)
            data = resp.get_json()
        assert resp.status_code == 503
        assert data["success"] is False


# ─────────────────────────────────────────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────────────────────────────────────────

class TestLogout:

    def test_logout_redirects_to_login(self, client, mock_local_conn):
        """GET /logout should clear session and redirect to /login."""
        cur = MagicMock()
        cur.fetchone.return_value = ADMIN_USER
        mock_local_conn.cursor.return_value = cur
        _login(client, "admin", ADMIN_PASSWORD)

        resp = client.get("/logout", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_logout_unauthenticated(self, client):
        """Logout when not logged in should still redirect cleanly."""
        resp = client.get("/logout", follow_redirects=False)
        assert resp.status_code == 302


# ─────────────────────────────────────────────────────────────────────────────
# /api/me
# ─────────────────────────────────────────────────────────────────────────────

class TestGetMe:

    def test_me_unauthenticated(self, client):
        """GET /api/me without session should return 401."""
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get("/api/me")
        data = resp.get_json()
        assert resp.status_code == 401
        assert data["success"] is False

    def test_me_authenticated(self, client, mock_local_conn):
        """GET /api/me with valid session returns user info."""
        cur = MagicMock()
        cur.fetchone.return_value = ADMIN_USER
        mock_local_conn.cursor.return_value = cur
        _login(client, "admin", ADMIN_PASSWORD)

        resp = client.get("/api/me")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        assert data["user"]["username"] == "admin"
        assert data["user"]["role"] == "superadmin"
        client.get("/logout")

    def test_me_fields_present(self, client, mock_local_conn):
        """Response must contain all required user fields."""
        cur = MagicMock()
        cur.fetchone.return_value = STAFF_USER
        mock_local_conn.cursor.return_value = cur
        _login(client, "juana", "Staff@1234")

        resp = client.get("/api/me")
        data = resp.get_json()
        user = data["user"]

        for field in ("user_id", "username", "full_name", "role"):
            assert field in user, f"Missing field: {field}"
        client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# PROTECTED ROUTE REDIRECT
# ─────────────────────────────────────────────────────────────────────────────

class TestProtectedRoutes:

    def test_dashboard_requires_auth(self, client):
        """GET /dashboard without auth should redirect to /login."""
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get("/dashboard", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_api_incidents_requires_auth(self, client):
        """GET /api/incidents without auth should return 401 JSON."""
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get("/api/incidents")
        data = resp.get_json()
        assert resp.status_code == 401
        assert data["success"] is False

    def test_user_management_requires_superadmin(self, client, mock_local_conn):
        """Staff users should be redirected away from /user_management."""
        cur = MagicMock()
        cur.fetchone.return_value = STAFF_USER
        mock_local_conn.cursor.return_value = cur
        _login(client, "juana", "Staff@1234")

        resp = client.get("/user_management", follow_redirects=False)
        # Should redirect (not 200)
        assert resp.status_code in (302, 403)
        client.get("/logout")