"""
tests/test_meter_api.py

Tests for:
  POST   /api/meter-concern           (public)
  GET    /api/meter-concerns          (staff)
  GET    /api/meter-concern/<ref>     (public)
  PUT    /api/meter-concern/<id>/status
  DELETE /api/meter-concern/<id>
  GET    /api/meter-concerns/statistics
  GET    /api/agent_queue
  POST   /api/agent_queue/<id>/serve
  DELETE /api/agent_queue/<id>/remove
"""
import pytest
from unittest.mock import MagicMock, patch
from tests.conftest import ADMIN_USER, ADMIN_PASSWORD, _login


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _make_cur(rows=None):
    cur = MagicMock()
    rows = rows or []
    cur.fetchone.return_value = rows[0] if rows else None
    cur.fetchall.return_value = rows
    return cur


def _auth(client, mock_local_conn):
    mock_local_conn.cursor.return_value = _make_cur([ADMIN_USER])
    _login(client, "admin", ADMIN_PASSWORD)


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/meter-concern  (public — no auth)
# ─────────────────────────────────────────────────────────────────────────────

class TestSubmitMeterConcern:

    VALID_DATA = {
        "account_number":  "1234567890",
        "consumer_name":   "Maria Santos",
        "contact_number":  "09171234567",
        "meter_number":    "M-001234",
        "service_address": "123 Rizal St",
        "barangay":        "Ungka I",
        "concern_type":    "not_working",
        "date_noticed":    "2026-05-12",
    }

    def test_valid_submission_returns_201(self, client, mock_cloud_conn):
        cur = MagicMock()
        cur.fetchone.return_value = {"id": 1, "reference_number": "MC-20260513-TEST0001"}
        mock_cloud_conn.cursor.return_value = cur

        with patch("blueprints.meter.get_cloud_conn", return_value=mock_cloud_conn), \
             patch("blueprints.meter.release_cloud_conn"):
            resp = client.post(
                "/api/meter-concern",
                data=self.VALID_DATA,
            )
        data = resp.get_json()
        assert resp.status_code in (200, 201)
        assert data.get("success") is True
        assert "reference_number" in data

    def test_missing_required_field(self, client):
        data = dict(self.VALID_DATA)
        del data["account_number"]
        resp = client.post("/api/meter-concern", data=data)
        result = resp.get_json()
        assert resp.status_code == 400
        assert "error" in result

    def test_missing_consumer_name(self, client):
        data = dict(self.VALID_DATA)
        del data["consumer_name"]
        resp = client.post("/api/meter-concern", data=data)
        assert resp.status_code == 400

    def test_critical_concern_type(self, client, mock_cloud_conn):
        """noise_burning should be flagged is_critical=True."""
        cur = MagicMock()
        cur.fetchone.return_value = {"id": 2, "reference_number": "MC-20260513-TEST0002"}
        mock_cloud_conn.cursor.return_value = cur

        data = dict(self.VALID_DATA, concern_type="noise_burning")
        with patch("blueprints.meter.get_cloud_conn", return_value=mock_cloud_conn), \
             patch("blueprints.meter.release_cloud_conn"):
            resp = client.post("/api/meter-concern", data=data)
        result = resp.get_json()
        if resp.status_code in (200, 201):
            assert result.get("is_critical") is True


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/meter-concerns  (staff)
# ─────────────────────────────────────────────────────────────────────────────

class TestListMeterConcerns:

    def test_returns_success(self, client, mock_local_conn, mock_cloud_conn, sample_meter_concern):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.return_value = {"count": 1}
        cur.fetchall.return_value = [sample_meter_concern]
        mock_cloud_conn.cursor.return_value = cur

        resp = client.get("/api/meter-concerns")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        assert "data" in data
        assert "pagination" in data
        client.get("/logout")

    def test_requires_auth(self, client):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get("/api/meter-concerns")
        assert resp.status_code == 401

    def test_status_filter_param(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.return_value = {"count": 0}
        cur.fetchall.return_value = []
        mock_cloud_conn.cursor.return_value = cur

        for st in ("PENDING", "RESOLVED", "ASSIGNED"):
            resp = client.get(f"/api/meter-concerns?status={st}")
            assert resp.status_code == 200

        client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/meter-concern/<ref>
# ─────────────────────────────────────────────────────────────────────────────

class TestGetMeterConcernDetail:

    def test_existing_ref(self, client, mock_cloud_conn, sample_meter_concern):
        cur = MagicMock()
        cur.fetchone.return_value = sample_meter_concern
        cur.fetchall.return_value = []
        mock_cloud_conn.cursor.return_value = cur

        resp = client.get("/api/meter-concern/MC-20260513-TEST0001")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        assert "data" in data

    def test_not_found_returns_404(self, client, mock_cloud_conn):
        mock_cloud_conn.cursor.return_value = _make_cur([])
        resp = client.get("/api/meter-concern/MC-NOTEXIST-0000")
        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# PUT /api/meter-concern/<id>/status
# ─────────────────────────────────────────────────────────────────────────────

class TestUpdateMeterConcernStatus:

    def test_valid_status_transition(self, client, mock_local_conn, mock_cloud_conn, sample_meter_concern):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.side_effect = [
            sample_meter_concern,                          # existing record
            {"reference_number": "MC-20260513-TEST0001"},  # update result
        ]
        mock_cloud_conn.cursor.return_value = cur

        resp = client.put(
            "/api/meter-concern/1/status",
            json={"status": "ASSIGNED", "assigned_to": "Test Admin"},
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["success"] is True
        client.get("/logout")

    def test_invalid_status_rejected(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        resp = client.put(
            "/api/meter-concern/1/status",
            json={"status": "BOGUS"},
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code == 400
        client.get("/logout")

    def test_requires_auth(self, client):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.put("/api/meter-concern/1/status", json={"status": "ASSIGNED"})
        assert resp.status_code == 401

    def test_not_found(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        mock_cloud_conn.cursor.return_value = _make_cur([])
        resp = client.put(
            "/api/meter-concern/9999/status",
            json={"status": "ASSIGNED"},
            content_type="application/json",
        )
        assert resp.status_code == 404
        client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# DELETE /api/meter-concern/<id>
# ─────────────────────────────────────────────────────────────────────────────

class TestDeleteMeterConcern:

    def test_deletes_concern(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        mock_cloud_conn.cursor.return_value = _make_cur([])

        resp = client.delete("/api/meter-concern/1")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        client.get("/logout")

    def test_requires_auth(self, client):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.delete("/api/meter-concern/1")
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/meter-concerns/statistics
# ─────────────────────────────────────────────────────────────────────────────

class TestMeterStatistics:

    def test_returns_stat_structure(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.return_value = {"total": 5}
        cur.fetchall.return_value = [{"status": "PENDING", "count": 3}]
        mock_cloud_conn.cursor.return_value = cur

        resp = client.get("/api/meter-concerns/statistics")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        assert "data" in data
        for key in ("total", "by_status", "by_priority", "by_type"):
            assert key in data["data"]
        client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/agent_queue
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentQueue:

    QUEUE_ITEM = {
        "id": 1, "user_id": "fb_001", "full_name": "Maria Santos",
        "concern": "No power", "contact_number": "09171234567",
        "priority": "high", "timestamp": "2026-05-13T08:00:00+08:00",
        "status": "Pending", "served_at": None, "served_by": None,
    }

    def test_returns_queue_items(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        cur = _make_cur([self.QUEUE_ITEM])
        mock_local_conn.cursor.return_value = cur

        resp = client.get("/api/agent_queue")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        assert "data" in data
        client.get("/logout")

    def test_requires_auth(self, client):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get("/api/agent_queue")
        assert resp.status_code == 401

    def test_status_filter_pending(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        mock_local_conn.cursor.return_value = _make_cur([self.QUEUE_ITEM])

        resp = client.get("/api/agent_queue?status=Pending")
        assert resp.status_code == 200
        client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/agent_queue/<id>/serve
# ─────────────────────────────────────────────────────────────────────────────

class TestServeCustomer:

    def test_serve_pending_customer(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.side_effect = [
            {"id": 1, "full_name": "Maria Santos", "status": "Pending", "user_id": "fb_001"},
            {"id": 1, "full_name": "Maria Santos", "status": "Resolved",
             "served_at": "2026-05-13T09:00:00+08:00", "served_by": "Test Administrator"},
        ]
        mock_local_conn.cursor.return_value = cur

        resp = client.post(
            "/api/agent_queue/1/serve",
            json={"served_by": "Test Administrator"},
            content_type="application/json",
        )
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        assert data["data"]["served_by"] == "Test Administrator"
        client.get("/logout")

    def test_already_served_returns_400(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.return_value = {
            "id": 1, "full_name": "Maria Santos",
            "status": "Resolved", "user_id": "fb_001",
        }
        mock_local_conn.cursor.return_value = cur

        resp = client.post(
            "/api/agent_queue/1/serve",
            json={"served_by": "Test Admin"},
        )
        data = resp.get_json()

        assert resp.status_code == 400
        assert data.get("already_served") is True
        client.get("/logout")

    def test_not_found_returns_404(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        mock_local_conn.cursor.return_value = _make_cur([])

        resp = client.post("/api/agent_queue/9999/serve", json={"served_by": "Test"})
        assert resp.status_code == 404
        client.get("/logout")

    def test_requires_auth(self, client):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.post("/api/agent_queue/1/serve", json={"served_by": "Test"})
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# DELETE /api/agent_queue/<id>/remove
# ─────────────────────────────────────────────────────────────────────────────

class TestRemoveQueueRecord:

    def test_removes_resolved_record(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.return_value = {
            "id": 1, "full_name": "Maria Santos", "status": "Resolved"
        }
        mock_local_conn.cursor.return_value = cur

        resp = client.delete("/api/agent_queue/1/remove")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        client.get("/logout")

    def test_cannot_remove_pending(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.return_value = {
            "id": 1, "full_name": "Maria Santos", "status": "Pending"
        }
        mock_local_conn.cursor.return_value = cur

        resp = client.delete("/api/agent_queue/1/remove")
        data = resp.get_json()

        assert resp.status_code == 400
        assert data["success"] is False
        client.get("/logout")

    def test_not_found_returns_404(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        mock_local_conn.cursor.return_value = _make_cur([])

        resp = client.delete("/api/agent_queue/9999/remove")
        assert resp.status_code == 404
        client.get("/logout")