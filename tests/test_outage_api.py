"""
tests/test_outage_api.py

Tests for:
  GET  /api/incidents
  GET  /api/incident/<id>
  GET  /api/dashboard_stats
  GET  /api/badge_counts
  GET  /api/recent_outages
  GET  /api/map_reports
  POST /api/submit_power_outage
  POST /api/update_incident_status/<id>
  POST /api/incident/<id>/remarks
  DELETE /api/incident/<id>/remove
  DELETE /api/report/<id>/remove
"""
import pytest
import json
from unittest.mock import MagicMock, patch, call

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
    """Log in as admin."""
    mock_local_conn.cursor.return_value = _make_cur([ADMIN_USER])
    _login(client, "admin", ADMIN_PASSWORD)


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/incidents
# ─────────────────────────────────────────────────────────────────────────────

class TestGetIncidents:

    def test_returns_success_json(self, client, mock_local_conn, mock_cloud_conn, sample_incident):
        _auth(client, mock_local_conn)
        mock_cloud_conn.cursor.return_value = _make_cur([sample_incident])

        resp = client.get("/api/incidents")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        assert "incidents" in data
        assert "count" in data
        client.get("/logout")

    def test_unauthenticated_returns_401(self, client):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.get("/api/incidents")
        assert resp.status_code == 401

    def test_status_filter_accepted(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        mock_cloud_conn.cursor.return_value = _make_cur([])

        for status in ("NEW", "ASSIGNED", "RESTORED", "all"):
            resp = client.get(f"/api/incidents?status={status}")
            assert resp.status_code == 200

        client.get("/logout")

    def test_cloud_db_unavailable_returns_503(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        with patch("db.pool.get_cloud_conn", return_value=None):
            resp = client.get("/api/incidents")
        assert resp.status_code == 503
        client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/incident/<id>
# ─────────────────────────────────────────────────────────────────────────────

class TestGetIncidentDetail:

    def test_existing_incident(self, client, mock_local_conn, mock_cloud_conn, sample_incident):
        _auth(client, mock_local_conn)
        cur = _make_cur([sample_incident])
        cur.fetchall.return_value = []   # no reports
        mock_cloud_conn.cursor.return_value = cur

        resp = client.get("/api/incident/1")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        assert "data" in data
        client.get("/logout")

    def test_missing_incident_returns_404(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        mock_cloud_conn.cursor.return_value = _make_cur([])  # not found

        resp = client.get("/api/incident/999")
        data = resp.get_json()

        assert resp.status_code == 404
        assert data["success"] is False
        client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/dashboard_stats
# ─────────────────────────────────────────────────────────────────────────────

class TestDashboardStats:

    def test_returns_all_stat_keys(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.side_effect = [(5,), (42,), (2,), (18,)]  # 4 queries
        mock_cloud_conn.cursor.return_value = cur

        resp = client.get("/api/dashboard_stats")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        stats = data["stats"]
        for key in ("active_outages", "affected_consumers", "critical_incidents", "reports_today"):
            assert key in stats, f"Missing stat: {key}"
        client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# GET /api/badge_counts
# ─────────────────────────────────────────────────────────────────────────────

class TestBadgeCounts:

    def test_returns_counts_dict(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        # Cloud cursor returns outages + meter counts
        cloud_cur = MagicMock()
        cloud_cur.fetchone.side_effect = [(3,), (1,)]
        mock_cloud_conn.cursor.return_value = cloud_cur
        # Local cursor returns queue count
        local_cur = MagicMock()
        local_cur.fetchone.return_value = (2,)
        mock_local_conn.cursor.return_value = local_cur

        resp = client.get("/api/badge_counts")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        for key in ("outages", "meter", "queue"):
            assert key in data["counts"]
        client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/submit_power_outage  (public route — no auth needed)
# ─────────────────────────────────────────────────────────────────────────────

class TestSubmitPowerOutage:

    VALID_PAYLOAD = {
        "full_name":      "Maria Santos",
        "contact_number": "09171234567",
        "address":        "123 Rizal St",
        "details":        "No power since 6am in our entire street",
        "town":           "Pavia",
        "barangay":       "Ungka I",
        "latitude":       10.789,
        "longitude":      122.562,
        "incident_type":  "power_outage",
        "source":         "Web Form",
    }

    def test_valid_submission(self, client, mock_cloud_conn):
        cloud_cur = MagicMock()
        # feeder validation → not found (returns None = skip feeder)
        cloud_cur.fetchone.side_effect = [
            None,                             # feeder validation
            None,                             # duplicate check
            None,                             # existing incident
            {"incident_id": 1},               # new incident insert
            {"report_id": 10, "local_ts": "2026-05-13T08:00:00"},  # report insert
        ]
        mock_cloud_conn.cursor.return_value = cloud_cur

        with patch("blueprints.outage.get_cloud_conn", return_value=mock_cloud_conn), \
             patch("blueprints.outage.release_cloud_conn"):
            resp = client.post(
                "/api/submit_power_outage",
                json=self.VALID_PAYLOAD,
                content_type="application/json",
            )
        data = resp.get_json()
        assert resp.status_code in (201, 200)
        assert data.get("success") is True

    def test_missing_required_field(self, client):
        payload = dict(self.VALID_PAYLOAD)
        del payload["contact_number"]
        resp = client.post("/api/submit_power_outage", json=payload)
        data = resp.get_json()
        assert resp.status_code == 400
        assert data["success"] is False

    def test_invalid_contact_number(self, client):
        payload = dict(self.VALID_PAYLOAD, contact_number="123")
        resp = client.post("/api/submit_power_outage", json=payload)
        data = resp.get_json()
        assert resp.status_code == 400
        assert data["success"] is False

    def test_invalid_coordinates_outside_ph(self, client):
        payload = dict(self.VALID_PAYLOAD, latitude=0.0, longitude=0.0)
        resp = client.post("/api/submit_power_outage", json=payload)
        data = resp.get_json()
        assert resp.status_code == 400
        assert data["success"] is False

    def test_missing_coordinates(self, client):
        payload = dict(self.VALID_PAYLOAD)
        del payload["latitude"]
        resp = client.post("/api/submit_power_outage", json=payload)
        data = resp.get_json()
        assert resp.status_code == 400
        assert data["success"] is False

    def test_invalid_email_rejected(self, client):
        payload = dict(self.VALID_PAYLOAD, email="notanemail")
        resp = client.post("/api/submit_power_outage", json=payload)
        data = resp.get_json()
        assert resp.status_code == 400
        assert data["success"] is False


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/update_incident_status/<id>
# ─────────────────────────────────────────────────────────────────────────────

class TestUpdateIncidentStatus:

    def test_valid_status_change(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        result_row = {"incident_id": 1, "barangay": "Ungka I", "town": "Pavia",
                      "assigned_by": "Test Admin", "restored_by": None}
        mock_cloud_conn.cursor.return_value = _make_cur([result_row])

        resp = client.post(
            "/api/update_incident_status/1",
            json={"status": "ASSIGNED"},
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["success"] is True
        client.get("/logout")

    def test_invalid_status_rejected(self, client, mock_local_conn):
        _auth(client, mock_local_conn)
        resp = client.post(
            "/api/update_incident_status/1",
            json={"status": "INVALID_STATUS"},
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code == 400
        assert data["success"] is False
        client.get("/logout")

    def test_requires_auth(self, client):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.post(
            "/api/update_incident_status/1",
            json={"status": "ASSIGNED"},
        )
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# POST /api/incident/<id>/remarks
# ─────────────────────────────────────────────────────────────────────────────

class TestUpdateRemarks:

    def test_saves_remarks(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        result_row = {"incident_id": 1, "remarks": "Crew dispatched"}
        mock_cloud_conn.cursor.return_value = _make_cur([result_row])

        resp = client.post(
            "/api/incident/1/remarks",
            json={"remarks": "Crew dispatched"},
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["success"] is True
        client.get("/logout")

    def test_incident_not_found_returns_404(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        mock_cloud_conn.cursor.return_value = _make_cur([])  # nothing found

        resp = client.post(
            "/api/incident/9999/remarks",
            json={"remarks": "test"},
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code == 404
        assert data["success"] is False
        client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# DELETE /api/incident/<id>/remove
# ─────────────────────────────────────────────────────────────────────────────

class TestRemoveIncident:

    def test_removes_existing_incident(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.return_value = {"incident_id": 1}
        mock_cloud_conn.cursor.return_value = cur

        resp = client.delete("/api/incident/1/remove")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        client.get("/logout")

    def test_not_found_returns_404(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        mock_cloud_conn.cursor.return_value = _make_cur([])

        resp = client.delete("/api/incident/9999/remove")
        data = resp.get_json()

        assert resp.status_code == 404
        assert data["success"] is False
        client.get("/logout")

    def test_requires_auth(self, client):
        with client.session_transaction() as sess:
            sess.clear()
        resp = client.delete("/api/incident/1/remove")
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# DELETE /api/report/<id>/remove
# ─────────────────────────────────────────────────────────────────────────────

class TestRemoveReport:

    def test_removes_report(self, client, mock_local_conn, mock_cloud_conn):
        _auth(client, mock_local_conn)
        cur = MagicMock()
        cur.fetchone.side_effect = [
            {"report_id": 1, "incident_id": 1},  # report found
            {"report_count": 2},                  # incident updated
        ]
        mock_cloud_conn.cursor.return_value = cur

        resp = client.delete("/api/report/1/remove")
        data = resp.get_json()

        assert resp.status_code == 200
        assert data["success"] is True
        client.get("/logout")