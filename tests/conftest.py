"""
tests/conftest.py

Shared pytest fixtures.
All tests use an in-memory SQLite-equivalent configuration so they
run on any machine without needing the real Postgres servers.

The app is imported via the factory pattern (create_app) with
TestingConfig so:
  - TESTING = True
  - WTF_CSRF_ENABLED = False
  - Rate limiting is disabled
  - Session cookies are insecure (HTTP allowed)

Database mocking strategy:
  - We patch db.pool.get_local_conn / get_cloud_conn / get_joblist_conn
    so routes that call them receive a real in-memory SQLite connection.
  - SQLite is close enough for unit-testing JSON responses and HTTP
    status codes. Integration tests that require PostGIS are skipped.
"""
import pytest
from unittest.mock import MagicMock, patch
from werkzeug.security import generate_password_hash


# ─────────────────────────────────────────────────────────────────────────────
# APP FIXTURE
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def app():
    """Create and configure the Flask app for testing."""
    import os
    os.environ.setdefault("FLASK_ENV", "testing")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-do-not-use-in-prod")
    os.environ.setdefault("LOCAL_DB_HOST", "localhost")
    os.environ.setdefault("LOCAL_DB_PASSWORD", "")
    os.environ.setdefault("CLOUD_DB_HOST", "")
    os.environ.setdefault("JOBLIST_DB_HOST", "")

    from app import create_app
    application = create_app()
    application.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SESSION_COOKIE_SECURE": False,
        "SECRET_KEY": "test-secret-key",
        "RATELIMIT_STORAGE_URI": "memory://",
        "RATELIMIT_ENABLED": False,
    })
    yield application


@pytest.fixture(scope="session")
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture(scope="session")
def runner(app):
    """Flask test CLI runner."""
    return app.test_cli_runner()


# ─────────────────────────────────────────────────────────────────────────────
# MOCK DB FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

def _make_mock_cursor(rows=None, description=None):
    """Build a mock psycopg2 cursor that returns given rows."""
    cur = MagicMock()
    rows = rows or []
    cur.fetchone.return_value = rows[0] if rows else None
    cur.fetchall.return_value = rows
    cur.rowcount = len(rows)
    if description:
        cur.description = description
    return cur


def _make_mock_conn(cursor=None):
    """Build a mock psycopg2 connection."""
    conn = MagicMock()
    conn.cursor.return_value = cursor or _make_mock_cursor()
    conn.commit.return_value = None
    conn.rollback.return_value = None
    conn.close.return_value = None
    return conn


@pytest.fixture
def mock_local_conn():
    """Patch get_local_conn to return a mock connection."""
    conn = _make_mock_conn()
    with patch("db.pool.get_local_conn", return_value=conn), \
         patch("db.pool.release_local_conn"):
        yield conn


@pytest.fixture
def mock_cloud_conn():
    """Patch get_cloud_conn to return a mock connection."""
    conn = _make_mock_conn()
    with patch("db.pool.get_cloud_conn", return_value=conn), \
         patch("db.pool.release_cloud_conn"):
        yield conn


# ─────────────────────────────────────────────────────────────────────────────
# AUTH FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

ADMIN_PASSWORD = "Admin@1234"
ADMIN_USER = {
    "id": 1,
    "username": "admin",
    "full_name": "Test Administrator",
    "role": "superadmin",
    "is_active": True,
    "password_hash": generate_password_hash(ADMIN_PASSWORD),
}

STAFF_USER = {
    "id": 2,
    "username": "juana",
    "full_name": "Juana Dela Cruz",
    "role": "staff",
    "is_active": True,
    "password_hash": generate_password_hash("Staff@1234"),
}


def _login(client, username, password):
    """Helper to POST /login and return the response."""
    return client.post(
        "/login",
        json={"username": username, "password": password},
        content_type="application/json",
    )


@pytest.fixture
def auth_admin(client, mock_local_conn):
    """
    Fixture that logs in as superadmin and yields the authenticated client.
    The session is maintained via the test client's cookie jar.
    """
    cur = _make_mock_cursor(rows=[ADMIN_USER])
    mock_local_conn.cursor.return_value = cur

    resp = _login(client, ADMIN_USER["username"], ADMIN_PASSWORD)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    yield client

    # Logout after test
    client.get("/logout")


@pytest.fixture
def auth_staff(client, mock_local_conn):
    """Fixture that logs in as staff and yields the authenticated client."""
    cur = _make_mock_cursor(rows=[STAFF_USER])
    mock_local_conn.cursor.return_value = cur

    resp = _login(client, STAFF_USER["username"], "Staff@1234")
    assert resp.status_code == 200
    yield client
    client.get("/logout")


# ─────────────────────────────────────────────────────────────────────────────
# SAMPLE DATA FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_incident():
    return {
        "incident_id": 1,
        "incident_type": "power_outage",
        "barangay": "Ungka I",
        "town": "Pavia",
        "location_display": "Ungka I, Pavia",
        "report_count": 3,
        "status": "NEW",
        "priority": "HIGH",
        "first_report_time": "2026-05-13T08:00:00+08:00",
        "last_report_time": "2026-05-13T09:00:00+08:00",
        "job_order_id": "JO-20260513-UNG-A1B2",
        "assigned_at": None,
        "restored_at": None,
        "assigned_by": None,
        "restored_by": None,
        "remarks": None,
        "lat": 10.7890,
        "lng": 122.5621,
        "feeder_name": "Feeder 11",
        "feeder_status": None,
        "feeder_is_active": False,
        "earliest_report_timestamp": "2026-05-13T08:00:00+08:00",
        "incident_time": "08:00:00",
    }


@pytest.fixture
def sample_report():
    return {
        "report_id": 1,
        "incident_id": 1,
        "full_name": "Maria Santos",
        "contact_number": "09171234567",
        "email": "maria@test.com",
        "account_number": "1234567890",
        "address": "123 Rizal St",
        "town": "Pavia",
        "barangay": "Ungka I",
        "details": "No power since 6am",
        "landmark": "Near Jollibee",
        "incident_type": "power_outage",
        "priority": "HIGH",
        "status": "NEW",
        "feeder_name": "Feeder 11",
        "lat": 10.789,
        "lng": 122.562,
    }


@pytest.fixture
def sample_meter_concern():
    return {
        "id": 1,
        "reference_number": "MC-20260513-TEST0001",
        "account_number": "1234567890",
        "consumer_name": "Maria Santos",
        "contact_number": "09171234567",
        "meter_number": "M-001234",
        "service_address": "123 Rizal St",
        "barangay": "Ungka I",
        "concern_type": "not_working",
        "date_noticed": "2026-05-12",
        "is_critical": False,
        "priority": "high",
        "status": "PENDING",
        "created_at": "2026-05-13T08:00:00+08:00",
        "updated_at": "2026-05-13T08:00:00+08:00",
        "resolved_at": None,
        "assigned_to": None,
    }