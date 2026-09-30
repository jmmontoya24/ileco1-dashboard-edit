import os
# ── FIX: eventlet's monkey-patched DNS resolver (greendns) hardcodes
# Google's public DNS (8.8.8.8 / 8.8.4.4) instead of using this
# machine's configured resolver. On networks where those IPs are
# blocked/unreachable (corporate firewalls, some ISPs, VPNs), EVERY
# hostname lookup made through eventlet-patched sockets times out —
# this is why the cloud Supabase host and the realtime listener both
# fail to resolve, even though the SAME hostname resolves fine outside
# Python (e.g. via nslookup or a browser). Setting this env var before
# monkey_patch() tells eventlet to skip greendns and fall back to the
# OS's normal, non-green DNS resolution, which respects whatever DNS
# server(s) this machine is actually configured to use.
os.environ['EVENTLET_NO_GREENDNS'] = 'yes'

import eventlet
eventlet.monkey_patch()
from psycogreen.eventlet import patch_psycopg
patch_psycopg()
import os
import logging
from datetime import datetime, timedelta, timezone,time
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory, flash
import json
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import traceback
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import secrets
import uuid
from werkzeug.utils import secure_filename
import pytz
from flask.json.provider import DefaultJSONProvider
from datetime import date, datetime, time, timedelta
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler
import requests
import dns.resolver
import time as _time_module
import uuid as _uuid_module
from datetime import datetime as _datetime
import pytz as _pytz
import re
from collections import defaultdict
import hashlib
import requests as _req
import os
import threading as _threading
from flask_wtf.csrf import CSRFError
import difflib



_LOGIN_MAX_ATTEMPTS     = 5
_LOGIN_LOCKOUT_WINDOW   = timedelta(minutes=15)   # window for counting failures
_LOGIN_LOCKOUT_DURATION = timedelta(minutes=15)   # how long account stays locked

_login_fail_store  = {}   # in-memory fallback: username -> {'count', 'first_attempt'}
_login_lock_store  = {}   # in-memory fallback: username -> lockout_until (epoch)
_login_lock_thread_lock = _threading.Lock()

_manually_paused_senders = set()
_manual_pause_lock = _threading.Lock()


def _is_account_locked(username: str):
    """Returns (is_locked: bool, seconds_remaining: int)."""
    key = f"login_lock:{username}"

    if _redis_client:
        try:
            ttl = _redis_client.ttl(key)
            if ttl and ttl > 0:
                return True, ttl
            return False, 0
        except Exception as e:
            logger.warning(f"Redis login-lock check failed, falling back to memory: {e}")

    # In-memory fallback
    now = _time_module.time()
    with _login_lock_thread_lock:
        until = _login_lock_store.get(username)
        if not until:
            return False, 0
        if now >= until:
            _login_lock_store.pop(username, None)
            _login_fail_store.pop(username, None)
            return False, 0
        return True, int(until - now)


def _register_failed_login(username: str):
    key_attempts = f"login_attempts:{username}"
    key_lock     = f"login_lock:{username}"

    if _redis_client:
        try:
            count = _redis_client.incr(key_attempts)
            if count == 1:
                _redis_client.expire(key_attempts, int(_LOGIN_LOCKOUT_WINDOW.total_seconds()))
            if count >= _LOGIN_MAX_ATTEMPTS:
                _redis_client.setex(key_lock, int(_LOGIN_LOCKOUT_DURATION.total_seconds()), "1")
                logger.warning(
                    f"🔒 Account '{username}' locked for {_LOGIN_LOCKOUT_DURATION} "
                    f"after {count} failed login attempts (Redis)"
                )
            return
        except Exception as e:
            logger.warning(f"Redis login-fail registration failed, falling back to memory: {e}")

    # In-memory fallback
    now = _time_module.time()
    with _login_lock_thread_lock:
        entry = _login_fail_store.get(username)
        if not entry or (now - entry['first_attempt']) > _LOGIN_LOCKOUT_WINDOW.total_seconds():
            entry = {'count': 0, 'first_attempt': now}
        entry['count'] += 1
        _login_fail_store[username] = entry
        if entry['count'] >= _LOGIN_MAX_ATTEMPTS:
            _login_lock_store[username] = now + _LOGIN_LOCKOUT_DURATION.total_seconds()
            logger.warning(
                f"🔒 Account '{username}' locked for {_LOGIN_LOCKOUT_DURATION} "
                f"after {entry['count']} failed login attempts (in-memory)"
            )


def _clear_failed_login(username: str):
    if _redis_client:
        try:
            _redis_client.delete(f"login_attempts:{username}", f"login_lock:{username}")
            return
        except Exception as e:
            logger.warning(f"Redis login-fail clear failed, falling back to memory: {e}")

    with _login_lock_thread_lock:
        _login_fail_store.pop(username, None)
        _login_lock_store.pop(username, None)

FAILED_TOKENS = {}  # ip -> {'count': int, 'last_seen': datetime}
BLOCKED_IPS = {}
_FAILED_TOKEN_TTL = timedelta(hours=1)

_badge_cache = {'data': None, 'ts': 0}
_BADGE_CACHE_TTL = 10  # seconds

_outages_cache = {'data': None, 'ts': 0}
_OUTAGES_CACHE_TTL = 10  # seconds

def _prune_failed_tokens():
    cutoff = datetime.now() - _FAILED_TOKEN_TTL
    stale = [ip for ip, v in FAILED_TOKENS.items() if v['last_seen'] < cutoff]
    for ip in stale:
        FAILED_TOKENS.pop(ip, None)

_PH_TZ = _pytz.timezone('Asia/Manila')

FEEDER_TABLE = '"ILECO_1_COVERAGE_AREA_FEEDERS_FINALoutput"'
FEEDER_NAME_COL = 'layer'
EXCLUDED_FEEDER = 'FEEDER_12A_FINAL'

# Columns that may or may not exist on the coverage table depending on
# how it was exported from QGIS/Supabase. Detected once at startup so
# a missing column degrades to NULL instead of throwing UndefinedColumn
# and surfacing as "Feeder Detection Temporarily unavailable" on the form.
_FEEDER_OPTIONAL_COLS = ['status', 'cause', 'start_time', 'end_time', 'outage_type', 'is_active']
_feeder_available_cols = None
TOWN_CODE_MAP = {
    'Cabatuan':    'CA',
    'Alimodian':   'AL',
    'Guimbal':     'GU',
    'Igbaras':     'IG',
    'Leganes':     'LG',
    'Leon':        'LE',
    'Maasin':      'MA',
    'Miag-ao':     'MI',
    'Oton':        'OT',
    'Pavia':       'PV',
    'San Joaquin': 'SJ',
    'San Miguel':  'SM',
    'Sta. Barbara':'SB',
    'Tigbauan':    'TG',
    'Tubungan':    'TU',
}
SUPABASE_STORAGE_BUCKET = os.getenv('SUPABASE_STORAGE_BUCKET', 'outage-evidence')
SUPABASE_PUBLIC_BUCKET  = os.getenv('SUPABASE_PUBLIC_BUCKET', 'outage-advisories')
ALLOWED_PHOTO_MIME = {
    'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp',
    'video/mp4': 'mp4', 'video/quicktime': 'mov', 'video/webm': 'webm',
}
MAX_PHOTO_BYTES = 20 * 1024 * 1024  # 20MB — covers short video clips
SUPABASE_METER_EVIDENCE_BUCKET = os.getenv('SUPABASE_METER_EVIDENCE_BUCKET', 'meter-evidence')
ALLOWED_METER_EVIDENCE_MIME = {'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp'}
MAX_METER_EVIDENCE_BYTES = 2 * 1024 * 1024   # 2MB — matches the bucket policy
MAX_METER_EVIDENCE_FILES = 5

# Validate config constants at startup — prevents SQL injection via config
SAFE_FEEDER_NAME_RE = re.compile(r'^[A-Za-z0-9_\- ]+$')

def _get_feeder_available_columns():
    global _feeder_available_cols
    if _feeder_available_cols is not None:
        return _feeder_available_cols
    cols = set()
    ok = False
    conn = get_db_connection()
    if conn:
        cur = None
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'ILECO_1_COVERAGE_AREA_FEEDERS_FINALoutput'
            """)
            cols = {r[0] for r in cur.fetchall()}
            ok = True
        except Exception as e:
            logger.warning(f"Could not introspect feeder table columns: {e}")
        finally:
            if cur: cur.close()
            release_db_connection(conn)
    if ok:
        _feeder_available_cols = cols
        logger.info(f"Feeder optional columns available: {cols & set(_FEEDER_OPTIONAL_COLS)}")
    return cols

def _feeder_optional_select() -> str:
    """Builds 'status, cause, NULL AS start_time, ...' based on what actually exists."""
    available = _get_feeder_available_columns()
    parts = [c if c in available else f'NULL AS {c}' for c in _FEEDER_OPTIONAL_COLS]
    return ', '.join(parts)
    

def _validate_config_constants():
    for name, val in [('FEEDER_NAME_COL', FEEDER_NAME_COL),
                      ('EXCLUDED_FEEDER', EXCLUDED_FEEDER)]:
        if not SAFE_FEEDER_NAME_RE.match(val):
            raise ValueError(f'Unsafe config constant {name}={val!r}')

TIMESTAMP_COLUMN = None

# ── Put get_timestamp_column_name FIRST ──
def get_timestamp_column_name():
    conn = get_db_connection()
    if not conn:
        return 'created_at'
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'outage_reports' 
            AND column_name IN ('timestamp', 'created_at')
        """)
        columns = [row[0] for row in cur.fetchall()]
        if 'timestamp' in columns:
            return 'timestamp'
        elif 'created_at' in columns:
            return 'created_at'
        else:
            return 'created_at'
    except Exception as e:
        return 'created_at'
    finally:
        if cur: cur.close()
        release_db_connection(conn)

# ── Then initialize_timestamp_column SECOND ──
def initialize_timestamp_column():
    """Initialize the timestamp column name on startup"""
    global TIMESTAMP_COLUMN
    TIMESTAMP_COLUMN = get_timestamp_column_name()
    logger.info(f"✅ Using timestamp column: {TIMESTAMP_COLUMN}")
# ============================================
# CONFIGURATION & INITIALIZATION
# ============================================
load_dotenv(override=True)

import sys
print(f"[Startup] JOBLIST_DB_PASSWORD configured: {bool(os.getenv('JOBLIST_DB_PASSWORD'))}", flush=True)
print(f"[Startup] LOCAL_DB_PASSWORD configured: {bool(os.getenv('LOCAL_DB_PASSWORD'))}", flush=True)

# Constants
PHILIPPINE_TZ = pytz.timezone('Asia/Manila')
UPLOAD_FOLDER = 'uploads/meter_concerns'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'webp'}

app = Flask(__name__, template_folder="templates", static_folder="static")
logger = app.logger

import logging as _logging
_startup_logger = _logging.getLogger(__name__)

secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    raise RuntimeError(
        'SECRET_KEY environment variable is not set. '
        'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
    )
app.secret_key = secret_key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_SECURE'] = (
    os.getenv('RAILWAY_ENVIRONMENT') is not None
    or os.getenv('FLASK_ENV') == 'production'
)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 24 * 1024 * 1024  # headroom above per-file 20MB cap
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Static assets (ileco-geodata.js, etc.) are immutable per-deploy —
# cache them for a week client-side so the ~40KB geodata file is
# fetched once and reused across every page view/navigation instead
# of being re-downloaded and re-parsed on every request.
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 7 * 24 * 60 * 60  # 7 days
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

# ── FIX: align CSRF token lifetime with the session lifetime.
# Flask-WTF's default WTF_CSRF_TIME_LIMIT is 3600s (1 hour), but
# PERMANENT_SESSION_LIFETIME is 24 hours. Pages like agent_queue.html
# are routinely left open by agents far longer than an hour while
# waiting for a pending customer. Once the CSRF token (baked into the
# page's <meta name="csrf-token"> at page-load time) outlived its
# 1-hour validity window — while the session cookie was still valid —
# every POST (Serve/Resolve, Pause, Remove, etc.) was rejected by
# csrf.protect() with "Your session has expired or the request could
# not be verified," even though the agent was still legitimately
# logged in. Tying this to PERMANENT_SESSION_LIFETIME means the CSRF
# token and the session expire together instead of the token dying
# first.
app.config['WTF_CSRF_TIME_LIMIT'] = int(app.config['PERMANENT_SESSION_LIFETIME'].total_seconds())

csrf = CSRFProtect(app)

_cors_origins = [
    o.strip()
    for o in os.getenv('CORS_ORIGINS', 'http://localhost:5000').split(',')
    if o.strip()
]

def _cors_preflight_response(allow_headers, allow_credentials=False):
    """Build an OPTIONS preflight response using the same origin
    whitelist as the rest of the app, instead of a hardcoded '*'."""
    origin = request.headers.get('Origin', '')
    response = jsonify({'status': 'ok'})
    if origin in _cors_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Vary'] = 'Origin'
    response.headers['Access-Control-Allow-Headers'] = allow_headers
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    if allow_credentials:
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response, 200

socketio = SocketIO(
    app,
    cors_allowed_origins=_cors_origins,
    async_mode='eventlet',
    ping_timeout=60,
    ping_interval=25,
    logger=False,
    engineio_logger=False,
    manage_session=False,
    always_connect=True,
    transports=['websocket', 'polling'],   # was ['polling'] only
    max_http_buffer_size=1_000_000,
    allow_upgrades=True,                    # was False
)

CORS(app,
     origins=_cors_origins,
     supports_credentials=True,
     allow_headers=['Content-Type', 'Accept', 'X-Requested-With',
                    'X-Form-Token', 'X-Submit-Time'],
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
)

_redis_url_env = os.getenv('REDIS_URL', '')
_is_production_env = (
    os.getenv('RAILWAY_ENVIRONMENT') is not None
    or os.getenv('FLASK_ENV') == 'production'
)
if _is_production_env and not _redis_url_env:
    raise RuntimeError(
        'REDIS_URL is required in production. In-memory rate limiting '
        'and form tokens are bypassable and break silently under more '
        'than one worker/process. Set REDIS_URL, or set '
        'FLASK_ENV=development to run locally with the in-memory fallback.'
    )

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per day", "300 per hour"],
    storage_uri=_redis_url_env or 'memory://'
)

# Endpoints that are intentionally public / unauthenticated — these
# cannot carry a CSRF token because there's no session, so they are
# explicitly exempted by exact path. Everything else under /api/
# (including all session-authenticated admin endpoints) now goes
# through normal CSRF protection.
PUBLIC_API_ENDPOINTS = {
    '/api/submit_power_outage',
    '/api/upload_outage_photo',
    '/api/check_feeder',
    '/api/feeder_polygon',
    '/api/form_token',
    '/api/map_config',
    '/api/meter-concern',
    '/api/verify_masterlist',
    '/api/complaints_in_feeder',
    '/api/complaints_nearby',
    '/api/internal/agent_queue',
}

# Endpoints that are called SERVER-TO-SERVER by the Rasa action server
# (authenticated via X-Internal-Secret, not a browser session), but that
# don't live under the /api/internal/ prefix because they're also reachable
# from the dashboard UI's own JS in other flows. CSRF must be skipped for
# these ONLY when the request actually carries a valid internal secret —
# is_internal_request() is checked here, not just the path, so a browser
# without the secret still gets normal CSRF enforcement.
INTERNAL_SECRET_CSRF_EXEMPT_PREFIXES = (
    '/api/agent_queue/',   # covers .../confirm_resolved, .../rate, .../requeue
)

@app.before_request
def csrf_protect_routes():
    if request.method == 'OPTIONS':
        return None
    if request.path.startswith('/socket.io'):
        return None
    if request.path.startswith('/api/internal/'):
        return None
    if request.method == "POST" and request.path in PUBLIC_API_ENDPOINTS:
        return None
    if (request.method == "POST"
            and request.path.startswith(INTERNAL_SECRET_CSRF_EXEMPT_PREFIXES)
            and is_internal_request()):
        return None
    if request.method in ("POST", "PUT", "DELETE"):
        csrf.protect()

@app.before_request
def enforce_https():
    # Skip health checks entirely
    if request.path == '/health':
        return None
    # Railway (and most PaaS proxies) terminate SSL and forward X-Forwarded-Proto
    # Never redirect if we're already coming from https upstream
    forwarded_proto = request.headers.get('X-Forwarded-Proto', '')
    if forwarded_proto == 'https':
        return None
    # Only redirect if we are DIRECTLY on HTTP (not behind a proxy)
    # and the env var says we want HTTPS enforcement
    if (not request.is_secure
            and forwarded_proto != 'https'
            and os.getenv('FORCE_HTTPS', '').lower() == 'true'):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)
    return None

# ============================================
# LOGGING CONFIGURATION
# ============================================
os.makedirs('logs', exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

file_handler = RotatingFileHandler(
    'logs/app.log',
    maxBytes=10485760,
    backupCount=10,
    encoding='utf-8'
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
))

error_handler = RotatingFileHandler(
    'logs/errors.log',
    maxBytes=10485760,
    backupCount=5,
    encoding='utf-8'
)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(pathname)s:%(lineno)d: %(message)s'
))

app.logger.addHandler(file_handler)
app.logger.addHandler(error_handler)
app.logger.setLevel(logging.INFO)



for handler in logging.getLogger().handlers:
    if isinstance(handler, logging.StreamHandler):
        handler.stream.reconfigure(encoding='utf-8', errors='replace')

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Resource not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal error: {e}", exc_info=True)
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'success': False, 'error': ' You have reached the maximum of 5 reports per hour from your connection. '
        'Please wait 1 hour before submitting again. '
        'For emergencies (fallen wire, fire, electric shock) call 09989893028 immediately.'}), 429

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'success': False, 'error': 'File too large. Maximum size is 16MB.'}), 413

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    logger.warning(f"CSRF validation failed on {request.method} {request.path}: {e.description}")
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False,
            'error': 'Your session has expired or the request could not be verified. Please refresh the page and try again.',
            'error_code': 'CSRF_INVALID'
        }), 400
    # Non-API pages (e.g. login/admin forms) still get a readable page
    return (
        '<h1>Session Expired</h1><p>Please refresh the page and try again.</p>',
        400,
    )

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(self)'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com "
        "https://cdnjs.cloudflare.com https://cdn.socket.io; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com "
        "https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https: blob:; "
        "media-src 'self' https://*.supabase.co blob:; "
        "connect-src 'self' https://*.supabase.co "
        "https://nominatim.openstreetmap.org https://api.mapbox.com "
        "https://graph.facebook.com; "
        "frame-ancestors 'self';"
    )
    return response



class CustomJSONProvider(DefaultJSONProvider):
    def default(self, obj):
        try:
            if isinstance(obj, (datetime, date)):
                return obj.isoformat()
            if isinstance(obj, timedelta):
                return str(obj)
            if obj is None:
                return None
        except Exception:
            pass
        return super().default(obj)

app.json = CustomJSONProvider(app)

local_db_pool = None
cloud_db_pool = None
joblist_db_pool = None

LOCAL_POOL_MAX = int(os.getenv('LOCAL_POOL_MAX', '3'))
_local_sem = _threading.BoundedSemaphore(LOCAL_POOL_MAX)
_local_pool_last_attempt = 0
_LOCAL_POOL_RETRY_SECONDS = 15

def initialize_local_pool():
    global local_db_pool, _local_pool_last_attempt
    if local_db_pool is not None:
        return True
    now = _time_module.time()
    if now - _local_pool_last_attempt < _LOCAL_POOL_RETRY_SECONDS:
        return False
    _local_pool_last_attempt = now
    try:
        local_db_pool = psycopg2.pool.ThreadedConnectionPool(
            1, LOCAL_POOL_MAX,
            host=os.getenv('LOCAL_DB_HOST', 'localhost'),
            port=int(os.getenv('LOCAL_DB_PORT', '5432')),
            database=os.getenv('LOCAL_DB_NAME', 'ileco1_user'),
            user=os.getenv('LOCAL_DB_USER', 'postgres'),
            password=os.getenv('LOCAL_DB_PASSWORD', ''),
            connect_timeout=4,
            **({} if int(os.getenv("LOCAL_DB_PORT", "5432")) == 6543
               else {'options': '-c statement_timeout=8000 -c timezone=Asia/Manila'})
        )
        logger.info("[OK] Local DB pool initialized")
        return True
    except Exception as e:
        logger.warning(f"[ERROR] Local DB pool failed — login will not work: {e}")
        local_db_pool = None
        return False

CLOUD_POOL_MAX = int(os.getenv('CLOUD_POOL_MAX', '5'))
_cloud_sem = _threading.BoundedSemaphore(CLOUD_POOL_MAX)   # greenthreads WAIT here instead of erroring
_cloud_init_lock = _threading.Lock()
_cloud_last_used = {}                                       # id(conn) -> epoch of last release
_CLOUD_PING_IDLE_SECONDS = 20

_cloud_pool_last_attempt = 0
_CLOUD_POOL_RETRY_SECONDS = 60


def initialize_cloud_pool():
    global cloud_db_pool, _cloud_pool_last_attempt
    with _cloud_init_lock:                       # only ONE greenthread may build the pool
        if cloud_db_pool is not None:
            return True

        now = _time_module.time()
        if now - _cloud_pool_last_attempt < _CLOUD_POOL_RETRY_SECONDS:
            return False
        _cloud_pool_last_attempt = now

        try:
            import socket
            host = os.getenv("CLOUD_DB_HOST", "")
            socket.getaddrinfo(host, None)

            cloud_db_pool = psycopg2.pool.ThreadedConnectionPool(
                1, CLOUD_POOL_MAX,
                host=host,
                port=int(os.getenv("CLOUD_DB_PORT", "5432")),
                database=os.getenv("CLOUD_DB_NAME"),
                user=os.getenv("CLOUD_DB_USER"),
                password=os.getenv("CLOUD_DB_PASSWORD"),
                connect_timeout=10,
                sslmode='require',
                keepalives=1,
                keepalives_idle=30,
                keepalives_interval=10,
                keepalives_count=5,
                   **({} if int(os.getenv("CLOUD_DB_PORT", "5432")) == 6543
      else {'options': '-c statement_timeout=8000 -c timezone=Asia/Manila'})
            )
            logger.info("[OK] Cloud DB pool initialized")
            return True
        except Exception:
            logger.exception("[ERROR] Cloud DB pool failed")
            cloud_db_pool = None
            return False


def _cloud_conn_healthy(conn) -> bool:
    if conn.closed:
        return False
    idle = _time_module.time() - _cloud_last_used.get(id(conn), 0)
    if idle < _CLOUD_PING_IDLE_SECONDS:
        return True                      # used moments ago — skip the extra round trip
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.rollback()
        return True
    except Exception:
        return False


def get_cloud_conn():
    global cloud_db_pool

    if not _cloud_sem.acquire(timeout=10):
        logger.error("Cloud DB: timed out waiting for a free connection slot")
        return None

    conn = None
    try:
        for attempt in range(3):
            if cloud_db_pool is None and not initialize_cloud_pool():
                break

            pool = cloud_db_pool
            try:
                candidate = pool.getconn()
            except Exception as e:
                logger.warning(
                    f"Cloud pool getconn failed (attempt {attempt + 1}/3): {e}"
                )
                _time_module.sleep(0.5 * (attempt + 1))   # green sleep under eventlet
                continue

            if _cloud_conn_healthy(candidate):
                conn = candidate
                break

            logger.warning("Discarding stale cloud connection")
            _cloud_last_used.pop(id(candidate), None)
            try:
                pool.putconn(candidate, close=True)
            except Exception as e:
                logger.warning(f"Failed to discard stale cloud connection: {e}")

        return conn
    finally:
        if conn is None:
            _cloud_sem.release()

def get_local_conn():
    global local_db_pool

    if not _local_sem.acquire(timeout=10):
        logger.error("Local DB: timed out waiting for a free connection slot")
        return None

    conn = None
    try:
        for attempt in range(3):
            if local_db_pool is None and not initialize_local_pool():
                break
            try:
                conn = local_db_pool.getconn()
                break
            except Exception as e:
                logger.warning(
                    f"Local pool getconn failed (attempt {attempt + 1}/3): {e}"
                )
                _time_module.sleep(0.5 * (attempt + 1))
        return conn
    finally:
        if conn is None:
            _local_sem.release()

def initialize_joblist_pool():
    global joblist_db_pool
    if joblist_db_pool is not None:
        return True
    try:
        # ── Joblist is on a SEPARATE server (172.17.100.6), not localhost ────
        db_host = os.getenv('JOBLIST_DB_HOST', '172.17.100.6')
        db_port = int(os.getenv('JOBLIST_DB_PORT', '5432'))
        db_name = os.getenv('JOBLIST_DB_NAME', 'joblist')
        db_user = os.getenv('JOBLIST_DB_USER', 'postgres')
        db_pass = os.getenv('JOBLIST_DB_PASSWORD', '')

        logger.info(
            f"[Joblist] Connecting → host={db_host}:{db_port} "
            f"db={db_name} user={db_user} "
            f"pass={'*' * len(db_pass) if db_pass else '(empty)'}"
        )

        joblist_db_pool = psycopg2.pool.ThreadedConnectionPool(
            1, 5,
            host=db_host,
            port=db_port,
            database=db_name,
            user=db_user,
            password=db_pass,
            connect_timeout=10,
            options='-c search_path=public'
        )
        logger.info(
            f"[OK] Joblist DB pool initialized — "
            f"connected to '{db_name}' at {db_host} as '{db_user}'"
        )
        return True
    except Exception as e:
        logger.exception(
            f"[ERROR] Joblist DB pool failed — OMMS assign will not work. "
            f"Tried: host={os.getenv('JOBLIST_DB_HOST', '172.17.100.6')} "
            f"db={os.getenv('JOBLIST_DB_NAME')} "
            f"user={os.getenv('JOBLIST_DB_USER')}"
        )
        joblist_db_pool = None
        return False

def get_joblist_conn():
    global joblist_db_pool
    if joblist_db_pool is None:
        initialize_joblist_pool()
    try:
        return joblist_db_pool.getconn() if joblist_db_pool else None
    except Exception as e:
        logger.exception("Error getting joblist DB connection")
        return None

def release_joblist_conn(conn):
    global joblist_db_pool
    try:
        if conn and joblist_db_pool:
            joblist_db_pool.putconn(conn)
    except Exception as e:
        logger.exception("Error releasing joblist connection")

def release_local_conn(conn):
    if not conn:
        return
    try:
        if local_db_pool:
            local_db_pool.putconn(conn)
        else:
            conn.close()
    except Exception:
        logger.exception("Error releasing local connection")
        try:
            conn.close()
        except Exception:
            pass
    finally:
        _local_sem.release()

def release_cloud_conn(conn):
    if not conn:
        return
    try:
        if cloud_db_pool:
            _cloud_last_used[id(conn)] = _time_module.time()
            cloud_db_pool.putconn(conn, close=bool(conn.closed))
        else:
            conn.close()
    except Exception:
        logger.exception("Error releasing cloud connection")
        try:
            conn.close()
        except Exception:
            pass
    finally:
        _cloud_sem.release()

def get_db_connection():
    return get_cloud_conn()

def release_db_connection(conn):
    release_cloud_conn(conn)

_SAFE_CHANNEL_RE = re.compile(r'^[a-z_][a-z0-9_]{0,62}$')

def notify_local(channel, payload):
    conn = None
    if not _SAFE_CHANNEL_RE.match(channel):
        return  # silently reject unsafe channel names
    try:
        conn = get_local_conn()
        if not conn:
            return
        old_level = conn.isolation_level
        conn.set_isolation_level(0)
        cur = conn.cursor()
        import json
        cur.execute(f"NOTIFY {channel}, %s", (json.dumps(payload),))
        cur.close()
        conn.set_isolation_level(old_level)
    except Exception as e:
        logger.warning(f"Local notify failed: {e}")
    finally:
        if conn:
            release_local_conn(conn)

def is_internal_request() -> bool:
    """
    Returns True for requests from Rasa or other internal services.
    
    On Railway: services talk via internal hostnames (not 127.0.0.1).
    We use a shared secret header instead of IP-based trust,
    which works both locally and on Railway.
    """
    # Method 1: Shared secret header (recommended for Railway)
    internal_secret = os.getenv('INTERNAL_API_SECRET', '')
    if internal_secret:
        request_secret = request.headers.get('X-Internal-Secret', '')
        if request_secret and request_secret == internal_secret:
            return True

    # Method 2: IP whitelist (works locally, fallback)
    allowed_ips = {
        '127.0.0.1', '::1',
        # Railway internal network
        '10.0.0.0', '172.16.0.0', '172.17.0.0', '172.18.0.0',
    }
    remote_ip = request.remote_addr or ''
    if remote_ip in allowed_ips:
        return True

    # Method 3: RFC-1918 private ranges (Docker/Railway internal)
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(remote_ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return True
    except ValueError:
        pass

    return False

def isoformat_safe(dt):
    """
    Serialize a datetime to ISO-8601 string, always with +08:00 offset.

    psycopg2 returns timezone-naive datetimes for columns stored as
    TIMESTAMP WITHOUT TIME ZONE (which is what TIMEZONE('Asia/Manila', ...)
    produces in PostgreSQL). Without an explicit offset, JavaScript's
    new Date() parses them as UTC — making PH timestamps appear 8 hours
    in the future and causing negative wait times in the dashboard.
    """
    if dt is None:
        return None
    try:
        if isinstance(dt, str):
            # Already a string — attach offset if missing
            if '+' not in dt and dt.count('-') <= 2 and not dt.endswith('Z'):
                return dt + '+08:00'
            return dt
        if isinstance(dt, datetime):
            if dt.tzinfo is None:
                # Naive datetime — assume it was stored as PH time
                dt = PHILIPPINE_TZ.localize(dt)
            else:
                dt = dt.astimezone(PHILIPPINE_TZ)
            return dt.isoformat()
        # date-only objects (no time component)
        return dt.isoformat()
    except Exception as e:
        logger.warning(f"Failed to convert datetime to ISO: {e}")
        return str(dt) if dt else None

def format_philippine_time(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = PHILIPPINE_TZ.localize(dt)
    else:
        dt = dt.astimezone(PHILIPPINE_TZ)
    return dt.strftime('%Y-%m-%dT%H:%M:%S+08:00')

_TOKEN_TTL = 7200        # tokens expire after 2 hours — the client now
                         # proactively refreshes every 45 min, so this is
                         # just a safety margin, not the primary defense

_redis_client = None
_token_store  = {}          # in-memory fallback: { token_str: issued_epoch }
_token_lock   = _threading.Lock()

def _init_token_backend():
    global _redis_client
    redis_url = os.getenv('REDIS_URL', '')
    if not redis_url or redis_url.startswith('memory://'):
        logger.warning(
            "⚠️ REDIS_URL not set — using in-memory token storage. "
            "Only safe for local, single-process development."
        )
        return
    try:
        import redis as _redis
        _redis_client = _redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=3)
        _redis_client.ping()
        logger.info("✅ Redis-backed form token store initialized")
    except Exception as e:
        if _is_production_env:
            raise RuntimeError(f'Redis connection failed in production: {e}') from e
        logger.error(f"❌ Redis connection failed ({e}) — falling back to in-memory token store")
        _redis_client = None

def initialize_feature_flags_table():
    """Create feature_flags table + seed default rows if missing (local DB)."""
    conn = get_local_conn()
    if not conn:
        return
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS feature_flags (
                flag_key    TEXT PRIMARY KEY,
                enabled     BOOLEAN NOT NULL DEFAULT TRUE,
                label       TEXT NOT NULL,
                description TEXT,
                updated_by  TEXT,
                updated_at  TIMESTAMP DEFAULT TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
            )
        """)
        # Seed every button your carousel actually gates on _BUTTON_FLAG_MAP
        defaults = [
            ('schedule_outage', 'Report Power Outage', 'Report Power Outage button'),
            ('follow_up_report', 'Follow-Up Report', 'Follow-Up Report button'),
            ('online_billing', 'Online Billing', 'Online Billing button'),
            ('payment_option', 'Payment Options', 'Payment Options button'),
            ('requirements_checklist', 'Requirements', 'Requirements checklist button'),
            ('schedule_pmos', 'PMOS Schedule', 'PMOS Schedule button'),
            ('download_forms', 'Application Forms', 'Application Forms button'),
            ('meter_concern', 'Meter Concern', 'Meter Concern (web_url) button'),
            ('transfer_of_meter', 'Transfer of Meter', 'Transfer of Meter button'),
            ('meter_concern_followup', 'Meter Follow-Up', 'Meter Follow-Up button'),
            ('contact_information', 'Contact Information', 'Contact Information button'),
            ('rates', 'Rates', 'Rates button'),
            ('office_location', 'Office Locations', 'Office Locations button'),
            ('talk_to_agent', 'Chat with an Agent', 'Chat with an Agent button — the one you want to toggle off'),
            ('report_power_outage', 'Report Power Outage (form)', 'Gate for the outage submission form'),
            ('energy_saving_tips', 'Energy Saving Tips', 'Energy saving tips response'),
        ]
        for key, label, desc in defaults:
            cur.execute("""
                INSERT INTO feature_flags (flag_key, enabled, label, description)
                VALUES (%s, TRUE, %s, %s)
                ON CONFLICT (flag_key) DO NOTHING
            """, (key, label, desc))
        conn.commit()
        logger.info("✅ feature_flags table ready (seeded defaults)")
    except Exception:
        try: conn.rollback()
        except Exception: pass
        logger.exception("Failed to initialize feature_flags table")
    finally:
        if cur: cur.close()
        release_local_conn(conn)

def _issue_form_token():
    import uuid as _uuid, time as _t
    token = str(_uuid.uuid4())

    if _redis_client:
        try:
            _redis_client.setex(f"form_token:{token}", _TOKEN_TTL, "1")
            return token
        except Exception as e:
            logger.warning(f"Redis setex failed, falling back to memory: {e}")

    # In-memory fallback
    now = _t.time()
    with _token_lock:
        _token_store[token] = now
        expired = [t for t, ts in _token_store.items() if now - ts > _TOKEN_TTL]
        for t in expired:
            del _token_store[t]
    return token


 
def _ws_throttle_ok(channel, min_interval=2.0):

    import time as _t
    if not hasattr(_ws_throttle_ok, '_last'):
        _ws_throttle_ok._last = {}
    now  = _t.time()
    last = _ws_throttle_ok._last.get(channel, 0)
    if now - last >= min_interval:
        _ws_throttle_ok._last[channel] = now
        return True
    return False

initialize_local_pool()
initialize_cloud_pool()
_get_feeder_available_columns()   # warm cache before any request holds a connection
_validate_config_constants()
_init_token_backend()      


from spam_detector import init_spam_detector, evaluate_message, log_spam_event

init_spam_detector(redis_client=_redis_client)
                               
import threading
threading.Thread(target=initialize_joblist_pool, daemon=True).start()
# ============================================
# HELPER FUNCTIONS
# ============================================

# ── AFTER — replace entirely ───────────────────────────────────
# Maps each incident_type to (category, priority_code, system_priority)
# category      : 'PI' | 'SE' | 'PQ' | 'AI' | 'PL'
# priority_code : 'P1' | 'P2' | 'P3' | 'P4'
# system_priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' — kept for
#                  existing OMMS / dashboard compatibility

_INCIDENT_TYPE_MAP = {
    'power_outage':      ('PI', 'P2', 'HIGH'),
    'partial_outage':    ('PI', 'P2', 'HIGH'),
    'voltage_issue':     ('PQ', 'P2', 'HIGH'),
    'sdi_problem':       ('PI', 'P3', 'MEDIUM'),
    'streetlight':       ('PL', 'P4', 'MEDIUM'),
    'fallen_wire':       ('SE', 'P1', 'CRITICAL'),
    'leaning_pole':      ('AI', 'P4', 'HIGH'),
    'tree_branch':          ('AI', 'P3', 'HIGH'),
'vegetation_clearing':  ('AI', 'P4', 'MEDIUM'),
'vehicular_accident':   ('SE', 'P1', 'CRITICAL'),   # ← ADD — pole/line hit by vehicle
'transformer_issue':    ('SE', 'P1', 'CRITICAL'),
    'fire_hazard':       ('SE', 'P1', 'CRITICAL'),
    'sparking':          ('SE', 'P1', 'CRITICAL'),
    'equipment_damage':  ('AI', 'P3', 'HIGH'),
    'other':             ('SE', 'P1', 'CRITICAL'),
}
# ── Cluster-group mapping ───────────────────────────────────────
# Maps the 5 fine-grained categories (PI/SE/PQ/AI/PL) down to the
# 4 dashboard cluster groups requested:
#   POWER  -> Power Outage Cluster   (PI + PQ)
#   SAFETY -> Safety Emergency Cluster (SE)
#   ASSET  -> Asset Maintenance Cluster (AI)
#   LIGHT  -> Streetlight Cluster    (PL)
CATEGORY_TO_CLUSTER_GROUP = {
    'PI': 'POWER',
    'PQ': 'POWER',
    'SE': 'SAFETY',
    'AI': 'ASSET',
    'PL': 'LIGHT',
}

CLUSTER_GROUP_META = {
    'POWER':  {'label': 'Power Outage Cluster',     'icon': '⚡'},
    'SAFETY': {'label': 'Safety Emergency Cluster',  'icon': '🚨'},
    'ASSET':  {'label': 'Asset Maintenance Cluster', 'icon': '🔧'},
    'LIGHT':  {'label': 'Streetlight Cluster',       'icon': '💡'},
}

# All incident_type values that belong to each cluster group —
# used by the clustering SQL below.
_CLUSTER_GROUP_TYPES = {
    'POWER':  [],
    'SAFETY': [],
    'ASSET':  [],
    'LIGHT':  [],
}
for _itype, (_cat, _pcode, _spri) in _INCIDENT_TYPE_MAP.items():
    _grp = CATEGORY_TO_CLUSTER_GROUP.get(_cat, 'SAFETY')
    _CLUSTER_GROUP_TYPES[_grp].append(_itype)


def get_cluster_group_for_type(incident_type: str) -> str:
    """Return 'POWER' | 'SAFETY' | 'ASSET' | 'LIGHT' for an incident_type."""
    cat = _INCIDENT_TYPE_MAP.get(incident_type, ('SE', 'P1', 'CRITICAL'))[0]
    return CATEGORY_TO_CLUSTER_GROUP.get(cat, 'SAFETY')

_SE_ESCALATION_KEYWORDS = [
    'fire', 'explosion', 'burning', 'smoke', 'accident',
    'fallen wire', 'electric shock', 'live wire', 'transformer burst',
    'emergency', 'danger', 'hazard', 'sparking', 'exposed wire',
    'electrocuted', 'injured', 'death', 'pole down', 'wire down',
    'short circuit', 'arcing', 'flames', 'about to fall',
    'blocking road', 'leaning badly', 'tilted',
]

_AI_ESCALATION_KEYWORDS = [
    'about to fall', 'blocking road', 'leaning badly',
    'tilted', 'wires touching', 'wire tension',
]

def classify_incident(incident_type: str, details: str) -> dict:
    """
    Returns a dict with:
        category        : 'PI' | 'SE' | 'PQ' | 'AI' | 'PL'
        priority_code   : 'P1' | 'P2' | 'P3' | 'P4'
        system_priority : 'CRITICAL' | 'HIGH' | 'MEDIUM'
        never_cluster   : bool  — True means NEVER merge with existing incident
    """
    d = (details or '').lower()
    cat, pcode, spri = _INCIDENT_TYPE_MAP.get(
        incident_type,
        ('SE', 'P1', 'CRITICAL')   # unknown type → treat as safety emergency
    )

    # Asset-integrity types escalate to SE if keywords indicate imminent danger
    if cat == 'AI' and any(k in d for k in _AI_ESCALATION_KEYWORDS):
        cat, pcode, spri = 'SE', 'P1', 'CRITICAL'

    # Any incident type escalates priority when description contains SE keywords
    if cat not in ('SE',) and any(k in d for k in _SE_ESCALATION_KEYWORDS):
        spri   = 'CRITICAL'
        pcode  = 'P1'
        # Do NOT change category — a power outage with a fire description
        # is still PI, but spawns an SE incident via the submission logic

    return {
        'category':        cat,
        'priority_code':   pcode,
        'system_priority': spri,
        'never_cluster':   cat == 'SE',   # SE incidents NEVER merge
    }

# Keep backward-compatible shim so nothing else breaks
def classify_priority(details: str) -> str:
    """Legacy shim — returns 'CRITICAL' | 'HIGH' | 'MEDIUM'."""
    d = (details or '').lower()
    if any(k in d for k in _SE_ESCALATION_KEYWORDS):
        return 'CRITICAL'
    return 'HIGH'


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            logger.warning(f"Unauthorized access attempt to {request.path}")
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Like login_required, but also requires role == 'superadmin'.
    Use this for destructive actions (hard deletes) — 'staff' should
    never be able to permanently remove incidents/reports/queue records."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'success': False, 'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        if session.get('role') != 'superadmin':
            logger.warning(
                f"Blocked destructive-action attempt by '{session.get('username')}' "
                f"(role={session.get('role')}) on {request.path}"
            )
            return jsonify({'success': False, 'error': 'Superadmin access required for this action'}), 403
        return f(*args, **kwargs)
    return decorated

# ── FEATURE FLAGS ────────────────────────────────────────────────
_feature_flags_cache = {'data': None, 'ts': 0}
_FEATURE_FLAGS_CACHE_TTL = 15  # seconds

def get_feature_flags(force_refresh=False):
    """Returns {flag_key: bool}. Falls back to last-known cache (or empty
    dict, which callers treat as fail-open) if the DB is unavailable —
    a DB hiccup must never silently hide buttons from every consumer."""
    now = _time_module.time()
    if not force_refresh and _feature_flags_cache['data'] is not None and \
       (now - _feature_flags_cache['ts']) < _FEATURE_FLAGS_CACHE_TTL:
        return _feature_flags_cache['data']

    conn = get_local_conn()
    if not conn:
        logger.warning("Feature flags: DB unavailable, using stale cache")
        return _feature_flags_cache['data'] or {}
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT flag_key, enabled FROM feature_flags")
        flags = {row[0]: row[1] for row in cur.fetchall()}
        _feature_flags_cache['data'] = flags
        _feature_flags_cache['ts'] = now
        return flags
    except Exception as e:
        logger.warning(f"Feature flags query failed: {e}")
        return _feature_flags_cache['data'] or {}
    finally:
        if cur: cur.close()
        release_local_conn(conn)


def is_feature_enabled(flag_key: str, default: bool = True) -> bool:
    return get_feature_flags().get(flag_key, default)


@app.route('/api/internal/feature_flags', methods=['GET'])
def api_internal_feature_flags():
    """Consumed by the Rasa action server — internal secret auth, not session."""
    if not is_internal_request():
        return jsonify({'success': False, 'error': 'Internal access only'}), 403
    return jsonify({'success': True, 'flags': get_feature_flags()})


@app.route('/api/admin/feature_flags', methods=['GET'])
@login_required
def api_admin_list_feature_flags():
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT flag_key, enabled, label, description, updated_by, updated_at
            FROM feature_flags ORDER BY label
        """)
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            r['updated_at'] = isoformat_safe(r.get('updated_at'))
        return jsonify({'success': True, 'flags': rows})
    except Exception as e:
        logger.exception("List feature flags error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@app.route('/api/admin/feature_flags/<flag_key>', methods=['POST'])
@login_required
def api_admin_toggle_feature_flag(flag_key):
    if session.get('role') != 'superadmin':
        return jsonify({'success': False, 'error': 'Superadmin access required'}), 403

    data = request.get_json() or {}
    if 'enabled' not in data:
        return jsonify({'success': False, 'error': 'Missing "enabled" field'}), 400
    enabled = bool(data['enabled'])
    actor = session.get('full_name') or session.get('username', 'Unknown')

    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            UPDATE feature_flags
            SET enabled = %s, updated_by = %s,
                updated_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
            WHERE flag_key = %s
            RETURNING flag_key, enabled, label
        """, (enabled, actor, flag_key))
        row = cur.fetchone()
        if not row:
            return jsonify({'success': False, 'error': f'Unknown flag: {flag_key}'}), 404
        conn.commit()
        _feature_flags_cache['ts'] = 0  # expire cache; next read refetches (no nested connection)
        logger.info(f"Feature flag '{flag_key}' set to {enabled} by {actor}")
        return jsonify({'success': True, 'flag': dict(row)})
    except Exception as e:
        conn.rollback()
        logger.exception("Toggle feature flag error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@app.route('/feature_flags')
@login_required
def feature_flags_dashboard():
    if session.get('role') != 'superadmin':
        return redirect(url_for('dashboard'))
    return render_template('feature_flags.html')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_meter_reference_number():
    date_str = datetime.now().strftime('%Y%m%d')
    unique_id = str(uuid.uuid4())[:8].upper()
    return f"MC-{date_str}-{unique_id}"

def normalize_town_for_db(town: str) -> str:
    if not town:
        return town
    normalized = " ".join(town.lower().strip().split())
    normalized = normalized.replace(".", "").replace(",", "")
    CANONICAL_TOWNS = {
        "tubungan":    "Tubungan",
        "alimodian":   "Alimodian",
        "cabatuan":    "Cabatuan",
        "guimbal":     "Guimbal",
        "igbaras":     "Igbaras",
        "leganes":     "Leganes",
        "leon":        "Leon",
        "miag-ao":     "Miag-ao",
        "miagao":      "Miag-ao",
        "oton":        "Oton",
        "pavia":       "Pavia",
        "san joaquin": "San Joaquin",
        "san miguel":  "San Miguel",
        "sta barbara": "Sta. Barbara",
        "sta. barbara":"Sta. Barbara",
        "maasin":      "Maasin",
        "tigbauan":    "Tigbauan",
    }
    return CANONICAL_TOWNS.get(normalized, town.strip().title())

def normalize_barangay_for_db(barangay: str) -> str:
    if not barangay:
        return barangay
    return " ".join(barangay.strip().title().split())

def _normalize_for_match(s: str) -> str:
    """Case/whitespace-insensitive compare key — collapses internal
    whitespace and strips punctuation noise so 'Dela Cruz, Juan' matches
    'DELA CRUZ,JUAN' or extra spaces from OCR/manual encoding."""
    if not s:
        return ''
    s = s.upper().strip()
    s = re.sub(r'[.\-]', '', s)
    s = re.sub(r'\s+', ' ', s)
    return s

NAME_MATCH_THRESHOLD = 0.80

def _name_key(s: str) -> str:
    """Order-insensitive key: 'DELA CRUZ, JUAN' == 'JUAN DELA CRUZ'."""
    s = _normalize_for_match(s).replace(',', ' ')
    return ' '.join(sorted(s.split()))

def _name_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    plain = difflib.SequenceMatcher(None, _normalize_for_match(a), _normalize_for_match(b)).ratio()
    sorted_ = difflib.SequenceMatcher(None, _name_key(a), _name_key(b)).ratio()
    return max(plain, sorted_)

def match_masterlist(cur, account_lookup, consumer_name, meter_lookup=''):
    """
    Returns dict: ok, field, error, matched_by ('account'|'name'), score.

    Rule:
      - Account number found            -> valid (name is ignored)
      - Account not found, name >= 80%  -> valid
      - Otherwise                       -> invalid
    Meter serial (if given) must belong to the matched record.
    """
    row, matched_by, score = None, None, 0.0

    # 1) Account number (exact match)
    if account_lookup:
        cur.execute("""SELECT consumer_name, meter_number
                       FROM consumer_masterlist
                       WHERE account_number = %s""",
                    (account_lookup,))
        row = cur.fetchone()
        if row:
            matched_by = 'account'
            score = _name_similarity(row['consumer_name'], consumer_name) if consumer_name else 0.0

    # 2) Fallback: fuzzy name. Pre-filter on the longest word of the typed
    #    name so "JUAN DELA CRUZ" still finds "DELA CRUZ, JUAN".
    if not row and consumer_name:
        tokens = [t for t in _name_key(consumer_name).split() if len(t) >= 3]
        if tokens:
            longest = max(tokens, key=len)
            cur.execute("""SELECT consumer_name, meter_number
                           FROM consumer_masterlist
                           WHERE UPPER(consumer_name) LIKE %s
                           LIMIT 5000""",
                        ('%' + longest + '%',))
            best_row, best_score = None, 0.0
            for cand in cur.fetchall():
                s = _name_similarity(cand['consumer_name'], consumer_name)
                if s > best_score:
                    best_row, best_score = cand, s
            score = best_score
            if best_row and best_score >= NAME_MATCH_THRESHOLD:
                row, matched_by = best_row, 'name'

    if not row:
        return {'ok': False, 'field': 'both', 'matched_by': None, 'score': score,
                'error': 'We could not find your record. Please check your account number '
                         'or your name exactly as printed on your bill.'}

    # 3) Meter serial must belong to the matched record
    if meter_lookup and _normalize_for_match(row['meter_number']) != _normalize_for_match(meter_lookup):
        return {'ok': False, 'field': 'meterNumber', 'matched_by': matched_by, 'score': score,
                'error': 'The meter serial number does not match our records. '
                         'Please check the number stamped on your meter.'}

    return {'ok': True, 'field': None, 'error': '', 'matched_by': matched_by, 'score': score}

@app.route('/api/verify_masterlist', methods=['POST'])
@limiter.limit("30 per hour")
def verify_masterlist():
    """
    Lightweight public check used by the meter-concern wizard to block
    'Continue' before the consumer even reaches later steps.

    Body: { "account_number": "...", "consumer_name": "...", "meter_number": "" (optional) }
    Returns: { valid: bool, field: 'accountNumber'|'consumerName'|'meterNumber'|None, error: str }
    """
    data = request.get_json(silent=True) or {}
    account_number_raw = (data.get('account_number') or '').strip()
    consumer_name       = (data.get('consumer_name') or '').strip()
    meter_number_raw    = (data.get('meter_number') or '').strip()

    account_number_lookup = re.sub(r'[^A-Za-z0-9]', '', account_number_raw)
    meter_number_lookup    = re.sub(r'[^A-Za-z0-9]', '', meter_number_raw)

    if not account_number_lookup and not consumer_name:
        return jsonify({'valid': False, 'field': 'both',
                        'error': 'Please enter your account number or your full name.'}), 200

    conn = get_db_connection()
    if not conn:
        return jsonify({'valid': False, 'field': None,
                        'error': 'Verification service unavailable. Please try again.'}), 200
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        r = match_masterlist(cur, account_number_lookup, consumer_name, meter_number_lookup)
        logger.info(f"verify_masterlist: ok={r['ok']} by={r['matched_by']} score={r['score']:.2f}")
        return jsonify({'valid': r['ok'], 'field': r['field'], 'error': r['error']}), 200
    except Exception as e:
        logger.warning(f"verify_masterlist error: {e}")
        return jsonify({'valid': False, 'field': None,
                        'error': 'Verification failed. Please try again.'}), 200
    finally:
        if cur: cur.close()
        release_db_connection(conn)

def validate_against_masterlist(conn, account_number: str, consumer_name: str, meter_number: str):
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        r = match_masterlist(cur, account_number, consumer_name, meter_number)
        return None if r['ok'] else r['error']
    finally:
        if cur:
            cur.close()
def validate_password_strength(password: str):
    """
    Returns an error string if the password fails complexity rules,
    or None if the password is acceptable.
 
    Rules:
      - Minimum 8 characters
      - At least one UPPERCASE letter
      - At least one lowercase letter
      - At least one digit (0-9)
    """
    if not password or len(password) < 8:
        return 'Password must be at least 8 characters'
    if not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter (A-Z)'
    if not re.search(r'[a-z]', password):
        return 'Password must contain at least one lowercase letter (a-z)'
    if not re.search(r'[0-9]', password):
        return 'Password must contain at least one number (0-9)'
    return None

# ─────────────────────────────────────────────────────────────────────────────
# PRIVATE HELPERS
# ─────────────────────────────────────────────────────────────────────────────
 
def _omms_timestamp(dt: _datetime) -> str:
    """
    Format a datetime exactly as OMMS stores it.
    Observed pattern in CSV:  '02/25/26  06:35:40 AM'
    Note the double-space between date and time — OMMS requires it.
    """
    return dt.strftime('%m/%d/%y  %I:%M:%S %p')
 
 
def _omms_unique_id(dt: _datetime) -> str:
    """
    Generate a unique_id that matches the OMMS numeric-text pattern.
    OMMS uses phone-number + date fragments (~22 digits).
    We use epoch-milliseconds + 6-char UUID fragment = 19-22 digits.
    Always unique, always purely numeric-ish text — safe for the text column.
    """
    epoch_ms = int(dt.timestamp() * 1000)
    rand_suffix = str(_uuid_module.uuid4().int)[:6]
    return f"{epoch_ms}{rand_suffix}"
 
 
def _omms_spinners(dt: _datetime) -> str:
    """
    OMMS 'spinners' is an internal tracker field (~1e33 magnitude).
    We use epoch-nanoseconds which has the right magnitude and is unique.
    """
    return str(_time_module.time_ns())
 
 
def _omms_section(incident_type: str) -> str:
    _map = {
        'power_outage':      'Primary Line',
        'sdi_problem':       'Secondary Line',
        'fallen_wire':       'Secondary Line',
        'leaning_pole':        'Secondary Line',
'vehicular_accident':  'Secondary Line',   # ← ADD — most pole strikes are on distribution poles
        'tree_branch':       'Primary Line',
        'vegetation_clearing': 'Primary Line',   # ← ADD THIS
        'streetlight':       'Secondary Line',
        'transformer_issue': 'Primary Line',
        'fire_hazard':       'Primary Line',
        'sparking':          'Secondary Line',
        'partial_outage':    'Secondary Line',
    }
    return _map.get((incident_type or '').lower(), 'Primary Line')
 
 
def _omms_cause(incident_type: str, details: str) -> str:
    """
    Derive OMMS cause from consumer's description text first,
    then fall back to incident_type mapping.
    Cause values match exactly what appears in the OMMS CSV dataset.
    """
    d = (details or '').lower()

    # Keyword scan — most specific first
    if any(k in d for k in ['tree', 'vegetation', 'branch', 'bamboo', 'clearing', 'ipil', 'acacia', 'mango']):
        return 'Vegetation'
    if any(k in d for k in ['cut-off', 'cutoff', 'cut off', 'cut wire', 'neutral line']):
        return 'Cut-off pri/sec/sdi line'
    if any(k in d for k in ['leaning pole', 'fallen pole', 'pole down', 'leaning']):
        return 'Correction of leaning pole/s'
    if any(k in d for k in ['animal', 'snake', 'bird', 'rat', 'cat']):
        return 'Birds/snakes/etc.'
    if any(k in d for k in ['fuse', 'blown', 'busted fuse', 'fuse cut']):
        return 'Blown fuse'
    if any(k in d for k in ['transformer', 'xfmr', 'transient']):
        return 'Transient fault'
    if any(k in d for k in ['fire', 'burning', 'burnt', 'smoke']):
        return 'Blown fuse'
    if any(k in d for k in ['short circuit', 'arcing', 'sparking']):
        return 'Others'
    if any(k in d for k in ['vehicular', 'accident', 'car hit', 'truck hit',
                             'motorcycle', 'sideswiped', 'crashed into', 'collision']):
        return 'Vehicular accident'   # ← VERIFY this exact string exists in your OMMS cause list

    # Fallback from incident_type
    _type_map = {
        'power_outage':        'Transient fault',
        'sdi_problem':         'Cut-off pri/sec/sdi line',
        'fallen_wire':         'Cut-off pri/sec/sdi line',
        'transformer_issue':   'Transformer related',
        'fire_hazard':         'Blown fuse',
        'sparking':            'Others',
        'partial_outage':      'Transient fault',
        'vegetation_clearing': 'Vegetation',
        'vehicular_accident':  'Vehicular accident',   # ← VERIFY, same caveat as above
    }
    return _type_map.get((incident_type or '').lower(), 'Others')
 
 
def _omms_equip(incident_type: str, details: str) -> str:
    """Derive OMMS equip field from context."""
    d = (details or '').lower()
    if any(k in d for k in ['transformer', 'xfmr']):
        return 'Transformer'
    if any(k in d for k in ['fuse cut', 'cutout', 'cut-out']):
        return 'Fuse cut-out'
    if any(k in d for k in ['pole', 'poles']):
        return 'Poles'
    if any(k in d for k in ['wire', 'line', 'neutral']):
        return 'Others'
    if any(k in d for k in ['vehicular', 'accident', 'hit a pole', 'car crash']):
        return 'Poles'
    _type_map = {
        'transformer_issue':  'Transformer',
        'fallen_wire':        'Others',
        'leaning_pole':       'Poles',
        'tree_branch':        'Others',
        'streetlight':        'Others',
        'sparking':           'Others',
        'vehicular_accident': 'Poles',
    }
    return _type_map.get((incident_type or '').lower(), 'Others')
 
 
def _omms_priority_type(priority: str) -> str:
    """Map system priority → OMMS type field (high/medium/low)."""
    return {
        'CRITICAL': 'high',
        'HIGH':     'high',
        'MEDIUM':   'medium',
        'LOW':      'low',
    }.get((priority or '').upper(), 'high')
 
 
def _omms_substation(feeder_name: str, town: str) -> str:
    """
    Derive OMMS subs (substation) from feeder name.
    Lookup table built from ILECO-1 feeder assignments seen in the OMMS CSV.
    Falls back to '<Town> S/S' which is the OMMS naming convention.
    """
    _feeder_ss = {
        'Feeder 7':   'San Miguel S/S',
        'Feeder 8':   'San Miguel S/S',
        'Feeder 9':   'San Miguel S/S',
        'Feeder 10':  'San Miguel S/S',
        'Feeder 11':  'Pavia S/S',
        'Feeder 12':  'Pavia S/S',
        'Feeder 12A': 'Pavia S/S',
        'Feeder 13':  'Oton S/S',
        'Feeder 14':  'Oton S/S',
        'Feeder 15':  'Oton S/S',
        'Feeder 16':  'Guimbal S/S',
        'Feeder 17':  'Guimbal S/S',
        'Feeder 18':  'Guimbal S/S',
        'Feeder 19':  'Guimbal S/S',
        'Feeder 20':  'Leganes S/S',
        'Feeder 21':  'Leganes S/S',
        'Feeder 22':  'Leganes S/S',
        'Feeder 23':  'Leganes S/S',
    }
    if feeder_name and feeder_name in _feeder_ss:
        return _feeder_ss[feeder_name]
    return f"{town} S/S" if town else 'Unknown S/S'
def generate_rpt_reference_id(conn, town: str, report_date=None) -> str:
    """
    Generate a unique, sequential RPT reference ID.

    Format: [TOWN_CODE][YY][MM][DD][SEQUENCE 4-digits]
    Example: CA2606170001

    Uses an advisory lock + upsert on rpt_sequences to guarantee
    uniqueness even under concurrent submissions.

    Args:
        conn       : active psycopg2 connection (cloud DB)
        town       : municipality name (must exist in TOWN_CODE_MAP)
        report_date: date to use (defaults to today PH time)

    Returns:
        Reference ID string e.g. "CA2606170001"

    Raises:
        ValueError  if town code not found
        RuntimeError if sequence exhausted (>9999/town/day)
    """
    town_code = TOWN_CODE_MAP.get(town)
    if not town_code:
        # Graceful fallback — use first two letters uppercased
        town_code = (town[:2]).upper() if town else 'XX'
        logger.warning(f"generate_rpt_reference_id: unknown town '{town}', using code '{town_code}'")

    if report_date is None:
        report_date = datetime.now(PHILIPPINE_TZ).date()

    yy = report_date.strftime('%y')   # 2-digit year
    mm = report_date.strftime('%m')
    dd = report_date.strftime('%d')
    date_str = f"{yy}{mm}{dd}"        # e.g. "260617"

    cur = conn.cursor()
    try:
        # INSERT or increment — single atomic statement, no race condition
        cur.execute("""
            INSERT INTO rpt_sequences (town_code, seq_date, last_seq)
            VALUES (%s, %s, 1)
            ON CONFLICT (town_code, seq_date)
            DO UPDATE SET last_seq = rpt_sequences.last_seq + 1
            RETURNING last_seq
        """, (town_code, report_date))

        row = cur.fetchone()
        seq = row[0]

        if seq > 9999:
            raise RuntimeError(
                f"RPT sequence exhausted for {town_code} on {report_date} "
                f"(seq={seq}). Maximum 9999 reports per municipality per day."
            )

        ref_id = f"{town_code}{date_str}{seq:04d}"
        logger.debug(f"Generated RPT reference ID: {ref_id} (town={town}, seq={seq})")
        return ref_id

    finally:
        cur.close()

@app.route('/api/form_token', methods=['GET'])
@limiter.limit("60 per hour")
def get_form_token():
    ua = request.headers.get('User-Agent', '')
    # Skip bot check for internal/localhost requests (Railway internal network)
    is_local = (request.remote_addr in ('127.0.0.1', '::1')
                or (request.remote_addr or '').startswith('172.')
                or (request.remote_addr or '').startswith('10.'))
    if not is_local:
        bot_ua = ['curl', 'python-requests', 'python/', 'wget', 'httpie',
                  'go-http', 'java/', 'libwww', 'scrapy', 'okhttp']
        if not ua or any(b in ua.lower() for b in bot_ua):
            return jsonify({'success': False, 'error': 'Access denied'}), 403
    token = _issue_form_token()
    return jsonify({'success': True, 'token': token})


# ============================================
# ROUTES
# ============================================
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/health')
def health():
    status = {'status': 'ok', 'checks': {}}
    http_status = 200

    conn = None
    try:
        conn = get_cloud_conn()
        if conn:
            cur = conn.cursor()
            cur.execute('SELECT 1')
            cur.close()
            status['checks']['cloud_db'] = 'ok'
        else:
            status['checks']['cloud_db'] = 'unavailable'
            status['status'] = 'degraded'
            http_status = 503
    except Exception as e:
        status['checks']['cloud_db'] = f'error: {str(e)}'
        status['status'] = 'degraded'
        http_status = 503
    finally:
        if conn:
            release_cloud_conn(conn)

    conn = None
    try:
        conn = get_local_conn()
        if conn:
            cur = conn.cursor()
            cur.execute('SELECT 1')
            cur.close()
            status['checks']['local_db'] = 'ok'
        else:
            status['checks']['local_db'] = 'unavailable'
    except Exception as e:
        status['checks']['local_db'] = f'error: {str(e)}'
    finally:
        if conn:
            release_local_conn(conn)

    return jsonify(status), http_status

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/report_outage')
def report_outage():
    return render_template('report_outage.html')

@app.route('/meter_concern')
def meter_concern():
    return render_template('meter_concern.html')

@app.route('/meter_dashboard')
@login_required
def meter_dashboard():
    return render_template('meter_dashboard.html')

@app.route('/chatbot_disclaimer')
def chatbot_disclaimer():
    return render_template('chatbot_disclaimer.html')

@app.route('/mapping_demo')
@login_required
def mapping_demo():
    return render_template('mapping_demo.html')

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    """Serve uploaded meter concern evidence files."""
    uploads_root = os.path.abspath('uploads')
    return send_from_directory(uploads_root, filename)

# app.py — add this route
@app.route('/api/map_config', methods=['GET'])
def get_map_config():
    """
    Public endpoint — only returns the Mapbox token for map rendering.
    Token is already exposed in the HTML for the public form anyway.
    Dashboard uses this too for satellite layer.
    """
    return jsonify({
        'mapbox_token': os.getenv('MAPBOX_TOKEN', '')
    })

    
@app.route('/api/check_feeder', methods=['POST'])
def check_feeder():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        data = request.get_json()
        lat = float(data.get('lat'))
        lng = float(data.get('lng'))
        cur = conn.cursor(cursor_factory=RealDictCursor)
        optional_cols = _feeder_optional_select()

        # ── ATTEMPT 1: Point-in-polygon (is the coordinate INSIDE a feeder zone?) ──
        cur.execute(f"""
            SELECT {FEEDER_NAME_COL},
                   {optional_cols}
            FROM {FEEDER_TABLE}
            WHERE {FEEDER_NAME_COL} != %s
              AND ST_Contains(
                      geom::geometry,
                      ST_SetSRID(ST_MakePoint(%s, %s), 4326)
                  )
            LIMIT 1
        """, (EXCLUDED_FEEDER, lng, lat))
        result = cur.fetchone()

        if result:
            logger.info(f"Point ({lat},{lng}) is INSIDE feeder: {result[FEEDER_NAME_COL]}")
            return jsonify({
                'success': True,
                'feeder': result[FEEDER_NAME_COL],
                'in_feeder': True,
                'method': 'contains',
                'status': result['status'],
                'cause': result['cause'],
                'start_time': result['start_time'],
                'end_time': result['end_time'],
                'outage_type': result['outage_type'],
                'is_active': result['is_active'],
            })

        # ── ATTEMPT 2: Nearest feeder (always returns something) ──
        cur.execute(f"""
            SELECT {FEEDER_NAME_COL},
                   {optional_cols},
                   ST_Distance(
                       geom::geography,
                       ST_SetSRID(ST_MakePoint(%s, %s), 4326)::geography
                   ) as dist_m
            FROM {FEEDER_TABLE}
            WHERE {FEEDER_NAME_COL} != %s
            ORDER BY dist_m ASC
            LIMIT 1
        """, (lng, lat, EXCLUDED_FEEDER))
        nearest = cur.fetchone()

        if nearest:
            dist_km = round(float(nearest['dist_m']) / 1000, 2)
            logger.info(
                f"Point ({lat},{lng}) outside all polygons. "
                f"Nearest: {nearest[FEEDER_NAME_COL]} at {dist_km}km"
            )
            if float(nearest['dist_m']) <= 5000:
                return jsonify({
                    'success': True,
                    'feeder': nearest[FEEDER_NAME_COL],
                    'in_feeder': True,
                    'method': 'nearest',
                    'distance_km': dist_km,
                    'status': nearest['status'],
                    'cause': nearest['cause'],
                    'start_time': nearest['start_time'],
                    'end_time': nearest['end_time'],
                    'outage_type': nearest['outage_type'],
                    'is_active': nearest['is_active'],
                })
            else:
                return jsonify({
                    'success': True,
                    'feeder': nearest[FEEDER_NAME_COL],
                    'in_feeder': False,
                    'method': 'nearest',
                    'distance_km': dist_km,
                    'status': nearest['status'],
                    'cause': nearest['cause'],
                    'start_time': nearest['start_time'],
                    'end_time': nearest['end_time'],
                    'outage_type': nearest['outage_type'],
                    'is_active': nearest['is_active'],
                })

        return jsonify({'success': True, 'feeder': None, 'in_feeder': False})

    except Exception as e:
        logger.exception("Check feeder error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)


@app.route('/api/feeder_polygon', methods=['GET'])
def get_feeder_polygon():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        optional_cols = _feeder_optional_select()

        cur.execute(f"""
            SELECT
                {FEEDER_NAME_COL},
                {optional_cols},
                layer,
                ST_AsGeoJSON(
                    ST_Transform(geom::geometry, 4326)
                )::json AS geometry,
                ST_IsEmpty(geom::geometry) as is_empty
            FROM {FEEDER_TABLE}
            WHERE geom IS NOT NULL
              AND NOT ST_IsEmpty(geom::geometry)
              AND {FEEDER_NAME_COL} != %s
        """, (EXCLUDED_FEEDER,))
        rows = cur.fetchall()
        logger.info(f"Feeder polygon query: {len(rows)} rows from {FEEDER_TABLE}")

        if len(rows) == 0:
            cur.execute(f"SELECT COUNT(*) FROM {FEEDER_TABLE}")
            total = cur.fetchone()['count']
            logger.warning(f"{FEEDER_TABLE} has {total} rows but 0 valid geometries")

        features = []
        for row in rows:
            if row['geometry'] is None or row['is_empty']:
                logger.warning(f"Skipping {row[FEEDER_NAME_COL]}: empty/null geometry")
                continue
            features.append({
                'type': 'Feature',
                'properties': {
                    'feeder_name': row[FEEDER_NAME_COL],
                    'status':      row['status'],
                    'cause':       row['cause'],
                    'start_time':  str(row['start_time']) if row['start_time'] else None,
                    'end_time':    str(row['end_time']) if row['end_time'] else None,
                    'outage_type': row['outage_type'],
                    'is_active':   row['is_active'],
                    'layer':       row['layer'],
                },
                'geometry': row['geometry']
            })

        logger.info(f"Returning {len(features)} feeder polygon features")
        return jsonify({'success': True, 'features': features})

    except Exception as e:
        logger.exception("Get feeder polygon error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)


@app.route('/api/debug_feeder2')
@login_required
def debug_feeder2():
    if os.getenv('ENABLE_DEBUG_ROUTES', 'false').lower() != 'true':
        return jsonify({'success': False, 'error': 'Not found'}), 404
    if session.get('role') != 'superadmin':
        return jsonify({'success': False, 'error': 'Superadmin only'}), 403
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'DB unavailable'}), 500
    cur = None
    results = {}
    try:
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {FEEDER_TABLE}")
        results['row_count'] = cur.fetchone()[0]
        cur.execute("""
            SELECT column_name, udt_name
            FROM information_schema.columns
            WHERE table_name='ILECO_1_COVERAGE_AREA_FEEDERS_FINALoutput'
        """)
        results['columns'] = [{'name': r[0], 'type': r[1]} for r in cur.fetchall()]
        try:
            cur.execute(f"""
                SELECT {FEEDER_NAME_COL},
                       ST_IsValid(geom::geometry) as valid,
                       ST_IsEmpty(geom::geometry) as empty,
                       ST_XMin(geom::geometry) as xmin,
                       ST_XMax(geom::geometry) as xmax,
                       ST_YMin(geom::geometry) as ymin,
                       ST_YMax(geom::geometry) as ymax
                FROM {FEEDER_TABLE}
                WHERE {FEEDER_NAME_COL} != %s
                LIMIT 5
            """, (EXCLUDED_FEEDER,))
            results['bounds'] = [
                dict(zip([d[0] for d in cur.description], r))
                for r in cur.fetchall()
            ]
        except Exception as e:
            results['bounds_error'] = str(e)
        return jsonify(results)
    except Exception as e:
        logger.exception("debug_feeder2 error")
        return jsonify({'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)


# ============================================
# UPDATED: /api/complaints_in_feeder
# Uses new feeder table + feeder_name column
# ============================================
@app.route('/api/complaints_in_feeder', methods=['POST'])
@limiter.limit("30 per minute")
def api_complaints_in_feeder():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500

    cur = None
    try:
        data = request.get_json()
        lat = float(data.get('lat'))
        lng = float(data.get('lng'))

        cur = conn.cursor(cursor_factory=RealDictCursor)

        # ── STEP 1: Determine which feeder the user point belongs to ──
        cur.execute(f"""
            SELECT {FEEDER_NAME_COL},
                   ST_Distance(
                       geom::geography,
                       ST_SetSRID(ST_MakePoint(%s, %s), 4326)::geography
                   ) as dist_m,
                   ST_Contains(
                       geom::geometry,
                       ST_SetSRID(ST_MakePoint(%s, %s), 4326)
                   ) as is_inside
            FROM {FEEDER_TABLE}
            WHERE {FEEDER_NAME_COL} != %s
            ORDER BY dist_m ASC
            LIMIT 1
        """, (lng, lat, lng, lat, EXCLUDED_FEEDER))

        feeder_row = cur.fetchone()

        if not feeder_row:
            return jsonify({
                'success': True,
                'complaints': [],
                'feeder_name': None,
                'message': 'No feeder zones defined in database',
                'count': 0
            })

        feeder_name = feeder_row[FEEDER_NAME_COL]
        dist_m      = float(feeder_row['dist_m'])

        logger.info(
            f"Feeder lookup ({lat},{lng}): feeder='{feeder_name}', "
            f"inside={feeder_row['is_inside']}, dist={dist_m:.0f}m"
        )

        # ── STEP 2A: Spatial join — incidents INSIDE the feeder polygon ──
        cur.execute(f"""
            SELECT
                i.incident_id        AS report_id,
                i.incident_type,
                i.barangay,
                i.town,
                i.report_count,
                i.status,
                i.priority,
                i.first_report_time  AS timestamp,
                i.job_order_id,
                i.remarks,
                ST_Y(i.geom::geometry) AS lat,
                ST_X(i.geom::geometry) AS lng,
                ST_Distance(
                    i.geom::geography,
                    ST_SetSRID(ST_MakePoint(%s, %s), 4326)::geography
                ) AS distance_meters,
                f.{FEEDER_NAME_COL} AS feeder_name
            FROM outage_incidents i
            INNER JOIN {FEEDER_TABLE} f
                ON ST_Contains(f.geom::geometry, i.geom::geometry)
            WHERE
                f.{FEEDER_NAME_COL} = %s
                AND f.{FEEDER_NAME_COL} != %s
                AND i.status NOT IN ('RESTORED', 'RESOLVED')
                AND i.geom IS NOT NULL
            ORDER BY
                CASE i.priority WHEN 'CRITICAL' THEN 1 ELSE 2 END,
                distance_meters ASC
            LIMIT 50
        """, (lng, lat, feeder_name, EXCLUDED_FEEDER))

        rows = cur.fetchall()
        logger.info(
            f"Spatial join result: {len(rows)} incidents inside '{feeder_name}' polygon"
        )

        search_method = 'spatial_join'

        # ── STEP 2B: FALLBACK — 5km radius search ──
        if len(rows) == 0:
            logger.info(
                f"Spatial join returned 0 — falling back to 5km radius "
                f"search around ({lat},{lng}) for feeder '{feeder_name}'"
            )
            search_method = 'radius_fallback'

            cur.execute(f"""
                SELECT
                    i.incident_id        AS report_id,
                    i.incident_type,
                    i.barangay,
                    i.town,
                    i.report_count,
                    i.status,
                    i.priority,
                    i.first_report_time  AS timestamp,
                    i.job_order_id,
                    i.remarks,
                    ST_Y(i.geom::geometry) AS lat,
                    ST_X(i.geom::geometry) AS lng,
                    ST_Distance(
                        i.geom::geography,
                        ST_SetSRID(ST_MakePoint(%s, %s), 4326)::geography
                    ) AS distance_meters,
                    %s AS feeder_name
                FROM outage_incidents i
                WHERE
                    ST_DWithin(
                        i.geom::geography,
                        ST_SetSRID(ST_MakePoint(%s, %s), 4326)::geography,
                        5000
                    )
                    AND i.status NOT IN ('RESTORED', 'RESOLVED')
                    AND i.geom IS NOT NULL
                ORDER BY
                    CASE i.priority WHEN 'CRITICAL' THEN 1 ELSE 2 END,
                    distance_meters ASC
                LIMIT 50
            """, (lng, lat, feeder_name, lng, lat))

            rows = cur.fetchall()
            logger.info(f"Radius fallback result: {len(rows)} incidents within 5km")

        # ── Build response ──
        complaints = []
        for row in rows:
            complaints.append({
                'report_id':       row['report_id'],
                'type':            row['incident_type'],
                'priority':        row['priority'],
                'status':          row['status'],
                'lat':             float(row['lat'])             if row['lat']             is not None else 0,
                'lng':             float(row['lng'])             if row['lng']             is not None else 0,
                'feeder_name':     row['feeder_name'],
                'distance_meters': round(float(row['distance_meters']), 2),
                'timestamp':       isoformat_safe(row['timestamp']),
                'barangay':        row['barangay']  or '',
                'town':            row['town']       or '',
                'report_count':    row.get('report_count') or 1,
                'job_order_id':    row.get('job_order_id') or '',
                'details':         row.get('remarks') or '',
            })

        return jsonify({
            'success':       True,
            'complaints':    complaints,
            'feeder_name':   feeder_name,
            'count':         len(complaints),
            'search_method': search_method,
            'search_center': {'lat': lat, 'lng': lng}
        })

    except ValueError as ve:
        logger.warning(f"Invalid coordinates in complaints_in_feeder: {ve}")
        return jsonify({'success': False, 'error': 'Invalid coordinates'}), 400
    except Exception as e:
        logger.exception("complaints_in_feeder query error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)


@app.route('/api/debug_feeder')
@login_required
def debug_feeder():
    if os.getenv('ENABLE_DEBUG_ROUTES', 'false').lower() != 'true':
        return jsonify({'success': False, 'error': 'Not found'}), 404
    if session.get('role') != 'superadmin':
        return jsonify({'success': False, 'error': 'Superadmin only'}), 403
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'DB unavailable'}), 500
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"""
            SELECT {FEEDER_NAME_COL},
                   ST_AsText(geom::geometry) as wkt_sample,
                   ST_SRID(geom::geometry) as srid,
                   ST_XMin(geom::geometry) as xmin,
                   ST_YMin(geom::geometry) as ymin,
                   ST_XMax(geom::geometry) as xmax,
                   ST_YMax(geom::geometry) as ymax
            FROM {FEEDER_TABLE}
            WHERE {FEEDER_NAME_COL} != %s
            LIMIT 3
        """, (EXCLUDED_FEEDER,))
        rows = cur.fetchall()
        return jsonify({'rows': [dict(r) for r in rows]})
    except Exception as e:
        logger.exception("debug_feeder error")
        return jsonify({'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)
    
    # ── helpers ──────────────────────────────────────────────────────────────

def get_cloud_db():
    """REMOVED — use get_cloud_conn() / release_cloud_conn() instead."""
    pass  # kept as stub so nothing breaks if called elsewhere

# ── LIST all outages ──────────────────────────────────────────────────────

@app.route("/admin/outages")
@login_required
def admin_outages():
    conn = get_cloud_conn()
    if not conn:
        flash("❌ Database unavailable.", "danger")
        return render_template("outages.html", outages=[])
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, outage_date, start_time, end_time,
                   reason, affected_areas, towns,
                   image_url, is_active, created_at
            FROM scheduled_outages
            ORDER BY outage_date DESC
        """)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        outages = []
        for row in rows:
            o = dict(zip(cols, row))
            areas = o.get("affected_areas", [])
            if isinstance(areas, str):
                try:
                    areas = json.loads(areas)
                except (ValueError, TypeError):
                    areas = [areas] if areas else []
            o["affected_areas"] = areas
            outages.append(o)
        return render_template("outages.html", outages=outages)
    except Exception as e:
        logger.exception("admin_outages error")
        flash(f"❌ Error loading outages: {e}", "danger")
        return render_template("outages.html", outages=[])
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)

@app.route("/admin/outages/toggle/<int:outage_id>", methods=["POST"])
@login_required
def admin_toggle_outage(outage_id):
    conn = get_cloud_conn()
    if not conn:
        flash("❌ Database unavailable.", "danger")
        return redirect(url_for("admin_outages"))
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE scheduled_outages
            SET is_active = NOT is_active
            WHERE id = %s
            RETURNING is_active
        """, (outage_id,))
        row = cur.fetchone()
        if not row:
            flash("❌ Outage not found.", "danger")
        else:
            conn.commit()
            flash(f"✅ Outage {'activated' if row[0] else 'deactivated'}.", "success")
    except Exception as e:
        try: conn.rollback()
        except Exception: pass
        logger.exception("admin_toggle_outage error")
        flash(f"❌ Error: {e}", "danger")
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)
    return redirect(url_for("admin_outages"))

@app.route("/admin/outages/add", methods=["GET", "POST"])
@login_required
def admin_add_outage():
    if request.method == "POST":
        areas_list = [
            line.strip()
            for line in request.form.get("affected_areas", "").strip().splitlines()
            if line.strip()
        ]
        towns_list = [
            t.strip()
            for t in request.form.get("towns", "").split(",")
            if t.strip()
        ]

        if not towns_list:
            flash("❌ Please enter at least one town — the chatbot uses this to match the advisory to consumers.", "danger")
            return render_template("add_outage.html")

        outage_date = request.form.get("outage_date") or None
        start_time  = request.form.get("start_time") or None
        end_time    = request.form.get("end_time") or None
        reason      = (request.form.get("reason") or "").strip()

        # ── Handle image upload to Supabase Storage ──
        image_url = None
        image_file = request.files.get("outage_image")
        if image_file and image_file.filename:
            mime = image_file.mimetype
            allowed = {'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp'}
            if mime in allowed:
                file_bytes = image_file.read()
                ext = allowed[mime]
                filename = f"scheduled-outages/{datetime.now():%Y/%m/%d}/{uuid.uuid4().hex}.{ext}"
                supabase_url = os.getenv('SUPABASE_URL', '')
                service_key  = os.getenv('SUPABASE_SERVICE_KEY', '')
                bucket       = SUPABASE_PUBLIC_BUCKET
                if supabase_url and service_key:
                    try:
                        import requests as req
                        upload_url = f"{supabase_url}/storage/v1/object/{bucket}/{filename}"
                        resp = req.post(
                            upload_url,
                            headers={
                                'Authorization': f'Bearer {service_key}',
                                'apikey': service_key,
                                'Content-Type': mime,
                                'x-upsert': 'false',
                            },
                            data=file_bytes,
                            timeout=15
                        )
                        if resp.status_code in (200, 201):
                            image_url = f"{supabase_url}/storage/v1/object/public/{bucket}/{filename}"
                        else:
                            flash(f"⚠️ Image upload failed: {resp.status_code}", "warning")
                    except Exception as e:
                        logger.exception("Outage image upload error")
                        flash("⚠️ Image upload failed — outage saved without image.", "warning")

        conn = get_cloud_conn()
        if not conn:
            flash("❌ Database unavailable.", "danger")
            return render_template("add_outage.html")
        cur = None
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO scheduled_outages (
                    outage_date, start_time, end_time,
                    reason, affected_areas, towns,
                    image_url, is_active
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                outage_date,
                start_time,
                end_time,
                reason,
                json.dumps(areas_list),
                towns_list,
                image_url,
                "is_active" in request.form
            ))
            conn.commit()
            flash("✅ Scheduled outage added successfully!", "success")
            return redirect(url_for("admin_outages"))
        except Exception as e:
            conn.rollback()
            logger.exception("admin_add_outage error")
            flash(f"❌ Error: {e}", "danger")
        finally:
            if cur: cur.close()
            release_cloud_conn(conn)

    return render_template("add_outage.html")
@app.route("/admin/outages/edit/<int:outage_id>", methods=["GET", "POST"])
@login_required
def admin_edit_outage(outage_id):
    conn = get_cloud_conn()
    if not conn:
        flash("❌ Database unavailable.", "danger")
        return redirect(url_for("admin_outages"))
    cur = None
    try:
        if request.method == "POST":
            areas_list = [
                line.strip()
                for line in request.form.get("affected_areas", "").strip().splitlines()
                if line.strip()
            ]
            towns_list = [
                t.strip()
                for t in request.form.get("towns", "").split(",")
                if t.strip()
            ]

            if not towns_list:
                flash("❌ Please enter at least one town — the chatbot uses this to match the advisory to consumers.", "danger")
                return redirect(url_for("admin_edit_outage", outage_id=outage_id))

            outage_date = request.form.get("outage_date") or None
            start_time  = request.form.get("start_time") or None
            end_time    = request.form.get("end_time") or None
            reason      = (request.form.get("reason") or "").strip()

            # ── Keep existing image unless a new one is uploaded ──
            image_url = request.form.get("existing_image_url") or None
            image_file = request.files.get("outage_image")
            if image_file and image_file.filename:
                mime = image_file.mimetype
                allowed = {'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp'}
                if mime in allowed:
                    file_bytes = image_file.read()
                    ext = allowed[mime]
                    filename = f"scheduled-outages/{datetime.now():%Y/%m/%d}/{uuid.uuid4().hex}.{ext}"
                    supabase_url = os.getenv('SUPABASE_URL', '')
                    service_key  = os.getenv('SUPABASE_SERVICE_KEY', '')
                    bucket       = SUPABASE_PUBLIC_BUCKET
                    if supabase_url and service_key:
                        try:
                            import requests as req
                            upload_url = f"{supabase_url}/storage/v1/object/{bucket}/{filename}"
                            resp = req.post(
                                upload_url,
                                headers={
                                    'Authorization': f'Bearer {service_key}',
                                    'apikey': service_key,
                                    'Content-Type': mime,
                                    'x-upsert': 'false',
                                },
                                data=file_bytes,
                                timeout=15
                            )
                            if resp.status_code in (200, 201):
                                image_url = f"{supabase_url}/storage/v1/object/public/{bucket}/{filename}"
                            else:
                                flash("⚠️ Image upload failed — keeping existing image.", "warning")
                        except Exception:
                            logger.exception("Outage image upload error on edit")
                            flash("⚠️ Image upload failed — keeping existing image.", "warning")

            cur = conn.cursor()
            cur.execute("""
                UPDATE scheduled_outages SET
                    outage_date    = %s,
                    start_time     = %s,
                    end_time       = %s,
                    reason         = %s,
                    affected_areas = %s,
                    towns          = %s,
                    image_url      = %s,
                    is_active      = %s
                WHERE id = %s
            """, (
                outage_date,
                start_time,
                end_time,
                reason,
                json.dumps(areas_list),
                towns_list,
                image_url,
                "is_active" in request.form,
                outage_id
            ))
            conn.commit()
            flash("✅ Outage updated successfully!", "success")
            return redirect(url_for("admin_outages"))
        else:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM scheduled_outages WHERE id = %s",
                (outage_id,)
            )
            row = cur.fetchone()
            if not row:
                flash("❌ Outage not found.", "danger")
                return redirect(url_for("admin_outages"))
            cols   = [d[0] for d in cur.description]
            outage = dict(zip(cols, row))
            areas  = outage.get("affected_areas", [])
            if isinstance(areas, str):
                try:
                    areas = json.loads(areas)
                except (ValueError, TypeError):
                    areas = [areas] if areas else []
            outage["affected_areas"] = areas
            outage["affected_areas_text"] = "\n".join(areas)
            outage["towns_text"] = ", ".join(outage.get("towns") or [])
            return render_template("add_outage.html", outage=outage)
    except Exception as e:
        try: conn.rollback()
        except Exception: pass
        logger.exception("admin_edit_outage error")
        flash(f"❌ Error: {e}", "danger")
        return redirect(url_for("admin_outages"))
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)
# ── DELETE outage ─────────────────────────────────────────────────────────

@app.route("/admin/outages/delete/<int:outage_id>", methods=["POST"])
@login_required
def admin_delete_outage(outage_id):
    conn = get_cloud_conn()
    if not conn:
        flash("❌ Database unavailable.", "danger")
        return redirect(url_for("admin_outages"))
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM scheduled_outages WHERE id = %s", (outage_id,))
        conn.commit()
        flash("✅ Outage deleted.", "success")
    except Exception as e:
        try: conn.rollback()
        except Exception: pass
        logger.exception("admin_delete_outage error")
        flash(f"❌ Error: {e}", "danger")
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)
    return redirect(url_for("admin_outages"))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''

        logger.info(f"Login attempt for username: {username}")

        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password required'}), 400

        # ── Per-account lockout check — BEFORE touching the DB ──
        username_key = username.lower()
        locked, seconds_left = _is_account_locked(username_key)
        if locked:
            minutes_left = max(1, seconds_left // 60)
            logger.warning(f"🔒 Blocked login attempt for locked account '{username}' ({seconds_left}s remaining)")
            return jsonify({
                'success': False,
                'error': (
                    f'Too many failed login attempts. This account is temporarily '
                    f'locked. Please try again in {minutes_left} minute'
                    f'{"s" if minutes_left != 1 else ""}.'
                ),
                'error_code': 'ACCOUNT_LOCKED'
            }), 429

        conn = get_local_conn()
        if not conn:
            logger.error("Database connection failed during login")
            return jsonify({'success': False, 'error': 'Database connection failed'}), 500

        cur = None
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT id, username, password_hash, full_name, role, is_active 
                FROM users 
                WHERE username=%s
            """, (username,))
            user = cur.fetchone()

            if user and check_password_hash(user['password_hash'], password) and user['is_active']:
                _clear_failed_login(username_key)
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['full_name'] = user['full_name'] or user['username']
                session['role'] = user['role']
                logger.info(f"✅ Login successful for user: {username}")
                return jsonify({
                    'success': True, 
                    'redirect': url_for('dashboard'),
                    'message': 'Login successful'
                })

            # Failed attempt — wrong password, unknown user, or inactive account.
            # Registered under the same key regardless of which case it was,
            # so this endpoint can't be used to enumerate valid usernames
            # via timing/response differences on the lockout path itself.
            _register_failed_login(username_key)
            logger.warning(f"❌ Failed login attempt for username: {username}")
            return jsonify({'success': False, 'error': 'Invalid credentials or inactive account'}), 401

        except Exception as e:
            logger.exception(f"Login error for user {username}")
            return jsonify({'success': False, 'error': 'Login failed due to server error'}), 500
        finally:
            if cur:
                cur.close()
            release_local_conn(conn)

    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    """
    Permanently delete a user account — superadmin only.
 
    Safety guards:
      1. You cannot delete your own account.
      2. You cannot delete the last remaining active superadmin
         (would lock everyone out of the system).
    """
    if session.get('role') != 'superadmin':
        return jsonify({'success': False, 'error': 'Superadmin access required'}), 403
 
    # Guard 1 — self-delete
    if session.get('user_id') == user_id:
        return jsonify({
            'success': False,
            'error': 'You cannot delete your own account while logged in'
        }), 400
 
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
 
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
 
        # Fetch the target user first
        cur.execute(
            "SELECT id, username, full_name, role FROM users WHERE id = %s",
            (user_id,)
        )
        user = cur.fetchone()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
 
        # Guard 2 — last superadmin protection
        if user['role'] == 'superadmin':
            cur.execute("""
                SELECT COUNT(*) AS cnt
                FROM users
                WHERE role = 'superadmin'
                  AND is_active = TRUE
            """)
            superadmin_count = cur.fetchone()['cnt']
            if superadmin_count <= 1:
                return jsonify({
                    'success': False,
                    'error': (
                        'Cannot delete the last active superadmin account. '
                        'Promote another user to superadmin first.'
                    )
                }), 400
 
        # ── Hard delete ───────────────────────────────────────────────────────
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
 
        logger.info(
            f"User '{user['username']}' (id={user_id}, role={user['role']}) "
            f"permanently deleted by '{session.get('username')}'"
        )
 
        return jsonify({
            'success': True,
            'message': f"User \"{user['username']}\" has been permanently deleted"
        })
 
    except Exception as e:
        conn.rollback()
        logger.exception("Delete user error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    session.clear()
    logger.info(f"User logged out: {username}")
    return redirect(url_for('login'))

@app.route('/api/me', methods=['GET'])
@login_required
def get_current_user():
    """Returns current logged-in user info for the header."""
    return jsonify({
        'success': True,
        'user': {
            'user_id':   session.get('user_id'),
            'username':  session.get('username'),
            'full_name': session.get('full_name'),
            'role':      session.get('role'),
        }
    })

@app.route('/api/recent_outages', methods=['GET'])
@login_required
def get_recent_outages():
    """Returns the 5 most recent active outage incidents for the header widget.
    Cached for _OUTAGES_CACHE_TTL seconds — the dropdown polls every 15s
    from every open tab; this collapses that into one shared query."""
    now = _time_module.time()
    if _outages_cache['data'] is not None and (now - _outages_cache['ts']) < _OUTAGES_CACHE_TTL:
        return jsonify({'success': True, 'outages': _outages_cache['data']})

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'DB error'}), 500
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"""
            SELECT
                i.incident_id,
                i.incident_type,
                i.barangay,
                i.town,
                i.report_count,
                i.status,
                i.priority,
                i.first_report_time,
                f.{FEEDER_NAME_COL} AS feeder_name
            FROM outage_incidents i
            LEFT JOIN {FEEDER_TABLE} f
                ON ST_Contains(f.geom::geometry, i.geom::geometry)
                AND f.{FEEDER_NAME_COL} != '{EXCLUDED_FEEDER}'
            WHERE i.status != 'RESTORED'
            ORDER BY i.first_report_time DESC
            LIMIT 5
        """)
        rows = cur.fetchall()
        result = []
        for r in rows:
            result.append({
                'incident_id':       r['incident_id'],
                'type':              r['incident_type'],
                'barangay':          r['barangay'],
                'town':              r['town'],
                'report_count':      r['report_count'],
                'status':            r['status'],
                'priority':          r['priority'],
                'feeder_name':       r['feeder_name'],
                'first_report_time': isoformat_safe(r['first_report_time']),
            })
        _outages_cache['data'] = result
        _outages_cache['ts'] = now
        return jsonify({'success': True, 'outages': result})
    except Exception as e:
        logger.exception("recent_outages error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)


@app.route('/api/admin/users', methods=['POST'])
@login_required
def create_user():
    """
    Create a new user account — superadmin only.
 
    Expected JSON body:
        {
            "username":  "bea.cruz",          -- required, lowercase/dots/numbers/_
            "full_name": "Beatrice Cruz",      -- optional
            "password":  "SecurePass1",        -- required, must pass complexity
            "role":      "staff"               -- staff | admin | superadmin
        }
 
    Password rules (enforced server-side AND matched in the frontend):
        - Minimum 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
    """
    if session.get('role') != 'superadmin':
        return jsonify({'success': False, 'error': 'Superadmin access required'}), 403
 
    data      = request.get_json() or {}
    username  = (data.get('username') or '').strip().lower()
    full_name = (data.get('full_name') or '').strip()
    password  = data.get('password') or ''
    role      = data.get('role', 'staff')
 
    # ── Field presence ────────────────────────────────────────────────────────
    if not username:
        return jsonify({'success': False, 'error': 'Username is required'}), 400
    if not password:
        return jsonify({'success': False, 'error': 'Password is required'}), 400
 
    # ── Username format ───────────────────────────────────────────────────────
    if not re.match(r'^[a-z0-9_.]+$', username):
        return jsonify({
            'success': False,
            'error': 'Username may only contain lowercase letters, numbers, underscores, and dots'
        }), 400
    if len(username) < 3:
        return jsonify({'success': False, 'error': 'Username must be at least 3 characters'}), 400
    if len(username) > 50:
        return jsonify({'success': False, 'error': 'Username must be 50 characters or fewer'}), 400
 
    # ── Password strength ─────────────────────────────────────────────────────
    pw_err = validate_password_strength(password)
    if pw_err:
        return jsonify({'success': False, 'error': pw_err}), 400
 
    # ── Role whitelist ────────────────────────────────────────────────────────
    if role not in ('staff', 'superadmin'):
        return jsonify({'success': False, 'error': 'Invalid role. Must be staff or superadmin'}), 400
 
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
 
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
 
        # ── Duplicate username check ──────────────────────────────────────────
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            return jsonify({'success': False, 'error': f'Username "{username}" is already taken'}), 409
 
        # ── Insert ────────────────────────────────────────────────────────────
        pw_hash = generate_password_hash(password)
        cur.execute("""
            INSERT INTO users
                (username, full_name, password_hash, role, is_active, created_at)
            VALUES
                (%s, %s, %s, %s, TRUE,
                 TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP))
            RETURNING id, username, full_name, role, is_active, created_at
        """, (
            username,
            full_name or username,   # fall back to username if no full name given
            pw_hash,
            role
        ))
        new_user = cur.fetchone()
        conn.commit()
 
        logger.info(
            f"User '{username}' (role={role}) created "
            f"by superadmin '{session.get('username')}'"
        )
 
        user_dict = dict(new_user)
        user_dict['created_at'] = isoformat_safe(user_dict.get('created_at'))
 
        return jsonify({'success': True, 'user': user_dict}), 201
 
    except Exception as e:
        conn.rollback()
        logger.exception("Create user error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)




@app.route('/api/admin/reset-password', methods=['POST'])
@login_required
def admin_reset_password():
    """
    Reset any user's password — superadmin only.
 
    Expected JSON body:
        {
            "username":     "bea.cruz",
            "new_password": "NewSecure1"
        }
 
    Password rules (same as create_user):
        - Minimum 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
    """
    if session.get('role') != 'superadmin':
        return jsonify({'success': False, 'error': 'Superadmin access required'}), 403
 
    data            = request.get_json() or {}
    target_username = (data.get('username') or '').strip()
    new_password    = data.get('new_password') or ''
 
    # ── Field presence ────────────────────────────────────────────────────────
    if not target_username:
        return jsonify({'success': False, 'error': 'Username is required'}), 400
    if not new_password:
        return jsonify({'success': False, 'error': 'New password is required'}), 400
 
    # ── Password strength ─────────────────────────────────────────────────────
    pw_err = validate_password_strength(new_password)
    if pw_err:
        return jsonify({'success': False, 'error': pw_err}), 400
 
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
 
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
 
        # ── Confirm the target user exists ────────────────────────────────────
        cur.execute(
            "SELECT id, username, full_name, is_active FROM users WHERE username = %s",
            (target_username,)
        )
        user = cur.fetchone()
        if not user:
            return jsonify({
                'success': False,
                'error': f'User "{target_username}" not found'
            }), 404
 
        # ── Warn if resetting password on a disabled account ──────────────────
        # (allowed — maybe admin is unlocking the account next — but logged)
        if not user['is_active']:
            logger.warning(
                f"Password reset performed on DISABLED account '{target_username}' "
                f"by '{session.get('username')}'"
            )
 
        # ── Hash and save ─────────────────────────────────────────────────────
        new_hash = generate_password_hash(new_password)
        cur.execute("""
            UPDATE users
            SET password_hash = %s
            WHERE username = %s
        """, (new_hash, target_username))
        conn.commit()
 
        logger.info(
            f"Password reset for user '{target_username}' "
            f"by superadmin '{session.get('username')}'"
        )
 
        return jsonify({
            'success': True,
            'message': f"Password successfully reset for {target_username}"
        })
 
    except Exception as e:
        conn.rollback()
        logger.exception("Admin reset password error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)
        

 
@app.route('/user_management')
@login_required
def user_management():
    if session.get('role') != 'superadmin':
        return redirect(url_for('dashboard'))
    return render_template('user_management.html')


@app.route('/api/internal/fb_profile/<sender_id>', methods=['GET'])
@login_required
def get_fb_profile(sender_id):
    """
    Looks up a Facebook Messenger user's name/photo via the Graph API,
    using the page access token server-side (never exposed to the browser).
    Only works for PSIDs that have messaged the page — Meta blocks
    lookups for unrelated users.
    """
    sender_id = (sender_id or '').strip()
    if not sender_id.isdigit():
        return jsonify({'success': False, 'error': 'Invalid sender ID'}), 400

    fb_token = os.getenv('FACEBOOK_PAGE_ACCESS_TOKEN', '')
    if not fb_token:
        return jsonify({'success': False, 'error': 'Page token not configured'}), 500

    try:
        resp = requests.get(
            f"https://graph.facebook.com/v19.0/{sender_id}",
            params={
                'fields': 'first_name,last_name,profile_pic',
                'access_token': fb_token
            },
            timeout=8
        )
        data = resp.json()
        if 'error' in data:
            fb_err = data['error'] or {}
            logger.warning(
                f"FB profile lookup failed for {sender_id} | "
                f"http_status={resp.status_code} | "
                f"code={fb_err.get('code')} | "
                f"type={fb_err.get('type')} | "
                f"message={fb_err.get('message')} | "
                f"fbtrace_id={fb_err.get('fbtrace_id')}"
            )
            return jsonify({
                'success': False,
                'error': 'Profile unavailable — search manually in Page Inbox',
                'debug_code': fb_err.get('code'),
                'debug_type': fb_err.get('type'),
            }), 404

        full_name = f"{data.get('first_name', '')} {data.get('last_name', '')}".strip()
        return jsonify({
            'success': True,
            'sender_id': sender_id,
            'full_name': full_name or 'Unknown',
            'profile_pic': data.get('profile_pic', '')
        })
    except Exception as e:
        logger.warning(f"FB profile lookup error for {sender_id}: {e}")
        return jsonify({'success': False, 'error': 'Lookup failed'}), 500

        

@app.route('/api/internal/meter-concern/<reference_number>', methods=['GET'])
def get_meter_concern_internal(reference_number):
    if not is_internal_request():
        logger.warning(
            f"Blocked external request to /api/internal/meter-concern "
            f"from IP: {request.remote_addr}"
        )
        return jsonify({'success': False, 'error': 'Internal access only'}), 403

    return get_meter_concern(reference_number)

@app.route('/api/internal/touch_activity/<sender_id>', methods=['POST'])
def touch_user_activity(sender_id):
    if not is_internal_request():
        return jsonify({'success': False, 'error': 'Internal access only'}), 403
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'DB unavailable'}), 500
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO user_activity (sender_id, last_message_at, nudged)
            VALUES (%s, TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP), FALSE)
            ON CONFLICT (sender_id) DO UPDATE
            SET last_message_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                nudged = FALSE
        """, (sender_id,))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        conn.rollback()
        logger.exception(f"touch_user_activity failed for {sender_id}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)

 


@app.route('/api/internal/incidents', methods=['GET'])
def get_incidents_internal():
    if not is_internal_request():
        logger.warning(
            f"Blocked external request to /api/internal/incidents "
            f"from IP: {request.remote_addr}"
        )
        return jsonify({'success': False, 'error': 'Internal access only'}), 403
 
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
 
    cur = None
    try:
        status = request.args.get('status', 'all').lower()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # FIX: same optional-column guard as get_incidents_api — f.status /
        # f.is_active may not exist on the feeder coverage table.
        _feeder_cols = _get_feeder_available_columns()
        _feeder_status_sql    = 'f.status'    if 'status'    in _feeder_cols else 'NULL'
        _feeder_is_active_sql = 'f.is_active' if 'is_active' in _feeder_cols else 'NULL'
 
        query = f"""
    SELECT 
        i.incident_id,
        i.incident_type as type,
        i.barangay,
        i.town,
        i.barangay || ', ' || i.town as location_display,
        i.report_count,
        i.status,
        i.priority,
        i.first_report_time,
        i.last_report_time,
        i.job_order_id,
        i.assigned_at,
        i.restored_at,
        i.assigned_by,
        i.restored_by,
        i.remarks,
        i.created_at,
        i.updated_at,
        ST_Y(i.geom::geometry) as lat,
        ST_X(i.geom::geometry) as lng,
        f.{FEEDER_NAME_COL} as feeder_name,
        {_feeder_status_sql} as feeder_status,
        {_feeder_is_active_sql} as feeder_is_active,
        agg.earliest_report_timestamp,
        agg.incident_time
    FROM outage_incidents i
    LEFT JOIN {FEEDER_TABLE} f
        ON ST_Contains(f.geom::geometry, i.geom::geometry)
        AND f.{FEEDER_NAME_COL} != '{EXCLUDED_FEEDER}'
    LEFT JOIN LATERAL (
        SELECT
            MIN(r.created_at) AS earliest_report_timestamp,
            (array_agg(r.incident_time ORDER BY r.created_at))[1] AS incident_time
        FROM outage_reports r
        WHERE r.incident_id = i.incident_id
    ) agg ON true
    WHERE 1=1
"""
 
        params = []
        if status != 'all':
            query += " AND UPPER(i.status) = UPPER(%s)"
            params.append(status)
 
        query += " ORDER BY i.first_report_time DESC"
        cur.execute(query, params if params else None)
        incidents = cur.fetchall()
 
        result = []
        for row in incidents:
            result.append({
                'incident_id':        row['incident_id'],
                'feeder_name':        row['feeder_name'],
                'feeder_status':      row['feeder_status'],
                'feeder_is_active':   row['feeder_is_active'],
                'type':               row['type'],
                'location_display':   row['location_display'],
                'barangay':           row['barangay'],
                'town':               row['town'],
                'report_count':       row['report_count'],
                'status':             row['status'],
                'priority':           row['priority'],
                'first_report_time':  isoformat_safe(row['first_report_time']),
                'last_report_time':   isoformat_safe(row['last_report_time']),
                'job_order_id':       row['job_order_id'],
                'assigned_at':        isoformat_safe(row['assigned_at']),
                'restored_at':        isoformat_safe(row['restored_at']),
                'assigned_by': row.get('assigned_by') or '',
                'restored_by': row.get('restored_by') or '',
                'actioned_by': row.get('assigned_by') or row.get('restored_by') or '',
                 'remarks':                   row['remarks'],
                'type_breakdown':            row.get('type_breakdown') or {},
                'lat':                       float(row['lat']) if row['lat'] else None,
                'lng':                       float(row['lng']) if row['lng'] else None,
                'earliest_report_timestamp': isoformat_safe(row['earliest_report_timestamp']),
                'incident_time':             str(row['incident_time']) if row['incident_time'] else None,
            })

        return jsonify({'success': True, 'incidents': result, 'count': len(result)})
 
    except Exception as e:
        logger.error(f"Internal incidents API error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

@app.route('/api/internal/agent_queue', methods=['POST'])
def add_to_agent_queue():
    if not is_internal_request():
        return jsonify({'success': False, 'error': 'Internal access only'}), 403

    data = request.get_json() or {}
    user_id        = (data.get('user_id') or '').strip()
    full_name      = (data.get('full_name') or 'Unknown').strip()
    concern        = (data.get('concern') or '').strip()
    contact_number = (data.get('contact_number') or '').strip()
    priority       = (data.get('priority') or 'medium').strip().lower()

    if not user_id:
        return jsonify({'success': False, 'error': 'user_id is required'}), 400

    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500

    cur = None
    # ── Declare response variables outside try so finally can't shadow them ──
    response_payload = None
    response_status  = 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Prevent duplicate pending entries for the same user
        cur.execute("""
            SELECT id FROM agent_queue
            WHERE user_id = %s AND status = 'Pending'
            LIMIT 1
        """, (user_id,))
        existing = cur.fetchone()

        if existing:
            cur.execute("""
                SELECT COUNT(*) AS pos
                FROM agent_queue
                WHERE status = 'Pending'
                  AND timestamp <= (
                      SELECT timestamp FROM agent_queue WHERE id = %s
                  )
            """, (existing['id'],))
            pos_row = cur.fetchone()
            queue_position = max(int(pos_row['pos']), 1) if pos_row else 1

            response_payload = {
                'success':        True,
                'message':        'Already in queue',
                'queue_id':       existing['id'],
                'already_queued': True,
                'queue_position': queue_position,
            }
            response_status = 200

        else:
            # ── INSERT the new record ──────────────────────────────────────────
            cur.execute("""
    INSERT INTO agent_queue
        (user_id, full_name, concern, contact_number, priority, status, timestamp)
    VALUES
        (%s, %s, %s, %s, %s, 'Pending', CURRENT_TIMESTAMP)
    RETURNING id, full_name, priority, status, timestamp
""", (user_id, full_name, concern, contact_number, priority))

            new_item = cur.fetchone()

            # Count total Pending AFTER insert on the SAME connection
            # so the uncommitted row is visible in this transaction.
            cur.execute("""
                SELECT COUNT(*) AS pos
                FROM agent_queue
                WHERE status = 'Pending'
            """)
            pos_row        = cur.fetchone()
            queue_position = max(int(pos_row['pos']), 1) if pos_row else 1

            conn.commit()

            logger.info(
                f"Agent queue: {full_name} (user_id={user_id}) added "
                f"with priority={priority}, position=#{queue_position}"
            )

            response_payload = {
                'success':        True,
                'message':        'Added to queue',
                'queue_id':       new_item['id'],
                'already_queued': False,
                'queue_position': queue_position,
            }
            response_status = 201

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logger.exception("add_to_agent_queue error")
        response_payload = {'success': False, 'error': str(e)}
        response_status  = 500

    finally:
        if cur:
            cur.close()
        release_local_conn(conn)

    # ── Always reached — Flask gets a valid response object ──────────────────
    return jsonify(response_payload), response_status

@app.route('/api/incidents', methods=['GET'])
@login_required
def get_incidents_api():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500

    cur = None
    try:
        status = request.args.get('status', 'all').lower()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # FIX: confirmed via information_schema that the feeder table has
        # ONLY id/geom/fid/layer — no status or is_active. This endpoint
        # (unlike get_incidents_internal) was still hardcoding f.status /
        # f.is_active, which throws UndefinedColumn -> 500 on every load.
        _feeder_cols = _get_feeder_available_columns()
        _feeder_status_sql    = 'f.status'    if 'status'    in _feeder_cols else 'NULL'
        _feeder_is_active_sql = 'f.is_active' if 'is_active' in _feeder_cols else 'NULL'

        query = f"""
    SELECT
        i.incident_id,
        i.incident_type AS type,
        i.barangay,
        i.town,
        i.barangay || ', ' || i.town AS location_display,
        i.report_count,
        i.status,
        i.priority,
        i.first_report_time,
        i.last_report_time,
        i.job_order_id,
        i.assigned_at,
        i.restored_at,
        i.assigned_by,
        i.restored_by,
        i.remarks,
        i.created_at,
        i.updated_at,
        i.type_breakdown,
        i.incident_category,
        i.priority_code,
        ST_Y(i.geom::geometry) AS lat,
        ST_X(i.geom::geometry) AS lng,
        f.{FEEDER_NAME_COL}    AS feeder_name,
        {_feeder_status_sql}    AS feeder_status,
        {_feeder_is_active_sql} AS feeder_is_active,
        agg.earliest_report_timestamp,
        agg.incident_time,
        agg.reference_id,
        agg.consumer_names,
        agg.account_numbers
    FROM outage_incidents i
    LEFT JOIN {FEEDER_TABLE} f
        ON ST_Contains(f.geom::geometry, i.geom::geometry)
        AND f.{FEEDER_NAME_COL} != '{EXCLUDED_FEEDER}'
    LEFT JOIN LATERAL (
        SELECT
            MIN(r.created_at) AS earliest_report_timestamp,
            (array_agg(r.incident_time ORDER BY r.created_at))[1] AS incident_time,
            (array_agg(r.reference_id ORDER BY r.created_at)
                FILTER (WHERE r.reference_id IS NOT NULL))[1] AS reference_id,
            string_agg(DISTINCT r.full_name, ', ')
                FILTER (WHERE r.full_name IS NOT NULL AND r.full_name != '') AS consumer_names,
            string_agg(DISTINCT r.account_number, ', ')
                FILTER (WHERE r.account_number IS NOT NULL AND r.account_number != '') AS account_numbers
        FROM outage_reports r
        WHERE r.incident_id = i.incident_id
    ) agg ON true
    WHERE 1=1
"""
        params = []
        if status != 'all':
            query += " AND UPPER(i.status) = UPPER(%s)"
            params.append(status)

        query += " ORDER BY i.first_report_time DESC"
        cur.execute(query, params if params else None)
        incidents = cur.fetchall()

        result = []
        for row in incidents:
                        result.append({
                'reference_id':              row.get('reference_id') or '',
                'consumer_names':            row.get('consumer_names') or '',
                'account_numbers':           row.get('account_numbers') or '',
                'incident_id':               row['incident_id'],
                'feeder_name':               row['feeder_name'],
                'feeder_status':             row['feeder_status'],
                'feeder_is_active':          row['feeder_is_active'],
                'type':                      row['type'],
                'type_breakdown':            row.get('type_breakdown') or {},   # ← ADDED
                'location_display':          row['location_display'],
                'barangay':                  row['barangay'],
                'town':                      row['town'],
                'report_count':              row['report_count'],
                'status':                    row['status'],
                'priority':                  row['priority'],
                'first_report_time':         isoformat_safe(row['first_report_time']),
                'last_report_time':          isoformat_safe(row['last_report_time']),
                'job_order_id':              row['job_order_id'],
                'assigned_at':               isoformat_safe(row['assigned_at']),
                'restored_at':               isoformat_safe(row['restored_at']),
                'assigned_by':               row.get('assigned_by') or '',
                'restored_by':               row.get('restored_by') or '',
                'actioned_by':               row.get('assigned_by') or row.get('restored_by') or '',
                'remarks':                   row['remarks'],
                'incident_category':         row.get('incident_category') or '',
                'priority_code':             row.get('priority_code') or '',
                'lat':                       float(row['lat']) if row['lat'] else None,
                'lng':                       float(row['lng']) if row['lng'] else None,
                'earliest_report_timestamp': isoformat_safe(row['earliest_report_timestamp']),
                'incident_time':             str(row['incident_time']) if row['incident_time'] else None,
            })

        return jsonify({'success': True, 'incidents': result, 'count': len(result)})

    except Exception as e:
        logger.error(f"Error fetching incidents: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)


@app.route('/api/incident/<int:incident_id>/update_position', methods=['POST'])
@login_required
def update_incident_position(incident_id):
    data = request.get_json() or {}
    try:
        lat = float(data.get('lat'))
        lng = float(data.get('lng'))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Invalid coordinates'}), 400
    if not (4.0 <= lat <= 21.0 and 116.0 <= lng <= 127.0):
        return jsonify({'success': False, 'error': 'Coordinates outside Philippines'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE outage_incidents
            SET geom = ST_SetSRID(ST_MakePoint(%s, %s), 4326),
                updated_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
            WHERE incident_id = %s
        """, (lng, lat, incident_id))
        if cur.rowcount == 0:
            return jsonify({'success': False, 'error': 'Incident not found'}), 404
        conn.commit()
        return jsonify({'success': True, 'lat': lat, 'lng': lng})
    except Exception as e:
        conn.rollback()
        logger.exception("update_incident_position error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)


@app.route('/api/report/<int:report_id>/update_position', methods=['POST'])
@login_required
def update_report_position(report_id):
    data = request.get_json() or {}
    try:
        lat = float(data.get('lat'))
        lng = float(data.get('lng'))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Invalid coordinates'}), 400
    if not (4.0 <= lat <= 21.0 and 116.0 <= lng <= 127.0):
        return jsonify({'success': False, 'error': 'Coordinates outside Philippines'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE outage_reports
            SET geom = ST_SetSRID(ST_MakePoint(%s, %s), 4326)
            WHERE report_id = %s
        """, (lng, lat, report_id))
        if cur.rowcount == 0:
            return jsonify({'success': False, 'error': 'Report not found'}), 404
        conn.commit()
        return jsonify({'success': True, 'lat': lat, 'lng': lng})
    except Exception as e:
        conn.rollback()
        logger.exception("update_report_position error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)

@app.route('/api/incident/<int:incident_id>')
@login_required
def get_incident_details(incident_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500

    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT incident_id, incident_type, barangay, town, report_count,
                   confidence_level, status, priority, first_report_time, last_report_time,
                   job_order_id, ST_Y(geom) as lat, ST_X(geom) as lng, 
                   resolved_at, assigned_at, restored_at, created_at, updated_at
            FROM outage_incidents
            WHERE incident_id = %s
        """, (incident_id,))

        incident = cur.fetchone()
        if not incident:
            return jsonify({'success': False, 'error': 'Incident not found'}), 404

        cur.execute("""
            SELECT report_id, full_name, contact_number, email, account_number, 
                   address, barangay, town, 
                   incident_type, affected_area, incident_time, duration,
                   details, landmark, timestamp, source, 
                   COALESCE(status, 'NEW') as status,
                   priority,
                   status_changed_at,
                   assigned_at,
                   restored_at,
                   reference_id,
                   photo_urls,
                   ST_Y(geom) as lat, ST_X(geom) as lng,
                   ST_AsText(geom) as geom_wkt
            FROM outage_reports
            WHERE incident_id = %s
            ORDER BY timestamp ASC
        """, (incident_id,))

        reports = cur.fetchall()

        rep_list = []
        for r in reports:
            rr = dict(r)
            for key, value in rr.items():
                if value is not None:
                    if isinstance(value, time):
                        rr[key] = value.strftime('%H:%M:%S')
                    elif hasattr(value, 'isoformat'):
                        rr[key] = isoformat_safe(value)
            rep_list.append(rr)

        incident_dict = dict(incident)
        incident_dict['first_report_time'] = isoformat_safe(incident_dict.get('first_report_time'))
        incident_dict['last_report_time'] = isoformat_safe(incident_dict.get('last_report_time'))
        incident_dict['resolved_at'] = isoformat_safe(incident_dict.get('resolved_at'))
        incident_dict['assigned_at'] = isoformat_safe(incident_dict.get('assigned_at'))
        incident_dict['restored_at'] = isoformat_safe(incident_dict.get('restored_at'))
        incident_dict['created_at'] = isoformat_safe(incident_dict.get('created_at'))
        incident_dict['updated_at'] = isoformat_safe(incident_dict.get('updated_at'))

        return jsonify({'success': True, 'data': {'incident': incident_dict, 'reports': rep_list}})

    except Exception as e:
        logger.exception("Get incident details error")
        return jsonify({'success': False, 'error': 'Failed to fetch incident details'}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

@app.route('/api/dashboard_stats', methods=['GET'])
@login_required
def get_dashboard_stats_api():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500

    cur = None
    try:
        cur = conn.cursor()
        
        cur.execute("""
            SELECT
                COUNT(*) FILTER (WHERE status != 'RESTORED') AS active_outages,
                COALESCE(SUM(report_count) FILTER (WHERE status != 'RESTORED'), 0) AS affected_consumers,
                COUNT(*) FILTER (WHERE priority = 'CRITICAL' AND status != 'RESTORED') AS critical_incidents
            FROM outage_incidents
        """)
        active_outages, affected_consumers, critical_incidents = cur.fetchone()

        cur.execute("SELECT COUNT(*) FROM outage_reports WHERE DATE(created_at AT TIME ZONE 'Asia/Manila') = CURRENT_DATE")
        reports_today = cur.fetchone()[0]
        
        return jsonify({
            'success': True,
            'stats': {
                'active_outages': active_outages,
                'affected_consumers': affected_consumers,
                'critical_incidents': critical_incidents,
                'reports_today': reports_today
            }
        })
        
    except Exception as e:
        logger.error(f"Stats error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)
    

@app.route('/api/incidents/last_updated', methods=['GET'])
@login_required
def incidents_last_updated():
    """Lightweight endpoint for smart polling — only returns last update timestamp."""
    conn = get_db_connection()
    if not conn:
        return jsonify({'ts': None}), 200
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT MAX(updated_at) FROM outage_incidents")
        ts = cur.fetchone()[0]
        return jsonify({'ts': isoformat_safe(ts)})
    except Exception as e:
        return jsonify({'ts': None}), 200
    finally:
        if cur: cur.close()
        release_db_connection(conn)

@app.route('/api/update_incident_status/<int:incident_id>', methods=['POST'])
@login_required
def update_incident_status(incident_id):
    data = request.get_json() or {}
    new_status = (data.get('status') or '').strip().upper()
    valid = ['NEW', 'ASSIGNED', 'RESTORED']
    if new_status not in valid:
        return jsonify({'success': False, 'error': 'Invalid status'}), 400

    actor = session.get('full_name') or session.get('username', 'Unknown')

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            UPDATE outage_incidents
            SET status      = %s,
                assigned_at = CASE WHEN %s='ASSIGNED' AND assigned_at IS NULL
                              THEN TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) ELSE assigned_at END,
                restored_at = CASE WHEN %s='RESTORED' AND restored_at IS NULL
                              THEN TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) ELSE restored_at END,
                resolved_at = CASE WHEN %s='RESTORED'
                              THEN TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) ELSE resolved_at END,
                assigned_by = CASE WHEN %s='ASSIGNED' AND assigned_at IS NULL
                              THEN %s ELSE assigned_by END,
                restored_by = CASE WHEN %s='RESTORED'
                              THEN %s ELSE restored_by END,
                updated_at  = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
            WHERE incident_id = %s
            RETURNING incident_id, job_order_id, barangay, town,
                      assigned_at, restored_at, assigned_by, restored_by
        """, (new_status, new_status, new_status, new_status,
              new_status, actor, new_status, actor, incident_id))
        res = cur.fetchone()
        if not res:
            return jsonify({'success': False, 'error': 'Incident not found'}), 404

        # ── Cascade to the individual consumer reports ──────────────
        #  ASSIGNED → only reports still NEW
        #  RESTORED → every report that is not already restored/resolved
        if new_status in ('ASSIGNED', 'RESTORED'):
            cur.execute("""
                UPDATE outage_reports
                SET status            = %s,
                    status_changed_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                    assigned_at = CASE WHEN %s='ASSIGNED' AND assigned_at IS NULL
                                  THEN TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) ELSE assigned_at END,
                    restored_at = CASE WHEN %s='RESTORED' AND restored_at IS NULL
                                  THEN TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) ELSE restored_at END
                WHERE incident_id = %s
                  AND status NOT IN ('RESTORED', 'RESOLVED')
                  AND (%s = 'RESTORED' OR status = 'NEW')
            """, (new_status, new_status, new_status, incident_id, new_status))

        conn.commit()
        logger.info(f"Incident {incident_id} → {new_status} by {actor} (reports cascaded)")
        try:
            socketio.emit('incident_updated', {
                'incident_id': incident_id,
                'new_status':  new_status,
                'actioned_by': actor,
                'location':    f"{res['town']} / {res['barangay']}",
                'timestamp':   isoformat_safe(datetime.now(timezone.utc))
            })
        except Exception:
            logger.exception("WebSocket broadcast error")
        return jsonify({
            'success': True,
            'message': f'Status updated to {new_status} by {actor}',
            'actioned_by': actor,
            'assigned_by': res.get('assigned_by'),
            'restored_by': res.get('restored_by'),
        })
    except Exception:
        conn.rollback()
        logger.exception("Update status error")
        return jsonify({'success': False, 'error': 'Failed to update incident status'}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)

def initialize_spam_logs_table():
    """Create spam_logs table if it doesn't exist yet (local DB)."""
    conn = get_local_conn()
    if not conn:
        return
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS spam_logs (
                id SERIAL PRIMARY KEY,
                sender_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message_sample TEXT,
                created_at TIMESTAMP DEFAULT TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                reviewed BOOLEAN DEFAULT FALSE,
                reviewed_by TEXT,
                reviewed_at TIMESTAMP
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_spam_logs_sender_id ON spam_logs(sender_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_spam_logs_reviewed ON spam_logs(reviewed)")
        conn.commit()
        logger.info("✅ spam_logs table ready")
    except Exception:
        try: conn.rollback()
        except Exception: pass
        logger.exception("Failed to initialize spam_logs table")
    finally:
        if cur: cur.close()
        release_local_conn(conn)

def initialize_user_activity_table():
    """Create user_activity table if it doesn't exist yet (local DB)."""
    conn = get_local_conn()
    if not conn:
        return
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_activity (
                sender_id TEXT PRIMARY KEY,
                last_message_at TIMESTAMP DEFAULT TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                nudged BOOLEAN DEFAULT FALSE
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_user_activity_last_message ON user_activity(last_message_at)")
        conn.commit()
        logger.info("✅ user_activity table ready")
    except Exception:
        try: conn.rollback()
        except Exception: pass
        logger.exception("Failed to initialize user_activity table")
    finally:
        if cur: cur.close()
        release_local_conn(conn)

def initialize_tracking_columns():
    """Add assigned_by / restored_by / type_breakdown / incident_category / priority_code
    on outage_incidents, and reference_id on outage_reports, if they don't exist yet."""
    conn = get_db_connection()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='outage_incidents' AND column_name='assigned_by'
                ) THEN
                    ALTER TABLE outage_incidents ADD COLUMN assigned_by TEXT;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='outage_incidents' AND column_name='restored_by'
                ) THEN
                    ALTER TABLE outage_incidents ADD COLUMN restored_by TEXT;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='outage_incidents' AND column_name='type_breakdown'
                ) THEN
                    ALTER TABLE outage_incidents ADD COLUMN type_breakdown JSONB DEFAULT '{}'::jsonb;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='outage_incidents' AND column_name='incident_category'
                ) THEN
                    ALTER TABLE outage_incidents ADD COLUMN incident_category TEXT;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='outage_incidents' AND column_name='priority_code'
                ) THEN
                    ALTER TABLE outage_incidents ADD COLUMN priority_code TEXT;
                END IF;
                -- FIX: /api/incidents' LATERAL join selects r.reference_id
                -- (aliased as agg.reference_id). submit_power_outage() writes
                -- to this column via UPDATE, which silently no-ops if the
                -- column doesn't exist rather than failing loudly — but the
                -- SELECT in /api/incidents throws UndefinedColumn and 500s
                -- the whole dashboard incident list/map.
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='outage_reports' AND column_name='reference_id'
                ) THEN
                    ALTER TABLE outage_reports ADD COLUMN reference_id TEXT;
                END IF;
            END $$;
        """)
        conn.commit()
        cur.close()
        logger.info(
            "✅ Tracking columns ready "
            "(assigned_by, restored_by, type_breakdown, incident_category, "
            "priority_code, outage_reports.reference_id)"
        )
    except Exception as e:
        logger.exception("Failed to initialize tracking columns")
    finally:
        release_db_connection(conn)

def initialize_performance_indexes():
    import socket as _socket

    conn = None
    cur = None
    try:
        host = os.getenv("CLOUD_DB_HOST", "")
        try:
            _socket.getaddrinfo(host, None)
        except Exception:
            logger.warning("Skipping index initialization — cloud DB host not resolvable")
            return

        # Dedicated connection, NOT from the pool — CONCURRENTLY requires
        # autocommit and must never be handed back to a pool that expects
        # connections to be in a known transactional state.
        conn = psycopg2.connect(
            host=host,
            port=int(os.getenv("CLOUD_DB_SESSION_PORT", "5432")),
            database=os.getenv("CLOUD_DB_NAME"),
            user=os.getenv("CLOUD_DB_USER"),
            password=os.getenv("CLOUD_DB_PASSWORD"),
            connect_timeout=10,
            sslmode='require',
        )

        # Roll back any implicitly-started transaction before enabling
        # autocommit — psycopg2 raises ProgrammingError otherwise.
        conn.rollback()
        conn.autocommit = True

        cur = conn.cursor()

        # ── Only one worker process should run index creation ──────────
        # Advisory lock keyed on a fixed arbitrary number. If another
        # worker already holds it, this one skips immediately instead of
        # queuing behind CREATE INDEX CONCURRENTLY on the same tables.
        cur.execute("SELECT pg_try_advisory_lock(918273645)")
        got_lock = cur.fetchone()[0]
        if not got_lock:
            logger.info("Skipping index initialization — another worker already holds the lock")
            return

        statements = [
            # outage_reports — duplicate-check gate (phone/account/email
            # all filter on this same barangay+town+type+status shape)
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_reports_dup_check
               ON outage_reports (contact_number, barangay, town, incident_type, status)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_reports_account_dup_check
               ON outage_reports (account_number, barangay, town, incident_type, status)
               WHERE account_number IS NOT NULL AND account_number != ''""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_reports_email_dup_check
               ON outage_reports (email, barangay, town, incident_type, status)
               WHERE email IS NOT NULL AND email != ''""",
            # outage_reports — reference ID lookups (chatbot status checks)
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_reports_reference_id
               ON outage_reports (reference_id)
               WHERE reference_id IS NOT NULL""",
            # outage_reports — incident join + timestamp ordering
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_reports_incident_id
               ON outage_reports (incident_id, timestamp)""",
            # outage_incidents — cluster lookup (barangay+town+type+status,
            # used by every non-critical submission to find an active cluster)
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_incidents_cluster_lookup
               ON outage_incidents (barangay, town, incident_type, status)""",
            # outage_incidents — dashboard list/poll queries
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_incidents_status_time
               ON outage_incidents (status, first_report_time DESC)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_incidents_updated_at
               ON outage_incidents (updated_at DESC)""",
            # Spatial GIST indexes — required for ST_Contains / ST_DWithin
            # to avoid a full scan on every feeder-check / nearby-complaints call
            f"""CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_feeder_geom_gist
               ON {FEEDER_TABLE} USING GIST (geom)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_incidents_geom_gist
               ON outage_incidents USING GIST (geom)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_reports_geom_gist
               ON outage_reports USING GIST (geom)""",

            # ── NEW: agent_queue — this table previously had ZERO indexes.
            # Every /api/agent_queue call (status filter, priority filter,
            # date filter, ORDER BY timestamp/served_at) was doing a full
            # sequential scan, which is why the Service Desk dashboard got
            # progressively slower as the queue history grew.
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_agent_queue_status_timestamp
               ON agent_queue (status, timestamp DESC)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_agent_queue_status_served_at
               ON agent_queue (status, served_at DESC)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_agent_queue_priority
               ON agent_queue (priority)
               WHERE status = 'Pending'""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_agent_queue_user_pending
               ON agent_queue (user_id, status)
               WHERE status = 'Pending'""",

            # ── NEW: meter_concerns — same problem, zero indexes.
            # /api/meter-concerns filters on status, priority, barangay,
            # concern_type, and date, then sorts by created_at/resolved_at.
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_meter_concerns_status_created
               ON meter_concerns (status, created_at DESC)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_meter_concerns_status_resolved
               ON meter_concerns (status, resolved_at DESC)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_meter_concerns_priority
               ON meter_concerns (priority)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_meter_concerns_concern_type
               ON meter_concerns (concern_type)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_meter_concerns_barangay
               ON meter_concerns (barangay)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_meter_concerns_reference_number
               ON meter_concerns (reference_number)""",
            # concern_evidence / concern_activity_log — every detail-modal
            # open does two lookups keyed on meter_concern_id
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_concern_evidence_concern_id
               ON concern_evidence (meter_concern_id)""",
            """CREATE INDEX CONCURRENTLY IF NOT EXISTS
               idx_concern_activity_log_concern_id
               ON concern_activity_log (meter_concern_id)""",
        ]

        for stmt in statements:
            try:
                cur.execute(stmt)
                logger.info(f"✅ Index ready: {stmt.splitlines()[1].strip()}")
            except Exception as idx_err:
                # Log and continue — one failing index (e.g. table not
                # yet present) shouldn't block the others. Each CONCURRENTLY
                # statement is auto-committed individually since autocommit
                # is on, so a failure here does not roll back prior successes.
                logger.warning(f"Index creation skipped/failed: {idx_err}")

        logger.info("✅ Performance index initialization complete")

    except Exception:
        logger.exception("Failed to initialize performance indexes")
    finally:
        if cur:
            try:
                cur.close()
            except Exception:
                pass
        if conn:
            try:
                conn.close()   # closed directly — never released to the pool
            except Exception:
                pass

@app.route('/api/map_reports', methods=['GET'])
@login_required
def get_map_reports():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500

    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT r.report_id as id, r.incident_id, r.full_name, r.contact_number, r.address,
                   r.details, r.priority, r.created_at, r.incident_type,
                   r.status,
                   ST_X(r.geom::geometry) as lng,
                   ST_Y(r.geom::geometry) as lat
            FROM outage_reports r
            WHERE ST_X(r.geom::geometry) IS NOT NULL 
            AND ST_Y(r.geom::geometry) IS NOT NULL
            AND r.status != 'RESOLVED'
            ORDER BY r.created_at DESC
        """)
        
        reports = cur.fetchall()
        result = []
        for row in reports:
                result.append({
                'id': row['id'],
                'incident_id': row['incident_id'],
                'customer': row['full_name'],
                'contact': row['contact_number'],
                'address': row['address'],
                'details': row['details'],
                'priority': row['priority'],
                'timestamp': row['created_at'].isoformat() if row['created_at'] else None,
                'incident_type': row['incident_type'],
                'status': row['status'],
                'lat': float(row['lat']) if row['lat'] else None,
                'lng': float(row['lng']) if row['lng'] else None
            })
        
        return jsonify({'success': True, 'reports': result, 'count': len(result)})
        
    except Exception as e:
        logger.error(f"Error fetching map reports: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

@app.route('/api/update_report_status/<int:report_id>', methods=['POST'])
@login_required
def update_report_status(report_id):
    data = request.get_json() or {}
    new_status = (data.get('status') or '').strip().upper()
    valid = ['NEW', 'ASSIGNED', 'RESTORED']
    if new_status not in valid:
        return jsonify({'success': False, 'error': 'Invalid status'}), 400

    actor = session.get('full_name') or session.get('username', 'Unknown')

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            UPDATE outage_reports
            SET status            = %s,
                status_changed_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                assigned_at       = CASE WHEN %s='ASSIGNED' AND assigned_at IS NULL
                                    THEN TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) ELSE assigned_at END,
                restored_at       = CASE WHEN %s='RESTORED' AND restored_at IS NULL
                                    THEN TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) ELSE restored_at END
            WHERE report_id = %s
            RETURNING report_id, full_name, incident_id, status_changed_at, assigned_at, restored_at
        """, (new_status,
              new_status,
              new_status,
              report_id))
        res = cur.fetchone()
        if not res:
            return jsonify({'success': False, 'error': 'Report not found'}), 404
        conn.commit()
        return jsonify({
            'success': True,
            'message': f'Report status updated to {new_status} by {actor}',
            'actioned_by': actor,
            'status_changed_at': isoformat_safe(res['status_changed_at'])
        })
    except Exception as e:
        conn.rollback()
        logger.exception("Update report status error")
        return jsonify({'success': False, 'error': 'Failed to update report status'}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)

def get_outage_rate_limit_key():
    """
    Rate-limit key for /api/submit_power_outage.

    Web-form submissions (no internal secret) are limited per client IP,
    as before. Chatbot-proxied submissions (carrying a valid
    X-Internal-Secret header from the Rasa action server) are limited
    per-consumer using their contact number instead — otherwise every
    Messenger user funnels through one shared action-server IP and a
    handful of chatbot reports exhausts the 5/hour bucket for every
    other chatbot user, even though each is a distinct real person.
    """
    internal_secret = os.getenv('INTERNAL_API_SECRET', '')
    request_secret = request.headers.get('X-Internal-Secret', '')
    if internal_secret and request_secret == internal_secret:
        try:
            data = request.get_json(silent=True) or {}
        except Exception:
            data = {}
        contact = (data.get('contact_number') or '').strip()
        if contact:
            return f"chatbot:{contact}"
    return get_client_ip()

def get_client_ip():
    """
    Returns the real client IP behind Railway's reverse proxy.

    We take the RIGHTMOST entry, not the leftmost. The proxy appends
    the true client IP as the last hop of X-Forwarded-For; the
    leftmost entry is attacker-controlled — anyone can send
    X-Forwarded-For: 1.2.3.4 and spoof past IP-based rate limiting
    and IP blocking if we trust it.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.remote_addr or "unknown"


def is_ip_blocked(ip):
    if ip not in BLOCKED_IPS:
        return False

    expires = BLOCKED_IPS[ip]

    if datetime.now() > expires:
        del BLOCKED_IPS[ip]
        return False

    return True


def register_failed_token(ip):
    _prune_failed_tokens()
    entry = FAILED_TOKENS.get(ip, {'count': 0, 'last_seen': datetime.now()})
    entry['count'] += 1
    entry['last_seen'] = datetime.now()
    FAILED_TOKENS[ip] = entry

    if entry['count'] >= 10:
        BLOCKED_IPS[ip] = datetime.now() + timedelta(hours=1)


def clear_failed_tokens(ip):
    FAILED_TOKENS.pop(ip, None)


def generate_device_fingerprint():
    ua = request.headers.get("User-Agent", "")
    lang = request.headers.get("Accept-Language", "")
    return hashlib.sha256(
        f"{ua}|{lang}".encode()
    ).hexdigest()


@app.route('/api/submit_power_outage', methods=['POST', 'OPTIONS'])
@limiter.limit(
    "5 per hour",
    key_func=get_outage_rate_limit_key,
    error_message=json.dumps({
        'success': False,
        'error': (
            'You have reached the maximum of 5 reports per hour from your connection. '
            'Please wait 1 hour before submitting again. '
            'For emergencies (fallen wire, fire, electric shock) call 09989893028 immediately.'
        ),
        'error_code': 'RATE_LIMIT_EXCEEDED'
    })
)
def submit_power_outage():
    # ----------------------------------------------------------
    # CORS preflight — Railway / Vercel proxy sends OPTIONS
    # before the actual POST.  Return 200 immediately so the
    # browser proceeds with the real request.
    # ----------------------------------------------------------
    if request.method == 'OPTIONS':
        return _cors_preflight_response('Content-Type, Accept, X-Form-Token, X-Submit-Time')
 
    logger.info("=" * 80)
    logger.info("📱 POWER OUTAGE SUBMISSION:")
    logger.info(f"   IP Address: {request.remote_addr}")
    logger.info(f"   Content-Type: {request.headers.get('Content-Type', 'N/A')}")
    logger.info("=" * 80)
 
    # ==========================================================
    # [A] USER-AGENT CHECK
    # Blocks automated scripts (curl, python-requests, etc.).
    # Real browsers always send a UA string.
    # Localhost / Railway internal calls are exempted so
    # health-check scripts or internal API consumers still work.
    # ==========================================================
    ua = request.headers.get('User-Agent', '')
    if not ua:
        logger.warning(f"Rejected: empty UA from {request.remote_addr}")
        return jsonify({'success': False, 'error': 'Invalid client'}), 403
 
    bot_signatures = [
        'curl', 'python-requests', 'python/', 'wget', 'httpie',
        'go-http', 'java/', 'libwww', 'scrapy', 'okhttp'
    ]
    if any(b in ua.lower() for b in bot_signatures):
        logger.warning(f"Rejected bot UA: '{ua[:60]}' from {request.remote_addr}")
        return jsonify({'success': False, 'error': 'Invalid client'}), 403
 
    # ==========================================================
    # [B] FORM TOKEN CHECK
    # _issue_form_token() generates a UUID stored server-side.
    # _validate_form_token() pops it (one-time use) and checks
    # it was issued within the last hour.  This blocks:
    #   • Automated POST replay attacks
    #   • Cross-site form submissions
    #   • Scrapers that POST without first loading the page
    # ==========================================================
    form_token = request.headers.get('X-Form-Token', '').strip()
    ip = get_client_ip()                   # ← define ip here, before first use
    if not _peek_form_token(form_token):

        register_failed_token(ip)

        logger.warning(
            f"Rejected: invalid/missing form token from {ip}"
        )

        return jsonify({
            'success': False,
            'error': (
                'Your session has expired. '
                'Please refresh the page and try again.'
            ),
            'error_code': 'TOKEN_INVALID'
        }), 403

    clear_failed_tokens(ip)
 
    # ==========================================================
    # [C] TIMING CHECK
    # The frontend stamps X-Submit-Time with milliseconds since
    # page load.  A genuine human cannot fill every required
    # field in under 8 seconds.  Anything faster is a bot.
    # ==========================================================
    try:
        elapsed_ms = int(request.headers.get('X-Submit-Time', '0'))
        if 0 < elapsed_ms < 8000:
            logger.warning(
                f"Rejected: form submitted in {elapsed_ms}ms "
                f"from {request.remote_addr}"
            )
            return jsonify({
                'success': False,
                'error': 'Please take a moment to review the form before submitting.'
            }), 429
    except (ValueError, TypeError):
        # Header missing or non-numeric — allow through.
        # We do not hard-reject on missing header because older
        # mobile browsers sometimes strip custom headers.
        pass
 
    conn = None
    cur  = None
    try:
        data = request.get_json(force=True)
 
        import re
        import html
 
        # ======================================================
        # [D] HONEYPOT CHECK
        # The form renders a hidden field (_hp_field) that is
        # invisible to humans via CSS.  Bots that fill all
        # fields will populate it.  We return a fake success
        # so the bot thinks it worked (no retry signal).
        # ======================================================
        if (data.get('_hp_field') or '') != '':
            logger.warning(
                f"Honeypot triggered from {request.remote_addr} — "
                f"discarding silently"
            )
            return jsonify({
                'success':      True,
                'message':      'Report submitted successfully',
                'report_id':    0,
                'incident_id':  0,
                'priority':     'HIGH',
                'feeder_name':  None,
                'reference_id': f"RPT-{datetime.now():%y%m%d}-BOT",
                'is_followup':  False,
            }), 201
 
        # ======================================================
        # 1. REQUIRED FIELD PRESENCE CHECK
        # Every field in this list must be non-empty string.
        # We check presence here; format is validated below.
        # ======================================================
        required_fields = [
            'full_name', 'contact_number', 'address',
            'details', 'town', 'barangay'
        ]
        for field in required_fields:
            if not data.get(field) or not str(data.get(field)).strip():
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
 
        # ======================================================
        # 2. CONTACT NUMBER FORMAT
        # Philippine mobile format: 09XXXXXXXXX (11 digits), valid
        # for ALL telcos (Globe, Smart/PLDT, DITO, Sun, TNT, TM, etc.)
        # since the numbering plan is carrier-agnostic and numbers
        # can be ported between carriers (RA 11202).
        #
        # Normalizes +639XXXXXXXXX / 639XXXXXXXXX / 09XXXXXXXXX —
        # the frontend should already send normalized 09XXXXXXXXX,
        # but this is defence-in-depth in case of direct API calls.
        # ======================================================
        def _normalize_ph_number(v: str) -> str:
            n = re.sub(r'[\s\-().]', '', v or '')
            if n.startswith('+63'):
                n = '0' + n[3:]
            elif n.startswith('63') and len(n) == 12:
                n = '0' + n[2:]
            return n

        contact_number = _normalize_ph_number(data.get('contact_number', '').strip())
        if not re.match(r'^09\d{9}$', contact_number):
            return jsonify({
                'success': False,
                'error': 'Invalid contact number format. Enter an 11-digit mobile number, e.g. 09171234567'
            }), 400
 
        # ======================================================
        # 3. OPTIONAL EMAIL FORMAT
        # Only validated when the consumer actually typed one.
        # An empty string is always accepted.
        # ======================================================
        email = data.get('email', '').strip()
        if email and not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            return jsonify({
                'success': False, 'error': 'Invalid email format'
            }), 400
 
        # ======================================================
        # 4. COORDINATE VALIDATION
        # Both lat/lng must be present and within the Philippine
        # bounding box.  Coordinates outside this box indicate
        # a manipulated request.
        # ======================================================
        latitude  = data.get('latitude')
        longitude = data.get('longitude')
        if latitude is None or longitude is None:
            return jsonify({
                'success': False, 'error': 'Missing coordinates'
            }), 400
        try:
            lat = float(latitude)
            lng = float(longitude)
            if not (4.0 <= lat <= 21.0 and 116.0 <= lng <= 127.0):
                return jsonify({
                    'success': False,
                    'error': 'Coordinates outside Philippines'
                }), 400
        except (ValueError, TypeError):
            return jsonify({
                'success': False, 'error': 'Invalid coordinate format'
            }), 400
 
        # ======================================================
        # 5. SANITIZE ALL TEXT INPUTS
        # html.escape() converts < > & " ' into safe entities.
        # This prevents XSS if any value is later rendered into
        # an HTML page without re-escaping (defence in depth).
        # ======================================================
        full_name = html.escape(data.get('full_name', '').strip())
        address   = html.escape(data.get('address',   '').strip())
        details   = html.escape(data.get('details',   '').strip())
        landmark  = html.escape(data.get('landmark',  '').strip()) if data.get('landmark') else ''
        email     = html.escape(email) if email else ''

# Normalize FIRST (fixes casing/whitespace), then escape for XSS safety
# This ensures "cagay", "Cagay", "CAGAY " all cluster to the same incident
        town     = html.escape(normalize_town_for_db(data.get('town',     '').strip()))
        barangay = html.escape(normalize_barangay_for_db(data.get('barangay', '').strip()))
 
        # ── Server-side field length limits ──────────────────
        # These mirror the maxlength attributes in the HTML form
        # but are enforced server-side as a second layer.
        field_limits = {
            'full_name': (full_name, 100),
            'address':   (address,   300),
            'details':   (details,   2000),
            'landmark':  (landmark,  200),
        }
        for field_name, (value, limit) in field_limits.items():
            if len(value) > limit:
                return jsonify({
                    'success': False,
                    'error': (
                        f'{field_name.replace("_", " ").title()} '
                        f'must be {limit} characters or fewer'
                    )
                }), 400
 
        # ── Account number: alphanumeric + hyphens only ───────
        account_number_raw = (data.get('account_number') or '').strip()
        if account_number_raw:
            if not re.match(r'^[A-Za-z0-9\-]{1,30}$', account_number_raw):
                return jsonify({
                    'success': False,
                    'error': 'Invalid account number format'
                }), 400
            account_number = html.escape(account_number_raw)
        else:
            account_number = ''
        
        # ── PHOTO URLS (optional, max 3, must be our Supabase storage URLs) ──
        photo_urls_raw = data.get('photo_urls') or []
        photo_urls = []
        if isinstance(photo_urls_raw, list):
            _supabase_url = os.getenv('SUPABASE_URL', '')
            _photo_prefix = f"{_supabase_url}/storage/v1/object/public/{SUPABASE_STORAGE_BUCKET}/"
            for u in photo_urls_raw[:3]:
                if isinstance(u, str) and u.startswith(_photo_prefix) and len(u) < 500:
                    photo_urls.append(u)
 
        # ======================================================
        # 6. VALIDATE FEEDER NAME AGAINST DATABASE
        # The frontend sends the feeder name detected by the map.
        # We verify it actually exists in our coverage table so a
        # manipulated POST cannot inject an arbitrary string into
        # the feeder_name column.
        # ======================================================
        feeder_name_raw = (data.get('feeder_name') or '').strip()
        feeder_name = None
        if feeder_name_raw:
            _val_conn = get_db_connection()
            if _val_conn:
                try:
                    _val_cur = _val_conn.cursor()
                    _val_cur.execute(
                        f"SELECT 1 FROM {FEEDER_TABLE} "
                        f"WHERE {FEEDER_NAME_COL} = %s LIMIT 1",
                        (feeder_name_raw,)
                    )
                    if _val_cur.fetchone():
                        feeder_name = feeder_name_raw
                    _val_cur.close()
                except Exception as _ve:
                    logger.warning(f"Feeder name validation failed: {_ve}")
                finally:
                    release_db_connection(_val_conn)
 
        logger.info(
            f"📱 Submission: {full_name} | {barangay},{town} | "
            f"feeder={feeder_name} | lat={lat:.4f},lng={lng:.4f}"
        )
 
        # ======================================================
        # 7. INCIDENT TYPE AND PRIORITY
        # ...
        # ======================================================
        incident_type = data.get('incident_type', 'power_outage')
        affected_area = data.get('affected_area', 'unknown')
        source        = data.get('source', 'Web Form')
        incident_time = data.get('incident_time')
        duration      = data.get('duration')
        classification = classify_incident(incident_type, details)
        priority       = classification['system_priority']   # 'CRITICAL'|'HIGH'|'MEDIUM'
        inc_category   = classification['category']          # 'PI'|'SE'|'PQ'|'AI'|'PL'
        priority_code  = classification['priority_code']     # 'P1'|'P2'|'P3'|'P4'
        never_cluster  = classification['never_cluster']     # True for SE

        # ── Cluster group for "no power" type incidents ──────────
        OUTAGE_CLUSTER_GROUP = ('power_outage', 'partial_outage', 'sdi_problem', 'voltage_issue')
        if incident_type in OUTAGE_CLUSTER_GROUP:
            cluster_type_filter = OUTAGE_CLUSTER_GROUP
        else:
            cluster_type_filter = (incident_type,)
 
        # ======================================================
        # 8. DATABASE OPERATIONS
        # ======================================================
        conn = get_db_connection()
        if not conn:
            return jsonify({
                'success': False,
                'error': 'Database connection failed'
            }), 500
 
        cur = conn.cursor(cursor_factory=RealDictCursor)
 
        # ======================================================
        # PERSONAL-DETAILS DUPLICATE CHECK — location-scoped
        # ──────────────────────────────────────────────────────
        # RULE:  Block a re-submission only when ALL of these
        #        match an existing ACTIVE report:
        #
        #   • Same contact identifier (phone / account# / email)
        #   • Same barangay
        #   • Same town
        #   • Same incident_type
        #   • Linked incident is NOT yet restored/resolved
        #   • Individual report is NOT yet restored/resolved
        #
        # WHY LOCATION SCOPE?
        #   A person can legitimately have service addresses in
        #   two different towns.  Blocking by phone globally
        #   would silently reject their second legitimate report.
        #   Scoping to (barangay + town + type) ensures:
        #     ✔  Genuine duplicates for the SAME problem blocked
        #     ✔  Different location → always allowed
        #     ✔  Different incident type → always allowed
        #     ✔  Restored in dashboard → gate opens immediately
        #
        # ANTI-ABUSE LAYERS (outside this check):
        #   • Flask-Limiter   20 POST/hour per IP
        #   • One-time token  prevents replay
        #   • 8-second timing rejects bots
        #   • Honeypot        catches automated form fillers
        #   • UA check        blocks scripting libraries
        # ======================================================
 
        # ── 8a. Phone-number gate (location + type scoped) ───────────────────
        #
        # This is the primary and most reliable identifier because
        # Philippine mobile numbers are tied to SIM registrations.
        # Adding barangay + town + incident_type means the same
        # phone can report:
        #   • A power outage in Cabatuan AND a fallen wire in Leon
        #   • Two different incident types at the same address
        #   • The same incident type AFTER the previous one was restored
        #
        cur.execute("""
            SELECT
                r.report_id,
                r.reference_id,
                r.contact_number,
                r.timestamp,
                r.incident_type,
                r.barangay,
                r.town,
                r.status            AS report_status,
                i.incident_id,
                i.status            AS incident_status,
                i.job_order_id
            FROM outage_reports r
            JOIN outage_incidents i ON r.incident_id = i.incident_id
            WHERE
                r.contact_number  = %s
                AND r.barangay    = %s
                AND r.town        = %s
                AND r.incident_type = ANY(%s)
                AND i.status  NOT IN ('RESTORED', 'RESOLVED')
                AND r.status  NOT IN ('RESTORED', 'RESOLVED')
            ORDER BY r.timestamp DESC
            LIMIT 1
        """, (contact_number, barangay, town, list(cluster_type_filter)))
 
        phone_dup = cur.fetchone()
 
        if phone_dup:
            existing_ref = (
                phone_dup.get('reference_id')
                or f"RPT-{datetime.now():%y%m%d}-{phone_dup['report_id']}"
            )
 
            reported_at = phone_dup['timestamp']
            if reported_at.tzinfo is None:
                reported_at = reported_at.replace(tzinfo=timezone.utc)
            minutes_since = (
                datetime.now(timezone.utc) - reported_at
            ).total_seconds() / 60
 
            incident_status_label = phone_dup['incident_status']
 
            if incident_status_label == 'ASSIGNED':
                status_msg = (
                    'A crew has already been dispatched for this location. '
                    'You can file a new report once power has been restored.'
                )
            else:
                status_msg = (
                    'Your report is queued and our team is reviewing it. '
                    'You can file a new report once this incident is closed.'
                )
 
            logger.info(
                f"[PHONE DUP] contact={contact_number} "
                f"barangay={barangay} town={town} type={incident_type} "
                f"ref={existing_ref} incident={phone_dup['incident_id']} "
                f"status={incident_status_label} age={minutes_since:.0f}min"
            )
 
            return jsonify({
                'success': False,
                'error': (
                    f'You already have an active report for this location '
                    f'and incident type.\n\n'
                    f'Reference number: {existing_ref}\n'
                    f'Location: {barangay}, {town}\n'
                    f'Status: {incident_status_label}\n\n'
                    f'{status_msg}\n\n'
                    f'For emergencies (fallen wire, fire, electric shock) '
                    f'call 09989893028 immediately.'
                ),
                'error_code':           'ACTIVE_REPORT_EXISTS',
                'existing_incident_id': phone_dup['incident_id'],
                'reference_id':         existing_ref,
                'incident_status':      incident_status_label,
                'minutes_ago':          round(minutes_since, 1),
            }), 429
 
        # ── 8b. Account-number gate (location + type scoped) ─────────────────
        #
        # Only runs when the consumer provided an account number.
        # Empty account_number is never used as a matching key —
        # otherwise every anonymous report would match each other.
        #
        if account_number:
            cur.execute("""
                SELECT
                    r.report_id,
                    r.reference_id,
                    r.timestamp,
                    r.status        AS report_status,
                    i.incident_id,
                    i.status        AS incident_status
                FROM outage_reports r
                JOIN outage_incidents i ON r.incident_id = i.incident_id
                WHERE
                    r.account_number  = %s
                    AND r.account_number != ''
                    AND r.barangay    = %s
                    AND r.town        = %s
                    AND r.incident_type = ANY(%s)
                    AND i.status NOT IN ('RESTORED', 'RESOLVED')
                    AND r.status NOT IN ('RESTORED', 'RESOLVED')
                ORDER BY r.timestamp DESC
                LIMIT 1
            """, (account_number, barangay, town, list(cluster_type_filter)))
 
            acct_dup = cur.fetchone()
 
            if acct_dup:
                existing_ref = (
                    acct_dup.get('reference_id')
                    or f"RPT-{datetime.now():%y%m%d}-{acct_dup['report_id']}"
                )
 
                reported_at = acct_dup['timestamp']
                if reported_at.tzinfo is None:
                    reported_at = reported_at.replace(tzinfo=timezone.utc)
                minutes_since = (
                    datetime.now(timezone.utc) - reported_at
                ).total_seconds() / 60
 
                incident_status_label = acct_dup['incident_status']
 
                logger.info(
                    f"[ACCT DUP] account={account_number} "
                    f"barangay={barangay} town={town} type={incident_type} "
                    f"ref={existing_ref} incident={acct_dup['incident_id']} "
                    f"status={incident_status_label}"
                )
 
                return jsonify({
                    'success': False,
                    'error': (
                        f'An active report already exists for account '
                        f'{account_number} at this location and incident type.\n\n'
                        f'Reference number: {existing_ref}\n'
                        f'Location: {barangay}, {town}\n'
                        f'Status: {incident_status_label}\n\n'
                        f'You can file a new report once the current incident '
                        f'is marked as restored. '
                        f'For emergencies call 09989893028.'
                    ),
                    'error_code':           'ACTIVE_REPORT_EXISTS',
                    'existing_incident_id': acct_dup['incident_id'],
                    'reference_id':         existing_ref,
                    'incident_status':      incident_status_label,
                    'minutes_ago':          round(minutes_since, 1),
                }), 429
 
        # ── 8c. Email gate (location + type scoped) ───────────────────────────
        #
        # Email is the weakest identifier (easily created, shared,
        # or spoofed) so it sits last.  Same location-scope logic
        # applies: a person can report different problems via the
        # same email address at different locations.
        #
        if email:
            cur.execute("""
                SELECT
                    r.report_id,
                    r.reference_id,
                    r.timestamp,
                    r.status        AS report_status,
                    i.incident_id,
                    i.status        AS incident_status
                FROM outage_reports r
                JOIN outage_incidents i ON r.incident_id = i.incident_id
                WHERE
                    r.email         = %s
                    AND r.email    != ''
                    AND LOWER(r.barangay) = LOWER(%s)
                    AND LOWER(r.town)     = LOWER(%s)
                    AND r.incident_type = ANY(%s)
                    AND i.status NOT IN ('RESTORED', 'RESOLVED')
                    AND r.status NOT IN ('RESTORED', 'RESOLVED')
                ORDER BY r.timestamp DESC
                LIMIT 1
            """, (email, barangay, town, list(cluster_type_filter)))
 
            email_dup = cur.fetchone()
 
            if email_dup:
                existing_ref = (
                    email_dup.get('reference_id')
                    or f"RPT-{datetime.now():%y%m%d}-{email_dup['report_id']}"
                )
 
                reported_at = email_dup['timestamp']
                if reported_at.tzinfo is None:
                    reported_at = reported_at.replace(tzinfo=timezone.utc)
                minutes_since = (
                    datetime.now(timezone.utc) - reported_at
                ).total_seconds() / 60
 
                incident_status_label = email_dup['incident_status']
 
                logger.info(
                    f"[EMAIL DUP] email={email} "
                    f"barangay={barangay} town={town} type={incident_type} "
                    f"ref={existing_ref} incident={email_dup['incident_id']} "
                    f"status={incident_status_label}"
                )
 
                return jsonify({
                    'success': False,
                    'error': (
                        f'An active report from this email already exists '
                        f'for this location and incident type.\n\n'
                        f'Reference number: {existing_ref}\n'
                        f'Location: {barangay}, {town}\n'
                        f'Status: {incident_status_label}\n\n'
                        f'You can file a new report once the current incident '
                        f'is marked as restored. '
                        f'For emergencies call 09989893028.'
                    ),
                    'error_code':           'ACTIVE_REPORT_EXISTS',
                    'existing_incident_id': email_dup['incident_id'],
                    'reference_id':         existing_ref,
                    'incident_status':      incident_status_label,
                    'minutes_ago':          round(minutes_since, 1),
                }), 429
 
        # ======================================================
        # LOCATION-BASED SMART COOLDOWN
        # ──────────────────────────────────────────────────────
        # All personal-detail checks passed — this is a unique
        # person (or at least a different location/type combo).
        #
        # Now check whether an active incident cluster already
        # exists for this (barangay + town + incident_type).
        #
        # If YES  → attach as a follow-up (different consumer,
        #            same cluster).  Increment report_count.
        # If NO   → create a brand-new incident + report.
        #
        # Critical incident types (fallen wire, fire, etc.) SKIP
        # the cluster cooldown and always create a new incident.
        # This ensures every critical event gets its own job order
        # and its own dispatch entry in the dashboard.
        # ======================================================
 
           # ── Cluster by GROUP (Power / Safety / Asset / Streetlight) ──────────
        # Per the 4-cluster dashboard design: a report only joins an existing
        # active incident at this location if that incident's type belongs
        # to the SAME cluster group (POWER, SAFETY, ASSET, or LIGHT).
        # SE (Safety) incidents already never_cluster via classify_incident,
        # so each safety report still gets its own incident/job order.
        this_cluster_group = get_cluster_group_for_type(incident_type)
        cluster_type_filter = tuple(_CLUSTER_GROUP_TYPES.get(this_cluster_group, ()))
        if not never_cluster:
            cur.execute("""
                SELECT
                    r.report_id,
                    r.timestamp,
                    r.contact_number,
                    r.reference_id,
                    i.incident_id,
                    i.status        AS incident_status,
                    i.job_order_id
                FROM outage_incidents i
                JOIN outage_reports r
                    ON r.incident_id = i.incident_id
                   AND r.report_id = (
                       SELECT report_id FROM outage_reports
                       WHERE incident_id = i.incident_id
                       ORDER BY timestamp ASC LIMIT 1
                   )
                WHERE
                    LOWER(i.barangay)   = LOWER(%s)
                    AND LOWER(i.town)   = LOWER(%s)
                    AND i.incident_type = ANY(%s)
                    AND i.status NOT IN ('RESTORED', 'RESOLVED')
                ORDER BY i.first_report_time DESC
                LIMIT 1
            """, (barangay, town, list(cluster_type_filter)))
 
            active_dup = cur.fetchone()
 
            if active_dup:
                reported_at = active_dup['timestamp']
                if reported_at.tzinfo is None:
                    reported_at = reported_at.replace(tzinfo=timezone.utc)
                minutes_ago = (
                    datetime.now(timezone.utc) - reported_at
                ).total_seconds() / 60
 
                existing_incident_id = active_dup['incident_id']
 
                # Increment the cluster report count and update
                # the last_report_time timestamp.
                # ── Priority escalation: cluster priority = MAX severity ──
                # Critical > High > Medium > Low. If this new report's
                # priority is more severe than the cluster's current
                # priority, bump the WHOLE cluster up. Never downgrade.
                PRIORITY_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
                cur.execute(
                    "SELECT priority FROM outage_incidents WHERE incident_id = %s",
                    (existing_incident_id,)
                )
                _existing_pri_row = cur.fetchone()
                _existing_priority = (_existing_pri_row['priority'] if _existing_pri_row else 'MEDIUM') or 'MEDIUM'

                _new_cluster_priority = _existing_priority
                if PRIORITY_RANK.get(priority, 0) > PRIORITY_RANK.get(_existing_priority, 0):
                    _new_cluster_priority = priority

                # Increment the cluster report count, update the
                # last_report_time timestamp, and (if needed) escalate
                # the cluster's overall priority to the new max severity.
                # ── REPLACE WITH ───────────────────────────────────────────────
                    # Increment the cluster report count, update the
                # last_report_time timestamp, and (if needed) escalate
                # the cluster's overall priority to the new max severity.

                cur.execute("""
                    UPDATE outage_incidents
                    SET
                        report_count      = report_count + 1,
                        priority          = %s,
                        incident_category = COALESCE(incident_category, %s),
                        priority_code     = CASE
                                              WHEN priority_code IS NULL THEN %s
                                              WHEN %s < priority_code THEN %s
                                              ELSE priority_code
                                            END,
                        type_breakdown    = COALESCE(type_breakdown, '{}'::jsonb)
                                             || jsonb_build_object(
                                                 %s,
                                                 COALESCE((type_breakdown->>%s)::int, 0) + 1
                                             ),
                        last_report_time  = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                        updated_at        = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
                    WHERE incident_id = %s
                    RETURNING incident_id,
                              report_count,
                              job_order_id,
                              priority,
                              type_breakdown
                """, (
                    _new_cluster_priority,
                    inc_category,
                    priority_code,
                    priority_code,
                    priority_code,
                    incident_type,
                    incident_type,
                    existing_incident_id
                ))

                updated = cur.fetchone()

                if _new_cluster_priority != _existing_priority:
                    logger.info(
                        f"⬆️ Incident {existing_incident_id} priority escalated "
                        f"{_existing_priority} → {_new_cluster_priority} "
                        f"(new report type={incident_type}, priority={priority})"
                    )
 
                # Insert a new outage_report row so this consumer's
                # contact details are stored and staff can see every
                # individual who called in.
                cur.execute("""
            INSERT INTO outage_reports
            (incident_id, full_name, contact_number, email,
             account_number, address, town, barangay, details,
             landmark, incident_type, affected_area, incident_time,
             duration, priority, status, source, feeder_name,
             photo_urls,
             timestamp, status_changed_at, geom)
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, 'NEW', %s, %s,
                %s,
                TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                ST_SetSRID(ST_MakePoint(%s, %s), 4326)
            )
            RETURNING report_id
        """, (
            existing_incident_id,
            full_name, contact_number, email, account_number,
            address, town, barangay, details, landmark,
            incident_type, affected_area, incident_time, duration,
            priority, source, feeder_name,
            json.dumps(photo_urls),
            lng, lat
        ))
                followup = cur.fetchone()
 
                # AFTER
                try:
                    ref_id = generate_rpt_reference_id(conn, town)
                except Exception as ref_err:
                    ref_id = f"RPT-{datetime.now():%y%m%d}-{followup['report_id']}"
                    logger.warning(f"RPT ref generation failed (follow-up): {ref_err}")

                cur.execute("""
                    UPDATE outage_reports
                    SET reference_id = %s
                    WHERE report_id = %s
                """, (ref_id, followup['report_id']))
 
                conn.commit()
                _consume_form_token(form_token)   # ← only burn it once we know this landed
 
                logger.info(
                    f"Follow-up report {followup['report_id']} "
                    f"(different consumer, same area) → "
                    f"incident {existing_incident_id} "
                    f"(report_count={updated['report_count']}, "
                    f"{minutes_ago:.0f}min since first report) "
                    f"ref_id={ref_id}"
                )
 
                try:
                    if _ws_throttle_ok('incident_followup', 2.0):
                        socketio.emit('incident_followup', {
                            'incident_id':  existing_incident_id,
                            'report_count': updated['report_count'],
                            'job_order_id': updated['job_order_id'],
                            'town':         town,
                            'barangay':     barangay,
                            'priority':     priority,
                            'message': (
                                f'Additional consumer — still no power '
                                f'after {minutes_ago:.0f} minutes'
                            ),
                        })
                except Exception:
                    pass  # WebSocket failure is non-fatal
 
                return jsonify({
                    'success':      True,
                    'message': (
                        'Your report has been added to the active incident '
                        'for this area. Our team is already responding.'
                    ),
                    'report_id':    followup['report_id'],
                    'incident_id':  existing_incident_id,
                    'reference_id': ref_id,
                    'is_followup':  True,
                    'priority':     priority,
                    'feeder_name':  feeder_name,
                }), 201
 

               # ======================================================
        # CREATE NEW INCIDENT + REPORT
        # Reached when:
        #   (a) No cluster existed for this location, OR
        #   (b) The incident type is configured to never cluster.
        # ======================================================

        job_order_id = (
            f"JO-{datetime.now():%Y%m%d}-{str(uuid.uuid4())[:6].upper()}"
        )

        # Insert parent incident
        cur.execute("""
            INSERT INTO outage_incidents
            (
                incident_type,
                barangay,
                town,
                status,
                priority,
                incident_category,
                priority_code,
                report_count,
                first_report_time,
                last_report_time,
                job_order_id,
                type_breakdown,
                created_at,
                updated_at,
                geom
            )
            VALUES (
                %s,
                %s,
                %s,
                'NEW',
                %s,
                %s,
                %s,
                1,
                TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                %s,
                %s::jsonb,
                TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                ST_SetSRID(ST_MakePoint(%s, %s), 4326)
            )
            RETURNING incident_id
        """, (
            incident_type,
            barangay,
            town,
            priority,
            inc_category,
            priority_code,
            job_order_id,
            json.dumps({incident_type: 1}),
            lng,
            lat
        ))

        incident_row = cur.fetchone()

        if not incident_row:
            conn.rollback()
            return jsonify({
                'success': False,
                'error': 'Failed to create incident record'
            }), 500

        incident_id = incident_row['incident_id']

        # Insert individual report
        cur.execute("""
            INSERT INTO outage_reports
            (
                incident_id,
                full_name,
                contact_number,
                email,
                account_number,
                address,
                town,
                barangay,
                details,
                landmark,
                incident_type,
                affected_area,
                incident_time,
                duration,
                priority,
                status,
                source,
                feeder_name,
                photo_urls,
                timestamp,
                status_changed_at,
                geom
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, 'NEW', %s, %s,
                %s,
                TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                ST_SetSRID(ST_MakePoint(%s, %s), 4326)
            )
            RETURNING report_id
        """, (
            incident_id,
            full_name,
            contact_number,
            email,
            account_number,
            address,
            town,
            barangay,
            details,
            landmark,
            incident_type,
            affected_area,
            incident_time,
            duration,
            priority,
            source,
            feeder_name,
            json.dumps(photo_urls),
            lng,
            lat
        ))

        result = cur.fetchone()

        if not result:
            conn.rollback()
            return jsonify({
                'success': False,
                'error': 'Failed to create report record'
            }), 500

        # AFTER
        # AFTER
        try:
            ref_id = generate_rpt_reference_id(conn, town)
        except Exception as ref_err:
            ref_id = f"RPT-{datetime.now():%y%m%d}-{result['report_id']}"
            logger.warning(f"RPT ref generation failed (new incident): {ref_err}")

        cur.execute("""
            UPDATE outage_reports
            SET reference_id = %s
            WHERE report_id = %s
        """, (ref_id, result['report_id']))

        conn.commit()
        _consume_form_token(form_token)   # ← only burn it once we know this landed

        logger.info(
            f"✅ New report {result['report_id']} → incident {incident_id} "
            f"| job_order={job_order_id} "
            f"| priority={priority} "
            f"| feeder={feeder_name} "
            f"| ref_id={ref_id}"
        )

        try:
            if _ws_throttle_ok('new_incident', 2.0):
                socketio.emit('new_incident', {
                    'incident_id': incident_id,
                    'report_id': result['report_id'],
                    'job_order_id': job_order_id,
                    'town': town,
                    'barangay': barangay,
                    'priority': priority,
                    'feeder_name': feeder_name,
                    'timestamp': isoformat_safe(
                        datetime.now(timezone.utc)
                    ),
                })
        except Exception:
            pass

        return jsonify({
            'success': True,
            'message': 'Report submitted successfully',
            'report_id': result['report_id'],
            'incident_id': incident_id,
            'priority': priority,
            'feeder_name': feeder_name,
            'reference_id': ref_id,
            'is_followup': False,
        }), 201
 
    except Exception as e:
        # Roll back any partial DB writes on unexpected errors.
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        logger.exception(f"submit_power_outage error: {e}")
        return jsonify({
            'success': False,
            'error':   f'Submission failed: {str(e)}'
        }), 500
 
    finally:
        # Always release cursor and connection back to the pool
        # even if an exception was raised inside the try block.
        if cur:
            try:
                cur.close()
            except Exception:
                pass
        if conn:
            try:
                release_db_connection(conn)
            except Exception:
                pass



@app.route('/api/upload_outage_photo', methods=['POST', 'OPTIONS'])
@limiter.limit("15 per hour", key_func=get_client_ip)
def upload_outage_photo():
    if request.method == 'OPTIONS':
        return _cors_preflight_response('Content-Type, Accept, X-Form-Token')

    ua = request.headers.get('User-Agent', '')
    if not ua:
        return jsonify({'success': False, 'error': 'Invalid client'}), 403

    form_token = request.headers.get('X-Form-Token', '').strip()
    if not _validate_form_token_for_upload(form_token):
        return jsonify({'success': False, 'error': 'Session expired. Please refresh the page.'}), 403

    if 'photo' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    file = request.files['photo']
    if not file or not file.filename:
        return jsonify({'success': False, 'error': 'Empty file'}), 400

    mime = file.mimetype
    if mime not in ALLOWED_PHOTO_MIME:
        return jsonify({'success': False,
                        'error': 'Only JPEG, PNG, WEBP images or MP4, MOV, WEBM videos are allowed'}), 400

    file_bytes = file.read()
    if len(file_bytes) > MAX_PHOTO_BYTES:
        return jsonify({'success': False,
                        'error': 'File too large (max 20MB). Please choose a smaller file.'}), 400

    ext = ALLOWED_PHOTO_MIME[mime]
    filename = f"{datetime.now():%Y/%m/%d}/{uuid.uuid4().hex}.{ext}"

    supabase_url = os.getenv('SUPABASE_URL', '')
    service_key  = os.getenv('SUPABASE_SERVICE_KEY', '')
    if not supabase_url or not service_key:
        logger.error("SUPABASE_SERVICE_KEY/SUPABASE_URL not configured")
        return jsonify({'success': False, 'error': 'Photo storage not configured'}), 500

    upload_url = f"{supabase_url}/storage/v1/object/{SUPABASE_STORAGE_BUCKET}/{filename}"  # ← now resolves from top-level constant

    try:
        resp = requests.post(
            upload_url,
            headers={
                'Authorization': f'Bearer {service_key}',
                'apikey': service_key,
                'Content-Type': mime,
                'x-upsert': 'false',
            },
            data=file_bytes,
            timeout=15
        )
        if resp.status_code not in (200, 201):
            logger.error(f"Supabase storage upload failed: {resp.status_code} {resp.text[:200]}")
            return jsonify({'success': False, 'error': 'Upload failed, please try again'}), 502

        public_url = f"{supabase_url}/storage/v1/object/public/{SUPABASE_STORAGE_BUCKET}/{filename}"
        return jsonify({'success': True, 'url': public_url}), 201

    except Exception:
        logger.exception("upload_outage_photo error")
        return jsonify({'success': False, 'error': 'Upload failed, please try again'}), 500


def _validate_form_token_for_upload(token):
    """
    Photo uploads happen BEFORE the main submit (so the token would normally
    get consumed early). We peek at the token without popping it, so the
    same token can still be used by submit_power_outage afterwards.
    """
    return _peek_form_token(token)


def _peek_form_token(token):
    """
    Check that a token exists and is unexpired, WITHOUT consuming it.

    Used at the top of submit_power_outage() so that a request which
    later fails validation, hits a duplicate-report gate, or errors out
    before the DB commit does NOT burn the token. Burning it too early
    was the root cause of "session expired, please refresh the page" —
    the token was popped on the FIRST attempt regardless of whether that
    attempt actually succeeded, so any retry (even one correcting a typo)
    was rejected with a fresh 403.
    """
    import time as _t
    if not token:
        return False

    if _redis_client:
        try:
            exists = _redis_client.get(f"form_token:{token}")
            return exists is not None
        except Exception as e:
            logger.warning(f"Redis peek failed, falling back to memory: {e}")

    with _token_lock:
        issued_at = _token_store.get(token)
    if issued_at is None:
        return False
    return (_t.time() - issued_at) <= _TOKEN_TTL


def _consume_form_token(token):
    """
    Actually invalidate a token — call this ONLY after the submission
    has been durably committed to the database. This is the single
    place a token should ever be popped/deleted for a real (non-upload)
    submission.
    """
    import time as _t
    if not token:
        return

    if _redis_client:
        try:
            _redis_client.delete(f"form_token:{token}")
            return
        except Exception as e:
            logger.warning(f"Redis delete on consume failed: {e}")

    with _token_lock:
        _token_store.pop(token, None)

@app.route('/api/internal/report_by_ref/<reference_id>', methods=['GET'])
def get_report_by_reference(reference_id):
    """
    Chatbot lookup: find a report and its incident by RPT reference ID.
    Uses individual outage_reports.status (not cluster incident status)
    so Assign/Restore actions from Consumer Details panel reflect immediately.
    Restricted to localhost / internal services only.
    """
    if not is_internal_request():
        return jsonify({'success': False, 'error': 'Internal access only'}), 403

    ref_clean = (reference_id or '').strip().upper()
    if not ref_clean:
        return jsonify({'success': False, 'error': 'Reference ID is required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500

    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT
                r.report_id,
                r.reference_id,
                r.full_name,
                r.town,
                r.barangay,
                r.incident_type,
                r.status         AS report_status,
                r.timestamp,
                r.assigned_at    AS report_assigned_at,
                r.restored_at    AS report_restored_at,
                i.incident_id,
                i.job_order_id
            FROM outage_reports r
            JOIN outage_incidents i ON r.incident_id = i.incident_id
            WHERE UPPER(TRIM(r.reference_id)) = %s
            LIMIT 1
        """, (ref_clean,))

        row = cur.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Reference ID not found'}), 404

        result = dict(row)
        for k, v in result.items():
            if hasattr(v, 'isoformat'):
                result[k] = isoformat_safe(v)

        return jsonify({'success': True, 'report': result})

    except Exception as e:
        logger.exception("report_by_ref lookup error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)

@app.route('/api/internal/report_status_by_ref/<reference_id>', methods=['GET'])
def get_report_status_by_ref(reference_id):
    """
    Rasa chatbot: look up a report by RPT reference ID and return
    a human-readable status reply.

    Supports both new format (CA2606170001) and legacy (RPT-260617-123).
    Restricted to localhost / internal services only.

    Returns:
        {
            "success": true,
            "reference_id": "CA2606170001",
            "municipality": "Cabatuan",
            "status": "Pending" | "Assigned" | "Restored",
            "reply": "Reference ID: CA2606170001\nMunicipality: Cabatuan\nStatus: Pending"
        }
    """
    if not is_internal_request():
        return jsonify({'success': False, 'error': 'Internal access only'}), 403

    ref_clean = (reference_id or '').strip().upper()
    if not ref_clean:
        return jsonify({'success': False, 'error': 'Reference ID is required'}), 400

    # Validate format — new: 2 letters + 6 digits + 4 digits = 12 chars
    # Legacy: RPT-YYMMDD-<digits>
    import re as _re
    new_fmt    = _re.compile(r'^[A-Z]{2}\d{10}$')
    legacy_fmt = _re.compile(r'^RPT-\d{6}-\d+$', _re.IGNORECASE)

    if not new_fmt.match(ref_clean) and not legacy_fmt.match(ref_clean):
        return jsonify({
            'success': False,
            'error':   f'Invalid reference ID format: {ref_clean}'
        }), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500

    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT
                r.report_id,
                r.reference_id,
                r.full_name,
                r.town,
                r.barangay,
                r.incident_type,
                r.status         AS report_status,
                r.timestamp,
                r.assigned_at    AS report_assigned_at,
                r.restored_at    AS report_restored_at,
                i.incident_id,
                i.status         AS incident_status,
                i.job_order_id,
                i.assigned_at    AS incident_assigned_at,
                i.restored_at    AS incident_restored_at
            FROM outage_reports r
            JOIN outage_incidents i ON r.incident_id = i.incident_id
            WHERE UPPER(r.reference_id) = %s
            LIMIT 1
        """, (ref_clean,))

        row = cur.fetchone()

        if not row:
            return jsonify({
                'success': False,
                'error':   f'Reference ID {ref_clean} not found',
                'reply':   (
                    f"Sorry, I couldn't find reference ID {ref_clean}. "
                    "Please check the ID and try again."
                )
            }), 404

           # ── Derive display status from INDIVIDUAL report, not cluster ─────────
        rpt_status = (row['report_status'] or 'NEW').upper()

        if rpt_status in ('RESTORED', 'RESOLVED', 'FINISHED'):
            display_status = 'Restored'
        elif rpt_status == 'ASSIGNED':
            display_status = 'Assigned'
        else:
            display_status = 'Pending'

        # ── Reverse-map town code → municipality name ─────────────────────────
        # row['town'] is already the full name stored in the DB
        municipality = row['town'] or 'Unknown'

        reply = (
            f"Reference ID: {ref_clean}\n"
            f"Municipality: {municipality}\n"
            f"Status: {display_status}"
        )

        return jsonify({
            'success':      True,
            'reference_id': ref_clean,
            'municipality': municipality,
            'barangay':     row['barangay'],
            'incident_type':row['incident_type'],
            'status':       display_status,
            'incident_id':  row['incident_id'],
            'job_order_id': row['job_order_id'],
            'reply':        reply,
        })

    except Exception as e:
        logger.exception("get_report_status_by_ref error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)

@app.route('/api/complaints_nearby', methods=['POST'])
@limiter.limit("30 per minute")
def api_complaints_nearby():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500

    cur = None
    try:
        data = request.get_json()
        lat = float(data.get('lat'))
        lng = float(data.get('lng'))
        radius = int(data.get('radius', 1000))
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute(f"""
            SELECT r.report_id, r.full_name, r.contact_number, r.address,
                   r.barangay, r.town, r.incident_type, r.priority, r.status,
                   r.timestamp, r.details,
                   ST_Y(r.geom::geometry) as lat,
                   ST_X(r.geom::geometry) as lng,
                   ST_Distance(
                       r.geom::geography,
                       ST_SetSRID(ST_MakePoint(%s, %s), 4326)::geography
                   ) as distance_meters,
                   f.{FEEDER_NAME_COL} as feeder_name
            FROM outage_reports r
            LEFT JOIN {FEEDER_TABLE} f
                ON ST_Contains(f.geom::geometry, r.geom::geometry)
                AND f.{FEEDER_NAME_COL} != %s
            WHERE
                ST_DWithin(
                    r.geom::geography,
                    ST_SetSRID(ST_MakePoint(%s, %s), 4326)::geography,
                    %s
                )
                AND r.status != 'RESTORED'
            ORDER BY distance_meters
            LIMIT 10
        """, (lng, lat,
              EXCLUDED_FEEDER,
              lng, lat,
              radius))

        rows = cur.fetchall()
        logger.info(f"Nearby complaints: {len(rows)} rows for lat={lat}, lng={lng}, radius={radius}m")

        complaints = []
        for row in rows:
            complaints.append({
                'report_id': row['report_id'],
                'full_name': row['full_name'],
                'type': row['incident_type'],
                'priority': row['priority'],
                'status': row['status'],
                'lat': float(row['lat']) if row['lat'] is not None else 0,
                'lng': float(row['lng']) if row['lng'] is not None else 0,
                'feeder_name': row['feeder_name'],
                'distance_meters': round(float(row['distance_meters']), 2),
                'timestamp': isoformat_safe(row['timestamp']),
                'barangay': row['barangay'] or '',
                'town': row['town'] or '',
                'details': row['details'] or ''
            })

        return jsonify({
            'success': True,
            'complaints': complaints,
            'count': len(complaints),
            'search_center': {'lat': lat, 'lng': lng},
            'radius_meters': radius
        })

    except Exception as e:
        logger.exception("Nearby complaints query error")
        return jsonify({'success': False, 'error': 'Failed to search nearby complaints'}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

# ============================================
# WEBSOCKET EVENTS
# ============================================
@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        logger.warning(f"Rejected unauthenticated WS from {request.remote_addr}")
        return False
    logger.info(f"Client connected: {request.sid} user={session.get('username')}")
    emit('connection_response', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('dashboard_request')
def handle_dashboard_request(data):
    conn = get_db_connection()
    if not conn:
        emit('dashboard_error', {'error': 'Database connection failed'})
        return

    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM outage_reports WHERE DATE(created_at) = CURRENT_DATE")
        total_today = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM outage_reports WHERE priority = 'CRITICAL' AND status != 'RESOLVED'")
        critical_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM outage_reports WHERE DATE(created_at) = CURRENT_DATE AND status = 'RESOLVED'")
        resolved_today = cur.fetchone()[0]
        
        emit('dashboard_update', {
            'total_today': total_today,
            'critical_count': critical_count,
            'resolved_today': resolved_today,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Dashboard data request error: {e}")
        emit('dashboard_error', {'error': str(e)})
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

@app.route('/api/restore_cluster', methods=['POST'])
@login_required
def restore_cluster():
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500

    cur = None
    try:
        data = request.get_json()
        incident_id = data.get('incident_id')
        restore_status = data.get('restore_status', 'RESTORED')

        if not incident_id:
            return jsonify({'success': False, 'error': 'Incident ID is required'}), 400

        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("UPDATE outage_incidents SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE incident_id = %s RETURNING incident_id, status", (restore_status, incident_id))
        incident = cur.fetchone()

        if not incident:
            return jsonify({'success': False, 'error': 'Incident not found'}), 404

        cur.execute("UPDATE outage_reports SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE incident_id = %s RETURNING report_id, status", (restore_status, incident_id))
        reports = cur.fetchall()
        conn.commit()

        return jsonify({
            'success': True,
            'message': 'Cluster and associated reports restored successfully',
            'incident_id': incident_id,
            'restored_reports': [report['report_id'] for report in reports]
        })

    except Exception as e:
        conn.rollback()
        logger.exception(f"Error restoring cluster: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

# ============================================
# METER CONCERN ROUTES (unchanged)
# ============================================

@app.route('/api/consumer/<account_number>', methods=['GET'])
def get_consumer_info(account_number):
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
    
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT account_number, consumer_name, contact_number, 
                   meter_number, service_address, barangay
            FROM consumers
            WHERE account_number = %s AND is_active = TRUE
        """, (account_number,))
        consumer = cur.fetchone()
        
        if consumer:
            return jsonify({'success': True, 'data': dict(consumer)})
        else:
            return jsonify({'success': False, 'message': 'Consumer not found'}), 404
    except Exception as e:
        logger.exception("Get consumer info error")
        return jsonify({'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

@app.route('/api/meter-concern', methods=['POST'])
@limiter.limit("5 per hour")
def submit_meter_concern():
    logger.info(f"📋 Form data keys: {list(request.form.keys())}")
    logger.info(f"📋 Files keys: {list(request.files.keys())}")
    logger.info(f"📋 Content-Type: {request.headers.get('Content-Type', 'N/A')}")

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cur = None
    try:
        data = request.form.to_dict()

        required_fields = [
            'account_number', 'consumer_name', 'contact_number',
            'meter_number', 'service_address', 'town', 'barangay',
            'concern_type', 'date_noticed'
        ]
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        ACCOUNT_NUMBER_RE = re.compile(r'^[A-Za-z0-9\-]{4,20}$')
        FULL_NAME_RE      = re.compile(r"^[A-Za-zÑñ.,'\-\s]{2,100}$")
        CONTACT_NUMBER_RE = re.compile(r'^09\d{9}$')
        METER_NUMBER_RE   = re.compile(r'^[A-Za-z0-9\-]{3,20}$')

        account_number = data['account_number'].strip()
        consumer_name   = data['consumer_name'].strip()
        contact_number  = data['contact_number'].strip()
        meter_number    = data['meter_number'].strip()
        concern_type    = data['concern_type'].strip()

        # Masterlist stores plain digits (e.g. "1931695"), but the form
        # allows hyphens (e.g. "193-1695") — strip non-digits so the
        # lookup key matches what's actually in consumer_masterlist.
        account_number_lookup = re.sub(r'[^A-Za-z0-9]', '', account_number)
        meter_number_lookup   = re.sub(r'[^A-Za-z0-9]', '', meter_number)

        if not ACCOUNT_NUMBER_RE.match(account_number):
            return jsonify({'error': 'Invalid account number. Use 4-20 letters/numbers.'}), 400
        if not FULL_NAME_RE.match(consumer_name) or not any(c.isalpha() for c in consumer_name):
            return jsonify({'error': 'Invalid consumer name. Please enter your full name.'}), 400
        if not CONTACT_NUMBER_RE.match(contact_number):
            return jsonify({'error': 'Invalid contact number. Use format 09XXXXXXXXX.'}), 400
        if not METER_NUMBER_RE.match(meter_number):
            return jsonify({'error': 'Invalid meter number. Use 3-20 letters/numbers.'}), 400

        # ══════════════════════════════════════════════════════════════
        # MASTERLIST VALIDATION — account_number, consumer_name, and
        # meter_number must all match the imported ConsumerMasterlist
        # (AcctNo / AcctName / MeterSN from MasterListConsumer.xlsx).
        # ══════════════════════════════════════════════════════════════
        masterlist_error = validate_against_masterlist(conn, account_number_lookup, consumer_name, meter_number_lookup)
        if masterlist_error:
            return jsonify({
                'error': masterlist_error,
                'error_code': 'MASTERLIST_MISMATCH'
            }), 400

        # ══════════════════════════════════════════════════════════════
        # EVIDENCE VALIDATION — must happen before any DB write.
        # At least one file, every file must match the bucket policy
        # (image/jpeg, image/png, image/webp, max 2MB each).
        # ══════════════════════════════════════════════════════════════
        raw_files = request.files.getlist('files[]') if 'files[]' in request.files else []
        valid_files = [f for f in raw_files if f and f.filename]

        if not valid_files:
            return jsonify({'error': 'At least one photo of your meter is required.'}), 400

        if len(valid_files) > MAX_METER_EVIDENCE_FILES:
            return jsonify({'error': f'Maximum {MAX_METER_EVIDENCE_FILES} files per submission.'}), 400

        file_payloads = []  # (original_name, bytes, mime, ext)
        for f in valid_files:
            mime = f.mimetype
            if mime not in ALLOWED_METER_EVIDENCE_MIME:
                return jsonify({
                    'error': f'"{f.filename}" is not a supported image type. Use JPG, PNG, or WEBP only.'
                }), 400
            file_bytes = f.read()
            if len(file_bytes) > MAX_METER_EVIDENCE_BYTES:
                return jsonify({
                    'error': f'"{f.filename}" is too large. Maximum size is 2MB per photo.'
                }), 400
            file_payloads.append((f.filename, file_bytes, mime, ALLOWED_METER_EVIDENCE_MIME[mime]))

        supabase_url = os.getenv('SUPABASE_URL', '')
        service_key  = os.getenv('SUPABASE_SERVICE_KEY', '')
        if not supabase_url or not service_key:
            logger.error("SUPABASE_URL/SUPABASE_SERVICE_KEY not configured — cannot store evidence")
            return jsonify({'error': 'Evidence storage is not configured. Please contact support.'}), 500

        cur = conn.cursor(cursor_factory=RealDictCursor)

        # ══════════════════════════════════════════════════════════════
        # DUPLICATE / ACTIVE-CONCERN CHECK — scoped to concern_type too,
        # so the same consumer/meter can file a DIFFERENT type of concern
        # even while a prior one is still open.
        # ══════════════════════════════════════════════════════════════
        cur.execute("""
            SELECT id, reference_number, status, created_at
            FROM meter_concerns
            WHERE account_number = %s
              AND consumer_name  = %s
              AND contact_number = %s
              AND meter_number   = %s
              AND concern_type   = %s
              AND status NOT IN ('RESOLVED', 'CLOSED')
            ORDER BY created_at DESC
            LIMIT 1
        """, (account_number, consumer_name, contact_number, meter_number, concern_type))
        existing_concern = cur.fetchone()

        if existing_concern:
            logger.info(
                f"[DUPLICATE BLOCKED] account={account_number} meter={meter_number} "
                f"type={concern_type} existing_ref={existing_concern['reference_number']} "
                f"status={existing_concern['status']}"
            )
            return jsonify({
                'error': (
                    f"You already have an active report for this same concern type "
                    f"(Reference: {existing_concern['reference_number']}, "
                    f"Status: {existing_concern['status']}). "
                    f"Please wait until it is resolved before submitting another report "
                    f"of the same type. You can still submit a different type of concern."
                ),
                'error_code': 'DUPLICATE_ACTIVE_CONCERN',
                'reference_number': existing_concern['reference_number'],
                'status': existing_concern['status']
            }), 409

        reference_number = generate_meter_reference_number()
        is_critical = concern_type == 'noise_burning'

        priority_map = {
            'noise_burning': 'critical',
            'not_working': 'high',
            'tampered_seal': 'high',
            'high_consumption': 'medium',
            'running_fast_slow': 'medium',
            'others': 'medium'
        }
        priority = priority_map.get(concern_type, 'medium')

        cur.execute("""
            INSERT INTO meter_concerns 
            (reference_number, account_number, consumer_name, contact_number,
             meter_number, service_address, barangay, concern_type,
             other_concern, date_noticed, additional_details, 
             is_critical, priority, status, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 
                    TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                    TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP))
            RETURNING id, reference_number, is_critical, status, priority
        """, (
            reference_number, account_number, consumer_name, contact_number,
            meter_number, data['service_address'], data['barangay'], concern_type,
            data.get('other_concern'), data['date_noticed'], data.get('additional_details'),
            is_critical, priority, 'PENDING'
        ))

        concern = cur.fetchone()
        if not concern or 'id' not in concern:
            conn.rollback()
            logger.error("Failed to insert meter concern - no ID returned")
            return jsonify({'error': 'Failed to create meter concern record'}), 500

        concern_id = concern['id']
        logger.info(f"Meter concern created with ID: {concern_id}, Reference: {reference_number}")

        # ══════════════════════════════════════════════════════════════
        # UPLOAD EVIDENCE TO SUPABASE STORAGE (meter-evidence bucket)
        # — NOT local disk. Railway's filesystem is ephemeral; anything
        # saved locally is lost on the next deploy/restart.
        # ══════════════════════════════════════════════════════════════
        uploaded_files = []
        for original_name, file_bytes, mime, ext in file_payloads:
            safe_name = secure_filename(original_name) or f'evidence.{ext}'
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            storage_filename = f"{reference_number}/{ts}_{uuid.uuid4().hex[:8]}_{safe_name}"
            upload_url = f"{supabase_url}/storage/v1/object/{SUPABASE_METER_EVIDENCE_BUCKET}/{storage_filename}"

            try:
                resp = requests.post(
                    upload_url,
                    headers={
                        'Authorization': f'Bearer {service_key}',
                        'apikey': service_key,
                        'Content-Type': mime,
                        'x-upsert': 'false',
                    },
                    data=file_bytes,
                    timeout=15
                )
            except Exception:
                conn.rollback()
                logger.exception(f"Meter evidence upload failed for {original_name}")
                return jsonify({'error': 'Failed to upload evidence photo. Please try again.'}), 502

            if resp.status_code not in (200, 201):
                conn.rollback()
                logger.error(f"Supabase meter-evidence upload failed: {resp.status_code} {resp.text[:200]}")
                return jsonify({'error': 'Failed to upload evidence photo. Please try again.'}), 502

            public_url = f"{supabase_url}/storage/v1/object/public/{SUPABASE_METER_EVIDENCE_BUCKET}/{storage_filename}"

            cur.execute("""
                INSERT INTO concern_evidence
                (meter_concern_id, file_name, file_path, file_type, file_size, uploaded_at)
                VALUES (%s, %s, %s, %s, %s, TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP))
                RETURNING id
            """, (concern_id, safe_name, public_url, mime, len(file_bytes)))

            file_result = cur.fetchone()
            logger.info(f"Evidence file inserted with ID: {file_result['id'] if file_result else 'None'}")
            uploaded_files.append({
                'filename': safe_name,
                'size': len(file_bytes),
                'file_url': public_url
            })

        try:
            cur.execute("""
                INSERT INTO concern_activity_log
                (meter_concern_id, activity_type, performed_by, description, created_at)
                VALUES (%s, %s, %s, %s, TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP))
            """, (
                concern_id, 'created', consumer_name,
                f"Meter concern created: {concern_type}"
            ))
        except Exception as log_error:
            logger.warning(f"Failed to insert activity log: {log_error}")

        conn.commit()

        notify_local('new_meter_concern', {
            'reference_number': reference_number,
            'concern_type': concern_type,
            'priority': priority
        })
        logger.info(f"Meter concern submitted successfully: {reference_number}")

        if is_critical:
            try:
                socketio.emit('critical_meter_concern', {
                    'reference_number': reference_number,
                    'concern_id': concern_id,
                    'concern_type': concern_type,
                    'barangay': data['barangay'],
                    'priority': 'critical',
                    'timestamp': isoformat_safe(datetime.now(timezone.utc))
                })
            except Exception:
                logger.exception("WebSocket broadcast error")

        return jsonify({
            'success': True,
            'message': 'Meter concern submitted successfully',
            'reference_number': reference_number,
            'concern_id': concern_id,
            'is_critical': is_critical,
            'priority': priority,
            'status': 'PENDING',
            'uploaded_files': uploaded_files,
            'files_count': len(uploaded_files)
        }), 201

    except Exception as e:
        if conn:
            conn.rollback()
        logger.exception("Submit meter concern error")
        return jsonify({'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

# ============================================
# USER MANAGEMENT ROUTES (superadmin only)
# ============================================

@app.route('/api/admin/users', methods=['GET'])
@login_required
def list_users():
    """List all users — superadmin only."""
    if session.get('role') != 'superadmin':
        return jsonify({'success': False, 'error': 'Superadmin access required'}), 403
 
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
 
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, username, full_name, role, is_active, created_at,
                   NULL::timestamptz AS last_login_at
            FROM users ORDER BY created_at DESC
        """)
        users = cur.fetchall()
        result = []
        for u in users:
            ud = dict(u)
            ud['created_at']    = isoformat_safe(ud.get('created_at'))
            ud['last_login_at'] = isoformat_safe(ud.get('last_login_at'))
            ud['updated_at']    = None  # column does not exist — send null so frontend never breaks
            result.append(ud)
        return jsonify({'success': True, 'users': result})
    except Exception as e:
        logger.exception("List users error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@app.route('/api/meter-concern/<int:concern_id>', methods=['DELETE'])
@admin_required
def delete_meter_concern(concern_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM concern_activity_log WHERE meter_concern_id = %s", (concern_id,))
        cur.execute("DELETE FROM concern_evidence WHERE meter_concern_id = %s", (concern_id,))
        cur.execute("DELETE FROM meter_concerns WHERE id = %s", (concern_id,))
        conn.commit()
        return jsonify({'success': True, 'message': 'Concern removed successfully'})
    except Exception as e:
        if conn: conn.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)

@app.route('/api/meter-concerns', methods=['GET'])
@login_required
def get_all_meter_concerns():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database error'}), 500

    cur = None
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        status = request.args.get('status')
        priority = request.args.get('priority')
        barangay = request.args.get('barangay')
        concern_type = request.args.get('concern_type')
        date_filter = request.args.get('date')
        
        query = "SELECT * FROM meter_concerns WHERE 1=1"
        params = []
        
        if status:
            query += " AND status = %s"
            params.append(status.upper())
        if priority:
            query += " AND priority = %s"
            params.append(priority.lower())
        if barangay:
            query += " AND barangay = %s"
            params.append(barangay)
        if concern_type:
            query += " AND concern_type = %s"
            params.append(concern_type)
        if date_filter:
            if status and status.upper() == 'RESOLVED':
                query += " AND DATE(resolved_at AT TIME ZONE 'Asia/Manila') = %s"
            else:
                query += " AND DATE(created_at AT TIME ZONE 'Asia/Manila') = %s"
            params.append(date_filter)
        
        cur = conn.cursor()
        count_query = query.replace("SELECT *", "SELECT COUNT(*)")
        cur.execute(count_query, params if params else None)
        total_count = cur.fetchone()[0]
        
        if status and status.upper() == 'RESOLVED':
            query += " ORDER BY resolved_at DESC"
        else:
            query += " ORDER BY created_at DESC"
        
        offset = (page - 1) * per_page
        query += " LIMIT %s OFFSET %s"
        params.extend([per_page, offset])
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(query, params)
        concerns = cur.fetchall()
        
        concerns_list = []
        for c in concerns:
            concern = dict(c)
            concern['date_noticed'] = str(concern['date_noticed']) if concern.get('date_noticed') else None
            concern['created_at'] = isoformat_safe(concern.get('created_at'))
            concern['updated_at'] = isoformat_safe(concern.get('updated_at'))
            concern['resolved_at'] = isoformat_safe(concern.get('resolved_at'))
            concerns_list.append(concern)
        
        return jsonify({
            'success': True,
            'data': concerns_list,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total_count,
                'pages': (total_count + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        logger.exception("Get meter concerns error")
        return jsonify({'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

@app.route('/api/debug_joblist_conn')
@login_required
def debug_joblist_conn():
    if os.getenv('ENABLE_DEBUG_ROUTES', 'false').lower() != 'true':
        return jsonify({'success': False, 'error': 'Not found'}), 404
    if session.get('role') != 'superadmin':
        return jsonify({'success': False, 'error': 'Superadmin only'}), 403
    import psycopg2 as _psycopg2
    results = {}
    conn = None
    cur = None
    try:
        conn = _psycopg2.connect(
            host=os.getenv('LOCAL_DB_HOST', 'localhost'),
            port=int(os.getenv('LOCAL_DB_PORT', '5432')),
            database=os.getenv('JOBLIST_DB_NAME', 'joblist'),
            user=os.getenv('LOCAL_DB_USER', 'postgres'),
            password=os.getenv('LOCAL_DB_PASSWORD', ''),
            connect_timeout=4
        )
        cur = conn.cursor()
        cur.execute("""
            SELECT table_schema, table_name
            FROM information_schema.tables
            WHERE table_name = 'converted'
        """)
        results['converted_table'] = cur.fetchall()
        cur.execute("SELECT datname FROM pg_database ORDER BY datname")
        results['databases'] = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT current_database()")
        results['current_db'] = cur.fetchone()[0]
        results['connection'] = 'SUCCESS'
    except Exception as e:
        results['connection'] = f'FAILED: {str(e)}'
    finally:
        if cur:
            try: cur.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass
    return jsonify(results)

@app.route('/api/meter-concern/<int:concern_id>/status', methods=['PUT'])
@login_required
def update_meter_concern_status(concern_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cur = None
    try:
        data = request.get_json()
        new_status = (data.get('status') or '').strip().upper()
        assigned_to = data.get('assigned_to')
        notes = data.get('notes')
        performed_by = session.get('full_name', session.get('username', 'System'))
        
        valid_statuses = ['PENDING', 'ASSIGNED', 'IN_PROGRESS', 'RESOLVED', 'CLOSED']
        if new_status not in valid_statuses:
            return jsonify({'error': 'Invalid status'}), 400
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("SELECT status, reference_number FROM meter_concerns WHERE id = %s", (concern_id,))
        current = cur.fetchone()
        if not current:
            return jsonify({'error': 'Concern not found'}), 404
        
        old_status = current['status']
        
        update_query = """
            UPDATE meter_concerns 
            SET status = %s, assigned_to = %s,
                updated_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
        """
        params = [new_status, assigned_to]
        
        if new_status == 'RESOLVED':
            update_query += ", resolved_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)"
        
        if notes:
            update_query += ", resolution_notes = %s"
            params.append(notes)
        
        update_query += " WHERE id = %s RETURNING reference_number"
        params.append(concern_id)
        
        cur.execute(update_query, params)
        result = cur.fetchone()
        
        description = f"Status changed from {old_status} to {new_status}"
        if notes:
            description += f". Notes: {notes}"
        
        cur.execute("""
            INSERT INTO concern_activity_log
            (meter_concern_id, activity_type, performed_by, description, old_value, new_value, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP))
        """, (concern_id, 'status_changed', performed_by, description, old_status, new_status))
        
        conn.commit()
        logger.info(f"Meter concern {concern_id} status updated to {new_status} by {performed_by}")
        
        try:
            socketio.emit('meter_concern_updated', {
                'concern_id': concern_id,
                'reference_number': result['reference_number'],
                'new_status': new_status,
                'updated_by': performed_by,
                'timestamp': isoformat_safe(datetime.now(timezone.utc))
            })
        except Exception as e:
            logger.exception("WebSocket broadcast error")
        
        return jsonify({'success': True, 'message': f'Meter concern status updated to {new_status}'})
        
    except Exception as e:
        conn.rollback()
        logger.exception("Update meter concern status error")
        return jsonify({'error': 'Failed to update status'}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

@app.route('/api/meter-concern/<reference_number>', methods=['GET'])
def get_meter_concern(reference_number):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM meter_concerns WHERE reference_number = %s", (reference_number,))
        concern = cur.fetchone()
        
        if not concern:
            return jsonify({'error': 'Concern not found'}), 404
        
        evidence = []
        try:
            cur.execute("""
                SELECT file_name, file_path, file_type, file_size, uploaded_at
                FROM concern_evidence
                WHERE meter_concern_id = %s
                ORDER BY uploaded_at DESC
            """, (concern['id'],))
            evidence = cur.fetchall()
        except Exception as e:
            logger.warning(f"Failed to fetch evidence files: {e}")
            evidence = []
        
        activities = []
        try:
            cur.execute("""
                SELECT activity_type, performed_by, description, 
                       old_value, new_value, created_at
                FROM concern_activity_log
                WHERE meter_concern_id = %s
                ORDER BY created_at DESC
            """, (concern['id'],))
            activities = cur.fetchall()
        except Exception as e:
            logger.warning(f"Failed to fetch activity log: {e}")
            activities = []
        
        concern_dict = dict(concern)
        concern_dict['date_noticed'] = str(concern_dict['date_noticed']) if concern_dict.get('date_noticed') else None
        concern_dict['created_at'] = isoformat_safe(concern_dict.get('created_at'))
        concern_dict['updated_at'] = isoformat_safe(concern_dict.get('updated_at'))
        concern_dict['resolved_at'] = isoformat_safe(concern_dict.get('resolved_at'))
        
    

        evidence_list = []
        for e in evidence:
            ev = dict(e)
            ev['uploaded_at'] = isoformat_safe(ev.get('uploaded_at'))
            fp = ev.get('file_path') or ''
            if fp.startswith('http://') or fp.startswith('https://'):
                ev['file_url'] = fp  # new records — already a Supabase public URL
            elif fp:
                ev['file_url'] = f"/uploads/{fp.replace(chr(92), '/')}"  # legacy local records
            else:
                ev['file_url'] = None
            evidence_list.append(ev)
        
        activity_list = []
        for a in activities:
            act = dict(a)
            act['created_at'] = isoformat_safe(act.get('created_at'))
            activity_list.append(act)
        
        return jsonify({
            'success': True, 
            'data': {
                'concern': concern_dict, 
                'evidence': evidence_list,
                'activities': activity_list
            }
        })
        
    except Exception as e:
        logger.exception("Get meter concern details error")
        return jsonify({'error': 'Failed to fetch concern details'}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)

@app.route('/api/meter-concerns/statistics', methods=['GET'])
@login_required
def get_meter_concern_statistics():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database error'}), 500
    
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT COUNT(*) as total FROM meter_concerns")
        total = cur.fetchone()['total']
        cur.execute("SELECT status, COUNT(*) as count FROM meter_concerns GROUP BY status")
        by_status = cur.fetchall()
        cur.execute("SELECT priority, COUNT(*) as count FROM meter_concerns GROUP BY priority")
        by_priority = cur.fetchall()
        cur.execute("SELECT concern_type, COUNT(*) as count FROM meter_concerns GROUP BY concern_type ORDER BY count DESC")
        by_type = cur.fetchall()
        cur.execute("SELECT reference_number, consumer_name, concern_type, status, priority, created_at FROM meter_concerns ORDER BY created_at DESC LIMIT 10")
        recent = cur.fetchall()
        
        recent_list = []
        for r in recent:
            rec = dict(r)
            rec['created_at'] = isoformat_safe(rec.get('created_at'))
            recent_list.append(rec)
        
        return jsonify({
            'success': True,
            'data': {
                'total': total,
                'by_status': [dict(s) for s in by_status],
                'by_priority': [dict(p) for p in by_priority],
                'by_type': [dict(t) for t in by_type],
                'recent_concerns': recent_list
            }
        })
        
    except Exception as e:
        logger.exception("Get meter concern statistics error")
        return jsonify({'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_db_connection(conn)
@app.route('/api/agent_queue', methods=['GET'])
@login_required
@limiter.exempt
def get_agent_queue():
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500

    cur = None
    try:
        status_filter   = (request.args.get('status', 'all') or 'all').strip()
        priority_filter = (request.args.get('priority', 'all') or 'all').strip()
        date_filter     = request.args.get('date')

        cur = conn.cursor(cursor_factory=RealDictCursor)

        query = """
            SELECT id, user_id, full_name, concern, contact_number,
                   priority, timestamp, status, served_at, served_by, rating
            FROM agent_queue WHERE 1=1
        """
        params = []

        # ── Case/whitespace-insensitive status match ──
        if status_filter.lower() != 'all':
            query += " AND TRIM(UPPER(status)) = UPPER(%s)"
            params.append(status_filter)

        # ── Case/whitespace-insensitive priority match ──
        if priority_filter.lower() != 'all':
            query += " AND TRIM(UPPER(priority)) = UPPER(%s)"
            params.append(priority_filter)

        if date_filter:
            if status_filter.lower() == 'resolved':
                query += " AND DATE(served_at AT TIME ZONE 'Asia/Manila') = %s"
            else:
                query += " AND DATE(timestamp AT TIME ZONE 'Asia/Manila') = %s"
            params.append(date_filter)

        if status_filter.lower() == 'resolved':
            query += " ORDER BY served_at DESC"
        else:
            query += " ORDER BY timestamp DESC"

        # Cap unbounded polling result size — filters/date can still narrow further.
        query += " LIMIT 500"

        cur.execute(query, params if params else None)
        queue_items = cur.fetchall()

        queue_list = []
        for item in queue_items:
            queue_dict = dict(item)
            queue_dict['timestamp'] = isoformat_safe(queue_dict.get('timestamp'))
            queue_dict['served_at'] = isoformat_safe(queue_dict.get('served_at'))
            queue_list.append(queue_dict)

        return jsonify({'success': True, 'data': queue_list, 'count': len(queue_list)})

    except Exception as e:
        logger.exception("Get agent queue error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_local_conn(conn)


_FB_PAGE_ACCESS_TOKEN = os.getenv("FB_PAGE_ACCESS_TOKEN", "")
_RASA_URL             = os.getenv("RASA_URL", "http://localhost:5005")
 
 

def _force_unpause_tracker(sender_id: str) -> bool:
    """
    Directly inject a ConversationResumed event into Rasa's tracker
    via the REST API. This is the only guaranteed way to clear
    ConversationPaused state regardless of Rasa version.
 
    Must be called BEFORE trigger_intent, otherwise trigger_intent
    may be silently rejected by the paused tracker.
    """
    import requests as _r
    import json as _json
 
    rasa_url = os.getenv("RASA_URL", "http://localhost:5005")
    url = f"{rasa_url}/conversations/{sender_id}/tracker/events"
 
    try:
        resp = _r.post(
            url,
            json={"event": "resume"},
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
        if resp.status_code == 200:
            logger.info(
                f"[ForceUnpause] ConversationResumed injected for {sender_id}"
            )
            # erase any messages the consumer sent while paused
            # so resume only reacts to a genuinely new incoming message.
            _discard_stale_paused_messages(sender_id)
            return True
        else:
            logger.warning(
                f"[ForceUnpause] Unexpected status {resp.status_code} "
                f"for {sender_id}: {resp.text[:200]}"
            )
            return False
    except Exception as e:
        logger.error(f"[ForceUnpause] Failed for {sender_id}: {e}")
        return False
 
AUTO_RESUME_TIMEOUT_SECONDS = 120  # 2 minutes

def _auto_resume_watcher(sender_id: str, queue_id: int) -> None:
    """
    Runs in a background thread. After AUTO_RESUME_TIMEOUT_SECONDS,
    checks whether the customer is STILL waiting (status='Pending')
    and NOT under a manual agent pause. If so, auto-resumes the bot
    so the consumer can keep using the menu while still queued —
    this does NOT mark the queue item as Resolved, so the agent
    still sees and can serve them later.
    """
    import time as _t
    _t.sleep(AUTO_RESUME_TIMEOUT_SECONDS)

    with _manual_pause_lock:
        if sender_id in _manually_paused_senders:
            logger.info(
                f"[AutoResume] Skipped for {sender_id} — agent has "
                f"manually paused this conversation."
            )
            return

    conn = get_local_conn()
    if not conn:
        logger.warning(f"[AutoResume] DB unavailable, cannot check queue #{queue_id}")
        return
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT status FROM agent_queue WHERE id = %s", (queue_id,))
        row = cur.fetchone()
        if row and row[0] == 'Pending':
            logger.info(
                f"[AutoResume] Queue #{queue_id} still Pending after "
                f"{AUTO_RESUME_TIMEOUT_SECONDS}s — auto-resuming bot for {sender_id}"
            )
            _trigger_rasa_auto_resume(sender_id)
        else:
            logger.info(
                f"[AutoResume] Queue #{queue_id} no longer Pending "
                f"(status={row[0] if row else 'missing'}) — no action needed."
            )
    except Exception:
        logger.exception(f"[AutoResume] Watcher failed for queue #{queue_id}")
    finally:
        if cur:
            cur.close()
        release_local_conn(conn)

def _discard_stale_paused_messages(sender_id: str) -> None:
    """
    Previously attempted to rewind stale UserUttered events logged while
    the conversation was paused. Replaced with a deliberate no-op.

    WHY THIS IS NOW A NO-OP:
    Each Rasa 'rewind' event walks the tracker backward past the nearest
    UserUttered AND every SlotSet between it and the prior user turn.
    With 14+ stale messages observed in production, cascading rewinds
    wiped critical slots set just moments earlier — specifically
    agent_queue_id and terms_agreed — which caused action_handle_
    resolution_confirmed and action_handle_resolution_declined to receive
    None for agent_queue_id and False for terms_agreed, silently breaking
    the entire Yes/No confirmation flow.

    The correct repair is performed by _send_resolution_confirmation()
    immediately after this function returns: it re-asserts ALL required
    slots (terms_agreed, agent_queue_id, escalate_to_agent, etc.) in a
    single atomic batch POST to the tracker. Those slot values are then
    verified via a GET /tracker call before the FB quick-reply is sent.

    Stale messages left in the tracker are harmless: they surface as
    unrecognized intents and are silently dropped by action_drop_zwsp
    or action_default_fallback on the next real user turn.
    """
    logger.info(
        f"[DiscardStale] No-op for {sender_id} — "
        f"slots will be re-asserted by _send_resolution_confirmation()."
    )
        
def _trigger_rasa_auto_resume(sender_id: str) -> None:
    """
    Distinct from _trigger_rasa_resume() (used when an agent actually
    resolves a case). This path fires the 'auto_resume_timeout' intent,
    which unpauses the bot WITHOUT sending the "conversation ended"
    closure message — the consumer is still in the queue, just no
    longer blocked from using the menu meanwhile.
    """
    import time as _t
    _force_unpause_tracker(sender_id)
    _t.sleep(0.3)

    rasa_url = os.getenv("RASA_URL", "http://localhost:5005")
    url = f"{rasa_url}/conversations/{sender_id}/trigger_intent?output_channel=latest"
    try:
        resp = requests.post(
            url,
            json={"name": "auto_resume_timeout", "entities": []},
            timeout=8,
        )
        resp.raise_for_status()
        logger.info(f"[AutoResume] trigger_intent OK for {sender_id}")
    except Exception as e:
        logger.error(f"[AutoResume] trigger_intent failed for {sender_id}: {e}")

def _trigger_rasa_resume(sender_id: str, served_by: str) -> bool:
    import time as _t
    import requests as _r

    _t.sleep(0.8)

    _force_unpause_tracker(sender_id)
    _t.sleep(0.3)

    rasa_url = os.getenv("RASA_URL", "http://localhost:5005")
    url = (
        f"{rasa_url}/conversations/{sender_id}"
        f"/trigger_intent?output_channel=latest"
    )
    rasa_ok = False
    try:
        resp = _r.post(
            url,
            json={
                "name": "resume_conversation",
                "entities": [
                    {"entity": "served_by_agent", "value": served_by}
                ],
            },
            timeout=8,
        )
        resp.raise_for_status()
        rasa_ok = True
        logger.info(
            f"[ResumeConversation] Rasa trigger OK for {sender_id} "
            f"(served_by={served_by!r})"
        )
    except Exception as e:
        logger.error(
            f"[ResumeConversation] Rasa trigger failed for {sender_id}: {e}"
        )

    fb_token = os.getenv("FB_PAGE_ACCESS_TOKEN", "")
    if fb_token and sender_id:
        # ── FIX: when Rasa's trigger_intent succeeded, action_resume_
        # conversation already sent the full, correct reply (closing
        # message + carousel) — do NOT also fire a second, separate
        # closure message here. That second message arriving right
        # after Rasa's own reply is what looked like the bot "spamming"
        # or reacting to the old paused conversation. Only fall back to
        # this raw Graph API message when the Rasa trigger itself failed,
        # since in that case nothing was sent to the consumer at all.
        if not rasa_ok:
            _send_fb_closure_message(
                sender_id, fb_token, served_by,
                send_carousel_fallback=True
            )

    return rasa_ok


def _send_fb_closure_message(
    sender_id: str, fb_token: str, served_by: str,
    send_carousel_fallback: bool = True
) -> None:
    import requests as _r
    import json as _json

    api_url = (
        f"https://graph.facebook.com/v19.0/me/messages"
        f"?access_token={fb_token}"
    )
    headers = {"Content-Type": "application/json"}

    closure_text = (
        "✅ Your conversation with our customer service representative has ended.\n\n"
        "Thank you for reaching out to ILECO I. We value your trust and are "
        "committed to providing reliable service to our member-consumer-owners.\n\n"
        "If you have further concerns or need additional assistance, simply "
        "send us a message anytime.\n\n"
        "💙 Thank you for choosing ILECO I. Have a great day!"
    )

    text_payload = {
        "recipient":      {"id": sender_id},
        "message":        {"text": closure_text},
        "messaging_type": "RESPONSE",
    }

    try:
        r = _r.post(
            api_url,
            headers=headers,
            data=_json.dumps(text_payload),
            timeout=10,
        )
        if r.status_code == 200:
            logger.info(f"[FB] Closure text sent to {sender_id}")
        else:
            logger.warning(
                f"[FB] Closure text failed for {sender_id}: "
                f"{r.status_code} {r.text[:200]}"
            )
    except Exception as e:
        logger.error(f"[FB] Closure text exception for {sender_id}: {e}")

    # ── FIX: skip this entirely when Rasa's carousel already went out —
    # this block used to fire unconditionally, duplicating the carousel.
    if not send_carousel_fallback:
        return

    flask_public_url       = os.getenv("FLASK_PUBLIC_URL",
                                       "http://localhost:5000/report_outage")
    flask_meter_url        = os.getenv("FLASK_METER_CONCERN_URL",
                                       "http://localhost:5000/meter_concern")
    flask_disclaimer_url   = os.getenv("FLASK_DISCLAIMER_URL",
                                       "http://localhost:5000/chatbot_disclaimer")

    img_power  = "https://i.postimg.cc/hP14f5Gz/Power-Outage.jpg"
    img_shared = "https://i.postimg.cc/sXt0kNnD/kari-kamo-upod-kita.jpg"
    img_agent  = "https://i.postimg.cc/02qJQ0F6/agentwew.jpg"

    carousel_elements = [
        {
            "title":     "Power Interruption Reports",
            "subtitle":  "Report outages or track power concerns",
            "image_url": img_power,
            "buttons": [
                {"type": "web_url",  "title": "Report Power Outage",
                 "url": flask_public_url},
                {"type": "postback", "title": "Scheduled Interruptions",
                 "payload": "/schedule_outage"},
                {"type": "postback", "title": "Follow-Up Report",
                 "payload": "/follow_up_report"},
            ],
        },
        {
            "title":     "Billing & Payments",
            "subtitle":  "View bills and manage payments",
            "image_url": img_shared,
            "buttons": [
                {"type": "postback", "title": "Online Billing",
                 "payload": "/online_billing"},
                {"type": "postback", "title": "Payment Options",
                 "payload": "/payment_option"},
            ],
        },
        {
            "title":     "New Service Connection",
            "subtitle":  "Apply for electric service connection",
            "image_url": img_shared,
            "buttons": [
                {"type": "postback", "title": "Requirements",
                 "payload": "/requirements_checklist"},
                {"type": "postback", "title": "PMOS Schedule",
                 "payload": "/schedule_pmos"},
                {"type": "postback", "title": "Application Forms",
                 "payload": "/download_forms"},
            ],
        },
        {
            "title":     "Technical Assistance",
            "subtitle":  "Meter services and technical support",
            "image_url": img_shared,
            "buttons": [
                {"type": "web_url",  "title": "Meter Concern",
                 "url": flask_meter_url},
                {"type": "postback", "title": "Transfer of Meter",
                 "payload": "/transfer_of_meter"},
                {"type": "postback", "title": "Meter Follow-Up",
                 "payload": "/meter_concern_followup"},
            ],
        },
        {
            "title":     "Customer Information",
            "subtitle":  "Service info and company details",
            "image_url": img_shared,
            "buttons": [
                {"type": "postback", "title": "Contact Information",
                 "payload": "/contact_information"},
                {"type": "postback", "title": "Rates",
                 "payload": "/rates"},
                {"type": "postback", "title": "Office Locations",
                 "payload": "/office_location"},
            ],
        },
        {
            "title":     "Chat with an Agent",
            "subtitle":  "Get help from our support team",
            "image_url": img_agent,
            "buttons": [
                {"type": "postback", "title": "Chat with an Agent",
                 "payload": "/talk_to_agent"},
            ],
        },
    ]

    carousel_payload = {
        "recipient": {"id": sender_id},
        "message": {
            "attachment": {
                "type": "template",
                "payload": {
                    "template_type": "generic",
                    "elements":      carousel_elements,
                },
            }
        },
        "messaging_type": "RESPONSE",
    }

    try:
        r = _r.post(api_url, headers=headers,
                    data=_json.dumps(carousel_payload), timeout=10)
        if r.status_code == 200:
            logger.info(f"[FB] Carousel sent to {sender_id}")
        else:
            logger.warning(
                f"[FB] Carousel failed for {sender_id}: "
                f"{r.status_code} {r.text[:200]}"
            )
    except Exception as e:
        logger.error(f"[FB] Carousel exception for {sender_id}: {e}")


 
@app.route('/api/internal/force_resume/<sender_id>', methods=['POST'])
def force_resume_single(sender_id):
    """
    Force-unpause a single stuck Facebook user by PSID.
    Injects ConversationResumed directly into Rasa tracker,
    then triggers resume_conversation intent.
 
    Usage:
        POST /api/internal/force_resume/<facebook_psid>
 
    Can be called from terminal:
        curl -X POST http://localhost:5000/api/internal/force_resume/PSID_HERE
    """
    if not is_internal_request():
        # Also allow superadmin session calls from browser
        if 'user_id' not in session or session.get('role') != 'superadmin':
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
 
    rasa_url = os.getenv('RASA_URL', 'http://localhost:5005')
    results = {}
 
    # Step 1: Inject ConversationResumed event directly into tracker
    try:
        r1 = requests.post(
            f"{rasa_url}/conversations/{sender_id}/tracker/events",
            json={"event": "resume"},
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
        results['inject_resume_event'] = {
            'status': r1.status_code,
            'ok': r1.status_code == 200,
        }
        logger.info(
            f"[ForceResume] Injected resume event for {sender_id}: "
            f"HTTP {r1.status_code}"
        )
    except Exception as e:
        results['inject_resume_event'] = {'status': 0, 'ok': False, 'error': str(e)}
        logger.error(f"[ForceResume] Event inject failed for {sender_id}: {e}")
 
    import time as _t
    _t.sleep(0.5)
 
    # Step 2: Trigger resume_conversation intent
    try:
        r2 = requests.post(
            f"{rasa_url}/conversations/{sender_id}"
            f"/trigger_intent?output_channel=latest",
            json={
                "name": "resume_conversation",
                "entities": [
                    {"entity": "served_by_agent", "value": "System"}
                ],
            },
            timeout=8,
        )
        results['trigger_intent'] = {
            'status': r2.status_code,
            'ok': r2.status_code == 200,
        }
        logger.info(
            f"[ForceResume] trigger_intent for {sender_id}: "
            f"HTTP {r2.status_code}"
        )
    except Exception as e:
        results['trigger_intent'] = {'status': 0, 'ok': False, 'error': str(e)}
        logger.error(f"[ForceResume] trigger_intent failed for {sender_id}: {e}")
 
    _t.sleep(0.5)
 
    # Step 3: Send closure message directly via FB Graph API
    fb_token = os.getenv('FB_PAGE_ACCESS_TOKEN', '')
    if fb_token:
        try:
            _send_fb_closure_message(sender_id, fb_token, 'System')
            results['fb_message'] = {'ok': True}
            logger.info(f"[ForceResume] FB closure message sent to {sender_id}")
        except Exception as e:
            results['fb_message'] = {'ok': False, 'error': str(e)}
            logger.error(f"[ForceResume] FB message failed for {sender_id}: {e}")
    else:
        results['fb_message'] = {
            'ok': False,
            'error': 'FB_PAGE_ACCESS_TOKEN not set'
        }
 
    overall_ok = results.get('inject_resume_event', {}).get('ok', False)
    return jsonify({
        'success':   overall_ok,
        'sender_id': sender_id,
        'results':   results,
    }), 200 if overall_ok else 500
 
 
@app.route('/api/admin/resume_all_stuck', methods=['POST'])
@login_required
def resume_all_stuck():
    """
    Find ALL users whose conversations might be stuck (ConversationPaused)
    and force-resume them.
 
    Looks in two places:
      1. agent_queue table — users with status 'Resolved' (served but
         whose bot was never resumed)
      2. agent_queue table — users with status 'Pending' for > 2 hours
         (agent never clicked Resolve, conversation is orphaned)
 
    Superadmin only.
 
    Usage from dashboard:
        POST /api/admin/resume_all_stuck
        (add a button to agent_queue.html or call from browser console)
 
    Or from terminal:
        curl -X POST http://localhost:5000/api/admin/resume_all_stuck \
             -H "Cookie: session=YOUR_SESSION_COOKIE"
    """
    if session.get('role') != 'superadmin':
        return jsonify({'success': False, 'error': 'Superadmin only'}), 403
 
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database unavailable'}), 500
 
    cur = None
    stuck_users = []
 
    try:
        cur = conn.cursor()
 
        # Resolved but bot may not have resumed
        cur.execute("""
            SELECT DISTINCT user_id, full_name, served_at
            FROM agent_queue
            WHERE status = 'Resolved'
              AND served_at >= NOW() - INTERVAL '7 days'
            ORDER BY served_at DESC
        """)
        resolved_rows = cur.fetchall()
        for row in resolved_rows:
            stuck_users.append({
                'user_id':    row[0],
                'full_name':  row[1],
                'reason':     'resolved_no_resume',
                'served_at':  str(row[2]),
            })
 
        # Pending > 2 hours (abandoned/orphaned)
        cur.execute("""
            SELECT DISTINCT user_id, full_name, timestamp
            FROM agent_queue
            WHERE status = 'Pending'
              AND timestamp < NOW() - INTERVAL '2 hours'
            ORDER BY timestamp DESC
        """)
        orphan_rows = cur.fetchall()
        for row in orphan_rows:
            stuck_users.append({
                'user_id':    row[0],
                'full_name':  row[1],
                'reason':     'pending_orphaned',
                'queued_at':  str(row[2]),
            })
 
    except Exception as e:
        logger.exception("resume_all_stuck: DB query failed")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:
            cur.close()
        release_local_conn(conn)
 
    if not stuck_users:
        return jsonify({
            'success': True,
            'message': 'No stuck users found.',
            'processed': 0,
        })
 
    rasa_url  = os.getenv('RASA_URL', 'http://localhost:5005')
    fb_token  = os.getenv('FB_PAGE_ACCESS_TOKEN', '')
    results   = []
 
    import time as _t
 
    for user in stuck_users:
        sender_id = user['user_id']
        if not sender_id:
            continue
 
        user_result = {
            'sender_id': sender_id,
            'full_name': user.get('full_name'),
            'reason':    user.get('reason'),
            'steps':     {},
        }
 
        # Step 1: Inject ConversationResumed
        try:
            r1 = requests.post(
                f"{rasa_url}/conversations/{sender_id}/tracker/events",
                json={"event": "resume"},
                headers={"Content-Type": "application/json"},
                timeout=8,
            )
            user_result['steps']['inject_event'] = r1.status_code
        except Exception as e:
            user_result['steps']['inject_event'] = f"ERROR: {e}"
 
        _t.sleep(0.3)
 
        # Step 2: trigger_intent
        try:
            r2 = requests.post(
                f"{rasa_url}/conversations/{sender_id}"
                f"/trigger_intent?output_channel=latest",
                json={
                    "name": "resume_conversation",
                    "entities": [
                        {"entity": "served_by_agent", "value": "System"}
                    ],
                },
                timeout=8,
            )
            user_result['steps']['trigger_intent'] = r2.status_code
        except Exception as e:
            user_result['steps']['trigger_intent'] = f"ERROR: {e}"
 
        _t.sleep(0.3)
 
        # Step 3: FB direct message
        if fb_token:
            try:
                _send_fb_closure_message(sender_id, fb_token, 'System')
                user_result['steps']['fb_message'] = 'sent'
            except Exception as e:
                user_result['steps']['fb_message'] = f"ERROR: {e}"
        else:
            user_result['steps']['fb_message'] = 'skipped (no FB token)'
 
        results.append(user_result)
        logger.info(
            f"[ResumeAllStuck] Processed {sender_id} "
            f"({user.get('full_name')}): {user_result['steps']}"
        )
 
        # Rate limit — don't hammer Rasa or FB API
        _t.sleep(0.5)
 
    return jsonify({
        'success':   True,
        'processed': len(results),
        'results':   results,
    })

# ============================================================
# FACEBOOK PAGE ACCESS TOKEN — single source of truth.
# Every FB-sending function in this file must read this SAME
# name. Two names (FB_PAGE_ACCESS_TOKEN vs FACEBOOK_PAGE_ACCESS_TOKEN)
# pointing at the same secret is what silently broke resolution
# confirmation messages — pick ONE and use it everywhere.
# ============================================================
FB_TOKEN_ENV_VAR = "FACEBOOK_PAGE_ACCESS_TOKEN"

def _get_fb_token() -> str:
    token = os.getenv(FB_TOKEN_ENV_VAR, "")
    if not token:
        logger.error(
            f"❌ {FB_TOKEN_ENV_VAR} is not set — no Facebook Messenger "
            f"send will work (resolution confirmations, closure messages, "
            f"idle nudges, etc. will all silently no-op)."
        )
    return token

@app.route("/api/agent_queue/<int:queue_id>/serve", methods=["POST"])
@login_required
def serve_queue_item(queue_id):
    data      = request.get_json() or {}
    served_by = (data.get("served_by") or "Agent").strip()

    fb_token = _get_fb_token()
    if not fb_token:
        return jsonify({
            "success": False,
            "error": (
                f"{FB_TOKEN_ENV_VAR} is not configured on the server. "
                "The customer cannot be messaged. Contact your administrator."
            ),
        }), 500

    conn = get_local_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database connection failed"}), 500

    cur     = None
    user_id = None

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='agent_queue' AND column_name='resolution_note'
                ) THEN ALTER TABLE agent_queue ADD COLUMN resolution_note TEXT; END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='agent_queue' AND column_name='confirmed_at'
                ) THEN ALTER TABLE agent_queue ADD COLUMN confirmed_at TIMESTAMP; END IF;
            END $$;
        """)

        cur.execute(
            "SELECT id, user_id, full_name, status FROM agent_queue WHERE id = %s",
            (queue_id,),
        )
        row = cur.fetchone()

        if not row:
            return jsonify({"success": False, "error": "Queue item not found"}), 404

        user_id        = (row["user_id"] or "").strip()
        current_status = row["status"]
        customer_name  = row["full_name"] or "Customer"

        if not user_id:
            return jsonify({
                "success": False,
                "error": "This queue entry has no Facebook user ID — cannot message the customer.",
            }), 400

        if current_status != "Pending":
            return jsonify({
                "success":       False,
                "already_served": True,
                "error":         "This ticket is not in Pending status (already actioned).",
            }), 409

        cur.execute(
    """
    UPDATE agent_queue
       SET status    = 'Awaiting Confirmation',
           served_at = CURRENT_TIMESTAMP,
           served_by = %s
     WHERE id = %s
    """,
    (served_by, queue_id),
)
        conn.commit()

        logger.info(
            f"[AgentQueue] #{queue_id} ({customer_name}) marked Awaiting "
            f"Confirmation by {served_by!r} — PSID={user_id}"
        )

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logger.exception(f"serve_queue_item DB error for queue_id={queue_id}")
        return jsonify({"success": False, "error": str(e)}), 500

    finally:
        if cur:
            cur.close()
        release_local_conn(conn)

    try:
        socketio.emit("queue_updated", {
            "action":    "awaiting_confirmation",
            "queue_id":  queue_id,
            "served_by": served_by,
            "timestamp": isoformat_safe(datetime.now(timezone.utc)),
        })
    except Exception as ws_err:
        logger.warning(f"[AgentQueue] WebSocket broadcast failed (non-fatal): {ws_err}")

    # ── FIX: RASA_URL is read HERE, at call time, and logged loudly.
    # If this env var is wrong/missing, you will now see it immediately
    # in the log instead of a silent timeout inside the thread.
    rasa_url_check = os.getenv("RASA_URL", "http://localhost:5005")
    logger.info(
        f"[AgentQueue] #{queue_id} — about to notify via RASA_URL={rasa_url_check}, "
        f"user_id={user_id}"
    )

    def _notify_async():
        logger.info(f"[AgentQueue] >>> THREAD START notify for #{queue_id}, user_id={user_id}")
        try:
            result = _send_resolution_confirmation(user_id, served_by, queue_id, fb_token)
            if not result["ok"]:
                logger.error(
                    f"[AgentQueue] !!! NOTIFY FAILED for #{queue_id}: {result['error']}"
                )
                try:
                    socketio.emit("queue_updated", {
                        "action":    "resolve_notify_failed",
                        "queue_id":  queue_id,
                        "error":     result["error"],
                        "timestamp": isoformat_safe(datetime.now(timezone.utc)),
                    })
                except Exception:
                    pass
            else:
                logger.info(f"[AgentQueue] <<< NOTIFY OK for #{queue_id}")
        except Exception:
            logger.exception(f"[AgentQueue] !!! THREAD CRASHED for #{queue_id}")

    import threading as _thr
    _thr.Thread(target=_notify_async, daemon=True).start()

    return jsonify({
        "success":   True,
        "notified":  True,
        "user_id":   user_id,
        "served_by": served_by,
    })


def _send_resolution_confirmation(
    sender_id: str,
    served_by: str,
    queue_id: int,
    fb_token: str,
) -> dict:
    import time as _t
    import requests as _r
    import json as _json

    rasa_url = os.getenv("RASA_URL", "http://localhost:5005")
    errors   = []

    # ── Step 0: Fail fast — verify Rasa is reachable ─────────────────────
    try:
        ping = _r.get(f"{rasa_url}/version", timeout=5)
        logger.info(
            f"[ResConf] Rasa reachable at {rasa_url} (HTTP {ping.status_code})"
        )
    except Exception as ping_err:
        final_error = (
            f"Rasa action server UNREACHABLE at {rasa_url}: {ping_err}"
        )
        logger.error(f"[ResConf] ABORTING for {sender_id} — {final_error}")
        return {"ok": False, "error": final_error}

    # ── Step 1: Unpause the tracker ───────────────────────────────────────
    # Retry twice with a 1-second gap — the tracker endpoint is occasionally
    # slow to respond on the first call right after a long pause.
    unpause_ok = False
    for attempt in (1, 2):
        try:
            r = _r.post(
                f"{rasa_url}/conversations/{sender_id}/tracker/events",
                json={"event": "resume"},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            unpause_ok = (r.status_code == 200)
            if not unpause_ok:
                errors.append(
                    f"unpause attempt {attempt} HTTP {r.status_code}: "
                    f"{r.text[:200]}"
                )
        except Exception as e:
            errors.append(f"unpause attempt {attempt} failed: {e}")

        if unpause_ok:
            logger.info(
                f"[ResConf] Tracker unpaused for {sender_id} (attempt {attempt})"
            )
            break
        if attempt == 1:
            _t.sleep(1.0)

    if not unpause_ok:
        final_error = (
            f"unpause failed after 2 attempts: {'; '.join(errors)}"
        )
        logger.error(f"[ResConf] ABORTING for {sender_id} — {final_error}")
        return {"ok": False, "error": final_error}

    _t.sleep(0.5)

    # ── Step 2: Set ALL required slots as a single atomic batch ──────────
    #
    # CRITICAL ORDER: slots MUST be set BEFORE _discard_stale_paused_messages
    # is called (or in this revised version, before any rewind-style cleanup),
    # because rewinds roll the tracker back past SlotSet events.
    #
    # We set MORE slots than strictly needed for the confirmation flow:
    #
    #   terms_agreed=True        — repair if rewinds wiped it (consumer
    #                              already accepted terms to reach this point)
    #   outage_awaiting_town=False — prevent action_ask_schedule_outage_town
    #                              from firing instead of the confirmation handler
    #   awaiting_star_rating=False — ensure we start the confirmation flow
    #                              clean, not mid-rating from a prior session
    #   escalate_to_agent=False  — clear any stale escalation flag so
    #                              talk_to_agent_form isn't blocked if the
    #                              consumer later taps "No, still need help"
    #   agent_queue_id           — the DB primary key the confirmation actions
    #                              use to call /confirm_resolved and /requeue
    #   served_by_agent          — displayed to the consumer in the follow-up
    #
    slot_events = [
        {"event": "slot", "name": "terms_agreed",         "value": True},
        {"event": "slot", "name": "outage_awaiting_town", "value": False},
        {"event": "slot", "name": "awaiting_star_rating", "value": False},
        {"event": "slot", "name": "escalate_to_agent",    "value": False},
        {"event": "slot", "name": "agent_queue_id",       "value": str(queue_id)},
        {"event": "slot", "name": "served_by_agent",      "value": served_by},
        # Clear any leftover form slots so talk_to_agent_form starts fresh
        # if the consumer declines resolution and needs to re-queue.
        {"event": "slot", "name": "tta_full_name",        "value": None},
        {"event": "slot", "name": "tta_contact_number",   "value": None},
        {"event": "slot", "name": "tta_concern",          "value": None},
    ]

    slots_ok = False
    for slot_attempt in (1, 2):
        try:
            r = _r.post(
                f"{rasa_url}/conversations/{sender_id}/tracker/events",
                json=slot_events,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            slots_ok = (r.status_code == 200)
            if slots_ok:
                logger.info(
                    f"[ResConf] Slots set for {sender_id} "
                    f"(agent_queue_id={queue_id}, served_by={served_by!r}, "
                    f"attempt={slot_attempt})"
                )
                break
            else:
                errors.append(
                    f"slot batch attempt {slot_attempt} HTTP "
                    f"{r.status_code}: {r.text[:200]}"
                )
        except Exception as e:
            errors.append(f"slot batch attempt {slot_attempt} failed: {e}")

        if slot_attempt == 1:
            _t.sleep(0.5)

    if not slots_ok:
        final_error = (
            f"slot-set failed after 2 attempts, aborting to avoid "
            f"untracked ticket: {'; '.join(errors)}"
        )
        logger.error(f"[ResConf] ABORTING for {sender_id} — {final_error}")
        return {"ok": False, "error": final_error}

    # ── Step 3: Verify the slots actually landed ──────────────────────────
    # This is the guard that catches the "slots appear to set but the
    # confirmation actions still see None" class of bugs. If agent_queue_id
    # is missing after the batch POST, the FB message is pointless — the
    # consumer would tap "Yes" and action_handle_resolution_confirmed would
    # silently skip the DB update.
    _t.sleep(0.3)
    try:
        verify_resp = _r.get(
            f"{rasa_url}/conversations/{sender_id}/tracker",
            timeout=8,
        )
        if verify_resp.status_code == 200:
            tracker_slots = verify_resp.json().get("slots", {})
            actual_queue_id = tracker_slots.get("agent_queue_id")
            actual_terms    = tracker_slots.get("terms_agreed")
            logger.info(
                f"[ResConf] Slot verification for {sender_id}: "
                f"agent_queue_id={actual_queue_id!r}, "
                f"terms_agreed={actual_terms!r}"
            )
            if actual_queue_id != str(queue_id):
                logger.error(
                    f"[ResConf] Slot verification FAILED — "
                    f"agent_queue_id={actual_queue_id!r} (expected {queue_id!r}). "
                    f"Aborting FB send to avoid broken confirmation flow."
                )
                return {
                    "ok": False,
                    "error": (
                        f"Slot verification failed: agent_queue_id was "
                        f"{actual_queue_id!r} after set, expected {queue_id!r}"
                    ),
                }
        else:
            logger.warning(
                f"[ResConf] Could not verify slots "
                f"(tracker HTTP {verify_resp.status_code}) — proceeding anyway."
            )
    except Exception as verify_err:
        logger.warning(
            f"[ResConf] Slot verification request failed: {verify_err} — "
            f"proceeding anyway."
        )

    # ── Step 4: Send the FB quick-reply message ───────────────────────────
    # This is what the consumer actually sees and taps. The quick-reply
    # payloads map to /resolution_confirmed and /resolution_declined, which
    # rules.yml routes to action_handle_resolution_confirmed and
    # action_handle_resolution_declined respectively.
    api_url = (
        f"https://graph.facebook.com/v19.0/me/messages"
        f"?access_token={fb_token}"
    )
        # ── FIX: embed agent_queue_id directly in the payload, Rasa-command
    # style (same pattern already used for /rate_service{"rating": N}).
    # Relying on the agent_queue_id SLOT breaks when the same consumer
    # has more than one ticket served close together — a second Resolve
    # click overwrites the slot before the first confirmation arrives,
    # permanently orphaning the earlier ticket at "Awaiting Confirmation".
    # Putting the queue_id in the payload itself makes each button
    # self-contained and immune to slot overwrites.
    import json as _json_payload
    confirmed_payload = "/resolution_confirmed" + _json_payload.dumps({"agent_queue_id": queue_id})
    declined_payload  = "/resolution_declined"  + _json_payload.dumps({"agent_queue_id": queue_id})

    payload = {
        "recipient":      {"id": sender_id},
        "message": {
            "text": (
                "✅ Our agent has resolved your concern.\n"
                "Was your issue fully resolved? 🙏"
            ),
            "quick_replies": [
                {
                    "content_type": "text",
                    "title":        "✅ Yes, resolved!",
                    "payload":      confirmed_payload,
                },
                {
                    "content_type": "text",
                    "title":        "❌ No, still need help",
                    "payload":      declined_payload,
                },
            ],
        },
        "messaging_type": "RESPONSE",
    }

    try:
        r = _r.post(
            api_url,
            headers={"Content-Type": "application/json"},
            data=_json.dumps(payload),
            timeout=15,
        )
        if r.status_code == 200:
            logger.info(
                f"[ResConf] FB quick-reply sent successfully to {sender_id}"
            )
            return {"ok": True, "error": None}
        else:
            err = (
                f"FB send failed: HTTP {r.status_code} {r.text[:300]}"
            )
            logger.error(f"[ResConf] {err}")
            return {"ok": False, "error": err}
    except Exception as e:
        err = f"FB send exception: {e}"
        logger.error(f"[ResConf] {err}")
        return {"ok": False, "error": err}

@app.route('/api/agent_queue/<int:queue_id>/confirm_resolved', methods=['POST'])
def confirm_queue_resolved(queue_id):
    """
    Called by action_handle_resolution_confirmed (actions.py) the moment
    the CONSUMER taps "✅ Yes, resolved!" in Messenger. This is the only
    place status actually becomes 'Resolved' — clicking Resolve in the
    dashboard only moves a ticket to 'Awaiting Confirmation'.

    Internal-only — authenticated via X-Internal-Secret header.
    """
    if not is_internal_request():
        return jsonify({'success': False, 'error': 'Internal access only'}), 403

    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500

    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "ALTER TABLE agent_queue ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMP"
        )
        cur.execute(
            "SELECT id, full_name, status FROM agent_queue WHERE id = %s",
            (queue_id,)
        )
        row = cur.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Queue record not found'}), 404

        if row['status'] not in ('Awaiting Confirmation', 'Pending'):
            # already Resolved/Unresolved/Auto-Closed — don't reopen it
            return jsonify({'success': True, 'already_final': True, 'status': row['status']})

        cur.execute(
    """
    UPDATE agent_queue
       SET status       = 'Resolved',
           confirmed_at = CURRENT_TIMESTAMP
     WHERE id = %s
    RETURNING id, full_name, status
    """,
    (queue_id,)
)
        result = cur.fetchone()
        conn.commit()

        logger.info(
            f"[Confirm] Queue #{queue_id} ({result['full_name']}) "
            f"confirmed Resolved by the consumer"
        )

        try:
            socketio.emit('queue_updated', {
                'action':    'confirmed_resolved',
                'queue_id':  queue_id,
                'timestamp': isoformat_safe(datetime.now(timezone.utc)),
            })
        except Exception:
            pass

        return jsonify({'success': True, 'queue_id': queue_id, 'status': 'Resolved'})

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logger.exception(f"confirm_queue_resolved error for queue_id={queue_id}")
        return jsonify({'success': False, 'error': str(e)}), 500

    finally:
        if cur:
            cur.close()
        release_local_conn(conn)

@app.route('/api/agent_queue/<int:queue_id>/requeue', methods=['POST'])
def requeue_declined_consumer(queue_id):
    """
    Called by action_handle_resolution_declined when the consumer says
    their concern was NOT resolved. The OLD ticket is closed out as
    'Unresolved' (a terminal state, kept for reporting) — it is NOT
    recycled back to Pending. A fresh Pending ticket is created
    separately once the consumer resubmits talk_to_agent_form.

    Internal-only — authenticated via X-Internal-Secret header.
    """
    if not is_internal_request():
        return jsonify({'success': False, 'error': 'Internal access only'}), 403

    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500

    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "ALTER TABLE agent_queue ADD COLUMN IF NOT EXISTS resolution_note TEXT"
        )

        cur.execute(
            "SELECT id, user_id, full_name, status FROM agent_queue WHERE id = %s",
            (queue_id,)
        )
        row = cur.fetchone()

        if not row:
            return jsonify({'success': False, 'error': 'Queue record not found'}), 404

        cur.execute(
            """
            UPDATE agent_queue
               SET status          = 'Unresolved',
                   resolution_note = 'Consumer indicated concern was not resolved'
             WHERE id = %s
            """,
            (queue_id,)
        )
        conn.commit()

        logger.info(
            f"[Requeue] Queue #{queue_id} ({row['full_name']}) marked "
            f"Unresolved — consumer declined resolution; a new ticket "
            f"will be created once they resubmit the agent form"
        )

        try:
            socketio.emit('queue_updated', {
                'action':    'marked_unresolved',
                'queue_id':  queue_id,
                'timestamp': isoformat_safe(datetime.now(timezone.utc)),
            })
        except Exception:
            pass

        return jsonify({
            'success':    True,
            'queue_id':   queue_id,
            'full_name':  row['full_name'],
            'new_status': 'Unresolved',
        })

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logger.exception(f"requeue_declined_consumer error for queue_id={queue_id}")
        return jsonify({'success': False, 'error': str(e)}), 500

    finally:
        if cur:
            cur.close()
        release_local_conn(conn)


@app.route('/api/agent_queue/<int:queue_id>/rate', methods=['POST'])
def rate_queue_resolution(queue_id):
    """
    Save a star rating (1–5) from the consumer after they confirmed
    their concern was resolved.

    Called by action_handle_star_rating in actions.py.
    Internal-only — authenticated via X-Internal-Secret header.
    """
    if not is_internal_request():
        return jsonify({'success': False, 'error': 'Internal access only'}), 403

    data   = request.get_json() or {}
    rating = data.get('rating')

    try:
        rating = int(rating)
        if not (1 <= rating <= 5):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Rating must be 1–5'}), 400

    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500

    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Add rating column if it doesn't exist yet (idempotent)
        cur.execute("""
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'agent_queue'
                      AND column_name = 'rating'
                ) THEN
                    ALTER TABLE agent_queue ADD COLUMN rating SMALLINT;
                END IF;
            END $$;
        """)

        cur.execute(
            "UPDATE agent_queue SET rating = %s WHERE id = %s RETURNING id, full_name, rating",
            (rating, queue_id)
        )
        row = cur.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Queue record not found'}), 404

        conn.commit()

        logger.info(
            f"[Rating] Queue #{queue_id} ({row['full_name']}) "
            f"rated {rating}/5 stars"
        )

        # Broadcast so dashboard can show the new rating live
        try:
            socketio.emit('queue_updated', {
                'action':   'rated',
                'queue_id': queue_id,
                'rating':   rating,
                'timestamp': isoformat_safe(datetime.now(timezone.utc)),
            })
        except Exception:
            pass

        return jsonify({'success': True, 'queue_id': queue_id, 'rating': rating})

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logger.exception(f"rate_queue_resolution error for queue_id={queue_id}")
        return jsonify({'success': False, 'error': str(e)}), 500

    finally:
        if cur:
            cur.close()
        release_local_conn(conn)

@app.route('/api/internal/pause_conversation/<sender_id>', methods=['POST'])
def pause_conversation_admin(sender_id):
    if not is_internal_request():
        if 'user_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401

    # ── FIX: guard against an empty/whitespace sender_id — Flask's
    # <sender_id> converter never matches an empty path segment, so a
    # blank value here would already 404 before reaching this code,
    # but this guard also catches whitespace-only PSIDs from malformed
    # dashboard payloads with a clear error instead of a confusing 404.
    sender_id = (sender_id or '').strip()
    if not sender_id:
        return jsonify({'success': False, 'error': 'Missing Facebook user ID'}), 400

    rasa_url = os.getenv('RASA_URL', 'http://localhost:5005')
    url = f"{rasa_url}/conversations/{sender_id}/tracker/events"

    try:
        resp = requests.post(
            url,
            json={"event": "pause"},
            headers={"Content-Type": "application/json"},
            timeout=8,
        )
        resp.raise_for_status()
        with _manual_pause_lock:
            _manually_paused_senders.add(sender_id)
        logger.info(
            f"[PauseConversation] Manually paused by "
            f"{session.get('username', 'internal')} for sender_id={sender_id}"
        )
        return jsonify({'success': True, 'sender_id': sender_id})
    except Exception as e:
        logger.error(f"[PauseConversation] Failed for {sender_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/internal/unpause_conversation/<sender_id>', methods=['POST'])
def unpause_conversation(sender_id):
    if not is_internal_request():
        return jsonify({'success': False, 'error': 'Internal access only'}), 403

    rasa_url = os.getenv('RASA_URL', 'http://localhost:5005')
    url = f"{rasa_url}/conversations/{sender_id}/trigger_intent?output_channel=latest"

    try:
        resp = requests.post(
            url,
            json={
                "name": "resume_conversation",
                "entities": [{"entity": "served_by_agent", "value": "System"}],
            },
            timeout=8,
        )
        resp.raise_for_status()
        # ── Clear the manual-pause flag — bot can now be auto-resumed
        # normally again by future timers.
        with _manual_pause_lock:
            _manually_paused_senders.discard(sender_id)
        logger.info(f"[Unpause] Successfully unpaused conversation for {sender_id}")
        return jsonify({'success': True, 'sender_id': sender_id})
    except Exception as e:
        logger.error(f"[Unpause] Failed for {sender_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/agent_queue/<int:queue_id>/remove', methods=['DELETE'])
@admin_required
def remove_queue_record(queue_id):
    """Remove a resolved queue record (dashboard cleanup)."""
    conn = get_local_conn()          # ← LOCAL db
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
 
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
 
        # Only allow removing Resolved records — never Pending
        cur.execute(
            "SELECT id, full_name, status FROM agent_queue WHERE id = %s",
            (queue_id,)
        )
        record = cur.fetchone()
 
        if not record:
            return jsonify({'success': False, 'error': 'Record not found'}), 404
 
        if record['status'] == 'Pending':
            return jsonify({
                'success': False,
                'error': 'Cannot remove a Pending customer. Serve them first.'
            }), 400
 
        cur.execute("DELETE FROM agent_queue WHERE id = %s", (queue_id,))
        conn.commit()
 
        logger.info(
            f"Queue record {queue_id} ({record['full_name']}) "
            f"removed by {session.get('username')}"
        )
 
        try:
            socketio.emit('queue_updated', {
                'action':   'removed',
                'queue_id': queue_id,
                'timestamp': isoformat_safe(datetime.now(timezone.utc))
            })
        except Exception:
            pass
 
        return jsonify({
            'success': True,
            'message': f"Record for {record['full_name']} removed."
        })
 
    except Exception as e:
        if conn: conn.rollback()
        logger.exception(f"Remove queue record error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur:  cur.close()
        release_local_conn(conn)     # ← LOCAL release

@app.route('/api/agent_queue/statistics', methods=['GET'])
@login_required
def get_queue_statistics():
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT COUNT(*) as total FROM agent_queue")
        total = cur.fetchone()['total']
        cur.execute("SELECT status, COUNT(*) as count FROM agent_queue GROUP BY status")
        by_status = cur.fetchall()
        cur.execute("SELECT priority, COUNT(*) as count FROM agent_queue WHERE status = 'Pending' GROUP BY priority")
        by_priority = cur.fetchall()
        cur.execute("SELECT COUNT(*) as count FROM agent_queue WHERE status = 'Resolved' AND DATE(timestamp) = CURRENT_DATE")
        served_today = cur.fetchone()['count']
        
        return jsonify({
            'success': True,
            'data': {
                'total': total,
                'by_status': [dict(s) for s in by_status],
                'by_priority': [dict(p) for p in by_priority],
                'served_today': served_today
            }
        })
    except Exception as e:
        logger.exception("Get queue statistics error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)

# ============================================
# SPAM CONTROL — status, conversation viewer, block/unblock
# ============================================
def initialize_spam_control_tables():
    conn = get_local_conn()
    if not conn:
        return
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS spam_sender_status (
                sender_id     TEXT PRIMARY KEY,
                status        TEXT NOT NULL DEFAULT 'BLOCKED',   -- BLOCKED | UNBLOCKED
                blocked_until TIMESTAMP,                          -- NULL = indefinite
                reason        TEXT,
                blocked_by    TEXT,
                blocked_at    TIMESTAMP DEFAULT TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                unblocked_by  TEXT,
                unblocked_at  TIMESTAMP
            )
        """)
        # NEW: SOFT = one restricted notice then silence; FULL = never reply
        cur.execute("""
            ALTER TABLE spam_sender_status
            ADD COLUMN IF NOT EXISTS block_mode TEXT NOT NULL DEFAULT 'SOFT'
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS spam_agent_actions (
                id           SERIAL PRIMARY KEY,
                sender_id    TEXT NOT NULL,
                action       TEXT NOT NULL,
                note         TEXT,
                performed_by TEXT,
                created_at   TIMESTAMP DEFAULT TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_spam_agent_actions_sender ON spam_agent_actions(sender_id, created_at DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_spam_logs_sender_created ON spam_logs(sender_id, created_at DESC)")
        conn.commit()
        logger.info("✅ spam control tables ready")
    except Exception:
        try: conn.rollback()
        except Exception: pass
        logger.exception("Failed to initialize spam control tables")
    finally:
        if cur: cur.close()
        release_local_conn(conn)
        # Rollback: ALTER TABLE spam_sender_status DROP COLUMN block_mode;
        #           (full: DROP TABLE spam_agent_actions; DROP TABLE spam_sender_status;)


_ACTIVE_BLOCK_SQL = """
    status = 'BLOCKED'
    AND (blocked_until IS NULL
         OR blocked_until > TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP))
"""

def _risk_level(total_flags, flags_1h, blocked_until, is_blocked):
    """Thresholds are illustrative — tune to your real traffic."""
    if is_blocked:
        return 'BLOCKED' if blocked_until is None else 'TEMPORARILY_BLOCKED'
    if flags_1h >= 5 or total_flags >= 10:
        return 'POTENTIAL_SPAM'
    if flags_1h >= 2 or total_flags >= 3:
        return 'SUSPICIOUS'
    return 'NORMAL'


def _fetch_rasa_messages(sender_id, limit=300):
    """Reads the conversation from Rasa's tracker. Returns (messages, available)."""
    rasa_url = os.getenv('RASA_URL', 'http://localhost:5005')
    try:
        resp = requests.get(
            f"{rasa_url}/conversations/{sender_id}/tracker",
            params={'include_events': 'ALL'}, timeout=8
        )
        if resp.status_code == 404:
            return [], True
        resp.raise_for_status()
        events = resp.json().get('events', [])
    except Exception as e:
        logger.warning(f"Rasa tracker fetch failed for {sender_id}: {e}")
        return [], False

    msgs = []
    for ev in events:
        kind = ev.get('event')
        if kind not in ('user', 'bot'):
            continue
        text = ev.get('text')
        if not text and kind == 'bot':
            data = ev.get('data') or {}
            if data.get('attachment') or data.get('elements'):
                text = '[carousel / attachment]'
            elif data.get('buttons'):
                text = '[buttons]'
        if not text:
            continue
        ts = ev.get('timestamp')
        msgs.append({
            'role': 'customer' if kind == 'user' else 'bot',
            'text': text[:1000],
            'timestamp': datetime.fromtimestamp(ts, PHILIPPINE_TZ).isoformat() if ts else None,
        })
    return msgs[-limit:], True


def _get_messenger_thread_link(sender_id):
    """
    Asks Meta (Conversations API) for the Page-inbox link of this PSID's thread.
    Returns (url|None, note). Never fabricates a URL.
    """
    fb_token = _get_fb_token()
    if not fb_token:
        return None, 'Page token not configured'
    try:
        resp = requests.get(
            "https://graph.facebook.com/v19.0/me/conversations",
            params={'platform': 'messenger', 'user_id': sender_id,
                    'fields': 'id,link,updated_time', 'access_token': fb_token},
            timeout=8
        )
        data = resp.json()
        if 'error' in data:
            err = data['error'] or {}
            logger.warning(f"Conversations API failed for {sender_id}: code={err.get('code')} msg={err.get('message')}")
            return None, 'Meta did not return a thread link (missing permission or no thread)'
        items = data.get('data') or []
        link = (items[0].get('link') if items else None) or ''
        if link.startswith('/'):
            link = 'https://www.facebook.com' + link
        if link.startswith('https://www.facebook.com/') or link.startswith('https://business.facebook.com/'):
            return link, None
        return None, 'No thread link available from Meta for this user'
    except Exception as e:
        logger.warning(f"Conversations API error for {sender_id}: {e}")
        return None, 'Lookup failed'


@app.route('/api/spam_senders/<sender_id>/conversation', methods=['GET'])
@login_required
def get_spam_sender_conversation(sender_id):
    sender_id = (sender_id or '').strip()
    if not sender_id.isdigit():
        return jsonify({'success': False, 'error': 'Invalid sender ID'}), 400

    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE created_at >= TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) - INTERVAL '1 hour') AS last_hour,
                   COUNT(*) FILTER (WHERE event_type LIKE '%%repeat%%') AS repeats,
                   COUNT(*) FILTER (WHERE event_type LIKE '%%flood%%')  AS floods,
                   MAX(created_at) AS last_activity
            FROM spam_logs WHERE sender_id = %s
        """, (sender_id,))
        agg = cur.fetchone()

        cur.execute(f"""
            SELECT status, blocked_until, reason, blocked_by, blocked_at, block_mode
            FROM spam_sender_status WHERE sender_id = %s AND {_ACTIVE_BLOCK_SQL}
        """, (sender_id,))
        block = cur.fetchone()

        cur.execute("""
            SELECT id, event_type, message_sample, created_at, reviewed, reviewed_by
            FROM spam_logs WHERE sender_id = %s ORDER BY created_at DESC LIMIT 50
        """, (sender_id,))
        events = [dict(r) for r in cur.fetchall()]
        for e in events:
            e['created_at'] = isoformat_safe(e['created_at'])

        cur.execute("""
            SELECT action, note, performed_by, created_at
            FROM spam_agent_actions WHERE sender_id = %s ORDER BY created_at DESC LIMIT 50
        """, (sender_id,))
        actions = [dict(r) for r in cur.fetchall()]
        for a in actions:
            a['created_at'] = isoformat_safe(a['created_at'])

        level = _risk_level(agg['total'], agg['last_hour'],
                            block['blocked_until'] if block else None, bool(block))
        messages, rasa_ok = _fetch_rasa_messages(sender_id)
        link, link_note = _get_messenger_thread_link(sender_id)

        return jsonify({
            'success': True,
            'sender_id': sender_id,
            'risk': {'level': level, 'flags_total': agg['total'], 'flags_1h': agg['last_hour'],
                     'repeat_events': agg['repeats'], 'flood_events': agg['floods'],
                     'last_activity': isoformat_safe(agg['last_activity'])},
            'block': ({'blocked_until': isoformat_safe(block['blocked_until']),
                       'reason': block['reason'],
                       'blocked_by': block['blocked_by'],
                       'blocked_at': isoformat_safe(block['blocked_at']),
                       'block_mode': block['block_mode']}
                      if block else None),
            'messages': messages,
            'rasa_available': rasa_ok,
            'spam_events': events,
            'agent_actions': actions,
            'messenger_link': link,
            'messenger_link_note': link_note,
            'reports_linked': False,   # outage_reports has no PSID column
        })
    except Exception as e:
        logger.exception("get_spam_sender_conversation error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@app.route('/api/spam_senders/<sender_id>/block', methods=['POST'])
@login_required
def block_spam_sender(sender_id):
    sender_id = (sender_id or '').strip()
    if not sender_id.isdigit():
        return jsonify({'success': False, 'error': 'Invalid sender ID'}), 400
    data = request.get_json(silent=True) or {}
    reason = (data.get('reason') or '').strip()[:300]

    mode = (data.get('mode') or 'SOFT').strip().upper()
    if mode not in ('SOFT', 'FULL'):
        mode = 'SOFT'

    minutes = data.get('duration_minutes')          # None => indefinite
    if minutes is not None:
        try:
            minutes = int(minutes)
            if not (1 <= minutes <= 60 * 24 * 30):
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'Invalid duration'}), 400
    actor = session.get('full_name') or session.get('username', 'Unknown')

    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO spam_sender_status (sender_id, status, blocked_until, reason, blocked_by, blocked_at,
                                            unblocked_by, unblocked_at, block_mode)
            VALUES (%s, 'BLOCKED',
                    CASE WHEN %s::int IS NULL THEN NULL
                         ELSE TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) + (%s::int * INTERVAL '1 minute') END,
                    %s, %s, TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP), NULL, NULL, %s)
            ON CONFLICT (sender_id) DO UPDATE SET
                status = 'BLOCKED', blocked_until = EXCLUDED.blocked_until, reason = EXCLUDED.reason,
                blocked_by = EXCLUDED.blocked_by, blocked_at = EXCLUDED.blocked_at,
                unblocked_by = NULL, unblocked_at = NULL, block_mode = EXCLUDED.block_mode
        """, (sender_id, minutes, minutes, reason, actor, mode))

        action_name = f"BLOCK_{mode}_" + ('INDEFINITE' if minutes is None else f'{minutes}MIN')
        cur.execute("""
            INSERT INTO spam_agent_actions (sender_id, action, note, performed_by)
            VALUES (%s, %s, %s, %s)
        """, (sender_id, action_name, reason, actor))
        conn.commit()
        logger.info(f"[SpamBlock] {sender_id} blocked by {actor} (mode={mode}, minutes={minutes})")
        return jsonify({'success': True, 'mode': mode})
    except Exception as e:
        try: conn.rollback()
        except Exception: pass
        logger.exception("block_spam_sender error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@app.route('/api/spam_senders/<sender_id>/unblock', methods=['POST'])
@login_required
def unblock_spam_sender(sender_id):
    sender_id = (sender_id or '').strip()
    if not sender_id.isdigit():
        return jsonify({'success': False, 'error': 'Invalid sender ID'}), 400
    actor = session.get('full_name') or session.get('username', 'Unknown')
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE spam_sender_status
               SET status = 'UNBLOCKED', unblocked_by = %s,
                   unblocked_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
             WHERE sender_id = %s
        """, (actor, sender_id))
        cur.execute("INSERT INTO spam_agent_actions (sender_id, action, performed_by) VALUES (%s, 'UNBLOCK', %s)",
                    (sender_id, actor))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        try: conn.rollback()
        except Exception: pass
        logger.exception("unblock_spam_sender error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@app.route('/api/internal/is_blocked/<sender_id>', methods=['GET'])
def internal_is_sender_blocked(sender_id):
    """Rasa/action server calls this before handling a message.
    Returns {blocked, mode}. Fails OPEN on DB error."""
    if not is_internal_request():
        return jsonify({'success': False, 'error': 'Internal access only'}), 403
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': True, 'blocked': False, 'mode': None, 'degraded': True})
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            f"SELECT block_mode FROM spam_sender_status WHERE sender_id = %s AND {_ACTIVE_BLOCK_SQL}",
            (sender_id,)
        )
        row = cur.fetchone()
        return jsonify({
            'success': True,
            'blocked': row is not None,
            'mode': row['block_mode'] if row else None,
        })
    except Exception:
        logger.exception("is_blocked check failed")
        return jsonify({'success': True, 'blocked': False, 'mode': None, 'degraded': True})
    finally:
        if cur: cur.close()
        release_local_conn(conn)

@app.route('/spam_monitor')
@login_required
def spam_monitor_dashboard():
    return render_template('spam_monitor.html')


@app.route('/api/spam_logs', methods=['GET'])
@login_required
def get_spam_logs():
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        reviewed_filter = request.args.get('reviewed', 'all')
        cur = conn.cursor(cursor_factory=RealDictCursor)

        query = """
            SELECT id, sender_id, event_type, message_sample,
                   created_at, reviewed, reviewed_by, reviewed_at
            FROM spam_logs WHERE 1=1
        """
        params = []
        if reviewed_filter == 'unreviewed':
            query += " AND reviewed = FALSE"
        elif reviewed_filter == 'reviewed':
            query += " AND reviewed = TRUE"

        query += " ORDER BY created_at DESC LIMIT 500"
        cur.execute(query, params if params else None)
        rows = cur.fetchall()

        result = []
        for r in rows:
            d = dict(r)
            d['created_at'] = isoformat_safe(d.get('created_at'))
            d['reviewed_at'] = isoformat_safe(d.get('reviewed_at'))
            result.append(d)

                # Aggregate: distinct senders, with 1h burst count, risk, and active block
        cur.execute("""
            SELECT s.sender_id,
                   COUNT(*) AS flag_count,
                   COUNT(*) FILTER (WHERE s.created_at >=
                        TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) - INTERVAL '1 hour') AS flags_1h,
                   MAX(s.created_at) AS last_flagged,
                   COUNT(*) FILTER (WHERE NOT s.reviewed) AS unreviewed_count,
                   (b.sender_id IS NOT NULL) AS is_blocked,
                   b.blocked_until
            FROM spam_logs s
            LEFT JOIN spam_sender_status b
                   ON b.sender_id = s.sender_id
                  AND b.status = 'BLOCKED'
                  AND (b.blocked_until IS NULL
                       OR b.blocked_until > TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP))
            GROUP BY s.sender_id, b.sender_id, b.blocked_until
            ORDER BY flag_count DESC, last_flagged DESC
            LIMIT 100
        """)
        summary = []
        for r in cur.fetchall():
            d = dict(r)
            d['risk'] = _risk_level(d['flag_count'], d['flags_1h'], d['blocked_until'], d['is_blocked'])
            d['any_reviewed'] = (d['unreviewed_count'] == 0)   # fixes BOOL_OR bug
            d['last_flagged'] = isoformat_safe(d.get('last_flagged'))
            d['blocked_until'] = isoformat_safe(d.get('blocked_until'))
            summary.append(d)

        return jsonify({'success': True, 'logs': result, 'summary': summary})
    except Exception as e:
        try:
            conn.rollback()          # ← ADD THIS
        except Exception:
            pass
        logger.exception("get_spam_logs error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@app.route('/api/spam_logs/<int:log_id>/review', methods=['POST'])
@login_required
def review_spam_log(log_id):
    performed_by = session.get('full_name') or session.get('username', 'Unknown')
    conn = get_local_conn()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE spam_logs
            SET reviewed = TRUE, reviewed_by = %s,
                reviewed_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
            WHERE id = %s
        """, (performed_by, log_id))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        conn.rollback()
        logger.exception("review_spam_log error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)

@app.route('/agent_queue')
@login_required
def agent_queue_dashboard():
    return render_template('agent_queue.html')

@socketio.on('new_agent_queue_item')
def handle_new_queue_item(data):
    try:
        logger.info(f"New agent queue item: {data.get('full_name')}")
        emit('new_queue_item', data)
    except Exception as e:
        logger.exception("WebSocket broadcast error for queue item")

@app.route('/api/incident/<int:incident_id>/remove', methods=['DELETE'])
@admin_required
def remove_incident(incident_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT incident_id, job_order_id FROM outage_incidents WHERE incident_id = %s", (incident_id,))
        incident = cur.fetchone()
        
        if not incident:
            return jsonify({'success': False, 'error': 'Incident not found'}), 404
        
        cur.execute("DELETE FROM outage_reports WHERE incident_id = %s", (incident_id,))
        cur.execute("DELETE FROM outage_incidents WHERE incident_id = %s", (incident_id,))
        conn.commit()
        
        try:
            socketio.emit('incident_removed', {
                'incident_id': incident_id,
                'job_order_id': incident.get('job_order_id'),
                'timestamp': isoformat_safe(datetime.now(timezone.utc))
            })
        except Exception as e:
            logger.exception("WebSocket broadcast error")
        
        return jsonify({'success': True, 'message': 'Incident removed successfully'})
        
    except Exception as e:
        conn.rollback()
        logger.exception("Remove incident error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)

@app.route('/api/incident/<int:incident_id>/assign_to_omms', methods=['POST'])
@login_required
def assign_incident_to_omms(incident_id):
    """
    Assign a power-outage consumer report to the OMMS `converted` table.
 
    POST body (JSON, optional):
        { "report_id": <int> }
        If omitted → uses the earliest consumer report for this incident.
 
    Database connections used:
        cloud_conn  → reads outage_incidents + outage_reports  (Supabase)
        local_conn  → INSERT into public.converted             (local OMMS DB)
        cloud_conn  → UPDATE outage_reports + outage_incidents (Supabase)
 
    Returns:
        { success, message, omms_unique_id, report_id, incident_id }
    """
    request_data = request.get_json() or {}
    report_id    = request_data.get('report_id')   # optional
    now_ph       = _datetime.now(_PH_TZ)
 
    # ── Connection handles — opened separately so each can be released cleanly
    cloud_conn = None
    local_conn = None
    cloud_cur  = None
    local_cur  = None
 
    try:
        # ── STEP 1: Open cloud connection — read incident + consumer ──────────
        cloud_conn = get_db_connection()
        if not cloud_conn:
            return jsonify({
                'success': False,
                'error':   'Cloud database connection failed'
            }), 500
 
        cloud_cur = cloud_conn.cursor(cursor_factory=RealDictCursor)
 
        # ── STEP 2: Load outage incident (with feeder via spatial join) ───────
        cloud_cur.execute(f"""
            SELECT
                i.incident_id,
                i.incident_type,
                i.barangay,
                i.town,
                i.priority,
                i.status,
                i.job_order_id,
                i.remarks,
                ST_Y(i.geom::geometry) AS lat,
                ST_X(i.geom::geometry) AS lng,
                f.{FEEDER_NAME_COL}    AS feeder_name
            FROM outage_incidents i
            LEFT JOIN {FEEDER_TABLE} f
                ON ST_Contains(f.geom::geometry, i.geom::geometry)
                AND f.{FEEDER_NAME_COL} != '{EXCLUDED_FEEDER}'
            WHERE i.incident_id = %s
        """, (incident_id,))
 
        incident = cloud_cur.fetchone()
        if not incident:
            return jsonify({
                'success': False,
                'error':   f'Incident {incident_id} not found'
            }), 404
 
        # ── STEP 3: Load the target consumer report ───────────────────────────
        if report_id:
            cloud_cur.execute("""
                SELECT
                    report_id, full_name, contact_number, email,
                    account_number, address, barangay, town,
                    details, landmark, priority, incident_type,
                    ST_Y(geom::geometry) AS lat,
                    ST_X(geom::geometry) AS lng
                FROM outage_reports
                WHERE report_id = %s AND incident_id = %s
            """, (report_id, incident_id))
        else:
            # Earliest consumer report for this incident
            cloud_cur.execute("""
                SELECT
                    report_id, full_name, contact_number, email,
                    account_number, address, barangay, town,
                    details, landmark, priority, incident_type,
                    ST_Y(geom::geometry) AS lat,
                    ST_X(geom::geometry) AS lng
                FROM outage_reports
                WHERE incident_id = %s
                ORDER BY timestamp ASC
                LIMIT 1
            """, (incident_id,))
 
        consumer = cloud_cur.fetchone()
        if not consumer:
            return jsonify({
                'success': False,
                'error':   'No consumer report found for this incident. '
                           'At least one consumer must have submitted a report.'
            }), 404
 
        # ── STEP 4: Build every OMMS field value ─────────────────────────────
        omms_ts        = _omms_timestamp(now_ph)
        omms_unique_id = _omms_unique_id(now_ph)
        omms_spinners  = _omms_spinners(now_ph)
 
        # Coordinates: prefer consumer GPS, fall back to incident centroid
        cons_lat = consumer['lat']
        cons_lng = consumer['lng']
        inc_lat  = incident['lat']
        inc_lng  = incident['lng']
        lat_val  = cons_lat if cons_lat is not None else inc_lat
        lng_val  = cons_lng if cons_lng is not None else inc_lng
        lat_text = str(round(float(lat_val), 7)) if lat_val is not None else ''
        lng_text = str(round(float(lng_val), 7)) if lng_val is not None else ''
 
        # Feeder & substation
        feeder_name = incident['feeder_name'] or ''
        substation  = _omms_substation(feeder_name, incident['town'] or '')
 
        # Incident type for mapping (prefer incident-level, fall back to report)
        inc_type = incident['incident_type'] or consumer.get('incident_type') or 'power_outage'
 
        # Consumer fields
        consumer_name    = (consumer['full_name'] or '').strip() or 'Unknown'
        contact_number   = (consumer['contact_number'] or '').strip()
        consumer_address = (consumer['address'] or '').strip()
        consumer_landmark= (consumer['landmark'] or '').strip()
        consumer_details = (consumer['details'] or '').strip()
 
        # Location fields — use consumer's barangay/town, fall back to incident
        town_val = (consumer['town'] or incident['town'] or '').strip()
        brgy_val = (consumer['barangay'] or incident['barangay'] or '').strip()
 
        # OMMS field values
        creator      = contact_number or incident['job_order_id'] or ''
        name_val     = consumer_name
        town0_val    = town_val
        brgy0_val    = brgy_val
        assignedto   = town_val        # crew dispatch goes to the town
        status_omms  = 'On-going'      # all new OMMS work orders = On-going
        section_val  = _omms_section(inc_type)
        cause_val    = _omms_cause(inc_type, consumer_details)
        equip_val    = _omms_equip(inc_type, consumer_details)
        type_val     = _omms_priority_type(incident['priority'] or consumer['priority'] or 'HIGH')
        notes_val    = consumer_details or incident.get('remarks') or ''
        location_val = consumer_address or f"{brgy_val}, {town_val}"
 
        logger.info(
            f"OMMS assign — incident={incident_id}, report={consumer['report_id']}, "
            f"feeder={feeder_name}, town={town_val}, brgy={brgy_val}, "
            f"cause={cause_val}, section={section_val}, type={type_val}"
        )
 
        # ── STEP 5: Open LOCAL connection — INSERT into converted ─────────────
        local_conn = get_joblist_conn()          # ← CHANGED from get_local_conn()
        if not local_conn:
            return jsonify({
                'success': False,
                'error':   'Joblist OMMS database connection failed. '
                           'Check JOBLIST_DB_NAME env variable (should be "joblist").'
            }), 500
 
        local_cur = local_conn.cursor(cursor_factory=RealDictCursor)
 
        # Safety: check for duplicate before insert
        local_cur.execute("""
            SELECT unique_id
            FROM public.converted
            WHERE unique_id = %s AND followed = %s
            LIMIT 1
        """, (omms_unique_id, omms_ts))
 
        if local_cur.fetchone():
            # Collision guard — append extra digit (happens <1 in a billion)
            omms_unique_id = omms_unique_id + str(_uuid_module.uuid4().int)[:2]
            logger.warning(f"unique_id collision — appended suffix: {omms_unique_id}")
 
        # INSERT into public.converted (local OMMS database)
        local_cur.execute("""
            INSERT INTO public.converted (
                unique_id,
                creator,
                created,
                follower,
                followed,
                name,
                spinners,
                town0,
                brgy0,
                town,
                brgy,
                town2,
                brgy2,
                assignedto,
                status,
                subs,
                feeder,
                section,
                cause,
                equip,
                type,
                notes,
                landmark,
                phone,
                location,
                latitude,
                longitude,
                actiontaken,
                submitted_at,
                assigned_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s,
                %s, %s,
                %s, %s,
                %s, %s,
                %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                NULL,
                %s, %s
            )
            ON CONFLICT (unique_id, followed) DO NOTHING
            RETURNING unique_id
        """, (
            # Row 1 — identity
            omms_unique_id,
            creator,
            omms_ts,
            creator,
            omms_ts,
            # Row 2 — name + spinners
            name_val,
            omms_spinners,
            # Row 3 — town0 / brgy0 (original location)
            town0_val,
            brgy0_val,
            # Row 4 — town / brgy (current location)
            town0_val,
            brgy0_val,
            # Row 5 — town2 / brgy2 (destination / same as current for outages)
            town0_val,
            brgy0_val,
            # Row 6 — assignment + status
            assignedto,
            status_omms,
            # Row 7 — substation / feeder / section
            substation,
            feeder_name,
            section_val,
            # Row 8 — cause / equip / type (priority)
            cause_val,
            equip_val,
            type_val,
            # Row 9 — description fields
            notes_val,
            consumer_landmark,
            contact_number,
            # Row 10 — location / coordinates
            location_val,
            lat_text,
            lng_text,
            # Row 11 — timestamps (actiontaken is NULL — crew fills later)
            omms_ts,   # submitted_at
            omms_ts,   # assigned_at
        ))
 
        omms_result = local_cur.fetchone()
        local_conn.commit()
 
        if omms_result is None:
            # ON CONFLICT DO NOTHING fired — still treat as success
            logger.warning(
                f"OMMS INSERT skipped (conflict) for unique_id={omms_unique_id}. "
                "Record may already exist in converted table."
            )
 
        logger.info(
            f"✅ OMMS converted INSERT OK — unique_id={omms_unique_id}, "
            f"town={town0_val}, brgy={brgy0_val}, feeder={feeder_name}"
        )
 
        # ── STEP 6: Update cloud DB — consumer report → ASSIGNED ─────────────
        cloud_cur.execute("""
            UPDATE outage_reports
            SET
                status            = 'ASSIGNED',
                assigned_at       = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP),
                status_changed_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
            WHERE report_id = %s
        """, (consumer['report_id'],))
 
        # ── STEP 7: Update cloud DB — incident → ASSIGNED (only if still NEW) -
        cloud_cur.execute("""
            UPDATE outage_incidents
            SET
                status      = CASE
                                  WHEN status = 'NEW' THEN 'ASSIGNED'
                                  ELSE status
                              END,
                assigned_at = CASE
                                  WHEN assigned_at IS NULL
                                  THEN TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
                                  ELSE assigned_at
                              END,
                updated_at  = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
            WHERE incident_id = %s
        """, (incident_id,))
 
        cloud_conn.commit()
        logger.info(
            f"✅ Cloud DB updated — incident={incident_id}, "
            f"report={consumer['report_id']} → ASSIGNED"
        )
 
        # ── STEP 8: WebSocket broadcast — refresh all open dashboard tabs ─────
        try:
            socketio.emit('incident_updated', {
                'incident_id':    incident_id,
                'new_status':     'ASSIGNED',
                'location':       f"{incident['town']} / {incident['barangay']}",
                'omms_unique_id': omms_unique_id,
                'timestamp':      isoformat_safe(now_ph),
            })
            socketio.emit('stats_update', {
                'trigger':   'omms_assigned',
                'timestamp': isoformat_safe(now_ph),
            })
        except Exception as ws_err:
            logger.warning(f"WebSocket broadcast failed (non-fatal): {ws_err}")
 
        # ── STEP 9: Return success ────────────────────────────────────────────
        return jsonify({
            'success':        True,
            'message':        'Successfully assigned to OMMS job list',
            'omms_unique_id': omms_unique_id,
            'report_id':      consumer['report_id'],
            'incident_id':    incident_id,
            'omms_fields': {
                'name':       name_val,
                'town':       town0_val,
                'brgy':       brgy0_val,
                'feeder':     feeder_name,
                'substation': substation,
                'section':    section_val,
                'cause':      cause_val,
                'equip':      equip_val,
                'type':       type_val,
                'status':     status_omms,
            }
        })
 
    except Exception as e:
        # Roll back both connections on any error
        try:
            if cloud_conn:
                cloud_conn.rollback()
        except Exception:
            pass
        try:
            if local_conn:
                local_conn.rollback()
        except Exception:
            pass
 
        logger.exception(
            f"❌ assign_incident_to_omms FAILED — "
            f"incident={incident_id}, report={report_id}, error={e}"
        )
        return jsonify({
            'success': False,
            'error':   f'Assignment failed: {str(e)}'
        }), 500
 
    finally:
        # Always release both connections back to their pools
        try:
            if cloud_cur:
                cloud_cur.close()
        except Exception:
            pass
        try:
            if local_cur:
                local_cur.close()
        except Exception:
            pass
        try:
            if cloud_conn:
                release_db_connection(cloud_conn)
        except Exception:
            pass
        try:
            if local_conn:
                release_joblist_conn(local_conn) 
        except Exception:
            pass

@app.route('/api/incident/<int:incident_id>/remarks', methods=['POST', 'OPTIONS'])
def update_incident_remarks(incident_id):
    if request.method == 'OPTIONS':
        return _cors_preflight_response('Content-Type, X-Requested-With', allow_credentials=True)
    
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated. Please log in again.'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        remarks = (data.get('remarks') or '').strip()
    except Exception as e:
        return jsonify({'success': False, 'error': 'Invalid request data'}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database connection failed'}), 500
    
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT incident_id, remarks FROM outage_incidents WHERE incident_id = %s", (incident_id,))
        existing = cur.fetchone()
        
        if not existing:
            return jsonify({'success': False, 'error': f'Incident {incident_id} not found'}), 404
        
        cur.execute("""
            UPDATE outage_incidents
            SET remarks = %s, updated_at = TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
            WHERE incident_id = %s
            RETURNING incident_id, job_order_id, remarks
        """, (remarks, incident_id))
        
        result = cur.fetchone()
        if not result:
            return jsonify({'success': False, 'error': 'Update failed'}), 500
        
        conn.commit()
        return jsonify({'success': True, 'message': 'Remarks updated successfully', 'remarks': result['remarks']}), 200
        
    except Exception as e:
        if conn: conn.rollback()
        logger.exception(f"CRITICAL ERROR updating remarks for incident {incident_id}")
        return jsonify({'success': False, 'error': f'Database error: {str(e)}'}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)



@app.route('/api/badge_counts', methods=['GET'])
@login_required
@limiter.exempt          # ← ADD THIS — badge polls are internal, not abuse vectors
def get_badge_counts():
    """Returns all nav badge counts in a single lightweight request.
    Cached for _BADGE_CACHE_TTL seconds — every open tab shares one
    result instead of each tab hitting both DBs on every poll."""
    now = _time_module.time()
    if _badge_cache['data'] is not None and (now - _badge_cache['ts']) < _BADGE_CACHE_TTL:
        return jsonify({'success': True, 'counts': _badge_cache['data']})

    cloud_conn = get_db_connection()
    counts = {'outages': 0, 'meter': 0, 'queue': 0, 'scheduled': 0, 'spam': 0}

    try:
        if cloud_conn:
            cur = cloud_conn.cursor()
            cur.execute("""
                SELECT
                    (SELECT COUNT(*) FROM outage_incidents WHERE status = 'NEW'),
                    (SELECT COUNT(*) FROM meter_concerns WHERE status = 'PENDING'),
                    (SELECT COUNT(*) FROM scheduled_outages
                       WHERE is_active = TRUE AND outage_date >= CURRENT_DATE)
            """)
            counts['outages'], counts['meter'], counts['scheduled'] = cur.fetchone()
            cur.close()
    except Exception as e:
        logger.warning(f"Badge count cloud query failed: {e}")
    finally:
        if cloud_conn:
            release_db_connection(cloud_conn)

    local_conn = get_local_conn()
    try:
        if local_conn:
            cur = local_conn.cursor()
            cur.execute("SELECT COUNT(*) FROM agent_queue WHERE status = 'Pending'")
            counts['queue'] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM spam_logs WHERE reviewed = FALSE")  # ← ADD
            counts['spam'] = cur.fetchone()[0]                                    # ← ADD
            cur.close()
    except Exception as e:
        logger.warning(f"Badge count local query failed: {e}")
    finally:
        if local_conn:
            release_local_conn(local_conn)

    _badge_cache['data'] = counts
    _badge_cache['ts'] = now
    return jsonify({'success': True, 'counts': counts})

@app.route('/api/report/<int:report_id>/remove', methods=['DELETE'])
@admin_required
def remove_report(report_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'error': 'Database error'}), 500
    
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT report_id, incident_id, full_name FROM outage_reports WHERE report_id = %s", (report_id,))
        report = cur.fetchone()
        
        if not report:
            return jsonify({'success': False, 'error': 'Report not found'}), 404
        
        incident_id = report['incident_id']
        cur.execute("DELETE FROM outage_reports WHERE report_id = %s", (report_id,))
        cur.execute("UPDATE outage_incidents SET report_count = report_count - 1, updated_at = CURRENT_TIMESTAMP WHERE incident_id = %s", (incident_id,))
        cur.execute("SELECT report_count FROM outage_incidents WHERE incident_id = %s", (incident_id,))
        updated_incident = cur.fetchone()
        
        if updated_incident and updated_incident['report_count'] <= 0:
            cur.execute("DELETE FROM outage_incidents WHERE incident_id = %s", (incident_id,))
        
        conn.commit()
        return jsonify({'success': True, 'message': 'Report removed successfully'})
        
    except Exception as e:
        conn.rollback()
        logger.exception("Remove report error")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        release_db_connection(conn)

try:
    from realtime_listener import start_realtime_listener
    import threading
    listener_thread = threading.Thread(target=start_realtime_listener, daemon=True)
    listener_thread.start()
    logger.info("✅ Realtime listener started")
except ImportError:
    logger.warning("⚠️ realtime_listener module not found — skipping")
except Exception as e:
    logger.warning(f"⚠️ Realtime listener failed to start: {e}")

initialize_timestamp_column()
initialize_tracking_columns()
initialize_spam_logs_table()
initialize_user_activity_table()
initialize_feature_flags_table()
initialize_spam_control_tables()
initialize_performance_indexes()

# ============================================
# IDLE-USER NUDGE SCHEDULER
# ============================================
from apscheduler.schedulers.background import BackgroundScheduler

IDLE_THRESHOLD_MINUTES = 10

def check_idle_users():
    conn = get_local_conn()
    if not conn:
        return
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT sender_id FROM user_activity
            WHERE nudged = FALSE
              AND last_message_at <= TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) - INTERVAL '%s minutes'
              AND last_message_at >= TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP) - INTERVAL '24 hours'
        """ % IDLE_THRESHOLD_MINUTES)
        idle_users = [row[0] for row in cur.fetchall()]

        fb_token = os.getenv('FACEBOOK_PAGE_ACCESS_TOKEN', '')
        for sender_id in idle_users:
            if fb_token:
                _send_idle_nudge(sender_id, fb_token)
            cur.execute("UPDATE user_activity SET nudged = TRUE WHERE sender_id = %s", (sender_id,))
        conn.commit()
    except Exception:
        logger.exception("check_idle_users failed")
        try: conn.rollback()
        except Exception: pass
    finally:
        if cur: cur.close()
        release_local_conn(conn)

AWAITING_CONFIRMATION_TIMEOUT_HOURS = 24

def check_awaiting_confirmation_timeout():
    """
    Any ticket sitting in 'Awaiting Confirmation' for >= 24 hours with
    no consumer reply (they never tapped Yes/No) gets auto-closed so it
    doesn't linger forever in the dashboard as a false 'in progress'.
    """
    conn = get_local_conn()
    if not conn:
        return
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "ALTER TABLE agent_queue ADD COLUMN IF NOT EXISTS resolution_note TEXT"
        )
        cur.execute("""
            SELECT id, user_id, full_name
            FROM agent_queue
            WHERE status = 'Awaiting Confirmation'
              AND served_at <= TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP)
                                - INTERVAL '%s hours'
        """ % AWAITING_CONFIRMATION_TIMEOUT_HOURS)
        stale = cur.fetchall()

        if not stale:
            return

        ids = [r['id'] for r in stale]
        cur.execute("""
            UPDATE agent_queue
               SET status          = 'Auto-Closed',
                   resolution_note = 'No customer response'
             WHERE id = ANY(%s)
        """, (ids,))
        conn.commit()

        logger.info(f"[AutoClose] Auto-closed {len(ids)} stale ticket(s): {ids}")

        fb_token = os.getenv('FACEBOOK_PAGE_ACCESS_TOKEN', '')
        for r in stale:
            try:
                socketio.emit('queue_updated', {
                    'action':    'auto_closed',
                    'queue_id':  r['id'],
                    'timestamp': isoformat_safe(datetime.now(timezone.utc)),
                })
            except Exception:
                pass
            if fb_token and r.get('user_id'):
                _send_autoclose_message(r['user_id'], fb_token)

    except Exception:
        logger.exception("check_awaiting_confirmation_timeout failed")
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        if cur:
            cur.close()
        release_local_conn(conn)


def _send_autoclose_message(sender_id, fb_token):
    """Courteous closing note + resume the bot so the consumer isn't stuck."""
    import requests as _r, json as _json
    payload = {
        "recipient": {"id": sender_id},
        "message": {
            "text": (
                "⌛ We didn't hear back from you, so we've closed this "
                "conversation for now.\n\n"
                "If you still need help, just send us a message anytime "
                "and we'll be glad to assist. 🙏"
            )
        },
        "messaging_type": "MESSAGE_TAG",
        "tag": "CONFIRMED_EVENT_UPDATE",
    }
    try:
        _r.post(
            f"https://graph.facebook.com/v19.0/me/messages?access_token={fb_token}",
            headers={"Content-Type": "application/json"},
            data=_json.dumps(payload),
            timeout=8,
        )
    except Exception:
        logger.exception(f"Auto-close FB message failed for {sender_id}")
    try:
        _force_unpause_tracker(sender_id)
    except Exception:
        pass

def _send_idle_nudge(sender_id, fb_token):
    payload = {
        "recipient": {"id": sender_id},
        "message": {
            "text": "👋 We haven't heard from you in a while. Is there anything else I can help you with?",
            "quick_replies": [
                {"content_type": "text", "title": "🏠 Main Menu", "payload": "/greet"},
                {"content_type": "text", "title": "💬 Talk to an Agent", "payload": "/talk_to_agent"},
            ],
        },
    }
    try:
        requests.post(
            f"https://graph.facebook.com/v19.0/me/messages?access_token={fb_token}",
            json=payload, timeout=5,
        )
    except Exception:
        logger.exception(f"Idle nudge send failed for {sender_id}")

_idle_scheduler = BackgroundScheduler()
_idle_scheduler.add_job(check_idle_users, "interval", minutes=1)
_idle_scheduler.add_job(check_awaiting_confirmation_timeout, "interval", minutes=30)
_idle_scheduler.start()
# ============================================
# STARTUP
# ============================================
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    logger.info("Starting ILECO-1 Power Outage System")
    try:
        socketio.run(
            app,
            host='0.0.0.0',
            port=port,
            debug=False,
            allow_unsafe_werkzeug=True,
            use_reloader=False,
            log_output=False
        )
    except Exception:
        logger.exception("Failed to start server")

logger.info("=" * 80)
logger.info("🔍 REGISTERED FLASK ROUTES:")
logger.info("=" * 80)
for rule in app.url_map.iter_rules():
    methods = ','.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
    logger.info(f"{rule.endpoint:50s} {methods:20s} {rule.rule}")
logger.info("=" * 80)