"""
db/pool.py

Manages three PostgreSQL connection pools:
  - local_pool   → local Postgres (users, agent_queue)
  - cloud_pool   → Supabase PostGIS (incidents, reports, feeders, meters)
  - joblist_pool → OMMS server 172.17.100.6 (write-only, public.converted)

Usage:
    from db.pool import get_local_conn, release_local_conn
    from db.pool import get_cloud_conn, release_cloud_conn
    from db.pool import get_joblist_conn, release_joblist_conn

Context-manager pattern (preferred):
    with cloud_conn() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        ...
"""
import logging
import socket
import time as _time
from contextlib import contextmanager

import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# ── Module-level pool handles ─────────────────────────────────────────────────
_local_pool = None
_cloud_pool = None
_joblist_pool = None

# ── Retry throttle (don't hammer a dead server) ───────────────────────────────
_cloud_last_attempt: float = 0.0
_CLOUD_RETRY_INTERVAL: float = 60.0

_joblist_last_attempt: float = 0.0
_JOBLIST_RETRY_INTERVAL: float = 60.0


# ─────────────────────────────────────────────────────────────────────────────
# INITIALISATION
# ─────────────────────────────────────────────────────────────────────────────

def init_local_pool(cfg) -> bool:
    global _local_pool
    if _local_pool is not None:
        return True
    try:
        _local_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=getattr(cfg, "LOCAL_DB_MIN_CONN", 1),
            maxconn=getattr(cfg, "LOCAL_DB_MAX_CONN", 5),
            host=cfg.LOCAL_DB_HOST,
            port=cfg.LOCAL_DB_PORT,
            database=cfg.LOCAL_DB_NAME,
            user=cfg.LOCAL_DB_USER,
            password=cfg.LOCAL_DB_PASSWORD,
            connect_timeout=5,
        )
        logger.info("✅ Local DB pool ready (%s/%s)", cfg.LOCAL_DB_HOST, cfg.LOCAL_DB_NAME)
        return True
    except Exception:
        logger.exception("❌ Local DB pool failed")
        _local_pool = None
        return False


def init_cloud_pool(cfg) -> bool:
    global _cloud_pool, _cloud_last_attempt
    if _cloud_pool is not None:
        return True
    now = _time.monotonic()
    if now - _cloud_last_attempt < _CLOUD_RETRY_INTERVAL:
        return False
    _cloud_last_attempt = now
    try:
        # Fail fast if DNS is broken
        socket.getaddrinfo(cfg.CLOUD_DB_HOST, None)
        _cloud_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=getattr(cfg, "CLOUD_DB_MIN_CONN", 2),
            maxconn=getattr(cfg, "CLOUD_DB_MAX_CONN", 10),
            host=cfg.CLOUD_DB_HOST,
            port=cfg.CLOUD_DB_PORT,
            database=cfg.CLOUD_DB_NAME,
            user=cfg.CLOUD_DB_USER,
            password=cfg.CLOUD_DB_PASSWORD,
            connect_timeout=10,
            sslmode="require",
            keepalives=1,
            keepalives_idle=30,
            keepalives_interval=10,
            keepalives_count=5,
        )
        logger.info("✅ Cloud DB pool ready (%s/%s)", cfg.CLOUD_DB_HOST, cfg.CLOUD_DB_NAME)
        return True
    except Exception:
        logger.exception("❌ Cloud DB pool failed")
        _cloud_pool = None
        _cloud_last_attempt = now   # reset so retry kicks in after interval
        return False


def init_joblist_pool(cfg) -> bool:
    global _joblist_pool, _joblist_last_attempt
    if _joblist_pool is not None:
        return True
    now = _time.monotonic()
    if now - _joblist_last_attempt < _JOBLIST_RETRY_INTERVAL:
        return False
    _joblist_last_attempt = now
    try:
        _joblist_pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=1,
            maxconn=5,
            host=cfg.JOBLIST_DB_HOST,
            port=cfg.JOBLIST_DB_PORT,
            database=cfg.JOBLIST_DB_NAME,
            user=cfg.JOBLIST_DB_USER,
            password=cfg.JOBLIST_DB_PASSWORD,
            connect_timeout=3,
            options="-c search_path=public",
        )
        logger.info("✅ Joblist DB pool ready (%s/%s)", cfg.JOBLIST_DB_HOST, cfg.JOBLIST_DB_NAME)
        return True
    except Exception:
        logger.exception("❌ Joblist DB pool failed (OMMS assign will not work)")
        _joblist_pool = None
        return False

def init_all_pools(cfg) -> None:
    """Call once from the application factory."""
    import threading
    init_local_pool(cfg)
    init_cloud_pool(cfg)
    t = threading.Thread(target=init_joblist_pool, args=(cfg,), daemon=True)
    t.start()

# ─────────────────────────────────────────────────────────────────────────────
# GETTERS / RELEASERS
# ─────────────────────────────────────────────────────────────────────────────

def _ping(conn) -> bool:
    """Return True if conn is alive."""
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return True
    except Exception:
        return False


def get_local_conn():
    global _local_pool
    if _local_pool is None:
        from config.settings import get_config
        init_local_pool(get_config())
    try:
        return _local_pool.getconn() if _local_pool else None
    except Exception:
        logger.exception("Error getting local DB connection")
        return None


def release_local_conn(conn) -> None:
    global _local_pool
    try:
        if conn and _local_pool:
            _local_pool.putconn(conn)
    except Exception:
        logger.exception("Error releasing local connection")


def get_cloud_conn():
    global _cloud_pool, _cloud_last_attempt
    if _cloud_pool is not None:
        try:
            conn = _cloud_pool.getconn()
            if _ping(conn):
                return conn
            # Stale connection — discard pool and retry once
            logger.warning("Stale cloud connection detected, resetting pool")
            try:
                _cloud_pool.closeall()
            except Exception:
                pass
            _cloud_pool = None
            _cloud_last_attempt = 0.0
        except Exception:
            logger.exception("Cloud pool getconn failed, resetting")
            try:
                _cloud_pool.closeall()
            except Exception:
                pass
            _cloud_pool = None
            _cloud_last_attempt = 0.0

    from config.settings import get_config
    if init_cloud_pool(get_config()):
        try:
            return _cloud_pool.getconn()
        except Exception:
            logger.exception("Cloud conn failed after re-init")
    return None


def release_cloud_conn(conn) -> None:
    global _cloud_pool
    try:
        if conn and _cloud_pool:
            _cloud_pool.putconn(conn)
    except Exception:
        logger.exception("Error releasing cloud connection")


def get_joblist_conn():
    global _joblist_pool
    if _joblist_pool is None:
        from config.settings import get_config
        init_joblist_pool(get_config())
    try:
        return _joblist_pool.getconn() if _joblist_pool else None
    except Exception:
        logger.exception("Error getting joblist DB connection")
        return None


def release_joblist_conn(conn) -> None:
    global _joblist_pool
    try:
        if conn and _joblist_pool:
            _joblist_pool.putconn(conn)
    except Exception:
        logger.exception("Error releasing joblist connection")


# ─────────────────────────────────────────────────────────────────────────────
# CONTEXT MANAGERS  (preferred usage pattern)
# ─────────────────────────────────────────────────────────────────────────────

@contextmanager
def local_conn():
    conn = get_local_conn()
    if conn is None:
        raise RuntimeError("Local DB connection unavailable")
    try:
        yield conn
    finally:
        release_local_conn(conn)


@contextmanager
def cloud_conn():
    conn = get_cloud_conn()
    if conn is None:
        raise RuntimeError("Cloud DB connection unavailable")
    try:
        yield conn
    finally:
        release_cloud_conn(conn)


@contextmanager
def joblist_conn():
    conn = get_joblist_conn()
    if conn is None:
        raise RuntimeError("Joblist DB connection unavailable")
    try:
        yield conn
    finally:
        release_joblist_conn(conn)