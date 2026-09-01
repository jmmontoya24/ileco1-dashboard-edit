"""
config/settings.py

Centralised configuration.  Import the active config with:

    from config.settings import get_config
    config = get_config()

Railway sets FLASK_ENV=production automatically via the railway.toml /
service environment variables.
"""
import os
import secrets
from datetime import timedelta


class BaseConfig:
    # ── Security ──────────────────────────────────────────────────────────────
    SECRET_KEY: str = os.getenv("SECRET_KEY", secrets.token_hex(32))
    WTF_CSRF_CHECK_DEFAULT: bool = False   # CSRF managed per-route
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    PERMANENT_SESSION_LIFETIME: timedelta = timedelta(hours=24)

    # ── Uploads ───────────────────────────────────────────────────────────────
    UPLOAD_FOLDER: str = os.getenv("UPLOAD_FOLDER", "uploads/meter_concerns")
    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024   # 16 MB
    ALLOWED_EXTENSIONS: set = {"png", "jpg", "jpeg", "gif", "mp4", "mov", "avi", "webp"}

    # ── Rate limiting ─────────────────────────────────────────────────────────
    RATELIMIT_STORAGE_URI: str = os.getenv("REDIS_URL", "memory://")
    RATELIMIT_DEFAULT: str = "1000 per day;300 per hour"

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS_ORIGINS: list = [
        o.strip()
        for o in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5000,http://127.0.0.1:5000",
        ).split(",")
        if o.strip()
    ]

    # ── Database — LOCAL (auth + queue) ───────────────────────────────────────
    LOCAL_DB_HOST: str = os.getenv("LOCAL_DB_HOST", "localhost")
    LOCAL_DB_PORT: int = int(os.getenv("LOCAL_DB_PORT", 5432))
    LOCAL_DB_NAME: str = os.getenv("LOCAL_DB_NAME", "ileco1_user")
    LOCAL_DB_USER: str = os.getenv("LOCAL_DB_USER", "postgres")
    LOCAL_DB_PASSWORD: str = os.getenv("LOCAL_DB_PASSWORD", "")

    # ── Database — CLOUD (Supabase, operational data) ─────────────────────────
    CLOUD_DB_HOST: str = os.getenv("CLOUD_DB_HOST", "")
    CLOUD_DB_PORT: int = int(os.getenv("CLOUD_DB_PORT", 5432))
    CLOUD_DB_NAME: str = os.getenv("CLOUD_DB_NAME", "postgres")
    CLOUD_DB_USER: str = os.getenv("CLOUD_DB_USER", "")
    CLOUD_DB_PASSWORD: str = os.getenv("CLOUD_DB_PASSWORD", "")

    # ── Database — JOBLIST (OMMS, write-only) ─────────────────────────────────
    JOBLIST_DB_HOST: str = os.getenv("JOBLIST_DB_HOST", "172.17.100.6")
    JOBLIST_DB_PORT: int = int(os.getenv("JOBLIST_DB_PORT", 5432))
    JOBLIST_DB_NAME: str = os.getenv("JOBLIST_DB_NAME", "joblist")
    JOBLIST_DB_USER: str = os.getenv("JOBLIST_DB_USER", "postgres")
    JOBLIST_DB_PASSWORD: str = os.getenv("JOBLIST_DB_PASSWORD", "")

    # ── SocketIO ──────────────────────────────────────────────────────────────
    SOCKETIO_ASYNC_MODE: str = "eventlet"
    SOCKETIO_PING_TIMEOUT: int = 60
    SOCKETIO_PING_INTERVAL: int = 25
    SOCKETIO_TRANSPORTS: list = ["polling", "websocket"]

    # ── Feeder table constants ────────────────────────────────────────────────
    FEEDER_TABLE: str = '"ILECO_1_COVERAGE_AREA_FEEDERS_FINALoutput"'
    FEEDER_NAME_COL: str = "feeder_name"
    EXCLUDED_FEEDER: str = "Feeder 12A"


class DevelopmentConfig(BaseConfig):
    DEBUG: bool = True
    FLASK_ENV: str = "development"
    SESSION_COOKIE_SECURE: bool = False
    TESTING: bool = False


class ProductionConfig(BaseConfig):
    DEBUG: bool = False
    FLASK_ENV: str = "production"
    SESSION_COOKIE_SECURE: bool = True   # HTTPS only on Railway
    TESTING: bool = False

    # Tighter pool limits in production
    LOCAL_DB_MIN_CONN: int = 2
    LOCAL_DB_MAX_CONN: int = 8
    CLOUD_DB_MIN_CONN: int = 2
    CLOUD_DB_MAX_CONN: int = 15


class TestingConfig(BaseConfig):
    TESTING: bool = True
    DEBUG: bool = True
    WTF_CSRF_ENABLED: bool = False
    SECRET_KEY: str = "test-secret-key"
    RATELIMIT_STORAGE_URI: str = "memory://"


_CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config():
    env = os.getenv("FLASK_ENV", "development").lower()
    return _CONFIG_MAP.get(env, DevelopmentConfig)()