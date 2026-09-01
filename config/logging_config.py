"""
config/logging_config.py

Call configure_logging(app) from the application factory.
Writes INFO to logs/app.log and ERROR to logs/errors.log.
In production (Railway) stdout is also captured by the platform.
"""
import logging
import os
from logging.handlers import RotatingFileHandler


def configure_logging(app):
    os.makedirs("logs", exist_ok=True)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── File: all INFO+ ───────────────────────────────────────────────────────
    fh = RotatingFileHandler(
        "logs/app.log", maxBytes=10_485_760, backupCount=10, encoding="utf-8"
    )
    fh.setLevel(logging.INFO)
    fh.setFormatter(fmt)

    # ── File: ERROR+ only ─────────────────────────────────────────────────────
    eh = RotatingFileHandler(
        "logs/errors.log", maxBytes=10_485_760, backupCount=5, encoding="utf-8"
    )
    eh.setLevel(logging.ERROR)
    eh.setFormatter(fmt)

    # ── Stdout (Railway captures this) ────────────────────────────────────────
    sh = logging.StreamHandler()
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)

    app.logger.handlers.clear()
    app.logger.addHandler(fh)
    app.logger.addHandler(eh)
    app.logger.addHandler(sh)
    app.logger.setLevel(logging.INFO)

    # Apply same config to root logger so psycopg2 / socketio warnings appear
    root = logging.getLogger()
    root.setLevel(logging.WARNING)
    root.addHandler(sh)

    # Silence noisy libraries
    logging.getLogger("engineio").setLevel(logging.ERROR)
    logging.getLogger("socketio").setLevel(logging.ERROR)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)