"""
realtime_listener.py

Background daemon thread that opens a dedicated PostgreSQL connection
to the LOCAL database and listens on NOTIFY channels.

When a notification arrives it emits a SocketIO event so every
connected browser tab refreshes automatically.

Channels listened:
    new_outage_report   → emits 'new_report'   to all clients
    new_meter_concern   → emits 'meter_concern_updated'
    incident_updated    → emits 'incident_updated'

Usage (called once from app.py):
    from realtime_listener import start_realtime_listener
    threading.Thread(target=start_realtime_listener, daemon=True).start()
"""
import json
import logging
import select
import time

import psycopg2
import psycopg2.extensions

logger = logging.getLogger(__name__)

CHANNELS = ["new_outage_report", "new_meter_concern", "incident_updated"]
RECONNECT_DELAY = 10  # seconds between reconnect attempts


def _get_listen_conn():
    """
    Open a raw psycopg2 connection (NOT from the pool) for LISTEN.
    LISTEN requires autocommit mode and a long-lived connection.
    Pool connections are not suitable.
    """
    import os
    return psycopg2.connect(
        host=os.getenv("LOCAL_DB_HOST", "localhost"),
        port=int(os.getenv("LOCAL_DB_PORT", 5432)),
        database=os.getenv("LOCAL_DB_NAME", "ileco1_user"),
        user=os.getenv("LOCAL_DB_USER", "postgres"),
        password=os.getenv("LOCAL_DB_PASSWORD", ""),
        connect_timeout=10,
    )


def _emit(channel: str, payload: dict):
    """Fire-and-forget SocketIO emit. Swallows errors so listener never dies."""
    try:
        from app import socketio
        event_map = {
            "new_outage_report": "new_report",
            "new_meter_concern": "meter_concern_updated",
            "incident_updated":  "incident_updated",
        }
        event = event_map.get(channel, channel)
        socketio.emit(event, payload)
        logger.debug("SocketIO emit: %s %s", event, payload)
    except Exception as exc:
        logger.warning("SocketIO emit failed (%s): %s", channel, exc)


def start_realtime_listener():
    """Entry point — runs forever in a daemon thread."""
    logger.info("Realtime listener starting (channels: %s)", CHANNELS)

    while True:
        conn = None
        try:
            conn = _get_listen_conn()
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            cur = conn.cursor()
            for ch in CHANNELS:
                cur.execute(f"LISTEN {ch};")
            cur.close()
            logger.info("Realtime listener connected and listening")

            while True:
                # Block up to 30 s waiting for a notification
                if select.select([conn], [], [], 30)[0]:
                    conn.poll()
                    while conn.notifies:
                        notify = conn.notifies.pop(0)
                        logger.info("NOTIFY %s: %s", notify.channel, notify.payload[:120])
                        try:
                            payload = json.loads(notify.payload) if notify.payload else {}
                        except json.JSONDecodeError:
                            payload = {"raw": notify.payload}
                        _emit(notify.channel, payload)
                else:
                    # Keepalive ping so the connection doesn't time out
                    try:
                        cur = conn.cursor()
                        cur.execute("SELECT 1")
                        cur.close()
                    except Exception:
                        raise  # triggers reconnect

        except Exception as exc:
            logger.warning("Realtime listener disconnected: %s — reconnecting in %ds",
                           exc, RECONNECT_DELAY)
        finally:
            try:
                if conn:
                    conn.close()
            except Exception:
                pass

        time.sleep(RECONNECT_DELAY)