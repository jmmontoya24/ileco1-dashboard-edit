"""
Spam DETECTION ONLY — no automatic blocking/muting.
Logs flood/repeat patterns to spam_logs so a human can review
the dashboard and manually block via the Facebook Page inbox.
"""

import os
import time
import logging

logger = logging.getLogger("ileco_spam_detector")

MAX_MESSAGES_PER_WINDOW = int(os.getenv("SPAM_MAX_MSGS_PER_WINDOW", "8"))
VELOCITY_WINDOW_SECONDS = int(os.getenv("SPAM_VELOCITY_WINDOW", "30"))

MAX_REPEATED_TEXT      = int(os.getenv("SPAM_MAX_REPEATED_TEXT", "4"))
REPEATED_TEXT_WINDOW    = int(os.getenv("SPAM_REPEATED_TEXT_WINDOW", "60"))

_redis_client = None
_memory_store = {}  # fallback only — fine for detection-only, low stakes


def init_spam_detector(redis_client=None):
    global _redis_client
    _redis_client = redis_client
    if _redis_client is None:
        logger.warning(
            "⚠️ Spam detector running without Redis — counters are "
            "per-process only. Fine for single-worker setups."
        )


def _now():
    return time.time()


def _incr_with_ttl(key: str, ttl_seconds: int) -> int:
    if _redis_client:
        try:
            pipe = _redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, ttl_seconds)
            count, _ = pipe.execute()
            return int(count)
        except Exception as e:
            logger.warning(f"Redis incr failed for {key}: {e}")

    entry = _memory_store.get(key, {"count": 0, "expires": _now() + ttl_seconds})
    if _now() > entry["expires"]:
        entry = {"count": 0, "expires": _now() + ttl_seconds}
    entry["count"] += 1
    _memory_store[key] = entry
    return entry["count"]


def evaluate_message(sender_id: str, text: str) -> dict:
    """
    DETECTION ONLY. Never blocks. Returns what was detected so the
    caller can decide whether to log it — the message should always
    still be forwarded to Rasa normally.

    Returns:
        {
            "flagged": bool,
            "reasons": ["flood", "repeat"],   # empty list if clean
            "message_count_in_window": int,
            "repeat_count": int,
        }
    """
    reasons = []

    msg_count = _incr_with_ttl(f"spamdet:velocity:{sender_id}", VELOCITY_WINDOW_SECONDS)
    if msg_count > MAX_MESSAGES_PER_WINDOW:
        reasons.append("flood")

    repeat_count = 0
    if text:
        normalized = text.strip().lower()[:200]
        text_hash = str(abs(hash(normalized)) % (10 ** 12))
        repeat_count = _incr_with_ttl(
            f"spamdet:repeat:{sender_id}:{text_hash}", REPEATED_TEXT_WINDOW
        )
        if repeat_count > MAX_REPEATED_TEXT:
            reasons.append("repeat")

    return {
        "flagged": len(reasons) > 0,
        "reasons": reasons,
        "message_count_in_window": msg_count,
        "repeat_count": repeat_count,
    }


def log_spam_event(sender_id: str, reasons: list, conn, message_text: str = ""):
    """Persist a flagged event to spam_logs for dashboard review."""
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO spam_logs (sender_id, event_type, message_sample, created_at)
            VALUES (%s, %s, %s, TIMEZONE('Asia/Manila', CURRENT_TIMESTAMP))
        """, (sender_id, ",".join(reasons), (message_text or "")[:200]))
        conn.commit()
        cur.close()
    except Exception as e:
        logger.warning(f"Failed to log spam event: {e}")
        try:
            conn.rollback()
        except Exception:
            pass