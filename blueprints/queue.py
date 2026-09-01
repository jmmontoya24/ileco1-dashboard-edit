"""
blueprints/queue.py

Routes:
    GET    /agent_queue
    GET    /api/agent_queue
    POST   /api/agent_queue/<id>/serve
    DELETE /api/agent_queue/<id>/remove
    GET    /api/agent_queue/statistics
"""
import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request, session
from psycopg2.extras import RealDictCursor

from blueprints.utils import login_required, isoformat_safe
from db.pool import get_local_conn, release_local_conn

logger = logging.getLogger(__name__)
queue_bp = Blueprint("queue", __name__)


@queue_bp.route("/agent_queue")
@login_required
def agent_queue_page():
    return render_template("agent_queue.html")


@queue_bp.route("/api/agent_queue")
@login_required
def get_queue():
    conn = get_local_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        status   = request.args.get("status", "all")
        priority = request.args.get("priority", "all")
        date_f   = request.args.get("date")

        where, params = ["1=1"], []
        if status.lower() != "all":
            where.append("status=%s"); params.append(status)
        if priority.lower() != "all":
            where.append("priority=%s"); params.append(priority)
        if date_f:
            col = "served_at" if status == "Resolved" else "timestamp"
            where.append(f"DATE({col} AT TIME ZONE 'Asia/Manila')=%s")
            params.append(date_f)

        order = "served_at DESC" if status == "Resolved" else "timestamp DESC"
        cur   = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            f"SELECT id, user_id, full_name, concern, contact_number, priority, "
            f"timestamp, status, served_at, served_by "
            f"FROM agent_queue WHERE {' AND '.join(where)} ORDER BY {order}",
            params if params else None,
        )
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            d["timestamp"] = isoformat_safe(d.get("timestamp"))
            d["served_at"] = isoformat_safe(d.get("served_at"))
            rows.append(d)

        return jsonify({"success": True, "data": rows, "count": len(rows)})
    except Exception:
        logger.exception("get_queue error")
        return jsonify({"success": False, "error": "Failed"}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@queue_bp.route("/api/agent_queue/<int:queue_id>/serve", methods=["POST", "OPTIONS"])
@login_required
def serve_customer(queue_id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    body       = request.get_json(silent=True) or {}
    served_by  = (body.get("served_by") or "").strip()
    if not served_by:
        served_by = session.get("full_name") or session.get("username", "Agent")

    conn = get_local_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, full_name, status, user_id FROM agent_queue WHERE id=%s", (queue_id,))
        customer = cur.fetchone()
        if not customer:
            return jsonify({"success": False, "error": "Customer not found"}), 404
        if customer["status"] == "Resolved":
            return jsonify({"success": False, "error": "Already served",
                            "already_served": True}), 400

        cur.execute("""
            UPDATE agent_queue
            SET status='Resolved',
                served_at=TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP),
                served_by=%s
            WHERE id=%s
            RETURNING id, full_name, status, served_at, served_by
        """, (served_by, queue_id))
        result = cur.fetchone()
        conn.commit()

        try:
            from app import socketio
            socketio.emit("queue_updated", {
                "queue_id":   queue_id,
                "new_status": "Resolved",
                "served_by":  result["served_by"],
                "served_at":  isoformat_safe(result["served_at"]),
            })
        except Exception:
            pass

        return jsonify({
            "success": True,
            "message": f"{result['full_name']} served by {result['served_by']}",
            "data": {
                "id":        result["id"],
                "full_name": result["full_name"],
                "status":    result["status"],
                "served_at": isoformat_safe(result["served_at"]),
                "served_by": result["served_by"],
            },
        })
    except Exception:
        if conn: conn.rollback()
        logger.exception("serve_customer error")
        return jsonify({"success": False, "error": "Serve failed"}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@queue_bp.route("/api/agent_queue/<int:queue_id>/remove", methods=["DELETE"])
@login_required
def remove_queue_record(queue_id):
    conn = get_local_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, full_name, status FROM agent_queue WHERE id=%s", (queue_id,))
        rec = cur.fetchone()
        if not rec:
            return jsonify({"success": False, "error": "Not found"}), 404
        if rec["status"] == "Pending":
            return jsonify({"success": False, "error": "Cannot remove a Pending customer"}), 400
        cur.execute("DELETE FROM agent_queue WHERE id=%s", (queue_id,))
        conn.commit()
        return jsonify({"success": True, "message": f"{rec['full_name']} removed"})
    except Exception:
        if conn: conn.rollback()
        logger.exception("remove_queue_record error")
        return jsonify({"success": False, "error": "Remove failed"}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)


@queue_bp.route("/api/agent_queue/statistics")
@login_required
def queue_statistics():
    conn = get_local_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT COUNT(*) AS total FROM agent_queue")
        total = cur.fetchone()["total"]
        cur.execute("SELECT status, COUNT(*) AS count FROM agent_queue GROUP BY status")
        by_status = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT priority, COUNT(*) AS count FROM agent_queue WHERE status='Pending' GROUP BY priority")
        by_priority = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT COUNT(*) AS count FROM agent_queue WHERE status='Resolved' AND DATE(timestamp)=CURRENT_DATE")
        served_today = cur.fetchone()["count"]
        return jsonify({"success": True, "data": {
            "total": total, "by_status": by_status,
            "by_priority": by_priority, "served_today": served_today,
        }})
    except Exception:
        logger.exception("queue_statistics error")
        return jsonify({"success": False, "error": "Failed"}), 500
    finally:
        if cur: cur.close()
        release_local_conn(conn)