"""
blueprints/dashboard.py

Routes:
    GET  /dashboard
    GET  /api/incidents
    GET  /api/incident/<id>
    GET  /api/dashboard_stats
    GET  /api/map_reports
    GET  /api/recent_outages
    GET  /api/badge_counts
    POST /api/update_incident_status/<id>
    POST /api/update_report_status/<id>
    POST /api/incident/<id>/remarks
    DELETE /api/incident/<id>/remove
    DELETE /api/report/<id>/remove
"""
import logging
import uuid
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request, session
from psycopg2.extras import RealDictCursor

from blueprints.utils import login_required, isoformat_safe
from db.pool import (
    get_cloud_conn, release_cloud_conn,
    get_local_conn, release_local_conn,
)

logger = logging.getLogger(__name__)
dashboard_bp = Blueprint("dashboard", __name__)

# ── Constants pulled from app config at request time ─────────────────────────
def _feeder_table():
    from flask import current_app
    return current_app.config.get("FEEDER_TABLE", '"ILECO_1_COVERAGE_AREA_FEEDERS_FINALoutput"')

def _feeder_col():
    from flask import current_app
    return current_app.config.get("FEEDER_NAME_COL", "feeder_name")

def _excluded():
    from flask import current_app
    return current_app.config.get("EXCLUDED_FEEDER", "Feeder 12A")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/")
@login_required
def root():
    from flask import redirect, url_for
    return redirect(url_for("dashboard.index"))


@dashboard_bp.route("/dashboard")
@login_required
def index():
    return render_template("dashboard.html")


# ─────────────────────────────────────────────────────────────────────────────
# API — INCIDENTS
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/api/incidents")
@login_required
def get_incidents():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    FT  = _feeder_table()
    FC  = _feeder_col()
    EXC = _excluded()
    cur = None
    try:
        status = request.args.get("status", "all").lower()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        query = f"""
            SELECT
                i.incident_id,
                i.incident_type,
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
                ST_Y(i.geom::geometry) AS lat,
                ST_X(i.geom::geometry) AS lng,
                f.{FC} AS feeder_name,
                f.status AS feeder_status,
                f.is_active AS feeder_is_active,
                (SELECT MIN(created_at) FROM outage_reports
                 WHERE incident_id = i.incident_id) AS earliest_report_timestamp,
                (SELECT incident_time FROM outage_reports
                 WHERE incident_id = i.incident_id
                 ORDER BY created_at LIMIT 1) AS incident_time
            FROM outage_incidents i
            LEFT JOIN {FT} f
                ON ST_Contains(f.geom::geometry, i.geom::geometry)
                AND f.{FC} != %s
            WHERE 1=1
        """
        params = [EXC]

        if status != "all":
            query += " AND UPPER(i.status) = UPPER(%s)"
            params.append(status)

        query += " ORDER BY i.first_report_time DESC"
        cur.execute(query, params)

        result = []
        for row in cur.fetchall():
            r = dict(row)
            for k in ("first_report_time","last_report_time","assigned_at",
                      "restored_at","created_at","updated_at","earliest_report_timestamp"):
                r[k] = isoformat_safe(r.get(k))
            if r.get("incident_time"):
                r["incident_time"] = str(r["incident_time"])
            r["lat"] = float(r["lat"]) if r.get("lat") is not None else None
            r["lng"] = float(r["lng"]) if r.get("lng") is not None else None
            result.append(r)

        return jsonify({"success": True, "incidents": result, "count": len(result)})

    except Exception:
        logger.exception("get_incidents error")
        return jsonify({"success": False, "error": "Failed to fetch incidents"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@dashboard_bp.route("/api/incident/<int:incident_id>")
@login_required
def get_incident_detail(incident_id):
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT incident_id, incident_type, barangay, town, report_count,
                   confidence_level, status, priority, first_report_time,
                   last_report_time, job_order_id, assigned_at, restored_at,
                   resolved_at, assigned_by, restored_by, remarks, created_at,
                   ST_Y(geom::geometry) AS lat, ST_X(geom::geometry) AS lng
            FROM outage_incidents WHERE incident_id = %s
        """, (incident_id,))
        inc = cur.fetchone()
        if not inc:
            return jsonify({"success": False, "error": "Incident not found"}), 404

        cur.execute("""
            SELECT report_id, full_name, contact_number, email, account_number,
                   address, barangay, town, incident_type, affected_area,
                   incident_time, duration, details, landmark,
                   timestamp, source, status, priority,
                   status_changed_at, assigned_at, restored_at,
                   ST_Y(geom::geometry) AS lat, ST_X(geom::geometry) AS lng
            FROM outage_reports
            WHERE incident_id = %s ORDER BY timestamp ASC
        """, (incident_id,))
        reports = cur.fetchall()

        def _fmt(row):
            r = dict(row)
            for k, v in r.items():
                if hasattr(v, "isoformat"):
                    r[k] = isoformat_safe(v)
                elif hasattr(v, "strftime"):  # time object
                    r[k] = str(v)
            return r

        inc_d = _fmt(inc)
        reps  = [_fmt(r) for r in reports]
        return jsonify({"success": True, "data": {"incident": inc_d, "reports": reps}})

    except Exception:
        logger.exception("get_incident_detail error")
        return jsonify({"success": False, "error": "Failed to fetch incident details"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@dashboard_bp.route("/api/dashboard_stats")
@login_required
def dashboard_stats():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM outage_incidents WHERE status != 'RESTORED'")
        active = cur.fetchone()[0]
        cur.execute("SELECT COALESCE(SUM(report_count),0) FROM outage_incidents WHERE status != 'RESTORED'")
        affected = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM outage_incidents WHERE priority='CRITICAL' AND status!='RESTORED'")
        critical = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM outage_reports WHERE DATE(created_at AT TIME ZONE 'Asia/Manila')=CURRENT_DATE")
        today = cur.fetchone()[0]
        return jsonify({"success": True, "stats": {
            "active_outages": active,
            "affected_consumers": affected,
            "critical_incidents": critical,
            "reports_today": today,
        }})
    except Exception:
        logger.exception("dashboard_stats error")
        return jsonify({"success": False, "error": "Stats unavailable"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@dashboard_bp.route("/api/map_reports")
@login_required
def map_reports():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT report_id AS id, full_name, contact_number, address,
                   details, priority, created_at, incident_type, status,
                   ST_X(geom::geometry) AS lng, ST_Y(geom::geometry) AS lat,
                   barangay, town
            FROM outage_reports
            WHERE geom IS NOT NULL AND status != 'RESTORED'
            ORDER BY created_at DESC
        """)
        result = []
        for row in cur.fetchall():
            r = dict(row)
            r["timestamp"] = isoformat_safe(r.pop("created_at", None))
            r["lat"] = float(r["lat"]) if r.get("lat") is not None else None
            r["lng"] = float(r["lng"]) if r.get("lng") is not None else None
            result.append(r)
        return jsonify({"success": True, "reports": result, "count": len(result)})
    except Exception:
        logger.exception("map_reports error")
        return jsonify({"success": False, "error": "Failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@dashboard_bp.route("/api/recent_outages")
@login_required
def recent_outages():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    FT  = _feeder_table()
    FC  = _feeder_col()
    EXC = _excluded()
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"""
            SELECT i.incident_id, i.incident_type, i.barangay, i.town,
                   i.report_count, i.status, i.priority, i.first_report_time,
                   f.{FC} AS feeder_name
            FROM outage_incidents i
            LEFT JOIN {FT} f
                ON ST_Contains(f.geom::geometry, i.geom::geometry)
                AND f.{FC} != %s
            WHERE i.status != 'RESTORED'
            ORDER BY i.first_report_time DESC LIMIT 5
        """, (EXC,))
        rows = cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["first_report_time"] = isoformat_safe(d.get("first_report_time"))
            result.append(d)
        return jsonify({"success": True, "outages": result})
    except Exception:
        logger.exception("recent_outages error")
        return jsonify({"success": False, "error": "Failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@dashboard_bp.route("/api/badge_counts")
@login_required
def badge_counts():
    from app import limiter
    counts = {"outages": 0, "meter": 0, "queue": 0}

    cloud = get_cloud_conn()
    local = get_local_conn()
    try:
        if cloud:
            cur = cloud.cursor()
            cur.execute("SELECT COUNT(*) FROM outage_incidents WHERE status='NEW'")
            counts["outages"] = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM meter_concerns WHERE status='PENDING'")
            counts["meter"] = cur.fetchone()[0]
            cur.close()
    except Exception:
        logger.warning("badge_counts cloud query failed")
    finally:
        if cloud: release_cloud_conn(cloud)

    try:
        if local:
            cur = local.cursor()
            cur.execute("SELECT COUNT(*) FROM agent_queue WHERE status='Pending'")
            counts["queue"] = cur.fetchone()[0]
            cur.close()
    except Exception:
        logger.warning("badge_counts local query failed")
    finally:
        if local: release_local_conn(local)

    return jsonify({"success": True, "counts": counts})


# ─────────────────────────────────────────────────────────────────────────────
# API — MUTATIONS
# ─────────────────────────────────────────────────────────────────────────────

@dashboard_bp.route("/api/update_incident_status/<int:incident_id>", methods=["POST"])
@login_required
def update_incident_status(incident_id):
    data       = request.get_json() or {}
    new_status = (data.get("status") or "").strip().upper()
    if new_status not in ("NEW", "ASSIGNED", "RESTORED"):
        return jsonify({"success": False, "error": "Invalid status"}), 400

    actor = session.get("full_name") or session.get("username", "Unknown")
    conn  = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            UPDATE outage_incidents SET
                status      = %s,
                assigned_at = CASE WHEN %s='ASSIGNED' AND assigned_at IS NULL
                              THEN TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP) ELSE assigned_at END,
                restored_at = CASE WHEN %s='RESTORED' AND restored_at IS NULL
                              THEN TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP) ELSE restored_at END,
                resolved_at = CASE WHEN %s='RESTORED'
                              THEN TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP) ELSE resolved_at END,
                assigned_by = CASE WHEN %s='ASSIGNED' AND assigned_at IS NULL
                              THEN %s ELSE assigned_by END,
                restored_by = CASE WHEN %s='RESTORED' THEN %s ELSE restored_by END,
                updated_at  = TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP)
            WHERE incident_id = %s
            RETURNING incident_id, barangay, town, assigned_by, restored_by
        """, (new_status, new_status, new_status, new_status,
              new_status, actor, new_status, actor, incident_id))
        res = cur.fetchone()
        if not res:
            return jsonify({"success": False, "error": "Incident not found"}), 404
        conn.commit()

        try:
            from app import socketio
            socketio.emit("incident_updated", {
                "incident_id": incident_id,
                "new_status": new_status,
                "actioned_by": actor,
                "timestamp": isoformat_safe(datetime.now(timezone.utc)),
            })
        except Exception:
            pass

        return jsonify({"success": True, "message": f"Status → {new_status}",
                        "actioned_by": actor})
    except Exception:
        conn.rollback()
        logger.exception("update_incident_status error")
        return jsonify({"success": False, "error": "Update failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@dashboard_bp.route("/api/update_report_status/<int:report_id>", methods=["POST"])
@login_required
def update_report_status(report_id):
    data       = request.get_json() or {}
    new_status = (data.get("status") or "").strip().upper()
    if new_status not in ("NEW", "ASSIGNED", "RESTORED"):
        return jsonify({"success": False, "error": "Invalid status"}), 400

    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            UPDATE outage_reports SET
                status            = %s,
                status_changed_at = TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP),
                assigned_at       = CASE WHEN %s='ASSIGNED' AND assigned_at IS NULL
                                    THEN TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP) ELSE assigned_at END,
                restored_at       = CASE WHEN %s='RESTORED' AND restored_at IS NULL
                                    THEN TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP) ELSE restored_at END
            WHERE report_id = %s
            RETURNING report_id, status_changed_at
        """, (new_status, new_status, new_status, report_id))
        res = cur.fetchone()
        if not res:
            return jsonify({"success": False, "error": "Report not found"}), 404
        conn.commit()
        return jsonify({"success": True, "message": f"Report → {new_status}"})
    except Exception:
        conn.rollback()
        logger.exception("update_report_status error")
        return jsonify({"success": False, "error": "Update failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@dashboard_bp.route("/api/incident/<int:incident_id>/remarks", methods=["POST", "OPTIONS"])
@login_required
def update_remarks(incident_id):
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
    data    = request.get_json(silent=True) or {}
    remarks = (data.get("remarks") or "").strip()

    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            UPDATE outage_incidents
            SET remarks = %s, updated_at = TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP)
            WHERE incident_id = %s
            RETURNING incident_id, remarks
        """, (remarks, incident_id))
        res = cur.fetchone()
        if not res:
            return jsonify({"success": False, "error": "Incident not found"}), 404
        conn.commit()
        return jsonify({"success": True, "remarks": res["remarks"]})
    except Exception:
        conn.rollback()
        logger.exception("update_remarks error")
        return jsonify({"success": False, "error": "Update failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@dashboard_bp.route("/api/incident/<int:incident_id>/remove", methods=["DELETE"])
@login_required
def remove_incident(incident_id):
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT incident_id FROM outage_incidents WHERE incident_id=%s", (incident_id,))
        if not cur.fetchone():
            return jsonify({"success": False, "error": "Incident not found"}), 404
        cur.execute("DELETE FROM outage_reports WHERE incident_id=%s", (incident_id,))
        cur.execute("DELETE FROM outage_incidents WHERE incident_id=%s", (incident_id,))
        conn.commit()
        try:
            from app import socketio
            socketio.emit("incident_removed", {"incident_id": incident_id})
        except Exception:
            pass
        return jsonify({"success": True, "message": "Incident removed"})
    except Exception:
        conn.rollback()
        logger.exception("remove_incident error")
        return jsonify({"success": False, "error": "Remove failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@dashboard_bp.route("/api/report/<int:report_id>/remove", methods=["DELETE"])
@login_required
def remove_report(report_id):
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT report_id, incident_id FROM outage_reports WHERE report_id=%s", (report_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Report not found"}), 404
        iid = row["incident_id"]
        cur.execute("DELETE FROM outage_reports WHERE report_id=%s", (report_id,))
        cur.execute("""
            UPDATE outage_incidents
            SET report_count = GREATEST(report_count - 1, 0),
                updated_at   = TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP)
            WHERE incident_id = %s
        """, (iid,))
        # Auto-remove incident if no reports left
        cur.execute("SELECT report_count FROM outage_incidents WHERE incident_id=%s", (iid,))
        remaining = cur.fetchone()
        if remaining and remaining["report_count"] <= 0:
            cur.execute("DELETE FROM outage_incidents WHERE incident_id=%s", (iid,))
        conn.commit()
        return jsonify({"success": True, "message": "Report removed"})
    except Exception:
        conn.rollback()
        logger.exception("remove_report error")
        return jsonify({"success": False, "error": "Remove failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)