"""
blueprints/meter.py

Routes:
    GET  /meter_dashboard
    GET  /meter_concern               (public form page)
    POST /api/meter-concern           (public submission, rate-limited)
    GET  /api/meter-concerns          (staff list)
    GET  /api/meter-concern/<ref>     (detail + evidence + activity)
    PUT  /api/meter-concern/<id>/status
    DELETE /api/meter-concern/<id>
    GET  /api/meter-concerns/statistics
"""
import logging
import os
import uuid
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request, session, current_app
from psycopg2.extras import RealDictCursor
from werkzeug.utils import secure_filename

from blueprints.utils import login_required, isoformat_safe
from db.pool import get_cloud_conn, release_cloud_conn

logger = logging.getLogger(__name__)
meter_bp = Blueprint("meter", __name__)

PRIORITY_MAP = {
    "noise_burning":     "critical",
    "not_working":       "high",
    "tampered_seal":     "high",
    "high_consumption":  "medium",
    "running_fast_slow": "medium",
    "others":            "medium",
}


def _allowed(filename: str) -> bool:
    exts = current_app.config.get("ALLOWED_EXTENSIONS", {"png","jpg","jpeg","gif","mp4","mov","avi","webp"})
    return "." in filename and filename.rsplit(".", 1)[1].lower() in exts


def _ref_number() -> str:
    return f"MC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"


# ─────────────────────────────────────────────────────────────────────────────
# PAGES
# ─────────────────────────────────────────────────────────────────────────────

@meter_bp.route("/meter_dashboard")
@login_required
def meter_dashboard():
    return render_template("meter_dashboard.html")


@meter_bp.route("/meter_concern")
def meter_concern_page():
    return render_template("meter_concern.html")


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC SUBMISSION
# ─────────────────────────────────────────────────────────────────────────────

@meter_bp.route("/api/meter-concern", methods=["POST"])
def submit_meter_concern():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"error": "Database unavailable"}), 503

    cur = None
    try:
        data = request.form.to_dict()
        required = ["account_number","consumer_name","contact_number",
                    "meter_number","service_address","barangay","concern_type","date_noticed"]
        for field in required:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400

        ref_number  = _ref_number()
        concern_type= data["concern_type"]
        priority    = PRIORITY_MAP.get(concern_type, "medium")
        is_critical = concern_type == "noise_burning"

        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            INSERT INTO meter_concerns
              (reference_number, account_number, consumer_name, contact_number,
               meter_number, service_address, barangay, concern_type,
               other_concern, date_noticed, additional_details,
               is_critical, priority, status, created_at, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING',
                    TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP),
                    TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP))
            RETURNING id, reference_number
        """, (ref_number, data["account_number"], data["consumer_name"],
              data["contact_number"], data["meter_number"],
              data["service_address"], data["barangay"], concern_type,
              data.get("other_concern"), data["date_noticed"],
              data.get("additional_details"), is_critical, priority))
        row       = cur.fetchone()
        concern_id = row["id"]

        # ── Evidence files ────────────────────────────────────────────────────
        uploaded = []
        if "files[]" in request.files:
            upload_root    = current_app.config.get("UPLOAD_FOLDER", "uploads/meter_concerns")
            concern_folder = os.path.join(upload_root, ref_number)
            os.makedirs(concern_folder, exist_ok=True)

            for f in request.files.getlist("files[]"):
                if f and f.filename and _allowed(f.filename):
                    fname    = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secure_filename(f.filename)}"
                    fpath    = os.path.join(concern_folder, fname)
                    f.save(fpath)
                    rel_path = os.path.join("meter_concerns", ref_number, fname).replace("\\", "/")
                    size     = os.path.getsize(fpath)
                    ftype    = f.content_type or "application/octet-stream"

                    cur.execute("""
                        INSERT INTO concern_evidence
                          (meter_concern_id, file_name, file_path, file_type, file_size, uploaded_at)
                        VALUES (%s,%s,%s,%s,%s,TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP))
                    """, (concern_id, fname, rel_path, ftype, size))
                    uploaded.append({"filename": fname, "size": size,
                                     "file_url": f"/uploads/{rel_path}"})

        # ── Activity log ──────────────────────────────────────────────────────
        try:
            cur.execute("""
                INSERT INTO concern_activity_log
                  (meter_concern_id, activity_type, performed_by, description, created_at)
                VALUES (%s,'created',%s,%s,TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP))
            """, (concern_id, data.get("consumer_name","System"),
                  f"Meter concern created: {concern_type}"))
        except Exception:
            pass

        conn.commit()

        if is_critical:
            try:
                from app import socketio
                socketio.emit("critical_meter_concern", {
                    "reference_number": ref_number,
                    "concern_type":     concern_type,
                    "barangay":         data["barangay"],
                    "priority":         "critical",
                })
            except Exception:
                pass

        return jsonify({
            "success":         True,
            "message":         "Meter concern submitted successfully",
            "reference_number": ref_number,
            "concern_id":      concern_id,
            "is_critical":     is_critical,
            "priority":        priority,
            "status":          "PENDING",
            "uploaded_files":  uploaded,
            "files_count":     len(uploaded),
        }), 201

    except Exception:
        if conn: conn.rollback()
        logger.exception("submit_meter_concern error")
        return jsonify({"error": "Submission failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


# ─────────────────────────────────────────────────────────────────────────────
# STAFF READS
# ─────────────────────────────────────────────────────────────────────────────

@meter_bp.route("/api/meter-concerns")
@login_required
def list_meter_concerns():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"error": "Database unavailable"}), 503
    cur = None
    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(100, int(request.args.get("per_page", 20)))
        status   = request.args.get("status")
        priority = request.args.get("priority")
        barangay = request.args.get("barangay")
        ctype    = request.args.get("concern_type")
        date_f   = request.args.get("date")

        where, params = ["1=1"], []
        if status:   where.append("status=%s");       params.append(status.upper())
        if priority: where.append("priority=%s");     params.append(priority.lower())
        if barangay: where.append("barangay=%s");     params.append(barangay)
        if ctype:    where.append("concern_type=%s"); params.append(ctype)
        if date_f:
            col = "resolved_at" if (status or "").upper() == "RESOLVED" else "created_at"
            where.append(f"DATE({col} AT TIME ZONE 'Asia/Manila')=%s")
            params.append(date_f)

        cur   = conn.cursor(cursor_factory=RealDictCursor)
        order = "resolved_at DESC" if (status or "").upper() == "RESOLVED" else "created_at DESC"
        base  = f"FROM meter_concerns WHERE {' AND '.join(where)}"

        cur.execute(f"SELECT COUNT(*) {base}", params)
        total = cur.fetchone()["count"]

        cur.execute(
            f"SELECT * {base} ORDER BY {order} LIMIT %s OFFSET %s",
            params + [per_page, (page - 1) * per_page]
        )
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            d["date_noticed"] = str(d["date_noticed"]) if d.get("date_noticed") else None
            for k in ("created_at","updated_at","resolved_at"):
                d[k] = isoformat_safe(d.get(k))
            rows.append(d)

        return jsonify({
            "success": True, "data": rows,
            "pagination": {"page": page, "per_page": per_page, "total": total,
                           "pages": (total + per_page - 1) // per_page},
        })
    except Exception:
        logger.exception("list_meter_concerns error")
        return jsonify({"error": "Failed to list concerns"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@meter_bp.route("/api/meter-concern/<reference_number>")
def get_meter_concern(reference_number):
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM meter_concerns WHERE reference_number=%s", (reference_number,))
        concern = cur.fetchone()
        if not concern:
            return jsonify({"error": "Not found"}), 404

        cid = concern["id"]

        cur.execute("""
            SELECT file_name, file_path, file_type, file_size, uploaded_at
            FROM concern_evidence WHERE meter_concern_id=%s ORDER BY uploaded_at DESC
        """, (cid,))
        evidence = cur.fetchall()

        cur.execute("""
            SELECT activity_type, performed_by, description, old_value, new_value, created_at
            FROM concern_activity_log WHERE meter_concern_id=%s ORDER BY created_at DESC
        """, (cid,))
        activities = cur.fetchall()

        def _fmt_concern(c):
            d = dict(c)
            d["date_noticed"] = str(d["date_noticed"]) if d.get("date_noticed") else None
            for k in ("created_at","updated_at","resolved_at"):
                d[k] = isoformat_safe(d.get(k))
            return d

        ev_list = []
        for e in evidence:
            ev = dict(e)
            ev["uploaded_at"] = isoformat_safe(ev.get("uploaded_at"))
            ev["file_url"] = f"/uploads/{ev['file_path'].replace(chr(92),'/')}" if ev.get("file_path") else None
            ev_list.append(ev)

        act_list = [dict(a) | {"created_at": isoformat_safe(a.get("created_at"))} for a in activities]

        return jsonify({"success": True, "data": {
            "concern":    _fmt_concern(concern),
            "evidence":   ev_list,
            "activities": act_list,
        }})
    except Exception:
        logger.exception("get_meter_concern error")
        return jsonify({"error": "Failed to fetch concern"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@meter_bp.route("/api/meter-concern/<int:concern_id>/status", methods=["PUT"])
@login_required
def update_meter_concern_status(concern_id):
    data       = request.get_json() or {}
    new_status = (data.get("status") or "").strip().upper()
    valid      = {"PENDING","ASSIGNED","IN_PROGRESS","RESOLVED","CLOSED"}
    if new_status not in valid:
        return jsonify({"error": "Invalid status"}), 400

    assigned_to = data.get("assigned_to")
    notes       = data.get("notes")
    actor       = session.get("full_name", session.get("username", "System"))

    conn = get_cloud_conn()
    if not conn:
        return jsonify({"error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT status, reference_number FROM meter_concerns WHERE id=%s", (concern_id,))
        existing = cur.fetchone()
        if not existing:
            return jsonify({"error": "Not found"}), 404

        old_status = existing["status"]
        extras     = ""
        ep         = []
        if new_status == "RESOLVED":
            extras += ", resolved_at=TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP)"
        if notes:
            extras += ", resolution_notes=%s"; ep.append(notes)

        cur.execute(f"""
            UPDATE meter_concerns
            SET status=%s, assigned_to=%s,
                updated_at=TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP){extras}
            WHERE id=%s RETURNING reference_number
        """, [new_status, assigned_to] + ep + [concern_id])
        res = cur.fetchone()

        cur.execute("""
            INSERT INTO concern_activity_log
              (meter_concern_id, activity_type, performed_by, description, old_value, new_value, created_at)
            VALUES (%s,'status_changed',%s,%s,%s,%s,TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP))
        """, (concern_id, actor, f"Status: {old_status} → {new_status}", old_status, new_status))
        conn.commit()

        try:
            from app import socketio
            socketio.emit("meter_concern_updated", {
                "concern_id":       concern_id,
                "reference_number": res["reference_number"],
                "new_status":       new_status,
            })
        except Exception:
            pass

        return jsonify({"success": True, "message": f"Status → {new_status}"})
    except Exception:
        conn.rollback()
        logger.exception("update_meter_concern_status error")
        return jsonify({"error": "Update failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@meter_bp.route("/api/meter-concern/<int:concern_id>", methods=["DELETE"])
@login_required
def delete_meter_concern(concern_id):
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM concern_activity_log WHERE meter_concern_id=%s", (concern_id,))
        cur.execute("DELETE FROM concern_evidence WHERE meter_concern_id=%s", (concern_id,))
        cur.execute("DELETE FROM meter_concerns WHERE id=%s", (concern_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Concern removed"})
    except Exception:
        conn.rollback()
        logger.exception("delete_meter_concern error")
        return jsonify({"success": False, "error": "Delete failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@meter_bp.route("/api/meter-concerns/statistics")
@login_required
def meter_statistics():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"error": "Database unavailable"}), 503
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT COUNT(*) AS total FROM meter_concerns")
        total = cur.fetchone()["total"]
        cur.execute("SELECT status, COUNT(*) AS count FROM meter_concerns GROUP BY status")
        by_status = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT priority, COUNT(*) AS count FROM meter_concerns GROUP BY priority")
        by_priority = [dict(r) for r in cur.fetchall()]
        cur.execute("SELECT concern_type, COUNT(*) AS count FROM meter_concerns GROUP BY concern_type ORDER BY count DESC")
        by_type = [dict(r) for r in cur.fetchall()]
        return jsonify({"success": True, "data": {
            "total": total, "by_status": by_status,
            "by_priority": by_priority, "by_type": by_type,
        }})
    except Exception:
        logger.exception("meter_statistics error")
        return jsonify({"error": "Failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)