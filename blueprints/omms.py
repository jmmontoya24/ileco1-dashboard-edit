"""
blueprints/omms.py

Routes:
    POST /api/incident/<id>/assign_to_omms
    GET  /api/internal/incidents          (Rasa internal, localhost only)
    GET  /api/internal/meter-concern/<ref> (Rasa internal, localhost only)
"""
import logging
import time as _time
import uuid as _uuid
from datetime import datetime

import pytz

from flask import Blueprint, jsonify, request, session
from psycopg2.extras import RealDictCursor

from blueprints.utils import login_required, internal_only, isoformat_safe
from db.pool import (
    get_cloud_conn, release_cloud_conn,
    get_joblist_conn, release_joblist_conn,
)

logger = logging.getLogger(__name__)
omms_bp = Blueprint("omms", __name__)

_PH_TZ = pytz.timezone("Asia/Manila")


# ─────────────────────────────────────────────────────────────────────────────
# OMMS FIELD BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def _ts(dt: datetime) -> str:
    return dt.strftime("%m/%d/%y  %I:%M:%S %p")


def _unique_id(dt: datetime) -> str:
    return f"{int(dt.timestamp() * 1000)}{str(_uuid.uuid4().int)[:6]}"


def _spinners() -> str:
    return str(_time.time_ns())


def _section(inc_type: str) -> str:
    return {
        "power_outage":      "Primary Line",
        "sdi_problem":       "Secondary Line",
        "fallen_wire":       "Secondary Line",
        "transformer_issue": "Primary Line",
        "fire_hazard":       "Primary Line",
        "sparking":          "Secondary Line",
        "partial_outage":    "Secondary Line",
    }.get((inc_type or "").lower(), "Primary Line")


def _cause(inc_type: str, details: str) -> str:
    d = (details or "").lower()
    if any(k in d for k in ["tree","vegetation","branch","bamboo","acacia","mango"]):
        return "Vegetation"
    if any(k in d for k in ["cut-off","cutoff","cut wire","neutral line"]):
        return "Cut-off pri/sec/sdi line"
    if any(k in d for k in ["leaning pole","fallen pole","pole down"]):
        return "Correction of leaning pole/s"
    if any(k in d for k in ["animal","snake","bird","rat","cat"]):
        return "Birds/snakes/etc."
    if any(k in d for k in ["fuse","blown","busted"]):
        return "Blown fuse"
    if any(k in d for k in ["transformer","xfmr","transient"]):
        return "Transient fault"
    if any(k in d for k in ["fire","burning","burnt","smoke"]):
        return "Blown fuse"
    return {
        "power_outage":      "Transient fault",
        "sdi_problem":       "Cut-off pri/sec/sdi line",
        "fallen_wire":       "Cut-off pri/sec/sdi line",
        "transformer_issue": "Transformer related",
        "fire_hazard":       "Blown fuse",
        "sparking":          "Others",
    }.get((inc_type or "").lower(), "Others")


def _equip(inc_type: str, details: str) -> str:
    d = (details or "").lower()
    if any(k in d for k in ["transformer","xfmr"]): return "Transformer"
    if any(k in d for k in ["fuse cut","cutout"]):  return "Fuse cut-out"
    if "pole" in d: return "Poles"
    if any(k in d for k in ["wire","line","neutral"]): return "Others"
    return {"transformer_issue": "Transformer", "fallen_wire": "Others"}.get(
        (inc_type or "").lower(), "Others"
    )


def _priority_type(priority: str) -> str:
    return {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(
        (priority or "").upper(), "high"
    )


def _substation(feeder_name: str, town: str) -> str:
    ss_map = {
        "Feeder 7": "San Miguel S/S", "Feeder 8": "San Miguel S/S",
        "Feeder 9": "San Miguel S/S", "Feeder 10": "San Miguel S/S",
        "Feeder 11": "Pavia S/S",     "Feeder 12": "Pavia S/S",
        "Feeder 12A": "Pavia S/S",    "Feeder 13": "Oton S/S",
        "Feeder 14": "Oton S/S",      "Feeder 15": "Oton S/S",
        "Feeder 16": "Guimbal S/S",   "Feeder 17": "Guimbal S/S",
        "Feeder 18": "Guimbal S/S",   "Feeder 19": "Guimbal S/S",
        "Feeder 20": "Leganes S/S",   "Feeder 21": "Leganes S/S",
        "Feeder 22": "Leganes S/S",   "Feeder 23": "Leganes S/S",
    }
    return ss_map.get(feeder_name or "", f"{town} S/S" if town else "Unknown S/S")


# ─────────────────────────────────────────────────────────────────────────────
# ASSIGN TO OMMS
# ─────────────────────────────────────────────────────────────────────────────

@omms_bp.route("/api/incident/<int:incident_id>/assign_to_omms", methods=["POST"])
@login_required
def assign_to_omms(incident_id):
    req_data  = request.get_json() or {}
    report_id = req_data.get("report_id")
    now_ph    = datetime.now(_PH_TZ)

    cloud_conn   = None
    joblist_conn = None
    cloud_cur    = None
    joblist_cur  = None

    try:
        # ── 1. Cloud: read incident ───────────────────────────────────────────
        cloud_conn = get_cloud_conn()
        if not cloud_conn:
            return jsonify({"success": False, "error": "Cloud DB unavailable"}), 503

        from flask import current_app
        FT  = current_app.config.get("FEEDER_TABLE",    '"ILECO_1_COVERAGE_AREA_FEEDERS_FINALoutput"')
        FC  = current_app.config.get("FEEDER_NAME_COL", "feeder_name")
        EXC = current_app.config.get("EXCLUDED_FEEDER", "Feeder 12A")

        cloud_cur = cloud_conn.cursor(cursor_factory=RealDictCursor)
        cloud_cur.execute(f"""
            SELECT i.incident_id, i.incident_type, i.barangay, i.town,
                   i.priority, i.status, i.job_order_id, i.remarks,
                   ST_Y(i.geom::geometry) AS lat, ST_X(i.geom::geometry) AS lng,
                   f.{FC} AS feeder_name
            FROM outage_incidents i
            LEFT JOIN {FT} f
                ON ST_Contains(f.geom::geometry, i.geom::geometry)
                AND f.{FC} != %s
            WHERE i.incident_id = %s
        """, (EXC, incident_id))
        incident = cloud_cur.fetchone()
        if not incident:
            return jsonify({"success": False, "error": f"Incident {incident_id} not found"}), 404

        # ── 2. Cloud: read consumer report ────────────────────────────────────
        if report_id:
            cloud_cur.execute("""
                SELECT report_id, full_name, contact_number, email,
                       account_number, address, barangay, town,
                       details, landmark, priority, incident_type,
                       ST_Y(geom::geometry) AS lat, ST_X(geom::geometry) AS lng
                FROM outage_reports WHERE report_id=%s AND incident_id=%s
            """, (report_id, incident_id))
        else:
            cloud_cur.execute("""
                SELECT report_id, full_name, contact_number, email,
                       account_number, address, barangay, town,
                       details, landmark, priority, incident_type,
                       ST_Y(geom::geometry) AS lat, ST_X(geom::geometry) AS lng
                FROM outage_reports WHERE incident_id=%s
                ORDER BY timestamp ASC LIMIT 1
            """, (incident_id,))
        consumer = cloud_cur.fetchone()
        if not consumer:
            return jsonify({"success": False,
                            "error": "No consumer report found for this incident"}), 404

        # ── 3. Build OMMS fields ──────────────────────────────────────────────
        omms_ts       = _ts(now_ph)
        omms_uid      = _unique_id(now_ph)
        omms_spin     = _spinners()

        lat_val = consumer["lat"] or incident["lat"]
        lng_val = consumer["lng"] or incident["lng"]
        lat_txt = str(round(float(lat_val), 7)) if lat_val is not None else ""
        lng_txt = str(round(float(lng_val), 7)) if lng_val is not None else ""

        feeder_name   = incident["feeder_name"] or ""
        substation    = _substation(feeder_name, incident["town"] or "")
        inc_type      = incident["incident_type"] or consumer.get("incident_type") or "power_outage"
        consumer_name = (consumer["full_name"] or "").strip() or "Unknown"
        contact       = (consumer["contact_number"] or "").strip()
        details_text  = (consumer["details"] or "").strip()
        landmark_txt  = (consumer["landmark"] or "").strip()
        town_val      = (consumer["town"] or incident["town"] or "").strip()
        brgy_val      = (consumer["barangay"] or incident["barangay"] or "").strip()
        notes_val     = details_text or incident.get("remarks") or ""
        location_val  = (consumer["address"] or f"{brgy_val}, {town_val}").strip()

        # ── 4. Joblist: INSERT into public.converted ──────────────────────────
        joblist_conn = get_joblist_conn()
        if not joblist_conn:
            return jsonify({"success": False,
                            "error": "OMMS joblist DB unavailable — check JOBLIST_DB_HOST"}), 503

        joblist_cur = joblist_conn.cursor(cursor_factory=RealDictCursor)

        # Collision guard
        joblist_cur.execute(
            "SELECT unique_id FROM public.converted WHERE unique_id=%s AND followed=%s LIMIT 1",
            (omms_uid, omms_ts),
        )
        if joblist_cur.fetchone():
            omms_uid += str(_uuid.uuid4().int)[:2]

        joblist_cur.execute("""
            INSERT INTO public.converted (
                unique_id, creator, created, follower, followed,
                name, spinners,
                town0, brgy0, town, brgy, town2, brgy2,
                assignedto, status,
                subs, feeder, section, cause, equip, type,
                notes, landmark, phone, location,
                latitude, longitude,
                actiontaken, submitted_at, assigned_at
            ) VALUES (
                %s,%s,%s,%s,%s,
                %s,%s,
                %s,%s,%s,%s,%s,%s,
                %s,%s,
                %s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,
                %s,%s,
                NULL,%s,%s
            )
            ON CONFLICT (unique_id, followed) DO NOTHING
            RETURNING unique_id
        """, (
            omms_uid, contact, omms_ts, contact, omms_ts,
            consumer_name, omms_spin,
            town_val, brgy_val, town_val, brgy_val, town_val, brgy_val,
            town_val, "On-going",
            substation, feeder_name,
            _section(inc_type), _cause(inc_type, details_text),
            _equip(inc_type, details_text),
            _priority_type(incident["priority"] or consumer.get("priority") or "HIGH"),
            notes_val, landmark_txt, contact,
            location_val, lat_txt, lng_txt,
            omms_ts, omms_ts,
        ))
        joblist_conn.commit()
        logger.info("✅ OMMS INSERT OK unique_id=%s feeder=%s town=%s",
                    omms_uid, feeder_name, town_val)

        # ── 5. Cloud: update report + incident to ASSIGNED ────────────────────
        cloud_cur.execute("""
            UPDATE outage_reports
            SET status='ASSIGNED',
                assigned_at=TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP),
                status_changed_at=TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP)
            WHERE report_id=%s
        """, (consumer["report_id"],))

        cloud_cur.execute("""
            UPDATE outage_incidents
            SET status=CASE WHEN status='NEW' THEN 'ASSIGNED' ELSE status END,
                assigned_at=CASE WHEN assigned_at IS NULL
                            THEN TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP) ELSE assigned_at END,
                updated_at=TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP)
            WHERE incident_id=%s
        """, (incident_id,))
        cloud_conn.commit()

        # ── 6. Broadcast ──────────────────────────────────────────────────────
        try:
            from app import socketio
            socketio.emit("incident_updated", {
                "incident_id":    incident_id,
                "new_status":     "ASSIGNED",
                "omms_unique_id": omms_uid,
                "timestamp":      isoformat_safe(now_ph),
            })
        except Exception:
            pass

        return jsonify({
            "success":        True,
            "message":        "Successfully assigned to OMMS job list",
            "omms_unique_id": omms_uid,
            "report_id":      consumer["report_id"],
            "incident_id":    incident_id,
        })

    except Exception:
        try:
            if cloud_conn:   cloud_conn.rollback()
        except Exception: pass
        try:
            if joblist_conn: joblist_conn.rollback()
        except Exception: pass
        logger.exception("assign_to_omms FAILED incident=%s", incident_id)
        return jsonify({"success": False, "error": "Assignment failed"}), 500

    finally:
        for cur in (cloud_cur, joblist_cur):
            try:
                if cur: cur.close()
            except Exception: pass
        if cloud_conn:   release_cloud_conn(cloud_conn)
        if joblist_conn: release_joblist_conn(joblist_conn)


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL (Rasa action server — localhost only)
# ─────────────────────────────────────────────────────────────────────────────

@omms_bp.route("/api/internal/incidents")
@internal_only
def internal_incidents():
    """Proxy to dashboard incidents — no session required, localhost only."""
    from blueprints.dashboard import get_incidents
    return get_incidents()


@omms_bp.route("/api/internal/meter-concern/<reference_number>")
@internal_only
def internal_meter_concern(reference_number):
    """Proxy to meter concern detail — no session required, localhost only."""
    from blueprints.meter import get_meter_concern
    return get_meter_concern(reference_number)