"""
blueprints/outage.py

Public-facing and internal outage routes:
    POST /api/submit_power_outage   (public, rate-limited)
    POST /api/check_feeder
    GET  /api/feeder_polygon
    POST /api/complaints_in_feeder
    POST /api/complaints_nearby
    GET  /report_outage             (public form page)
"""
import html
import logging
import re
import uuid
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request, current_app
from psycopg2.extras import RealDictCursor

from blueprints.utils import isoformat_safe, classify_priority, login_required
from db.pool import get_cloud_conn, release_cloud_conn

logger = logging.getLogger(__name__)
outage_bp = Blueprint("outage", __name__)


def _ft():  return current_app.config.get("FEEDER_TABLE", '"ILECO_1_COVERAGE_AREA_FEEDERS_FINALoutput"')
def _fc():  return current_app.config.get("FEEDER_NAME_COL", "feeder_name")
def _exc(): return current_app.config.get("EXCLUDED_FEEDER", "Feeder 12A")


# ─────────────────────────────────────────────────────────────────────────────
# PAGE
# ─────────────────────────────────────────────────────────────────────────────

@outage_bp.route("/report_outage")
def report_outage_page():
    return render_template("report_outage.html")


# ─────────────────────────────────────────────────────────────────────────────
# FEEDER LOOKUP
# ─────────────────────────────────────────────────────────────────────────────

@outage_bp.route("/api/check_feeder", methods=["POST"])
def check_feeder():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    cur = None
    FT, FC, EXC = _ft(), _fc(), _exc()
    try:
        data = request.get_json(force=True)
        lat  = float(data["lat"])
        lng  = float(data["lng"])
        cur  = conn.cursor(cursor_factory=RealDictCursor)

        # Attempt 1: strict point-in-polygon
        cur.execute(f"""
            SELECT {FC}, status, cause, start_time, end_time, outage_type, is_active,
                   ST_Distance(geom::geography,
                     ST_SetSRID(ST_MakePoint(%s,%s),4326)::geography) AS dist_m
            FROM {FT}
            WHERE ST_Contains(geom::geometry, ST_SetSRID(ST_MakePoint(%s,%s),4326))
              AND {FC} != %s
            LIMIT 1
        """, (lng, lat, lng, lat, EXC))
        row = cur.fetchone()

        if row:
            return jsonify({"success": True, "feeder": row[FC], "in_feeder": True,
                            "method": "contains", **_feeder_props(row)})

        # Attempt 2: nearest feeder within 5 km
        cur.execute(f"""
            SELECT {FC}, status, cause, start_time, end_time, outage_type, is_active,
                   ST_Distance(geom::geography,
                     ST_SetSRID(ST_MakePoint(%s,%s),4326)::geography) AS dist_m
            FROM {FT} WHERE {FC} != %s
            ORDER BY dist_m LIMIT 1
        """, (lng, lat, EXC))
        row = cur.fetchone()

        if row:
            dist_m  = float(row["dist_m"])
            dist_km = round(dist_m / 1000, 2)
            in_f    = dist_m <= 5000
            return jsonify({"success": True, "feeder": row[FC], "in_feeder": in_f,
                            "method": "nearest", "distance_km": dist_km,
                            **_feeder_props(row)})

        return jsonify({"success": True, "feeder": None, "in_feeder": False})

    except (KeyError, TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid coordinates"}), 400
    except Exception:
        logger.exception("check_feeder error")
        return jsonify({"success": False, "error": "Feeder lookup failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


def _feeder_props(row):
    return {
        "status":      row.get("status"),
        "cause":       row.get("cause"),
        "start_time":  str(row["start_time"])  if row.get("start_time")  else None,
        "end_time":    str(row["end_time"])    if row.get("end_time")    else None,
        "outage_type": row.get("outage_type"),
        "is_active":   row.get("is_active"),
    }


@outage_bp.route("/api/feeder_polygon")
def feeder_polygon():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    FT, FC, EXC = _ft(), _fc(), _exc()
    cur = None
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"""
            SELECT {FC}, status, cause, start_time, end_time, outage_type,
                   is_active, layer,
                   ST_AsGeoJSON(ST_Transform(geom::geometry,4326))::json AS geometry,
                   ST_IsEmpty(geom::geometry) AS is_empty
            FROM {FT}
            WHERE geom IS NOT NULL AND NOT ST_IsEmpty(geom::geometry)
              AND {FC} != %s
        """, (EXC,))

        features = []
        for row in cur.fetchall():
            if not row["geometry"] or row["is_empty"]:
                continue
            features.append({
                "type": "Feature",
                "properties": {
                    "feeder_name": row[FC],
                    "status":      row["status"],
                    "cause":       row["cause"],
                    "start_time":  str(row["start_time"])  if row.get("start_time")  else None,
                    "end_time":    str(row["end_time"])    if row.get("end_time")    else None,
                    "outage_type": row["outage_type"],
                    "is_active":   row["is_active"],
                    "layer":       row["layer"],
                },
                "geometry": row["geometry"],
            })
        return jsonify({"success": True, "features": features})
    except Exception:
        logger.exception("feeder_polygon error")
        return jsonify({"success": False, "error": "Failed to load feeder polygons"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@outage_bp.route("/api/complaints_in_feeder", methods=["POST"])
def complaints_in_feeder():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    FT, FC, EXC = _ft(), _fc(), _exc()
    cur = None
    try:
        data = request.get_json(force=True)
        lat  = float(data["lat"])
        lng  = float(data["lng"])
        cur  = conn.cursor(cursor_factory=RealDictCursor)

        # Identify feeder
        cur.execute(f"""
            SELECT {FC},
                   ST_Distance(geom::geography,
                     ST_SetSRID(ST_MakePoint(%s,%s),4326)::geography) AS dist_m,
                   ST_Contains(geom::geometry,
                     ST_SetSRID(ST_MakePoint(%s,%s),4326)) AS is_inside
            FROM {FT} WHERE {FC} != %s ORDER BY dist_m LIMIT 1
        """, (lng, lat, lng, lat, EXC))
        feeder_row = cur.fetchone()
        if not feeder_row:
            return jsonify({"success": True, "complaints": [], "feeder_name": None, "count": 0})

        feeder_name = feeder_row[FC]

        # Spatial join first
        cur.execute(f"""
            SELECT i.incident_id AS report_id, i.incident_type, i.barangay, i.town,
                   i.report_count, i.status, i.priority, i.first_report_time AS timestamp,
                   i.job_order_id, i.remarks,
                   ST_Y(i.geom::geometry) AS lat, ST_X(i.geom::geometry) AS lng,
                   ST_Distance(i.geom::geography,
                     ST_SetSRID(ST_MakePoint(%s,%s),4326)::geography) AS distance_meters,
                   f.{FC} AS feeder_name
            FROM outage_incidents i
            INNER JOIN {FT} f ON ST_Contains(f.geom::geometry, i.geom::geometry)
            WHERE f.{FC} = %s AND f.{FC} != %s
              AND i.status NOT IN ('RESTORED','RESOLVED') AND i.geom IS NOT NULL
            ORDER BY distance_meters LIMIT 50
        """, (lng, lat, feeder_name, EXC))
        rows = cur.fetchall()
        method = "spatial_join"

        if not rows:
            cur.execute(f"""
                SELECT i.incident_id AS report_id, i.incident_type, i.barangay, i.town,
                       i.report_count, i.status, i.priority, i.first_report_time AS timestamp,
                       i.job_order_id, i.remarks,
                       ST_Y(i.geom::geometry) AS lat, ST_X(i.geom::geometry) AS lng,
                       ST_Distance(i.geom::geography,
                         ST_SetSRID(ST_MakePoint(%s,%s),4326)::geography) AS distance_meters,
                       %s AS feeder_name
                FROM outage_incidents i
                WHERE ST_DWithin(i.geom::geography,
                        ST_SetSRID(ST_MakePoint(%s,%s),4326)::geography, 5000)
                  AND i.status NOT IN ('RESTORED','RESOLVED') AND i.geom IS NOT NULL
                ORDER BY distance_meters LIMIT 50
            """, (lng, lat, feeder_name, lng, lat))
            rows = cur.fetchall()
            method = "radius_fallback"

        complaints = [_row_to_complaint(r) for r in rows]
        return jsonify({"success": True, "complaints": complaints, "feeder_name": feeder_name,
                        "count": len(complaints), "search_method": method})

    except (KeyError, TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid request"}), 400
    except Exception:
        logger.exception("complaints_in_feeder error")
        return jsonify({"success": False, "error": "Search failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


@outage_bp.route("/api/complaints_nearby", methods=["POST"])
def complaints_nearby():
    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503
    FT, FC, EXC = _ft(), _fc(), _exc()
    cur = None
    try:
        data   = request.get_json(force=True)
        lat    = float(data["lat"])
        lng    = float(data["lng"])
        radius = min(int(data.get("radius", 1000)), 10000)  # cap at 10 km
        cur    = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"""
            SELECT r.report_id, r.full_name, r.barangay, r.town,
                   r.incident_type, r.priority, r.status, r.timestamp,
                   r.details, ST_Y(r.geom::geometry) AS lat, ST_X(r.geom::geometry) AS lng,
                   ST_Distance(r.geom::geography,
                     ST_SetSRID(ST_MakePoint(%s,%s),4326)::geography) AS distance_meters,
                   f.{FC} AS feeder_name
            FROM outage_reports r
            LEFT JOIN {FT} f ON ST_Contains(f.geom::geometry, r.geom::geometry)
              AND f.{FC} != %s
            WHERE ST_DWithin(r.geom::geography,
                    ST_SetSRID(ST_MakePoint(%s,%s),4326)::geography, %s)
              AND r.status != 'RESTORED'
            ORDER BY distance_meters LIMIT 10
        """, (lng, lat, EXC, lng, lat, radius))

        result = []
        for row in cur.fetchall():
            r = dict(row)
            r["timestamp"]       = isoformat_safe(r.get("timestamp"))
            r["distance_meters"] = round(float(r["distance_meters"]), 2)
            r["lat"]  = float(r["lat"])  if r.get("lat")  is not None else 0
            r["lng"]  = float(r["lng"])  if r.get("lng")  is not None else 0
            result.append(r)

        return jsonify({"success": True, "complaints": result, "count": len(result),
                        "radius_meters": radius})
    except Exception:
        logger.exception("complaints_nearby error")
        return jsonify({"success": False, "error": "Search failed"}), 500
    finally:
        if cur: cur.close()
        release_cloud_conn(conn)


def _row_to_complaint(row):
    r = dict(row)
    return {
        "report_id":       r.get("report_id"),
        "type":            r.get("incident_type"),
        "priority":        r.get("priority"),
        "status":          r.get("status"),
        "lat":             float(r["lat"])             if r.get("lat")             is not None else 0,
        "lng":             float(r["lng"])             if r.get("lng")             is not None else 0,
        "feeder_name":     r.get("feeder_name"),
        "distance_meters": round(float(r["distance_meters"]), 2) if r.get("distance_meters") else 0,
        "timestamp":       isoformat_safe(r.get("timestamp")),
        "barangay":        r.get("barangay") or "",
        "town":            r.get("town") or "",
        "report_count":    r.get("report_count") or 1,
        "details":         r.get("remarks") or "",
    }


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC SUBMISSION
# ─────────────────────────────────────────────────────────────────────────────

@outage_bp.route("/api/submit_power_outage", methods=["POST", "OPTIONS"])
def submit_power_outage():
    if request.method == "OPTIONS":
        resp = jsonify({"status": "ok"})
        resp.headers.update({
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Headers": "Content-Type,Accept",
            "Access-Control-Allow-Methods": "POST,OPTIONS",
        })
        return resp, 200

    conn = get_cloud_conn()
    if not conn:
        return jsonify({"success": False, "error": "Database unavailable"}), 503

    cur = None
    try:
        data = request.get_json(force=True)

        # ── Validation ────────────────────────────────────────────────────────
        required = ["full_name","contact_number","address","details","town","barangay"]
        for f in required:
            if not (data.get(f) or "").strip():
                return jsonify({"success": False, "error": f"Missing field: {f}"}), 400

        contact = data["contact_number"].strip()
        if not re.match(r"^09\d{9}$", contact):
            return jsonify({"success": False, "error": "Contact must be 09XXXXXXXXX"}), 400

        email = data.get("email", "").strip()
        if email and not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            return jsonify({"success": False, "error": "Invalid email"}), 400

        try:
            lat = float(data["latitude"])
            lng = float(data["longitude"])
            if not (4.0 <= lat <= 21.0 and 116.0 <= lng <= 127.0):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            return jsonify({"success": False, "error": "Invalid or missing coordinates"}), 400

        # ── Sanitise ──────────────────────────────────────────────────────────
        def s(k, default=""):
            return html.escape((data.get(k) or default).strip())

        full_name      = s("full_name")
        address        = s("address")
        town           = s("town")
        barangay       = s("barangay")
        details        = s("details")
        landmark       = s("landmark")
        account_number = s("account_number")
        incident_type  = data.get("incident_type", "power_outage")
        source         = data.get("source", "Web Form")
        incident_time  = data.get("incident_time")
        duration       = data.get("duration")

        if incident_type == "sdi_problem":
            priority = "MEDIUM"
        else:
            priority = classify_priority(details)
            if incident_type in ("fallen_wire","fire_hazard","transformer_issue","sparking"):
                priority = "CRITICAL"

        # ── Verify feeder server-side ─────────────────────────────────────────
        feeder_name = None
        raw_feeder  = (data.get("feeder_name") or "").strip()
        FT, FC, EXC = _ft(), _fc(), _exc()

        if raw_feeder:
            cur = conn.cursor()
            cur.execute(f"SELECT 1 FROM {FT} WHERE {FC}=%s LIMIT 1", (raw_feeder,))
            if cur.fetchone():
                feeder_name = raw_feeder
            cur.close()
            cur = None

        cur = conn.cursor(cursor_factory=RealDictCursor)

        # ── Duplicate guard (same contact, <100 m, last 5 min) ────────────────
        cur.execute("""
            SELECT report_id FROM outage_reports
            WHERE contact_number = %s
              AND ST_DWithin(geom::geography,
                    ST_SetSRID(ST_MakePoint(%s,%s),4326)::geography, 100)
              AND timestamp > TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP) - INTERVAL '5 minutes'
            LIMIT 1
        """, (contact, lng, lat))
        dup = cur.fetchone()
        if dup:
            return jsonify({"success": False,
                            "error": "Duplicate report — please wait 5 minutes before resubmitting.",
                            "existing_report_id": dup["report_id"]}), 429

        # ── Find / create incident cluster ────────────────────────────────────
        cur.execute("""
            SELECT incident_id, priority FROM outage_incidents
            WHERE barangay=%s AND town=%s AND status IN ('NEW','ASSIGNED')
            ORDER BY first_report_time DESC LIMIT 1
        """, (barangay, town))
        existing = cur.fetchone()

        rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        if existing:
            incident_id    = existing["incident_id"]
            merged_priority = existing["priority"] if rank.get(existing["priority"], 0) >= rank.get(priority, 0) else priority
            cur.execute("""
                UPDATE outage_incidents
                SET report_count=report_count+1, priority=%s,
                    last_report_time=TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP),
                    updated_at=TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP)
                WHERE incident_id=%s
            """, (merged_priority, incident_id))
        else:
            job_order = f"JO-{datetime.now():%Y%m%d}-{barangay[:3].upper()}-{uuid.uuid4().hex[:4].upper()}"
            cur.execute("""
                INSERT INTO outage_incidents
                  (incident_type, barangay, town, report_count, confidence_level,
                   status, priority, first_report_time, last_report_time,
                   job_order_id, geom, created_at, updated_at)
                VALUES (%s,%s,%s,1,'UNVERIFIED','NEW',%s,
                        TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP),
                        TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP),
                        %s, ST_SetSRID(ST_MakePoint(%s,%s),4326),
                        TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP),
                        TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP))
                RETURNING incident_id
            """, (incident_type, barangay, town, priority, job_order, lng, lat))
            incident_id = cur.fetchone()["incident_id"]

        # ── Insert consumer report ────────────────────────────────────────────
        cur.execute("""
            INSERT INTO outage_reports
              (incident_id, full_name, contact_number, email, account_number,
               address, town, barangay, details, landmark,
               incident_type, affected_area, incident_time, duration,
               priority, status, source, feeder_name,
               timestamp, status_changed_at,
               geom)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'NEW',%s,%s,
                    TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP),
                    TIMEZONE('Asia/Manila',CURRENT_TIMESTAMP),
                    ST_SetSRID(ST_MakePoint(%s,%s),4326))
            RETURNING report_id,
                      timestamp AT TIME ZONE 'Asia/Manila' AS local_ts
        """, (incident_id, full_name, contact, email, account_number,
              address, town, barangay, details, landmark,
              incident_type, data.get("affected_area","unknown"),
              incident_time, duration,
              priority, source, feeder_name, lng, lat))

        result = cur.fetchone()
        conn.commit()

        logger.info("✅ Report %s saved (incident=%s feeder=%s priority=%s)",
                    result["report_id"], incident_id, feeder_name, priority)

        # ── WebSocket broadcast ───────────────────────────────────────────────
        try:
            from app import socketio
            socketio.emit("new_report", {
                "report_id":   result["report_id"],
                "incident_id": incident_id,
                "town": town, "barangay": barangay,
                "feeder_name": feeder_name,
                "priority":    priority,
                "type":        incident_type,
                "timestamp":   isoformat_safe(result["local_ts"]),
            })
            socketio.emit("stats_update", {"trigger": "new_report"})
        except Exception:
            pass

        return jsonify({
            "success":     True,
            "message":     "Report submitted successfully",
            "report_id":   result["report_id"],
            "incident_id": incident_id,
            "priority":    priority,
            "feeder_name": feeder_name,
        }), 201

    except Exception:
        if conn: conn.rollback()
        logger.exception("submit_power_outage critical error")
        return jsonify({"success": False, "error": "Submission failed — please try again"}), 500
    finally:
        if cur:  cur.close()
        if conn: release_cloud_conn(conn)