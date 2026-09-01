-- scripts/init_cloud_db.sql
-- Run in the Supabase SQL editor (postgres database)
-- Requires: PostGIS extension enabled in Supabase dashboard first

BEGIN;

-- ── Extensions ────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Outage incidents (one row per cluster) ────────────────────────────────
CREATE TABLE IF NOT EXISTS outage_incidents (
    incident_id         SERIAL PRIMARY KEY,
    incident_type       VARCHAR(50) NOT NULL DEFAULT 'power_outage',
    barangay            VARCHAR(100),
    town                VARCHAR(100),
    report_count        INTEGER NOT NULL DEFAULT 0,
    confidence_level    VARCHAR(20) DEFAULT 'UNVERIFIED',
    status              VARCHAR(20) NOT NULL DEFAULT 'NEW'
                            CHECK (status IN ('NEW','ASSIGNED','RESTORED')),
    priority            VARCHAR(20) NOT NULL DEFAULT 'HIGH'
                            CHECK (priority IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    first_report_time   TIMESTAMPTZ,
    last_report_time    TIMESTAMPTZ,
    job_order_id        VARCHAR(50),
    assigned_at         TIMESTAMPTZ,
    restored_at         TIMESTAMPTZ,
    resolved_at         TIMESTAMPTZ,
    assigned_by         TEXT,
    restored_by         TEXT,
    remarks             TEXT,
    geom                GEOMETRY(Point, 4326),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_status   ON outage_incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_priority  ON outage_incidents (priority);
CREATE INDEX IF NOT EXISTS idx_incidents_barangay  ON outage_incidents (barangay, town);
CREATE INDEX IF NOT EXISTS idx_incidents_geom      ON outage_incidents USING GIST (geom);
CREATE INDEX IF NOT EXISTS idx_incidents_time      ON outage_incidents (first_report_time DESC);

-- ── Individual consumer reports ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS outage_reports (
    report_id           SERIAL PRIMARY KEY,
    incident_id         INTEGER REFERENCES outage_incidents (incident_id) ON DELETE CASCADE,
    full_name           VARCHAR(200),
    contact_number      VARCHAR(30),
    email               VARCHAR(200),
    account_number      VARCHAR(50),
    address             TEXT,
    town                VARCHAR(100),
    barangay            VARCHAR(100),
    details             TEXT,
    landmark            TEXT,
    incident_type       VARCHAR(50) DEFAULT 'power_outage',
    affected_area       VARCHAR(100),
    incident_time       TIME,
    duration            VARCHAR(50),
    priority            VARCHAR(20) DEFAULT 'HIGH',
    status              VARCHAR(20) NOT NULL DEFAULT 'NEW'
                            CHECK (status IN ('NEW','ASSIGNED','RESTORED')),
    source              VARCHAR(50) DEFAULT 'Web Form',
    feeder_name         VARCHAR(50),          -- denormalised from feeder lookup
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status_changed_at   TIMESTAMPTZ,
    assigned_at         TIMESTAMPTZ,
    restored_at         TIMESTAMPTZ,
    geom                GEOMETRY(Point, 4326),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_incident  ON outage_reports (incident_id);
CREATE INDEX IF NOT EXISTS idx_reports_status    ON outage_reports (status);
CREATE INDEX IF NOT EXISTS idx_reports_contact   ON outage_reports (contact_number);
CREATE INDEX IF NOT EXISTS idx_reports_geom      ON outage_reports USING GIST (geom);
CREATE INDEX IF NOT EXISTS idx_reports_timestamp ON outage_reports (timestamp DESC);

-- ── Meter concerns ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS meter_concerns (
    id                  SERIAL PRIMARY KEY,
    reference_number    VARCHAR(40) NOT NULL UNIQUE,
    account_number      VARCHAR(50) NOT NULL,
    consumer_name       VARCHAR(200) NOT NULL,
    contact_number      VARCHAR(30) NOT NULL,
    meter_number        VARCHAR(50),
    service_address     TEXT,
    barangay            VARCHAR(100) NOT NULL,
    concern_type        VARCHAR(50) NOT NULL,
    other_concern       TEXT,
    date_noticed        DATE,
    time_noticed        TIME,
    additional_details  TEXT,
    is_critical         BOOLEAN NOT NULL DEFAULT FALSE,
    priority            VARCHAR(20) NOT NULL DEFAULT 'medium',
    status              VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                            CHECK (status IN ('PENDING','ASSIGNED','IN_PROGRESS','RESOLVED','CLOSED')),
    assigned_to         TEXT,
    resolution_notes    TEXT,
    resolved_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_meter_status    ON meter_concerns (status);
CREATE INDEX IF NOT EXISTS idx_meter_priority  ON meter_concerns (priority);
CREATE INDEX IF NOT EXISTS idx_meter_barangay  ON meter_concerns (barangay);
CREATE INDEX IF NOT EXISTS idx_meter_account   ON meter_concerns (account_number);

-- ── Meter evidence files ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS concern_evidence (
    id                  SERIAL PRIMARY KEY,
    meter_concern_id    INTEGER NOT NULL REFERENCES meter_concerns (id) ON DELETE CASCADE,
    file_name           VARCHAR(255) NOT NULL,
    file_path           TEXT NOT NULL,
    file_type           VARCHAR(100),
    file_size           BIGINT,
    uploaded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_concern ON concern_evidence (meter_concern_id);

-- ── Meter activity log ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS concern_activity_log (
    id                  SERIAL PRIMARY KEY,
    meter_concern_id    INTEGER NOT NULL REFERENCES meter_concerns (id) ON DELETE CASCADE,
    activity_type       VARCHAR(50) NOT NULL,
    performed_by        TEXT,
    description         TEXT,
    old_value           TEXT,
    new_value           TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_concern ON concern_activity_log (meter_concern_id);

COMMIT;