-- scripts/seed_dev.sql
-- Safe to run multiple times (ON CONFLICT DO NOTHING everywhere).
-- Run AFTER init_local_db.sql and init_cloud_db.sql.
--
-- Local DB:
--   psql -U postgres -d ileco1_user -f scripts/seed_dev.sql
--
-- Cloud DB (Supabase SQL editor — paste the second section manually):

-- ═══════════════════════════════════════════════════════════════
-- SECTION 1 — LOCAL DB  (ileco1_user)
-- ═══════════════════════════════════════════════════════════════

BEGIN;

-- Seed users (passwords are bcrypt of the plain-text shown in comments)
INSERT INTO users (username, full_name, password_hash, role, is_active)
VALUES
  -- password: Admin@1234
  ('admin',    'System Administrator',
   '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36X8vhYEGFSWCJRXBp62ld2',
   'superadmin', TRUE),
  -- password: Staff@1234
  ('juana',    'Juana dela Cruz',
   '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtGkLHrV3s0X5q6X7k5X8v9Y0Z1A',
   'staff', TRUE),
  -- password: Staff@1234
  ('pedro',    'Pedro Reyes',
   '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtGkLHrV3s0X5q6X7k5X8v9Y0Z1A',
   'staff', TRUE)
ON CONFLICT (username) DO NOTHING;

-- Seed agent queue items
INSERT INTO agent_queue (user_id, full_name, contact_number, concern, priority, status, timestamp)
VALUES
  ('fb_001', 'Maria Santos',  '09171234567', 'No power since 6am in Barangay Ungka', 'high',   'Pending',  NOW() - INTERVAL '2 hours'),
  ('fb_002', 'Jose Reyes',    '09281234567', 'Meter running fast, consumption doubled', 'medium','Pending',  NOW() - INTERVAL '1 hour'),
  ('fb_003', 'Ana Garcia',    '09391234567', 'Sparking wire near our gate', 'critical', 'Pending',  NOW() - INTERVAL '30 minutes'),
  ('fb_004', 'Luis Bautista', '09451234567', 'Power restored thank you', 'low',     'Resolved', NOW() - INTERVAL '3 hours')
ON CONFLICT DO NOTHING;

COMMIT;

-- ═══════════════════════════════════════════════════════════════
-- SECTION 2 — CLOUD DB  (Supabase — paste in SQL editor)
-- ═══════════════════════════════════════════════════════════════

-- NOTE: Run this in the Supabase SQL editor, NOT via psql locally.
-- Replace lat/lng values with real Iloilo coordinates as needed.

/*
BEGIN;

-- Sample incident cluster 1 — Pavia
INSERT INTO outage_incidents
  (incident_type, barangay, town, report_count, confidence_level,
   status, priority, first_report_time, last_report_time,
   job_order_id, geom, created_at, updated_at)
VALUES (
  'power_outage', 'Ungka I', 'Pavia', 3, 'VERIFIED',
  'NEW', 'HIGH',
  NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour',
  'JO-20260513-UNG-A1B2',
  ST_SetSRID(ST_MakePoint(122.5621, 10.7890), 4326),
  NOW() - INTERVAL '2 hours', NOW() - INTERVAL '1 hour'
);

-- Sample incident cluster 2 — Oton (critical)
INSERT INTO outage_incidents
  (incident_type, barangay, town, report_count, confidence_level,
   status, priority, first_report_time, last_report_time,
   job_order_id, geom, created_at, updated_at)
VALUES (
  'fallen_wire', 'Poblacion', 'Oton', 7, 'VERIFIED',
  'ASSIGNED', 'CRITICAL',
  NOW() - INTERVAL '4 hours', NOW() - INTERVAL '30 minutes',
  'JO-20260513-POB-C3D4',
  ST_SetSRID(ST_MakePoint(122.4778, 10.6934), 4326),
  NOW() - INTERVAL '4 hours', NOW() - INTERVAL '30 minutes'
);

-- Sample consumer reports for incident 1 (adjust incident_id after insert)
-- INSERT INTO outage_reports ...

-- Sample meter concerns
INSERT INTO meter_concerns
  (reference_number, account_number, consumer_name, contact_number,
   meter_number, service_address, barangay, concern_type,
   date_noticed, is_critical, priority, status, created_at, updated_at)
VALUES
  ('MC-20260513-DEV0001', '1234567890', 'Maria Santos', '09171234567',
   'M-001234', '123 Rizal St', 'Ungka I', 'not_working',
   '2026-05-12', FALSE, 'high', 'PENDING', NOW(), NOW()),
  ('MC-20260513-DEV0002', '0987654321', 'Jose Reyes',   '09281234567',
   'M-005678', '45 Mabini Ave', 'Poblacion', 'noise_burning',
   '2026-05-13', TRUE,  'critical', 'PENDING', NOW(), NOW())
ON CONFLICT (reference_number) DO NOTHING;

COMMIT;
*/