-- scripts/init_local_db.sql
-- Run once on the local PostgreSQL instance (ileco1_user database)
-- psql -U postgres -d ileco1_user -f scripts/init_local_db.sql

BEGIN;

-- ── Users ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(50) NOT NULL UNIQUE,
    full_name       VARCHAR(120),
    password_hash   TEXT NOT NULL,
    role            VARCHAR(20) NOT NULL DEFAULT 'staff'
                        CHECK (role IN ('staff', 'admin', 'superadmin')),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_role     ON users (role);

-- ── Agent queue ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_queue (
    id              SERIAL PRIMARY KEY,
    user_id         TEXT,                          -- Facebook Messenger user ID
    full_name       VARCHAR(200) NOT NULL,
    contact_number  VARCHAR(30),
    concern         TEXT,
    priority        VARCHAR(20) NOT NULL DEFAULT 'medium'
                        CHECK (priority IN ('critical','high','medium','low')),
    status          VARCHAR(20) NOT NULL DEFAULT 'Pending'
                        CHECK (status IN ('Pending','Resolved')),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    served_at       TIMESTAMPTZ,
    served_by       TEXT                           -- full_name of the agent who served
);

CREATE INDEX IF NOT EXISTS idx_queue_status    ON agent_queue (status);
CREATE INDEX IF NOT EXISTS idx_queue_timestamp ON agent_queue (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_queue_user_id   ON agent_queue (user_id);

-- ── Seed: first superadmin (password: Admin@1234 — change immediately) ────
INSERT INTO users (username, full_name, password_hash, role)
VALUES (
    'admin',
    'System Administrator',
    -- bcrypt of 'Admin@1234' — regenerate with generate_password_hash() in prod
    '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36X8vhYEGFSWCJRXBp62ld2',
    'superadmin'
)
ON CONFLICT (username) DO NOTHING;

COMMIT;