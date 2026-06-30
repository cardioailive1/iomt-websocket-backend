-- migrations/001_create_users.sql
-- ==============================================================================
-- IoMT CardioAI — PostgreSQL Schema
-- ==============================================================================
-- Run this once against your Render PostgreSQL database before first deploy.
--
-- HOW TO RUN
-- ----------
--   Render Dashboard → your Postgres instance → "Connect" → copy the
--   "External Connection String", then:
--
--     psql "<external-connection-string>" -f migrations/001_create_users.sql
--
--   Or paste the contents of this file into Render's built-in
--   "PSQL Command" shell (Dashboard → Postgres instance → Connect → PSQL).
-- ==============================================================================

-- ── Enable UUID generation ─────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Roles ──────────────────────────────────────────────────────────────────────
-- Stored as plain text with a CHECK constraint rather than a Postgres ENUM,
-- so adding a new role later is a one-line migration instead of an ALTER TYPE.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role_check') THEN
        NULL; -- placeholder, constraint applied directly on the column below
    END IF;
END$$;

-- ── users table ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT UNIQUE NOT NULL,
    name            TEXT NOT NULL DEFAULT '',
    role            TEXT NOT NULL CHECK (role IN ('patient', 'nurse', 'cardiologist', 'admin')),
    patient_id      TEXT UNIQUE,              -- set only when role = 'patient'
    password_hash   TEXT NOT NULL DEFAULT '', -- bcrypt hash; empty for Apple-only accounts
    apple_user_id   TEXT UNIQUE,              -- set for accounts created via Sign in with Apple
    is_active       BOOLEAN NOT NULL DEFAULT true,
    mfa_secret      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_email         ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_apple_user_id ON users (apple_user_id);
CREATE INDEX IF NOT EXISTS idx_users_role          ON users (role);

-- ── refresh_tokens table ──────────────────────────────────────────────────────
-- Replaces the in-memory RefreshTokenStore. One row per issued refresh token;
-- consuming a token deletes the row (rotation = delete + insert new row).
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id    TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id    ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);

-- ── audit_log table ───────────────────────────────────────────────────────────
-- Tracks auth events for compliance (login attempts, role changes, etc.)
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type  TEXT NOT NULL,    -- 'login_success' | 'login_failed' | 'role_change' | etc.
    ip_address  TEXT,
    detail      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_user_id    ON audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log (created_at);

-- ── updated_at auto-touch trigger ─────────────────────────────────────────────
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

-- ── Seed three test accounts (matches the old in-memory stub) ─────────────────
-- Password for all three: "changeme_in_prod"
-- Generate your own hash with:
--   python3 -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt(12)).decode())"
--
-- IMPORTANT: change these passwords immediately after first deploy in production.

INSERT INTO users (email, name, role, patient_id, password_hash, is_active)
VALUES
    ('patient@hospital.local', 'John Anderson',    'patient',      'PT_12345', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKWNl3p4hQq9LRC', true),
    ('nurse@hospital.local',   'Sarah Chen',        'nurse',        NULL,       '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKWNl3p4hQq9LRC', true),
    ('cardio@hospital.local',  'Dr. James Okafor',  'cardiologist', NULL,       '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKWNl3p4hQq9LRC', true)
ON CONFLICT (email) DO NOTHING;

-- ── Verification query ────────────────────────────────────────────────────────
-- Run this after the migration to confirm it worked:
--   SELECT id, email, name, role, is_active FROM users;
