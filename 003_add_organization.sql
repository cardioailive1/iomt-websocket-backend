-- migrations/003_add_organization.sql
-- ==============================================================================
-- IoMT CardioAI — Add organization column to users table
-- ==============================================================================
-- Run this AFTER 001_create_users.sql and 002_create_large_devices.sql.
-- Safe to run on a database that already has the users table populated —
-- uses ADD COLUMN IF NOT EXISTS so it won't fail if already applied.
--
-- HOW TO RUN
-- ----------
--   psql "<connection-string>" -f migrations/003_add_organization.sql
-- ==============================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS organization TEXT NOT NULL DEFAULT '';

-- Backfill a sensible default for the three seeded test accounts, if present
UPDATE users SET organization = 'Test Hospital'
WHERE email IN ('patient@hospital.local', 'nurse@hospital.local', 'cardio@hospital.local')
  AND organization = '';

-- ── Verification query ────────────────────────────────────────────────────────
-- Run after migration:
--   SELECT email, organization, role FROM users;
