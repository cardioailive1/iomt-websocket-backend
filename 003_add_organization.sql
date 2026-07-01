-- migrations/003_create_organizations.sql
-- Canonical organization registry with admin-managed allowed email domains.
-- Run this AFTER 001_create_users.sql and 002_create_large_devices.sql
-- (if you have that one) on your existing database.
--
-- This does NOT touch the existing `users.organization` text column —
-- that stays as-is for display purposes. This table is the source of
-- truth for "which email domains are allowed to self-register under
-- this organization name."

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS organizations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT UNIQUE NOT NULL,
    name_normalized  TEXT UNIQUE NOT NULL,   -- lower(trim(name)), used for signup lookups
    allowed_domains  TEXT[] NOT NULL DEFAULT '{}',
    auto_registered  BOOLEAN NOT NULL DEFAULT FALSE,  -- true if created implicitly by first signup
    created_by       UUID REFERENCES users(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_organizations_name_normalized ON organizations (name_normalized);

COMMIT;
