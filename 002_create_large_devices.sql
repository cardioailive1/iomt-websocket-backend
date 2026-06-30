-- migrations/002_create_large_devices.sql
-- ==============================================================================
-- IoMT CardioAI — Large/Implanted Device Registry Schema
-- ==============================================================================
-- Run this AFTER 001_create_users.sql.
--
-- This schema is for devices a clinician implants/attaches and registers on
-- the patient's behalf — pacemakers, ICDs, implantable loop recorders — as
-- opposed to consumer BLE wearables, which patients self-register via the
-- iOS app's Bluetooth pairing flow (POST /devices/register, unchanged).
--
-- Data path for these devices:
--   Vendor implant/monitor → Vendor's cloud gateway → POST /vendor-gateway/ingest
--   (authenticated by per-vendor API key, NOT a patient JWT)
--   → Kafka topic "iomt.vendor.raw" → consumer normalizes → 7-agent pipeline
--
-- HOW TO RUN
-- ----------
--   psql "<connection-string>" -f migrations/002_create_large_devices.sql
-- ==============================================================================

-- ── Supported vendors ──────────────────────────────────────────────────────────
-- Stored as text with a CHECK constraint (not a Postgres ENUM) so adding a
-- new vendor is a one-line ALTER TABLE instead of an ALTER TYPE migration.

CREATE TABLE IF NOT EXISTS large_devices (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Vendor-assigned identifier for this specific implant/device.
    -- This is what arrives in every gateway payload from the vendor —
    -- it's how we look up which patient a given event belongs to.
    vendor_device_id    TEXT UNIQUE NOT NULL,

    vendor              TEXT NOT NULL CHECK (vendor IN (
                            'medtronic', 'abbott', 'boston_scientific',
                            'biotronik', 'other'
                         )),
    device_type         TEXT NOT NULL CHECK (device_type IN (
                            'pacemaker', 'icd', 'crt_d', 'crt_p',
                            'implantable_loop_recorder', 'other'
                         )),
    model_number         TEXT,

    patient_id           TEXT NOT NULL,            -- links to users.patient_id
    implanted_at          DATE,
    implanting_clinician_id UUID REFERENCES users(id) ON DELETE SET NULL,
    registered_by_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Per-vendor API key used to authenticate THAT vendor's gateway pushes.
    -- One key can cover many devices from the same vendor — this column
    -- exists for audit/lookup convenience, the actual key material lives in
    -- the vendor_api_keys table below, hashed.
    vendor_account_ref    TEXT,

    is_active             BOOLEAN NOT NULL DEFAULT true,
    notes                 TEXT,

    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_event_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_large_devices_patient_id   ON large_devices (patient_id);
CREATE INDEX IF NOT EXISTS idx_large_devices_vendor       ON large_devices (vendor);
CREATE INDEX IF NOT EXISTS idx_large_devices_vendor_dev_id ON large_devices (vendor_device_id);

DROP TRIGGER IF EXISTS trg_large_devices_updated_at ON large_devices;
CREATE TRIGGER trg_large_devices_updated_at
    BEFORE UPDATE ON large_devices
    FOR EACH ROW
    EXECUTE FUNCTION touch_updated_at();

-- ── Vendor API keys ───────────────────────────────────────────────────────────
-- Each vendor's gateway authenticates to POST /vendor-gateway/ingest using
-- a bearer-style API key in the X-Vendor-Api-Key header. Keys are hashed
-- with SHA-256 (fast, deterministic — these are machine-to-machine keys
-- checked on every single ingested event, so bcrypt's deliberate slowness
-- would be the wrong tool here; bcrypt is reserved for human passwords).

CREATE TABLE IF NOT EXISTS vendor_api_keys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor        TEXT NOT NULL CHECK (vendor IN (
                      'medtronic', 'abbott', 'boston_scientific',
                      'biotronik', 'other'
                  )),
    key_hash      TEXT UNIQUE NOT NULL,   -- SHA-256 hex digest of the raw key
    label         TEXT NOT NULL DEFAULT '', -- e.g. "Medtronic CareLink prod gateway"
    is_active     BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_vendor_api_keys_key_hash ON vendor_api_keys (key_hash);

-- ── Vendor event audit table ──────────────────────────────────────────────────
-- Every raw payload received from a vendor gateway is recorded here BEFORE
-- normalization, regardless of whether it was successfully matched to a
-- registered device. This is the audit trail for "what did the vendor
-- actually send us" — separate from the normalized data that flows into
-- Kafka and the 7-agent pipeline.

CREATE TABLE IF NOT EXISTS vendor_events_raw (
    id                BIGSERIAL PRIMARY KEY,
    vendor            TEXT NOT NULL,
    vendor_device_id  TEXT,
    large_device_id   UUID REFERENCES large_devices(id) ON DELETE SET NULL,
    raw_payload       JSONB NOT NULL,
    matched           BOOLEAN NOT NULL DEFAULT false,
    kafka_published   BOOLEAN NOT NULL DEFAULT false,
    received_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vendor_events_raw_device_id   ON vendor_events_raw (large_device_id);
CREATE INDEX IF NOT EXISTS idx_vendor_events_raw_received_at ON vendor_events_raw (received_at);

-- ── Seed a development vendor API key ─────────────────────────────────────────
-- This is a TEST key only — generate and store real per-vendor keys via the
-- POST /admin/vendor-keys endpoint before connecting any real vendor gateway.
--
-- The raw test key value is: "test-vendor-key-do-not-use-in-production"
-- SHA-256 of that string is precomputed below.

INSERT INTO vendor_api_keys (vendor, key_hash, label, is_active)
VALUES (
    'medtronic',
    encode(digest('test-vendor-key-do-not-use-in-production', 'sha256'), 'hex'),
    'Development test key — DO NOT use in production',
    true
)
ON CONFLICT (key_hash) DO NOTHING;

-- ── Verification query ────────────────────────────────────────────────────────
-- Run after migration:
--   SELECT vendor, device_type, patient_id, is_active FROM large_devices;
--   SELECT vendor, label, is_active FROM vendor_api_keys;
