-- migrations/005_add_fhir_config_and_device_org_link.sql
-- Enables multi-hospital FHIR routing: each organization can have its own
-- FHIR server config, and implanted devices are linked to the organization
-- of the clinician who registered them, so alerts route to the correct
-- hospital's EHR.
--
-- Scope note: this links ORGANIZATIONS to FHIR config, and DEVICES to
-- organizations. It does not (yet) link BLE-only patients to an
-- organization — only implant-sourced alerts can be routed per-hospital
-- with this migration. BLE-sourced alerts continue to use the global
-- FHIR_* environment variables as a fallback. See README "What's not
-- built yet" for the full picture.

BEGIN;

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS fhir_enabled                   BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS fhir_base_url                  TEXT,
    ADD COLUMN IF NOT EXISTS fhir_token_url                 TEXT,
    ADD COLUMN IF NOT EXISTS fhir_client_id                 TEXT,
    ADD COLUMN IF NOT EXISTS fhir_client_secret              TEXT,
    ADD COLUMN IF NOT EXISTS fhir_patient_identifier_system  TEXT,
    ADD COLUMN IF NOT EXISTS fhir_min_alert_level            TEXT NOT NULL DEFAULT 'medium';

ALTER TABLE large_devices
    ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);

CREATE INDEX IF NOT EXISTS idx_large_devices_organization_id ON large_devices (organization_id);

COMMIT;
