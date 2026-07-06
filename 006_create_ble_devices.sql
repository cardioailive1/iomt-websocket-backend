-- migrations/006_create_ble_devices.sql
-- Persists patient-paired BLE wearables to the database (previously they
-- only lived in the backend's in-memory DeviceSessionRegistry and vanished
-- on every restart/redeploy). Also adds the organization link that BLE
-- devices were missing — patients self-pair via the app, but clinical
-- staff must then "claim"/configure the device for their hospital so its
-- alerts route to the correct FHIR/HL7 destination, exactly like implants
-- already do via large_devices.organization_id (migration 005).

BEGIN;

CREATE TABLE IF NOT EXISTS ble_devices (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id             TEXT UNIQUE NOT NULL,   -- BLE peripheral UUID from the app
    device_type           TEXT NOT NULL,          -- ecg_monitor | bp_monitor | pulse_oximeter | activity_tracker | ...
    device_name           TEXT,                   -- friendly name, e.g. "Polar H10"
    patient_id            TEXT NOT NULL,           -- the patient's own patient_id (users.patient_id)
    paired_by_user_id     UUID REFERENCES users(id),  -- the patient who self-paired it
    organization_id       UUID REFERENCES organizations(id),  -- set by clinical staff — null until configured
    configured_by_user_id UUID REFERENCES users(id),          -- which clinician configured it
    configured_at         TIMESTAMPTZ,
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    last_data_at          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ble_devices_patient_id      ON ble_devices (patient_id);
CREATE INDEX IF NOT EXISTS idx_ble_devices_organization_id ON ble_devices (organization_id);
CREATE INDEX IF NOT EXISTS idx_ble_devices_unconfigured    ON ble_devices (organization_id) WHERE organization_id IS NULL;

COMMIT;
