# db.py (patched)
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import asyncpg
import bcrypt

logger = logging.getLogger("cardioai.db")


class UserRole(str, Enum):
    PATIENT      = "patient"
    NURSE        = "nurse"
    CARDIOLOGIST = "cardiologist"
    ADMIN        = "admin"


@dataclass
class HospitalUser:
    id:            str
    email:         str
    name:          str
    role:          UserRole
    patient_id:    Optional[str]
    password_hash: str = field(repr=False)
    organization:  str = ""
    apple_user_id: Optional[str] = None
    is_active:     bool = True
    mfa_secret:    Optional[str] = field(default=None, repr=False)

    def verify_password(self, plain: str) -> bool:
        if not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), self.password_hash.encode("utf-8"))
        except Exception:
            return False

    @classmethod
    def from_row(cls, row: asyncpg.Record) -> "HospitalUser":
        # PATCHED: defensive against schema drift — uses .get()-with-default
        # via explicit key membership checks instead of row["col"] direct
        # indexing, so a column that doesn't exist in your actual migration
        # (e.g. no apple_user_id / mfa_secret / organization column) no
        # longer crashes every single request that loads a user with a
        # raw, unhandled KeyError.
        keys = row.keys()
        return cls(
            id            = str(row["id"]),
            email         = row["email"],
            name          = row["name"] if "name" in keys else (
                              row["full_name"] if "full_name" in keys else ""
                           ),
            role          = UserRole(row["role"]),
            patient_id    = row["patient_id"] if "patient_id" in keys else None,
            password_hash = row["password_hash"] or "",
            organization  = row["organization"] if "organization" in keys else "",
            apple_user_id = row["apple_user_id"] if "apple_user_id" in keys else (
                              row["apple_sub"] if "apple_sub" in keys else None
                           ),
            is_active     = row["is_active"],
            mfa_secret    = row["mfa_secret"] if "mfa_secret" in keys else None,
        )


class Database:
    def __init__(self, dsn: Optional[str] = None) -> None:
        self._dsn = dsn or os.environ.get("DATABASE_URL", "")
        self._pool: Optional[asyncpg.Pool] = None

    @property
    def is_connected(self) -> bool:
        return self._pool is not None

    async def connect(self) -> None:
        if not self._dsn:
            raise RuntimeError("DATABASE_URL is not set.")
        dsn = self._dsn.replace("postgres://", "postgresql://", 1)
        self._pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10, command_timeout=10)
        logger.info("[DB] connection pool established")

    async def disconnect(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            logger.info("[DB] connection pool closed")

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("Database not connected — call connect() first")
        return self._pool

    async def get_user_by_email(self, email: str) -> Optional[HospitalUser]:
        pool = self._require_pool()
        row = await pool.fetchrow("SELECT * FROM users WHERE email = $1", email.lower().strip())
        return HospitalUser.from_row(row) if row else None

    async def get_user_by_id(self, user_id: str) -> Optional[HospitalUser]:
        pool = self._require_pool()
        try:
            row = await pool.fetchrow("SELECT * FROM users WHERE id = $1::uuid", user_id)
        except (ValueError, asyncpg.DataError):
            return None
        return HospitalUser.from_row(row) if row else None

    async def get_user_by_apple_id(self, apple_user_id: str) -> Optional[HospitalUser]:
        pool = self._require_pool()
        row = await pool.fetchrow("SELECT * FROM users WHERE apple_user_id = $1", apple_user_id)
        return HospitalUser.from_row(row) if row else None

    async def get_patient_by_patient_id(self, patient_id: str) -> Optional[HospitalUser]:
        """
        Look up a patient by their patient_id (not their user UUID). Used
        to validate a clinician-entered patient_id before registering a
        device on that patient's behalf — a typo shouldn't silently create
        a device tied to a nonexistent patient record.
        """
        pool = self._require_pool()
        row = await pool.fetchrow("SELECT * FROM users WHERE patient_id = $1 AND role = 'patient'", patient_id)
        return HospitalUser.from_row(row) if row else None

    async def create_patient_from_apple(self, apple_user_id: str, email: str, name: str) -> HospitalUser:
        pool = self._require_pool()
        row = await pool.fetchrow(
            """
            INSERT INTO users (email, name, role, patient_id, apple_user_id, password_hash, is_active)
            VALUES ($1, $2, 'patient', $3, $4, '', true)
            ON CONFLICT (email) DO UPDATE SET apple_user_id = EXCLUDED.apple_user_id
            RETURNING *
            """,
            email, name, apple_user_id, apple_user_id,
        )
        logger.info("[DB] provisioned patient via Apple: %s", email)
        return HospitalUser.from_row(row)

    async def update_last_login(self, user_id: str) -> None:
        pool = self._require_pool()
        await pool.execute("UPDATE users SET last_login_at = now() WHERE id = $1::uuid", user_id)

    async def list_users(self, role: Optional[UserRole] = None, limit: int = 100, offset: int = 0) -> List[HospitalUser]:
        pool = self._require_pool()
        if role is not None:
            rows = await pool.fetch(
                "SELECT * FROM users WHERE role = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                role.value, limit, offset,
            )
        else:
            rows = await pool.fetch("SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
        return [HospitalUser.from_row(r) for r in rows]

    async def set_user_active(self, user_id: str, is_active: bool) -> bool:
        pool = self._require_pool()
        result = await pool.execute("UPDATE users SET is_active = $1 WHERE id = $2::uuid", is_active, user_id)
        return result != "UPDATE 0"

    async def set_user_role(self, user_id: str, role: UserRole) -> bool:
        pool = self._require_pool()
        result = await pool.execute("UPDATE users SET role = $1 WHERE id = $2::uuid", role.value, user_id)
        return result != "UPDATE 0"

    async def get_organization_domains(self, organization: str) -> List[str]:
        """
        LEGACY fallback (pre-organizations-table heuristic): return the
        distinct email domains already used by accounts registered under
        this organization name (case-insensitive match on organization).
        Only used by signup() when no canonical `organizations` row exists
        yet for this name — see get_organization_by_name() below, which is
        checked first.
        """
        pool = self._require_pool()
        rows = await pool.fetch(
            """
            SELECT DISTINCT lower(split_part(email, '@', 2)) AS domain
            FROM users
            WHERE lower(organization) = lower($1) AND organization IS NOT NULL AND organization != ''
            """,
            organization.strip(),
        )
        return [r["domain"] for r in rows if r["domain"]]

    # ── Canonical organization registry ─────────────────────────────────────

    @staticmethod
    def _normalize_org_name(name: str) -> str:
        return " ".join(name.strip().lower().split())

    async def get_organization_by_name(self, name: str) -> Optional["Organization"]:
        """Look up a canonical organization record by name (case/whitespace-insensitive)."""
        pool = self._require_pool()
        row = await pool.fetchrow(
            "SELECT * FROM organizations WHERE name_normalized = $1",
            self._normalize_org_name(name),
        )
        return Organization.from_row(row) if row else None

    async def get_organization_by_id(self, org_id: str) -> Optional["Organization"]:
        pool = self._require_pool()
        try:
            row = await pool.fetchrow("SELECT * FROM organizations WHERE id = $1::uuid", org_id)
        except (ValueError, asyncpg.DataError):
            return None
        return Organization.from_row(row) if row else None

    async def list_organizations(self) -> List["Organization"]:
        pool = self._require_pool()
        rows = await pool.fetch("SELECT * FROM organizations ORDER BY name ASC")
        return [Organization.from_row(r) for r in rows]

    async def create_organization(
        self, name: str, allowed_domains: Optional[List[str]] = None,
        created_by: Optional[str] = None, auto_registered: bool = False,
    ) -> "Organization":
        """
        Create a canonical organization record.

        auto_registered=True  — implicitly created by the first signup under
                                 this name (no admin action yet); the founding
                                 email's domain becomes its only allowed domain.
        auto_registered=False — explicitly created by an admin via
                                 POST /admin/organizations, who sets the
                                 allowed domain list directly.
        """
        pool = self._require_pool()
        domains = sorted({d.strip().lower() for d in (allowed_domains or []) if d.strip()})
        row = await pool.fetchrow(
            """
            INSERT INTO organizations (name, name_normalized, allowed_domains, auto_registered, created_by)
            VALUES ($1, $2, $3, $4, $5::uuid)
            RETURNING *
            """,
            name.strip(), self._normalize_org_name(name), domains, auto_registered, created_by,
        )
        return Organization.from_row(row)

    async def update_organization(
        self, org_id: str, allowed_domains: Optional[List[str]] = None, name: Optional[str] = None,
        fhir_enabled: Optional[bool] = None, fhir_base_url: Optional[str] = None,
        fhir_token_url: Optional[str] = None, fhir_client_id: Optional[str] = None,
        fhir_client_secret: Optional[str] = None, fhir_patient_identifier_system: Optional[str] = None,
        fhir_min_alert_level: Optional[str] = None,
    ) -> Optional["Organization"]:
        """
        Admin-only: update an organization's allowed domains, name, and/or
        per-hospital FHIR write-back configuration (requires migration 005).
        Only the fields explicitly passed (not None) are updated.
        """
        pool = self._require_pool()
        sets, params = [], []
        idx = 1
        if allowed_domains is not None:
            domains = sorted({d.strip().lower() for d in allowed_domains if d.strip()})
            sets.append(f"allowed_domains = ${idx}"); params.append(domains); idx += 1
        if name is not None:
            sets.append(f"name = ${idx}"); params.append(name.strip()); idx += 1
            sets.append(f"name_normalized = ${idx}"); params.append(self._normalize_org_name(name)); idx += 1
        if fhir_enabled is not None:
            sets.append(f"fhir_enabled = ${idx}"); params.append(fhir_enabled); idx += 1
        if fhir_base_url is not None:
            sets.append(f"fhir_base_url = ${idx}"); params.append(fhir_base_url); idx += 1
        if fhir_token_url is not None:
            sets.append(f"fhir_token_url = ${idx}"); params.append(fhir_token_url); idx += 1
        if fhir_client_id is not None:
            sets.append(f"fhir_client_id = ${idx}"); params.append(fhir_client_id); idx += 1
        if fhir_client_secret is not None:
            sets.append(f"fhir_client_secret = ${idx}"); params.append(fhir_client_secret); idx += 1
        if fhir_patient_identifier_system is not None:
            sets.append(f"fhir_patient_identifier_system = ${idx}"); params.append(fhir_patient_identifier_system); idx += 1
        if fhir_min_alert_level is not None:
            sets.append(f"fhir_min_alert_level = ${idx}"); params.append(fhir_min_alert_level); idx += 1
        if not sets:
            return await self.get_organization_by_id(org_id)
        sets.append("updated_at = now()")
        params.append(org_id)
        query = f"UPDATE organizations SET {', '.join(sets)} WHERE id = ${idx}::uuid RETURNING *"
        row = await pool.fetchrow(query, *params)
        return Organization.from_row(row) if row else None

    async def create_staff_user(
        self, email: str, name: str, role: UserRole, password_hash: str,
        organization: str = "", is_active: bool = True,
    ) -> HospitalUser:
        pool = self._require_pool()
        row = await pool.fetchrow(
            """
            INSERT INTO users (email, name, organization, role, password_hash, is_active)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            """,
            email.lower().strip(), name, organization, role.value, password_hash, is_active,
        )
        return HospitalUser.from_row(row)

    async def issue_refresh_token(self, user_id: str, ttl_seconds: int) -> str:
        import secrets as _secrets
        pool = self._require_pool()
        token_id = _secrets.token_urlsafe(48)
        await pool.execute(
            "INSERT INTO refresh_tokens (token_id, user_id, expires_at) VALUES ($1, $2::uuid, now() + ($3 || ' seconds')::interval)",
            token_id, user_id, str(ttl_seconds),
        )
        return token_id

    async def consume_refresh_token(self, token_id: str) -> Optional[str]:
        pool = self._require_pool()
        row = await pool.fetchrow(
            "DELETE FROM refresh_tokens WHERE token_id = $1 AND expires_at > now() RETURNING user_id",
            token_id,
        )
        return str(row["user_id"]) if row else None

    async def revoke_all_refresh_tokens(self, user_id: str) -> int:
        pool = self._require_pool()
        result = await pool.execute("DELETE FROM refresh_tokens WHERE user_id = $1::uuid", user_id)
        try:
            return int(result.split()[-1])
        except (ValueError, IndexError):
            return 0

    async def purge_expired_refresh_tokens(self) -> int:
        pool = self._require_pool()
        result = await pool.execute("DELETE FROM refresh_tokens WHERE expires_at <= now()")
        try:
            return int(result.split()[-1])
        except (ValueError, IndexError):
            return 0

    async def log_event(self, event_type: str, user_id: Optional[str] = None, ip_address: Optional[str] = None, detail: Optional[str] = None) -> None:
        pool = self._require_pool()
        try:
            await pool.execute(
                "INSERT INTO audit_log (user_id, event_type, ip_address, detail) VALUES ($1::uuid, $2, $3, $4)",
                user_id, event_type, ip_address, detail,
            )
        except Exception as exc:
            logger.warning("[DB] audit log write failed: %s", exc)

    async def register_large_device(
        self, vendor_device_id: str, vendor: str, device_type: str, patient_id: str,
        model_number: Optional[str] = None, implanted_at: Optional[str] = None,
        implanting_clinician_id: Optional[str] = None, registered_by_user_id: Optional[str] = None,
        vendor_account_ref: Optional[str] = None, notes: Optional[str] = None,
        organization_id: Optional[str] = None,
    ) -> "LargeDevice":
        """
        organization_id links this device to the organization of the
        clinician who registered it — see migration 005. Required for
        multi-hospital FHIR routing in CommunicationAgent; alerts from a
        device with no organization_id fall back to the global FHIR_*
        environment variables (single-tenant behavior).
        """
        pool = self._require_pool()
        row = await pool.fetchrow(
            """
            INSERT INTO large_devices (
                vendor_device_id, vendor, device_type, patient_id,
                model_number, implanted_at, implanting_clinician_id,
                registered_by_user_id, vendor_account_ref, notes, organization_id
            )
            VALUES ($1, $2, $3, $4, $5, $6::date, $7::uuid, $8::uuid, $9, $10, $11::uuid)
            ON CONFLICT (vendor_device_id) DO UPDATE
                SET patient_id = EXCLUDED.patient_id, is_active = true,
                    organization_id = COALESCE(EXCLUDED.organization_id, large_devices.organization_id)
            RETURNING *
            """,
            vendor_device_id, vendor, device_type, patient_id,
            model_number, implanted_at, implanting_clinician_id,
            registered_by_user_id, vendor_account_ref, notes, organization_id,
        )
        return LargeDevice.from_row(row)

    async def get_large_device_by_vendor_id(self, vendor_device_id: str) -> Optional["LargeDevice"]:
        pool = self._require_pool()
        row = await pool.fetchrow("SELECT * FROM large_devices WHERE vendor_device_id = $1", vendor_device_id)
        return LargeDevice.from_row(row) if row else None

    async def list_large_devices(self, patient_id: Optional[str] = None, vendor: Optional[str] = None, limit: int = 100, offset: int = 0) -> List["LargeDevice"]:
        pool = self._require_pool()
        conditions = []
        params: List[Any] = []
        if patient_id:
            params.append(patient_id)
            conditions.append(f"patient_id = ${len(params)}")
        if vendor:
            params.append(vendor)
            conditions.append(f"vendor = ${len(params)}")
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])
        rows = await pool.fetch(
            f"SELECT * FROM large_devices {where} ORDER BY created_at DESC LIMIT ${len(params)-1} OFFSET ${len(params)}",
            *params,
        )
        return [LargeDevice.from_row(r) for r in rows]

    async def set_large_device_active(self, device_id: str, is_active: bool) -> bool:
        pool = self._require_pool()
        result = await pool.execute("UPDATE large_devices SET is_active = $1 WHERE id = $2::uuid", is_active, device_id)
        return result != "UPDATE 0"

    async def touch_large_device_last_event(self, vendor_device_id: str) -> None:
        pool = self._require_pool()
        await pool.execute("UPDATE large_devices SET last_event_at = now() WHERE vendor_device_id = $1", vendor_device_id)

    async def verify_vendor_api_key(self, raw_key: str) -> Optional[str]:
        import hashlib as _hashlib
        pool = self._require_pool()
        key_hash = _hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        row = await pool.fetchrow("SELECT vendor, is_active FROM vendor_api_keys WHERE key_hash = $1", key_hash)
        if row is None or not row["is_active"]:
            return None
        await pool.execute("UPDATE vendor_api_keys SET last_used_at = now() WHERE key_hash = $1", key_hash)
        return row["vendor"]

    async def create_vendor_api_key(self, vendor: str, label: str = "") -> tuple[str, str]:
        import hashlib as _hashlib
        import secrets as _secrets
        pool = self._require_pool()
        raw_key = _secrets.token_urlsafe(40)
        key_hash = _hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        row = await pool.fetchrow(
            "INSERT INTO vendor_api_keys (vendor, key_hash, label, is_active) VALUES ($1, $2, $3, true) RETURNING id",
            vendor, key_hash, label,
        )
        return raw_key, str(row["id"])

    async def log_vendor_event(
        self, vendor: str, raw_payload: Dict[str, Any], vendor_device_id: Optional[str] = None,
        large_device_id: Optional[str] = None, matched: bool = False, kafka_published: bool = False,
    ) -> None:
        import json as _json
        pool = self._require_pool()
        try:
            await pool.execute(
                """
                INSERT INTO vendor_events_raw
                    (vendor, vendor_device_id, large_device_id, raw_payload, matched, kafka_published)
                VALUES ($1, $2, $3::uuid, $4::jsonb, $5, $6)
                """,
                vendor, vendor_device_id, large_device_id,
                _json.dumps(raw_payload), matched, kafka_published,
            )
        except Exception as exc:
            logger.warning("[DB] vendor event audit write failed: %s", exc)

    # ── Patient-paired BLE devices ───────────────────────────────────────
    #
    # Persists what previously only lived in the in-memory
    # DeviceSessionRegistry — BLE pairings now survive restarts, and
    # clinical staff can query/configure them (assign an organization)
    # after a patient self-pairs. See migration 006.

    async def upsert_ble_device(
        self, device_id: str, device_type: str, patient_id: str,
        device_name: Optional[str] = None, paired_by_user_id: Optional[str] = None,
        organization_id: Optional[str] = None, configured_by_user_id: Optional[str] = None,
    ) -> "BLEDevice":
        """
        Called from POST /devices/register — used by BOTH paths:

        - Patient self-pairing (organization_id=None): re-pairing an
          already-known device_id updates its type/name/active status but
          deliberately does NOT touch organization_id — once clinical staff
          have configured a device for their hospital, a patient simply
          re-pairing it shouldn't silently un-configure it.

        - Clinician registering on a patient's behalf (e.g. an unconscious
          patient who can't use their own phone) — organization_id IS
          provided and set immediately, since the registering clinician's
          own hospital affiliation is already known at registration time.
          No separate "configure" step is needed afterward for this path.
        """
        pool = self._require_pool()
        row = await pool.fetchrow(
            """
            INSERT INTO ble_devices (
                device_id, device_type, device_name, patient_id, paired_by_user_id,
                organization_id, configured_by_user_id, configured_at
            )
            VALUES ($1, $2, $3, $4, $5::uuid, $6::uuid, $7::uuid, CASE WHEN $6::uuid IS NOT NULL THEN now() ELSE NULL END)
            ON CONFLICT (device_id) DO UPDATE
                SET device_type = EXCLUDED.device_type,
                    device_name = COALESCE(EXCLUDED.device_name, ble_devices.device_name),
                    patient_id  = EXCLUDED.patient_id,
                    is_active   = true,
                    updated_at  = now(),
                    organization_id       = COALESCE(EXCLUDED.organization_id, ble_devices.organization_id),
                    configured_by_user_id = COALESCE(EXCLUDED.configured_by_user_id, ble_devices.configured_by_user_id),
                    configured_at         = COALESCE(EXCLUDED.configured_at, ble_devices.configured_at)
            RETURNING *
            """,
            device_id, device_type, device_name, patient_id, paired_by_user_id,
            organization_id, configured_by_user_id,
        )
        return BLEDevice.from_row(row)

    async def get_ble_device_by_device_id(self, device_id: str) -> Optional["BLEDevice"]:
        pool = self._require_pool()
        row = await pool.fetchrow("SELECT * FROM ble_devices WHERE device_id = $1", device_id)
        return BLEDevice.from_row(row) if row else None

    async def list_ble_devices(
        self, patient_id: Optional[str] = None, unconfigured_only: bool = False,
    ) -> List["BLEDevice"]:
        pool = self._require_pool()
        conditions, params = [], []
        if patient_id:
            params.append(patient_id)
            conditions.append(f"patient_id = ${len(params)}")
        if unconfigured_only:
            conditions.append("organization_id IS NULL")
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = await pool.fetch(f"SELECT * FROM ble_devices {where} ORDER BY created_at DESC", *params)
        return [BLEDevice.from_row(r) for r in rows]

    async def configure_ble_device(
        self, device_id: str, organization_id: str, configured_by_user_id: str,
    ) -> Optional["BLEDevice"]:
        """Clinical staff action: assign a patient-paired BLE device to their organization."""
        pool = self._require_pool()
        row = await pool.fetchrow(
            """
            UPDATE ble_devices
            SET organization_id = $1::uuid, configured_by_user_id = $2::uuid,
                configured_at = now(), updated_at = now()
            WHERE device_id = $3
            RETURNING *
            """,
            organization_id, configured_by_user_id, device_id,
        )
        return BLEDevice.from_row(row) if row else None

    async def touch_ble_device_last_data(self, device_id: str) -> None:
        pool = self._require_pool()
        await pool.execute(
            "UPDATE ble_devices SET last_data_at = now() WHERE device_id = $1", device_id,
        )


@dataclass
class BLEDevice:
    """A patient-paired BLE wearable, persisted so it survives restarts
    and can be configured (assigned an organization) by clinical staff."""

    id:                    str
    device_id:             str
    device_type:           str
    device_name:           Optional[str]
    patient_id:            str
    paired_by_user_id:     Optional[str]
    organization_id:       Optional[str]
    configured_by_user_id: Optional[str]
    configured_at:         Optional[str]
    is_active:             bool
    last_data_at:          Optional[str]
    created_at:            str

    @classmethod
    def from_row(cls, row: asyncpg.Record) -> "BLEDevice":
        return cls(
            id                    = str(row["id"]),
            device_id             = row["device_id"],
            device_type           = row["device_type"],
            device_name           = row["device_name"],
            patient_id            = row["patient_id"],
            paired_by_user_id     = str(row["paired_by_user_id"]) if row["paired_by_user_id"] else None,
            organization_id       = str(row["organization_id"]) if row["organization_id"] else None,
            configured_by_user_id = str(row["configured_by_user_id"]) if row["configured_by_user_id"] else None,
            configured_at         = str(row["configured_at"]) if row["configured_at"] else None,
            is_active             = row["is_active"],
            last_data_at          = str(row["last_data_at"]) if row["last_data_at"] else None,
            created_at            = str(row["created_at"]),
        )

    @property
    def is_configured(self) -> bool:
        return self.organization_id is not None


@dataclass
class Organization:
    """Canonical organization record — admin-managed allowed email domains
    and, optionally, per-hospital FHIR R4 write-back configuration."""

    id:              str
    name:            str
    name_normalized: str
    allowed_domains: List[str]
    auto_registered: bool
    created_by:      Optional[str]
    created_at:      str
    fhir_enabled:                  bool = False
    fhir_base_url:                 Optional[str] = None
    fhir_token_url:                Optional[str] = None
    fhir_client_id:                Optional[str] = None
    fhir_client_secret:            Optional[str] = None
    fhir_patient_identifier_system: Optional[str] = None
    fhir_min_alert_level:          str = "medium"

    @classmethod
    def from_row(cls, row: asyncpg.Record) -> "Organization":
        keys = row.keys()
        return cls(
            id              = str(row["id"]),
            name            = row["name"],
            name_normalized = row["name_normalized"],
            allowed_domains = list(row["allowed_domains"] or []),
            auto_registered = row["auto_registered"],
            created_by      = str(row["created_by"]) if row["created_by"] else None,
            created_at      = str(row["created_at"]),
            # Defensive: these columns only exist after migration 005.
            # Reading a row before that migration runs should not crash —
            # it should just report FHIR as unconfigured for this org.
            fhir_enabled                   = row["fhir_enabled"] if "fhir_enabled" in keys else False,
            fhir_base_url                  = row["fhir_base_url"] if "fhir_base_url" in keys else None,
            fhir_token_url                 = row["fhir_token_url"] if "fhir_token_url" in keys else None,
            fhir_client_id                 = row["fhir_client_id"] if "fhir_client_id" in keys else None,
            fhir_client_secret             = row["fhir_client_secret"] if "fhir_client_secret" in keys else None,
            fhir_patient_identifier_system = row["fhir_patient_identifier_system"] if "fhir_patient_identifier_system" in keys else None,
            fhir_min_alert_level           = row["fhir_min_alert_level"] if "fhir_min_alert_level" in keys else "medium",
        )

    def has_fhir_config(self) -> bool:
        """True if this org has FHIR enabled AND all required fields set."""
        return bool(
            self.fhir_enabled and self.fhir_base_url and self.fhir_token_url
            and self.fhir_client_id and self.fhir_client_secret
        )


@dataclass
class LargeDevice:

    id:                      str
    vendor_device_id:        str
    vendor:                  str
    device_type:             str
    model_number:            Optional[str]
    patient_id:               str
    implanted_at:             Optional[str]
    implanting_clinician_id:  Optional[str]
    registered_by_user_id:    Optional[str]
    vendor_account_ref:       Optional[str]
    is_active:                bool
    notes:                    Optional[str]
    last_event_at:            Optional[str]
    organization_id:          Optional[str] = None

    @classmethod
    def from_row(cls, row: asyncpg.Record) -> "LargeDevice":
        keys = row.keys()
        return cls(
            id                      = str(row["id"]),
            vendor_device_id        = row["vendor_device_id"],
            vendor                  = row["vendor"],
            device_type             = row["device_type"],
            model_number            = row["model_number"],
            patient_id              = row["patient_id"],
            implanted_at            = str(row["implanted_at"]) if row["implanted_at"] else None,
            implanting_clinician_id = str(row["implanting_clinician_id"]) if row["implanting_clinician_id"] else None,
            registered_by_user_id   = str(row["registered_by_user_id"]) if row["registered_by_user_id"] else None,
            vendor_account_ref      = row["vendor_account_ref"],
            is_active               = row["is_active"],
            notes                   = row["notes"],
            last_event_at           = str(row["last_event_at"]) if row["last_event_at"] else None,
            organization_id         = str(row["organization_id"]) if ("organization_id" in keys and row["organization_id"]) else None,
        )


db = Database()
