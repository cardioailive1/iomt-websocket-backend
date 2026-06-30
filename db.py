# db.py
# ==============================================================================
# IoMT CardioAI — PostgreSQL Database Layer
# ==============================================================================
#
# Replaces the in-memory _STUB_USERS dict and RefreshTokenStore class with
# real asyncpg-backed Postgres queries. Drop this file alongside
# iomt_cardioai_production.py and import from it.
#
# Required environment variable
# -------------------------------
#   DATABASE_URL   postgres connection string, e.g.
#                   postgresql://user:pass@host:5432/dbname
#                   Render auto-provisions this when you attach a Postgres
#                   database to your service via render.yaml.
#
# Schema
# ------
#   See migrations/001_create_users.sql — run that once before first deploy.
#
# Pool lifecycle
# ---------------
#   Call `await db.connect()` once at startup (in main()), and
#   `await db.disconnect()` on shutdown. A single connection pool is shared
#   across all requests.
# ==============================================================================

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import asyncpg
import bcrypt

logger = logging.getLogger("cardioai.db")


# ============================================================================
# User Role (mirrors the enum in iomt_cardioai_production.py)
# ============================================================================

class UserRole(str, Enum):
    PATIENT      = "patient"
    NURSE        = "nurse"
    CARDIOLOGIST = "cardiologist"
    ADMIN        = "admin"


# ============================================================================
# User Model
# ============================================================================

@dataclass
class HospitalUser:
    """Represents an authenticated user, loaded from Postgres."""

    id:            str
    email:         str
    name:          str
    role:          UserRole
    patient_id:    Optional[str]
    password_hash: str = field(repr=False)
    apple_user_id: Optional[str] = None
    is_active:     bool = True
    mfa_secret:    Optional[str] = field(default=None, repr=False)

    def verify_password(self, plain: str) -> bool:
        """Constant-time bcrypt verification."""
        if not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(
                plain.encode("utf-8"),
                self.password_hash.encode("utf-8"),
            )
        except Exception:
            return False

    @classmethod
    def from_row(cls, row: asyncpg.Record) -> "HospitalUser":
        return cls(
            id            = str(row["id"]),
            email         = row["email"],
            name          = row["name"],
            role          = UserRole(row["role"]),
            patient_id    = row["patient_id"],
            password_hash = row["password_hash"] or "",
            apple_user_id = row["apple_user_id"],
            is_active     = row["is_active"],
            mfa_secret    = row["mfa_secret"],
        )


# ============================================================================
# Database Pool Manager
# ============================================================================

class Database:
    """
    Owns the asyncpg connection pool and exposes all user/token/audit queries.
    Construct once, call connect() at startup, disconnect() at shutdown.
    """

    def __init__(self, dsn: Optional[str] = None) -> None:
        self._dsn = dsn or os.environ.get("DATABASE_URL", "")
        self._pool: Optional[asyncpg.Pool] = None

    @property
    def is_connected(self) -> bool:
        return self._pool is not None

    async def connect(self) -> None:
        if not self._dsn:
            raise RuntimeError(
                "DATABASE_URL is not set. Attach a PostgreSQL database to "
                "this service (see render.yaml) or set DATABASE_URL manually."
            )
        # Render's internal Postgres URLs sometimes use postgres:// — asyncpg
        # requires postgresql://
        dsn = self._dsn.replace("postgres://", "postgresql://", 1)
        self._pool = await asyncpg.create_pool(
            dsn,
            min_size=2,
            max_size=10,
            command_timeout=10,
        )
        logger.info("[DB] connection pool established")

    async def disconnect(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            logger.info("[DB] connection pool closed")

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("Database not connected — call connect() first")
        return self._pool

    # ── User queries ─────────────────────────────────────────────────────────

    async def get_user_by_email(self, email: str) -> Optional[HospitalUser]:
        pool = self._require_pool()
        row = await pool.fetchrow(
            "SELECT * FROM users WHERE email = $1", email.lower().strip()
        )
        return HospitalUser.from_row(row) if row else None

    async def get_user_by_id(self, user_id: str) -> Optional[HospitalUser]:
        pool = self._require_pool()
        try:
            row = await pool.fetchrow(
                "SELECT * FROM users WHERE id = $1::uuid", user_id
            )
        except (ValueError, asyncpg.DataError):
            return None
        return HospitalUser.from_row(row) if row else None

    async def get_user_by_apple_id(self, apple_user_id: str) -> Optional[HospitalUser]:
        pool = self._require_pool()
        row = await pool.fetchrow(
            "SELECT * FROM users WHERE apple_user_id = $1", apple_user_id
        )
        return HospitalUser.from_row(row) if row else None

    async def create_patient_from_apple(
        self,
        apple_user_id: str,
        email:         str,
        name:          str,
    ) -> HospitalUser:
        """Auto-provision a patient account on first Apple Sign In."""
        pool = self._require_pool()
        row = await pool.fetchrow(
            """
            INSERT INTO users (email, name, role, patient_id, apple_user_id, password_hash, is_active)
            VALUES ($1, $2, 'patient', $3, $4, '', true)
            ON CONFLICT (email) DO UPDATE
                SET apple_user_id = EXCLUDED.apple_user_id
            RETURNING *
            """,
            email, name, apple_user_id, apple_user_id,
        )
        logger.info("[DB] provisioned patient via Apple: %s", email)
        return HospitalUser.from_row(row)

    async def update_last_login(self, user_id: str) -> None:
        pool = self._require_pool()
        await pool.execute(
            "UPDATE users SET last_login_at = now() WHERE id = $1::uuid", user_id
        )

    async def list_users(
        self,
        role:   Optional[UserRole] = None,
        limit:  int = 100,
        offset: int = 0,
    ) -> List[HospitalUser]:
        """Admin-only: list all users, optionally filtered by role."""
        pool = self._require_pool()
        if role is not None:
            rows = await pool.fetch(
                "SELECT * FROM users WHERE role = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                role.value, limit, offset,
            )
        else:
            rows = await pool.fetch(
                "SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                limit, offset,
            )
        return [HospitalUser.from_row(r) for r in rows]

    async def set_user_active(self, user_id: str, is_active: bool) -> bool:
        """Admin-only: enable/disable an account."""
        pool = self._require_pool()
        result = await pool.execute(
            "UPDATE users SET is_active = $1 WHERE id = $2::uuid", is_active, user_id
        )
        return result != "UPDATE 0"

    async def set_user_role(self, user_id: str, role: UserRole) -> bool:
        """Admin-only: change a user's role."""
        pool = self._require_pool()
        result = await pool.execute(
            "UPDATE users SET role = $1 WHERE id = $2::uuid", role.value, user_id
        )
        return result != "UPDATE 0"

    async def create_staff_user(
        self,
        email:         str,
        name:          str,
        role:          UserRole,
        password_hash: str,
    ) -> HospitalUser:
        """Admin-only: create a new nurse/cardiologist/admin account."""
        pool = self._require_pool()
        row = await pool.fetchrow(
            """
            INSERT INTO users (email, name, role, password_hash, is_active)
            VALUES ($1, $2, $3, $4, true)
            RETURNING *
            """,
            email.lower().strip(), name, role.value, password_hash,
        )
        return HospitalUser.from_row(row)

    # ── Refresh token queries ────────────────────────────────────────────────

    async def issue_refresh_token(self, user_id: str, ttl_seconds: int) -> str:
        import secrets as _secrets
        pool = self._require_pool()
        token_id = _secrets.token_urlsafe(48)
        await pool.execute(
            """
            INSERT INTO refresh_tokens (token_id, user_id, expires_at)
            VALUES ($1, $2::uuid, now() + ($3 || ' seconds')::interval)
            """,
            token_id, user_id, str(ttl_seconds),
        )
        return token_id

    async def consume_refresh_token(self, token_id: str) -> Optional[str]:
        """
        Validate + rotate (delete) in one atomic query. Returns user_id or None.
        """
        pool = self._require_pool()
        row = await pool.fetchrow(
            """
            DELETE FROM refresh_tokens
            WHERE token_id = $1 AND expires_at > now()
            RETURNING user_id
            """,
            token_id,
        )
        return str(row["user_id"]) if row else None

    async def revoke_all_refresh_tokens(self, user_id: str) -> int:
        pool = self._require_pool()
        result = await pool.execute(
            "DELETE FROM refresh_tokens WHERE user_id = $1::uuid", user_id
        )
        # result looks like "DELETE 3"
        try:
            return int(result.split()[-1])
        except (ValueError, IndexError):
            return 0

    async def purge_expired_refresh_tokens(self) -> int:
        pool = self._require_pool()
        result = await pool.execute(
            "DELETE FROM refresh_tokens WHERE expires_at <= now()"
        )
        try:
            return int(result.split()[-1])
        except (ValueError, IndexError):
            return 0

    # ── Audit log ────────────────────────────────────────────────────────────

    async def log_event(
        self,
        event_type: str,
        user_id:    Optional[str] = None,
        ip_address: Optional[str] = None,
        detail:     Optional[str] = None,
    ) -> None:
        pool = self._require_pool()
        try:
            await pool.execute(
                """
                INSERT INTO audit_log (user_id, event_type, ip_address, detail)
                VALUES ($1::uuid, $2, $3, $4)
                """,
                user_id, event_type, ip_address, detail,
            )
        except Exception as exc:
            # Audit logging must never break the request it's logging
            logger.warning("[DB] audit log write failed: %s", exc)

    # ── Large / implanted device registry ───────────────────────────────────

    async def register_large_device(
        self,
        vendor_device_id:          str,
        vendor:                    str,
        device_type:               str,
        patient_id:                str,
        model_number:              Optional[str] = None,
        implanted_at:              Optional[str] = None,
        implanting_clinician_id:   Optional[str] = None,
        registered_by_user_id:     Optional[str] = None,
        vendor_account_ref:        Optional[str] = None,
        notes:                     Optional[str] = None,
    ) -> "LargeDevice":
        """
        Register a pacemaker / ICD / other implanted device against a
        patient. Called by a clinician via POST /clinical/devices/register-implant
        — never by a patient directly, since implants are placed by clinical
        staff, not self-paired like a BLE wearable.
        """
        pool = self._require_pool()
        row = await pool.fetchrow(
            """
            INSERT INTO large_devices (
                vendor_device_id, vendor, device_type, patient_id,
                model_number, implanted_at, implanting_clinician_id,
                registered_by_user_id, vendor_account_ref, notes
            )
            VALUES ($1, $2, $3, $4, $5, $6::date, $7::uuid, $8::uuid, $9, $10)
            ON CONFLICT (vendor_device_id) DO UPDATE
                SET patient_id = EXCLUDED.patient_id,
                    is_active  = true
            RETURNING *
            """,
            vendor_device_id, vendor, device_type, patient_id,
            model_number, implanted_at, implanting_clinician_id,
            registered_by_user_id, vendor_account_ref, notes,
        )
        return LargeDevice.from_row(row)

    async def get_large_device_by_vendor_id(
        self, vendor_device_id: str,
    ) -> Optional["LargeDevice"]:
        """Look up a registered implant by the vendor's device identifier."""
        pool = self._require_pool()
        row = await pool.fetchrow(
            "SELECT * FROM large_devices WHERE vendor_device_id = $1",
            vendor_device_id,
        )
        return LargeDevice.from_row(row) if row else None

    async def list_large_devices(
        self,
        patient_id: Optional[str] = None,
        vendor:     Optional[str] = None,
        limit:      int = 100,
        offset:     int = 0,
    ) -> List["LargeDevice"]:
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
            f"SELECT * FROM large_devices {where} "
            f"ORDER BY created_at DESC LIMIT ${len(params)-1} OFFSET ${len(params)}",
            *params,
        )
        return [LargeDevice.from_row(r) for r in rows]

    async def set_large_device_active(self, device_id: str, is_active: bool) -> bool:
        pool = self._require_pool()
        result = await pool.execute(
            "UPDATE large_devices SET is_active = $1 WHERE id = $2::uuid",
            is_active, device_id,
        )
        return result != "UPDATE 0"

    async def touch_large_device_last_event(self, vendor_device_id: str) -> None:
        pool = self._require_pool()
        await pool.execute(
            "UPDATE large_devices SET last_event_at = now() WHERE vendor_device_id = $1",
            vendor_device_id,
        )

    # ── Vendor API keys ──────────────────────────────────────────────────────

    async def verify_vendor_api_key(self, raw_key: str) -> Optional[str]:
        """
        Hash the provided raw key with SHA-256 and look it up. Returns the
        vendor name if the key is valid and active, else None.

        SHA-256 (not bcrypt) is deliberate here: this check runs on every
        single ingested device event, potentially thousands per minute
        across many devices. Vendor API keys are long, high-entropy,
        machine-generated secrets — they don't need bcrypt's deliberate
        slowness, which exists specifically to slow down brute-forcing
        short human-chosen passwords.
        """
        import hashlib as _hashlib
        pool = self._require_pool()
        key_hash = _hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        row = await pool.fetchrow(
            "SELECT vendor, is_active FROM vendor_api_keys WHERE key_hash = $1",
            key_hash,
        )
        if row is None or not row["is_active"]:
            return None
        await pool.execute(
            "UPDATE vendor_api_keys SET last_used_at = now() WHERE key_hash = $1",
            key_hash,
        )
        return row["vendor"]

    async def create_vendor_api_key(
        self, vendor: str, label: str = "",
    ) -> tuple[str, str]:
        """
        Admin-only: generate a new vendor API key. Returns (raw_key, key_id).
        The raw key is shown to the admin EXACTLY ONCE at creation time and
        is never recoverable afterward — only its hash is stored.
        """
        import hashlib as _hashlib
        import secrets as _secrets
        pool = self._require_pool()
        raw_key = _secrets.token_urlsafe(40)
        key_hash = _hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        row = await pool.fetchrow(
            """
            INSERT INTO vendor_api_keys (vendor, key_hash, label, is_active)
            VALUES ($1, $2, $3, true)
            RETURNING id
            """,
            vendor, key_hash, label,
        )
        return raw_key, str(row["id"])

    # ── Vendor raw event audit ────────────────────────────────────────────────

    async def log_vendor_event(
        self,
        vendor:           str,
        raw_payload:      Dict[str, Any],
        vendor_device_id: Optional[str] = None,
        large_device_id:  Optional[str] = None,
        matched:          bool = False,
        kafka_published:  bool = False,
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


# ============================================================================
# Large Device Model
# ============================================================================

@dataclass
class LargeDevice:
    """Represents a registered implanted/large device (pacemaker, ICD, etc.)."""

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

    @classmethod
    def from_row(cls, row: asyncpg.Record) -> "LargeDevice":
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
        )


# ============================================================================
# Module-level singleton (mirrors the pattern used for other globals
# in iomt_cardioai_production.py)
# ============================================================================

db = Database()
