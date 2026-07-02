"""
fhir_client.py — FHIR R4 write-back client
=============================================
Pushes CardioAI alerts to a hospital's FHIR R4 server as standard
resources (Condition + Flag), so critical/high/medium alerts surface
inside the hospital's own EHR (Epic, Cerner, etc.) alongside everything
else clinicians already look at.

Design
------
- SMART-on-FHIR backend-services style OAuth2 client-credentials auth.
  Token is fetched once and cached until shortly before expiry.
- Patient identity: this system's internal `patient_id` (e.g. "PT_12345")
  is almost certainly NOT the same as the FHIR server's own Patient.id.
  Instead we resolve it by searching:
      GET {base_url}/Patient?identifier={identifier_system}|{patient_id}
  and cache the resolved FHIR Patient.id. Set FHIR_PATIENT_IDENTIFIER_SYSTEM
  to whatever identifier system your hospital uses to store this same
  value (e.g. an MRN system OID/URI) — ask their integration team.
- Fully opt-in and fail-safe: if FHIR_ENABLED is not "true" or
  FHIR_BASE_URL is unset, every method below becomes a no-op immediately.
  Existing deployments that haven't configured FHIR are completely
  unaffected — this was built to bolt on, not to change default behavior.
- Never raises out of push_alert(). A FHIR server being down, misconfigured,
  or rejecting a resource must NEVER block or crash the clinical alert
  pipeline — at worst, the write-back to FHIR is skipped and logged.

Required environment variables (all optional — omit to disable entirely)
--------------------------------------------------------------------------
  FHIR_ENABLED                    "true" to activate (default: "false")
  FHIR_BASE_URL                   e.g. https://fhir.hospital.org/api/FHIR/R4
  FHIR_TOKEN_URL                  OAuth2 token endpoint for client-credentials grant
  FHIR_CLIENT_ID                  registered app's client_id
  FHIR_CLIENT_SECRET              registered app's client_secret
  FHIR_PATIENT_IDENTIFIER_SYSTEM  identifier system URI matching your patient_id values
  FHIR_MIN_ALERT_LEVEL            minimum alert level to push: low|medium|high|critical
                                   (default: "medium" — routine LOW alerts stay internal)

NOTE ON SECRETS: FHIR_CLIENT_SECRET is a real credential. Store it exactly
like IOMT_JWT_SECRET / IOMT_SHARED_SECRET — as a Render environment
variable, never committed to source control.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import aiohttp

logger = logging.getLogger("IoMT.FHIR")

_ALERT_LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


@dataclass
class FHIRConfig:
    """
    Resolved FHIR configuration for a single push — either the global
    single-tenant config (from environment variables) or a per-organization
    override (from the `organizations` table, migration 005).
    """
    base_url: str
    token_url: str
    client_id: str
    client_secret: str
    patient_identifier_system: str
    min_alert_level: str = "medium"

    @property
    def is_complete(self) -> bool:
        return bool(self.base_url and self.token_url and self.client_id and self.client_secret)

    @classmethod
    def from_env(cls) -> "FHIRConfig":
        return cls(
            base_url=_env("FHIR_BASE_URL").rstrip("/"),
            token_url=_env("FHIR_TOKEN_URL"),
            client_id=_env("FHIR_CLIENT_ID"),
            client_secret=_env("FHIR_CLIENT_SECRET"),
            patient_identifier_system=_env("FHIR_PATIENT_IDENTIFIER_SYSTEM"),
            min_alert_level=_env("FHIR_MIN_ALERT_LEVEL", "medium").lower(),
        )

    @classmethod
    def from_organization(cls, org: Any) -> Optional["FHIRConfig"]:
        """
        Build a config from an Organization row (db.py). Returns None if
        the organization doesn't have FHIR fully configured — callers
        should fall back to the global env-based config in that case.
        """
        if not getattr(org, "has_fhir_config", lambda: False)():
            return None
        return cls(
            base_url=(org.fhir_base_url or "").rstrip("/"),
            token_url=org.fhir_token_url or "",
            client_id=org.fhir_client_id or "",
            client_secret=org.fhir_client_secret or "",
            patient_identifier_system=org.fhir_patient_identifier_system or "",
            min_alert_level=(org.fhir_min_alert_level or "medium").lower(),
        )


class FHIRClient:
    """
    Thin async FHIR R4 client scoped to exactly what CardioAI needs:
    OAuth2 client-credentials auth, patient identifier resolution, and
    posting Condition/Flag resources. Not a general-purpose FHIR SDK.

    Multi-hospital support: every method takes an explicit FHIRConfig
    rather than reading from `self` — this lets ONE client instance serve
    both the global single-tenant config (self.default_config, from
    environment variables) and any number of per-organization configs
    (built via FHIRConfig.from_organization()) without them colliding.
    Token and patient-identifier caches are keyed by base_url so different
    hospitals' credentials/patients are never mixed up.
    """

    def __init__(self) -> None:
        self.enabled = _env("FHIR_ENABLED", "false").lower() == "true"
        self.default_config = FHIRConfig.from_env()

        if self.enabled and not self.default_config.is_complete:
            logger.warning(
                "[FHIR] FHIR_ENABLED=true but one or more of FHIR_BASE_URL / "
                "FHIR_TOKEN_URL / FHIR_CLIENT_ID / FHIR_CLIENT_SECRET is "
                "missing — global FHIR write-back will be skipped until all "
                "are set. Per-organization FHIR config (if any) is unaffected."
            )

        # Keyed by base_url so multiple hospitals' tokens/patient caches
        # never collide within one running process.
        self._tokens: Dict[str, str] = {}
        self._token_expires_at: Dict[str, float] = {}
        self._patient_id_cache: Dict[str, Dict[str, Optional[str]]] = {}

        if self.enabled and self.default_config.is_complete:
            logger.info("[FHIR] global write-back enabled — base_url=%s", self.default_config.base_url)
        else:
            logger.info("[FHIR] global write-back disabled (set FHIR_ENABLED=true to activate)")

    # ── Auth ─────────────────────────────────────────────────────────────

    async def _get_token(self, session: aiohttp.ClientSession, config: FHIRConfig) -> Optional[str]:
        now = time.time()
        cached = self._tokens.get(config.base_url)
        if cached and now < self._token_expires_at.get(config.base_url, 0) - 30:
            return cached

        try:
            async with session.post(
                config.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                    "scope": "system/Condition.write system/Flag.write system/Patient.read",
                },
                headers={"Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error("[FHIR] token request failed base_url=%s status=%s body=%s", config.base_url, resp.status, body[:300])
                    return None
                data = await resp.json()
                token = data.get("access_token")
                expires_in = int(data.get("expires_in", 300))
                self._tokens[config.base_url] = token
                self._token_expires_at[config.base_url] = now + expires_in
                return token
        except Exception:
            logger.exception("[FHIR] token request raised an exception base_url=%s", config.base_url)
            return None

    # ── Patient identity resolution ─────────────────────────────────────

    async def _resolve_patient_fhir_id(self, session: aiohttp.ClientSession, token: str, config: FHIRConfig, patient_id: str) -> Optional[str]:
        cache = self._patient_id_cache.setdefault(config.base_url, {})
        if patient_id in cache:
            return cache[patient_id]

        if not config.patient_identifier_system:
            logger.warning(
                "[FHIR] no patient_identifier_system configured for base_url=%s — cannot safely "
                "resolve internal patient_id=%s to a FHIR Patient.id. Skipping.",
                config.base_url, patient_id,
            )
            cache[patient_id] = None
            return None

        try:
            async with session.get(
                f"{config.base_url}/Patient",
                params={"identifier": f"{config.patient_identifier_system}|{patient_id}"},
                headers={"Authorization": f"Bearer {token}", "Accept": "application/fhir+json"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    logger.error("[FHIR] Patient search failed base_url=%s status=%s patient_id=%s", config.base_url, resp.status, patient_id)
                    cache[patient_id] = None
                    return None
                bundle = await resp.json()
                entries = bundle.get("entry", [])
                if not entries:
                    logger.warning("[FHIR] no matching Patient found base_url=%s patient_id=%s", config.base_url, patient_id)
                    cache[patient_id] = None
                    return None
                fhir_id = entries[0]["resource"]["id"]
                cache[patient_id] = fhir_id
                return fhir_id
        except Exception:
            logger.exception("[FHIR] Patient search raised an exception base_url=%s patient_id=%s", config.base_url, patient_id)
            cache[patient_id] = None
            return None

    # ── Resource creation ────────────────────────────────────────────────

    async def _create_resource(self, session: aiohttp.ClientSession, token: str, config: FHIRConfig, resource_type: str, resource: Dict[str, Any]) -> bool:
        try:
            async with session.post(
                f"{config.base_url}/{resource_type}",
                json=resource,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/fhir+json",
                    "Accept": "application/fhir+json",
                },
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status not in (200, 201):
                    body = await resp.text()
                    logger.error(
                        "[FHIR] %s create failed base_url=%s status=%s body=%s",
                        resource_type, config.base_url, resp.status, body[:500],
                    )
                    return False
                return True
        except Exception:
            logger.exception("[FHIR] %s create raised an exception base_url=%s", resource_type, config.base_url)
            return False

    # ── Resource builders ────────────────────────────────────────────────

    @staticmethod
    def _build_condition(fhir_patient_id: str, alert) -> Dict[str, Any]:
        return {
            "resourceType": "Condition",
            "clinicalStatus": {
                "coding": [{
                    "system": "http://terminology.hl7.org/CodeSystem/condition-clinical",
                    "code": "active",
                }]
            },
            "verificationStatus": {
                "coding": [{
                    "system": "http://terminology.hl7.org/CodeSystem/condition-ver-status",
                    "code": "unconfirmed",
                }]
            },
            "code": {"text": alert.description},
            "subject": {"reference": f"Patient/{fhir_patient_id}"},
            "recordedDate": alert.timestamp,
            "note": [{
                "text": (
                    f"Detected by IoMT CardioAI clinical AI pipeline. "
                    f"Alert level: {alert.alert_level.value}. "
                    f"This is an algorithmic detection pending clinician confirmation."
                )
            }],
        }

    @staticmethod
    def _build_flag(fhir_patient_id: str, alert) -> Dict[str, Any]:
        return {
            "resourceType": "Flag",
            "status": "active",
            "category": [{
                "coding": [{
                    "system": "http://terminology.hl7.org/CodeSystem/flag-category",
                    "code": "clinical",
                    "display": "Clinical",
                }]
            }],
            "code": {"text": f"[{alert.alert_level.value.upper()}] {alert.description}"},
            "subject": {"reference": f"Patient/{fhir_patient_id}"},
            "period": {"start": alert.timestamp},
            "note": [{"text": "; ".join(alert.required_actions)}] if alert.required_actions else [],
        }

    # ── Public entry point ───────────────────────────────────────────────

    async def push_alert(self, alert, organization: Any = None) -> None:
        """
        Push an Alert to a FHIR server as Condition + Flag resources.

        Config resolution order:
          1. If `organization` is provided and has FHIR fully configured
             (org.has_fhir_config()), use that hospital's own FHIR server.
          2. Otherwise fall back to the global FHIR_* environment variables
             (self.default_config) — the original single-tenant behavior.
          3. If neither is configured/enabled, this is a no-op.

        No-op if the resolved config's min_alert_level is above this
        alert's level. Never raises — failures are logged and swallowed
        so the clinical pipeline is never affected by FHIR server
        availability, regardless of which hospital's server is involved.
        """
        config: Optional[FHIRConfig] = None
        if organization is not None:
            config = FHIRConfig.from_organization(organization)
            if config:
                logger.debug("[FHIR] using per-organization config for org=%s", getattr(organization, "name", "?"))

        if config is None:
            if not (self.enabled and self.default_config.is_complete):
                return
            config = self.default_config

        level = alert.alert_level.value if hasattr(alert.alert_level, "value") else str(alert.alert_level)
        if _ALERT_LEVEL_RANK.get(level, 0) < _ALERT_LEVEL_RANK.get(config.min_alert_level, 1):
            return

        try:
            async with aiohttp.ClientSession() as session:
                token = await self._get_token(session, config)
                if not token:
                    return

                fhir_patient_id = await self._resolve_patient_fhir_id(session, token, config, alert.patient_id)
                if not fhir_patient_id:
                    return

                condition = self._build_condition(fhir_patient_id, alert)
                flag = self._build_flag(fhir_patient_id, alert)

                cond_ok = await self._create_resource(session, token, config, "Condition", condition)
                flag_ok = await self._create_resource(session, token, config, "Flag", flag)

                if cond_ok and flag_ok:
                    logger.info(
                        "[FHIR] pushed alert=%s patient_id=%s (fhir_id=%s) level=%s base_url=%s",
                        alert.alert_id, alert.patient_id, fhir_patient_id, level, config.base_url,
                    )
        except Exception:
            # Belt-and-braces: absolutely nothing from this module should
            # ever propagate up into the clinical pipeline.
            logger.exception("[FHIR] push_alert failed unexpectedly for alert=%s", getattr(alert, "alert_id", "?"))


# Module-level singleton, mirroring the pattern used for _db / _kafka_producer
# in iomt_cardioai_production.py.
fhir_client = FHIRClient()
