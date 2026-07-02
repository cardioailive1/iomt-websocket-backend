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
from typing import Any, Dict, Optional

import aiohttp

logger = logging.getLogger("IoMT.FHIR")

_ALERT_LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


class FHIRClient:
    """
    Thin async FHIR R4 client scoped to exactly what CardioAI needs:
    OAuth2 client-credentials auth, patient identifier resolution, and
    posting Condition/Flag resources. Not a general-purpose FHIR SDK.
    """

    def __init__(self) -> None:
        self.enabled = _env("FHIR_ENABLED", "false").lower() == "true"
        self.base_url = _env("FHIR_BASE_URL").rstrip("/")
        self.token_url = _env("FHIR_TOKEN_URL")
        self.client_id = _env("FHIR_CLIENT_ID")
        self.client_secret = _env("FHIR_CLIENT_SECRET")
        self.patient_identifier_system = _env("FHIR_PATIENT_IDENTIFIER_SYSTEM")
        self.min_alert_level = _env("FHIR_MIN_ALERT_LEVEL", "medium").lower()

        if self.enabled and not (self.base_url and self.token_url and self.client_id and self.client_secret):
            logger.warning(
                "[FHIR] FHIR_ENABLED=true but one or more of FHIR_BASE_URL / "
                "FHIR_TOKEN_URL / FHIR_CLIENT_ID / FHIR_CLIENT_SECRET is "
                "missing — FHIR write-back will be skipped until all are set."
            )
            self.enabled = False

        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._patient_id_cache: Dict[str, Optional[str]] = {}

        if self.enabled:
            logger.info("[FHIR] write-back enabled — base_url=%s", self.base_url)
        else:
            logger.info("[FHIR] write-back disabled (FHIR_ENABLED not set to 'true')")

    # ── Auth ─────────────────────────────────────────────────────────────

    async def _get_token(self, session: aiohttp.ClientSession) -> Optional[str]:
        now = time.time()
        if self._token and now < self._token_expires_at - 30:
            return self._token

        try:
            async with session.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "system/Condition.write system/Flag.write system/Patient.read",
                },
                headers={"Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error("[FHIR] token request failed status=%s body=%s", resp.status, body[:300])
                    return None
                data = await resp.json()
                self._token = data.get("access_token")
                expires_in = int(data.get("expires_in", 300))
                self._token_expires_at = now + expires_in
                return self._token
        except Exception:
            logger.exception("[FHIR] token request raised an exception")
            return None

    # ── Patient identity resolution ─────────────────────────────────────

    async def _resolve_patient_fhir_id(self, session: aiohttp.ClientSession, token: str, patient_id: str) -> Optional[str]:
        if patient_id in self._patient_id_cache:
            return self._patient_id_cache[patient_id]

        if not self.patient_identifier_system:
            logger.warning(
                "[FHIR] FHIR_PATIENT_IDENTIFIER_SYSTEM not set — cannot safely "
                "resolve internal patient_id=%s to a FHIR Patient.id. Skipping.",
                patient_id,
            )
            self._patient_id_cache[patient_id] = None
            return None

        try:
            async with session.get(
                f"{self.base_url}/Patient",
                params={"identifier": f"{self.patient_identifier_system}|{patient_id}"},
                headers={"Authorization": f"Bearer {token}", "Accept": "application/fhir+json"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    logger.error("[FHIR] Patient search failed status=%s patient_id=%s", resp.status, patient_id)
                    self._patient_id_cache[patient_id] = None
                    return None
                bundle = await resp.json()
                entries = bundle.get("entry", [])
                if not entries:
                    logger.warning("[FHIR] no matching Patient found for patient_id=%s", patient_id)
                    self._patient_id_cache[patient_id] = None
                    return None
                fhir_id = entries[0]["resource"]["id"]
                self._patient_id_cache[patient_id] = fhir_id
                return fhir_id
        except Exception:
            logger.exception("[FHIR] Patient search raised an exception for patient_id=%s", patient_id)
            self._patient_id_cache[patient_id] = None
            return None

    # ── Resource creation ────────────────────────────────────────────────

    async def _create_resource(self, session: aiohttp.ClientSession, token: str, resource_type: str, resource: Dict[str, Any]) -> bool:
        try:
            async with session.post(
                f"{self.base_url}/{resource_type}",
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
                        "[FHIR] %s create failed status=%s body=%s",
                        resource_type, resp.status, body[:500],
                    )
                    return False
                return True
        except Exception:
            logger.exception("[FHIR] %s create raised an exception", resource_type)
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

    async def push_alert(self, alert) -> None:
        """
        Push an Alert to the configured FHIR server as Condition + Flag
        resources. No-op if FHIR isn't enabled/configured, or if the
        alert's level is below FHIR_MIN_ALERT_LEVEL. Never raises —
        failures are logged and swallowed so the clinical pipeline is
        never affected by FHIR server availability.
        """
        if not self.enabled:
            return

        level = alert.alert_level.value if hasattr(alert.alert_level, "value") else str(alert.alert_level)
        if _ALERT_LEVEL_RANK.get(level, 0) < _ALERT_LEVEL_RANK.get(self.min_alert_level, 1):
            return

        try:
            async with aiohttp.ClientSession() as session:
                token = await self._get_token(session)
                if not token:
                    return

                fhir_patient_id = await self._resolve_patient_fhir_id(session, token, alert.patient_id)
                if not fhir_patient_id:
                    return

                condition = self._build_condition(fhir_patient_id, alert)
                flag = self._build_flag(fhir_patient_id, alert)

                cond_ok = await self._create_resource(session, token, "Condition", condition)
                flag_ok = await self._create_resource(session, token, "Flag", flag)

                if cond_ok and flag_ok:
                    logger.info(
                        "[FHIR] pushed alert=%s patient_id=%s (fhir_id=%s) level=%s",
                        alert.alert_id, alert.patient_id, fhir_patient_id, level,
                    )
        except Exception:
            # Belt-and-braces: absolutely nothing from this module should
            # ever propagate up into the clinical pipeline.
            logger.exception("[FHIR] push_alert failed unexpectedly for alert=%s", getattr(alert, "alert_id", "?"))


# Module-level singleton, mirroring the pattern used for _db / _kafka_producer
# in iomt_cardioai_production.py.
fhir_client = FHIRClient()
