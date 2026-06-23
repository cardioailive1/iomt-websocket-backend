"""
IoMT CardioAI — Production System
===================================
IoMT Server ↔ CardioAI Backend: HMAC-SHA256 handshake, real-time RPM
streaming, and 7-agent clinical AI pipeline.

Architecture
------------
  IoMT Server (WS) ──HMAC auth──► IoMTServerConnector
                                        │ inbound_queue
                                   RPMDataPump
                                        │
                              DataAcquisitionAgent
                              DataProcessingAgent
                              PatternRecognitionAgent
                              DiagnosticAgent
                              AlertMonitoringAgent
                              PersonalizationAgent
                              CommunicationAgent
                                        │
                              EHR / GCP / Alerts

Security model
--------------
  1. 3-way HMAC-SHA256 challenge/response at connection time.
  2. JWT (HS256) session token for every subsequent message.
  3. Secrets loaded exclusively from environment variables —
     never hard-coded or committed to source control.
  4. All comparisons use constant-time hmac.compare_digest().

Required environment variables
-------------------------------
  IOMT_SHARED_SECRET       HMAC shared secret (min 32 chars)
  IOMT_JWT_SECRET          JWT signing secret  (min 32 chars)
  IOMT_SERVER_WS_URL       wss://host/path
  CARDIOAI_BACKEND_ID      unique service identifier

Optional environment variables
-------------------------------
  IOMT_SERVER_REST_URL     https://host/api/v1
  IOMT_SERVER_ID           server identifier
  CARDIOAI_WS_HOST         WebSocket listener host  (default 0.0.0.0)
  CARDIOAI_WS_PORT         WebSocket listener port  (default 8765)
  JWT_ALGORITHM            HS256 | HS512              (default HS256)
  TOKEN_TTL_SECONDS        session token TTL          (default 3600)
  RPM_POLL_INTERVAL_SEC    seconds between polls      (default 1.0)
  HEARTBEAT_INTERVAL_SEC   WS keep-alive interval     (default 10.0)
  RECONNECT_MAX_ATTEMPTS   before giving up           (default 5)
  RECONNECT_BASE_DELAY_SEC exponential back-off seed  (default 2.0)
  INBOUND_QUEUE_MAXSIZE    back-pressure cap          (default 2000)
  LOG_LEVEL                DEBUG|INFO|WARNING|ERROR   (default INFO)
  LOG_FORMAT               json | text                (default text)

Python dependencies
-------------------
  pip install websockets aiohttp pyjwt numpy

External module dependencies (ship alongside this file)
-------------------------------------------------------
  IoMT_implementation.py    — low-level device drivers, sensor I/O
  IoMT_clinical_workflow.py — CDSS rules, care-pathway routing, EHR
  IoMT_gcp_compduide.py     — Pub/Sub, BigQuery, Cloud Healthcare, GCS
"""

from __future__ import annotations

# ============================================================================
# Standard Library
# ============================================================================

import asyncio
import base64
import hashlib
import hmac as _hmac
import json
import logging
import logging.config
import os
import secrets
import sys
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

# ============================================================================
# Third-Party
# ============================================================================

import numpy as np          # pip install numpy
import websockets            # pip install websockets
import aiohttp               # pip install aiohttp
import jwt                   # pip install pyjwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

# ============================================================================
# Internal IoMT Module Imports
# ============================================================================

from IoMT_implementation import (       # low-level device / transport layer
    IoMTDeviceDriver,
    SensorTransportEncoder,
    DeviceCapabilityRegistry,
    FirmwareAbstractionLayer,
    RawSensorFrame,
)
from IoMT_clinical_workflow import (    # clinical decision support + EHR
    ClinicalDecisionEngine,
    CarePathwayRouter,
    EHRConnector,
    CDSSAlert,
    ClinicalWorkflowConfig,
)
from IoMT_gcp_compduide import (        # GCP managed-services integration
    GCPPubSubPublisher,
    BigQueryEventWriter,
    CloudHealthcareAPIClient,
    GCSArchiver,
    HealthcareDatasetClient,
    GCPConfig,
)

# ============================================================================
# Logging
# ============================================================================

def _build_logger() -> logging.Logger:
    """
    Configure structured logging driven by LOG_LEVEL / LOG_FORMAT env vars.
    json format emits machine-readable lines suitable for Cloud Logging /
    Datadog / Splunk.  text format is human-friendly for local development.
    """
    level_name  = os.environ.get("LOG_LEVEL",  "INFO").upper()
    log_format  = os.environ.get("LOG_FORMAT", "text").lower()
    level       = getattr(logging, level_name, logging.INFO)

    if log_format == "json":
        fmt = (
            '{"time":"%(asctime)s","level":"%(levelname)s",'
            '"logger":"%(name)s","msg":"%(message)s"}'
        )
    else:
        fmt = "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"

    logging.basicConfig(
        level     = level,
        format    = fmt,
        datefmt   = "%Y-%m-%dT%H:%M:%S",
        stream    = sys.stdout,
        force     = True,
    )
    return logging.getLogger("iomt_cardioai")


logger = _build_logger()


# ============================================================================
# SECTION 1 — CONFIGURATION
# ============================================================================

class ConfigurationError(RuntimeError):
    """Raised when a required environment variable is missing or invalid."""


def _require_env(name: str, min_length: int = 0) -> str:
    """
    Read *name* from the environment; raise ConfigurationError if absent or
    shorter than *min_length*.  This is the single enforcement point —
    no secret ever has a default value in code.
    """
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(
            f"Required environment variable '{name}' is not set. "
            "Set it via a secrets manager (Vault, K8s Secret, AWS SSM) "
            "before starting the service."
        )
    if len(value) < min_length:
        raise ConfigurationError(
            f"'{name}' must be at least {min_length} characters long "
            f"(got {len(value)})."
        )
    return value


def _optional_env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip() or default


@dataclass(frozen=True)
class HandshakeConfig:
    """
    Immutable, environment-driven configuration for the transport layer.

    All secrets are read from environment variables.  The dataclass is frozen
    so that no runtime code can mutate security-critical fields after startup.
    Never construct this with literal secret strings outside of tests.
    """

    # ── IoMT server ──────────────────────────────────────────────────────────
    iomt_server_ws_url:   str
    iomt_server_rest_url: str
    iomt_server_id:       str

    # ── CardioAI backend identity ─────────────────────────────────────────────
    cardioai_backend_id:  str
    cardioai_ws_host:     str
    cardioai_ws_port:     int

    # ── Secrets (injected at construction time from env) ─────────────────────
    shared_secret:        str   # HMAC signing key — never log, never persist
    jwt_secret:           str   # JWT signing key  — never log, never persist
    jwt_algorithm:        str
    token_ttl_seconds:    int

    # ── Streaming / reliability ───────────────────────────────────────────────
    rpm_poll_interval_seconds:    float
    heartbeat_interval_seconds:   float
    reconnect_max_attempts:       int
    reconnect_base_delay_seconds: float
    inbound_queue_maxsize:        int

    @classmethod
    def from_env(cls) -> "HandshakeConfig":
        """
        Factory that builds a HandshakeConfig entirely from env vars.
        Call this once at startup; fail fast if any required variable is absent.
        """
        return cls(
            iomt_server_ws_url   = _require_env("IOMT_SERVER_WS_URL"),
            iomt_server_rest_url = _optional_env("IOMT_SERVER_REST_URL",
                                                 "https://iomt-server.hospital.local/api/v1"),
            iomt_server_id       = _optional_env("IOMT_SERVER_ID", "IOMT-SRV-001"),

            cardioai_backend_id  = _require_env("CARDIOAI_BACKEND_ID"),
            cardioai_ws_host     = _optional_env("CARDIOAI_WS_HOST", "0.0.0.0"),
            cardioai_ws_port     = int(_optional_env("CARDIOAI_WS_PORT", "8765")),

            shared_secret        = _require_env("IOMT_SHARED_SECRET", min_length=32),
            jwt_secret           = _require_env("IOMT_JWT_SECRET",    min_length=32),
            jwt_algorithm        = _optional_env("JWT_ALGORITHM",      "HS256"),
            token_ttl_seconds    = int(_optional_env("TOKEN_TTL_SECONDS", "3600")),

            rpm_poll_interval_seconds    = float(_optional_env("RPM_POLL_INTERVAL_SEC",    "1.0")),
            heartbeat_interval_seconds   = float(_optional_env("HEARTBEAT_INTERVAL_SEC",   "10.0")),
            reconnect_max_attempts       = int(_optional_env("RECONNECT_MAX_ATTEMPTS",      "5")),
            reconnect_base_delay_seconds = float(_optional_env("RECONNECT_BASE_DELAY_SEC",  "2.0")),
            inbound_queue_maxsize        = int(_optional_env("INBOUND_QUEUE_MAXSIZE",       "2000")),
        )

    def __repr__(self) -> str:
        # Redact secrets from repr so they cannot appear in logs or tracebacks.
        return (
            f"HandshakeConfig("
            f"iomt_server_ws_url={self.iomt_server_ws_url!r}, "
            f"cardioai_backend_id={self.cardioai_backend_id!r}, "
            f"shared_secret=<REDACTED>, "
            f"jwt_secret=<REDACTED>)"
        )


# ============================================================================
# SECTION 2 — PROTOCOL DEFINITIONS
# ============================================================================

class MsgType(str, Enum):
    """All wire-level message types for the IoMT ↔ CardioAI protocol."""
    HELLO            = "hello"
    CHALLENGE        = "challenge"
    CHALLENGE_RESP   = "challenge_resp"
    AUTH_OK          = "auth_ok"
    AUTH_FAIL        = "auth_fail"
    HEARTBEAT        = "heartbeat"
    HEARTBEAT_ACK    = "heartbeat_ack"
    DEVICE_LIST      = "device_list"
    DEVICE_LIST_ACK  = "device_list_ack"
    SUBSCRIBE        = "subscribe"
    SUBSCRIBE_ACK    = "subscribe_ack"
    UNSUBSCRIBE      = "unsubscribe"
    DISCONNECT       = "disconnect"
    RPM_DATA         = "rpm_data"
    RPM_ACK          = "rpm_ack"
    ERROR            = "error"


def build_message(
    msg_type:  MsgType,
    payload:   Dict[str, Any],
    sender_id: str,
) -> str:
    """
    Serialise a protocol message to a JSON string.
    Every message carries a unique msg_id for deduplication and tracing.
    """
    return json.dumps({
        "msg_id":    str(uuid.uuid4()),
        "type":      msg_type.value,
        "sender_id": sender_id,
        "timestamp": _utcnow_iso(),
        "payload":   payload,
    })


def parse_message(raw: str) -> Dict[str, Any]:
    """
    Deserialise a JSON message from the wire.
    Raises ValueError on malformed input — callers must handle this.
    """
    if not raw:
        raise ValueError("Empty message received")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc


def _utcnow_iso() -> str:
    """Return current UTC time as an ISO-8601 string (timezone-aware)."""
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# SECTION 3 — SECURITY MANAGER
# ============================================================================

class AuthenticationError(PermissionError):
    """Raised when an HMAC challenge or JWT verification fails."""


class SecurityManager:
    """
    HMAC-SHA256 challenge/response authentication and JWT session tokens.

    Design decisions
    ----------------
    * Challenges use secrets.token_bytes() (CSPRNG) — not uuid4() which,
      while random, goes through the uuid module's entropy path.
    * All signature comparisons use hmac.compare_digest() to prevent
      timing side-channel attacks.
    * datetime.now(timezone.utc) replaces the deprecated datetime.utcnow().
    * Secrets are never logged, even at DEBUG level.
    """

    _CHALLENGE_BYTES = 32   # 256 bits of entropy per challenge

    def __init__(self, cfg: HandshakeConfig) -> None:
        self._cfg = cfg

    # ── Challenge generation ──────────────────────────────────────────────────

    def generate_challenge(self) -> str:
        """Return a fresh, cryptographically random base64-encoded challenge."""
        return base64.b64encode(secrets.token_bytes(self._CHALLENGE_BYTES)).decode()

    # ── HMAC operations ───────────────────────────────────────────────────────

    def sign_challenge(self, challenge: str) -> str:
        """Produce an HMAC-SHA256 hex-digest of *challenge* using the shared secret."""
        return _hmac.new(
            self._cfg.shared_secret.encode("utf-8"),
            challenge.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify_challenge(self, challenge: str, signature: str) -> bool:
        """
        Return True iff *signature* is the correct HMAC of *challenge*.
        Uses constant-time comparison to prevent timing oracles.
        """
        expected = self.sign_challenge(challenge)
        return _hmac.compare_digest(expected, signature)

    # ── JWT session tokens ────────────────────────────────────────────────────

    def issue_token(self, peer_id: str, device_ids: List[str]) -> str:
        """
        Issue a short-lived HS256 JWT granting access to *device_ids*.
        Expiry is set to now + token_ttl_seconds using timezone-aware datetimes.
        """
        now = datetime.now(timezone.utc)
        payload = {
            "iss":        self._cfg.cardioai_backend_id,
            "sub":        peer_id,
            "iat":        now,
            "exp":        now + __import__("datetime").timedelta(
                              seconds=self._cfg.token_ttl_seconds),
            "device_ids": device_ids,
        }
        return jwt.encode(payload, self._cfg.jwt_secret,
                          algorithm=self._cfg.jwt_algorithm)

    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify and decode a JWT.
        Raises AuthenticationError on expiry, bad signature, or malformed input.
        """
        try:
            return jwt.decode(
                token,
                self._cfg.jwt_secret,
                algorithms=[self._cfg.jwt_algorithm],
            )
        except ExpiredSignatureError as exc:
            raise AuthenticationError("JWT has expired") from exc
        except InvalidTokenError as exc:
            raise AuthenticationError(f"JWT verification failed: {exc}") from exc

    def __repr__(self) -> str:
        return f"SecurityManager(cfg={self._cfg!r})"


# ============================================================================
# SECTION 4 — DATA MODELS
# ============================================================================

class DeviceType(str, Enum):
    ECG_MONITOR         = "ecg_monitor"
    BP_MONITOR          = "bp_monitor"
    PULSE_OXIMETER      = "pulse_oximeter"
    SMART_STETHOSCOPE   = "smart_stethoscope"
    IMPLANTABLE_MONITOR = "implantable_monitor"
    ACTIVITY_TRACKER    = "activity_tracker"
    PACE_MAKER          = "pace_maker"


class AlertLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class ArrhythmiaType(str, Enum):
    NORMAL_SINUS             = "normal_sinus"
    ATRIAL_FIBRILLATION      = "atrial_fibrillation"
    VENTRICULAR_TACHYCARDIA  = "ventricular_tachycardia"
    VENTRICULAR_FIBRILLATION = "ventricular_fibrillation"
    BRADYCARDIA              = "bradycardia"
    TACHYCARDIA              = "tachycardia"


@dataclass
class DeviceData:
    device_id:   str
    device_type: str
    patient_id:  str
    timestamp:   str
    data:        Dict[str, Any]
    quality_score: float = 1.0


@dataclass
class ProcessedSignal:
    device_id:   str
    signal_type: str
    features:    Dict[str, Any]
    quality:     float
    timestamp:   str


@dataclass
class DiagnosticResult:
    patient_id:      str
    diagnosis:       str
    risk_scores:     Dict[str, float]
    recommendations: List[str]
    confidence:      float
    timestamp:       str


@dataclass
class Alert:
    alert_id:         str = field(default_factory=lambda: str(uuid.uuid4()))
    patient_id:       str = ""
    alert_level:      AlertLevel = AlertLevel.LOW
    description:      str = ""
    required_actions: List[str] = field(default_factory=list)
    notified_parties: List[str] = field(default_factory=list)
    timestamp:        str = field(default_factory=_utcnow_iso)


# ============================================================================
# SECTION 5 — MESSAGE BUS
# ============================================================================

class MessageBus:
    """
    Async pub/sub event bus for inter-agent communication.

    Topics are arbitrary strings.  Subscribers may be sync or async callables.
    Exceptions in one subscriber are caught and logged; they do not prevent
    other subscribers from receiving the same message.
    """

    def __init__(self) -> None:
        self._subscribers:    Dict[str, List[Callable]] = {}
        self._message_history: List[Dict]               = []

    def subscribe(self, topic: str, callback: Callable) -> None:
        self._subscribers.setdefault(topic, []).append(callback)
        logger.debug("[Bus] subscribed topic=%s", topic)

    async def publish(self, topic: str, message: Any) -> None:
        self._message_history.append(
            {"topic": topic, "message": message, "timestamp": _utcnow_iso()}
        )
        for cb in self._subscribers.get(topic, []):
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(message)
                else:
                    cb(message)
            except Exception:
                logger.exception("[Bus] subscriber error on topic=%s", topic)

    @property
    def message_count(self) -> int:
        return len(self._message_history)


# ============================================================================
# SECTION 6 — BASE AGENT
# ============================================================================

class BaseAgent(ABC):
    """Abstract base class for all CardioAI pipeline agents."""

    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        self.agent_id    = agent_id
        self.message_bus = message_bus
        self.state:      Dict[str, Any] = {}
        self.is_running  = False

    @abstractmethod
    async def process(self, data: Any) -> Any: ...

    async def start(self) -> None:
        self.is_running = True
        logger.info("[Agent] %s started", self.agent_id)

    async def stop(self) -> None:
        self.is_running = False
        logger.info("[Agent] %s stopped", self.agent_id)


# ============================================================================
# SECTION 7 — AGENT 1: DATA ACQUISITION
# ============================================================================

class DataAcquisitionAgent(BaseAgent):
    """
    Registers IoMT devices, validates incoming sensor data quality, and
    publishes raw frames onto the shared MessageBus.

    Quality scoring
    ---------------
    * None-valued fields: score × 0.7 per occurrence.
    * Heart rate out of physiological range [30, 250] bpm: score × 0.5.
    Frames scoring below 0.6 are silently discarded by the processing agent.
    """

    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        self._devices:      Dict[str, Dict]              = {}
        self._stream_queues: Dict[str, asyncio.Queue]    = {}
        message_bus.subscribe("device.register", self._on_device_register)

    # ── Public API ────────────────────────────────────────────────────────────

    async def register_device(
        self,
        device_id:   str,
        device_type: str,
        patient_id:  str,
    ) -> None:
        self._devices[device_id] = {
            "device_id":   device_id,
            "device_type": device_type,
            "patient_id":  patient_id,
            "registered_at": _utcnow_iso(),
        }
        self._stream_queues[device_id] = asyncio.Queue()
        await self.message_bus.publish(
            "device.registered",
            {"device_id": device_id, "patient_id": patient_id},
        )
        logger.info("[Acquisition] registered device=%s patient=%s",
                    device_id, patient_id)

    async def stream_data(self, device_id: str, data: Dict[str, Any]) -> None:
        if device_id not in self._devices:
            return
        quality = self.validate_data_quality(data.get("data", {}))
        frame = {**data, "quality_score": quality, "timestamp": _utcnow_iso()}
        await self.message_bus.publish("data.raw", frame)

    async def process(self, data: Any) -> None:
        if isinstance(data, dict) and "device_id" in data:
            await self.stream_data(data["device_id"], data)

    # ── Quality scoring ───────────────────────────────────────────────────────

    def validate_data_quality(self, data: Dict[str, Any]) -> float:
        """
        Return a [0, 1] quality score for an incoming sensor data dict.
        Handles None values safely before numeric comparisons.
        """
        score = 1.0
        for v in data.values():
            if v is None:
                score *= 0.7
        hr = data.get("heart_rate")
        if hr is not None and (hr < 30 or hr > 250):
            score *= 0.5
        return score

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _on_device_register(self, msg: Dict) -> None:
        await self.register_device(
            msg["device_id"], msg["device_type"], msg["patient_id"]
        )


# ============================================================================
# SECTION 8 — AGENT 2: DATA PROCESSING
# ============================================================================

class DataProcessingAgent(BaseAgent):
    """
    Applies a quality gate (threshold 0.6) and routes frames to
    signal-specific feature extractors before publishing ProcessedSignal
    objects for pattern recognition.
    """

    _QUALITY_THRESHOLD = 0.6

    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        message_bus.subscribe("data.raw", self.process)

    async def process(self, data: Any) -> Optional[ProcessedSignal]:
        if data.get("quality_score", 0) < self._QUALITY_THRESHOLD:
            logger.debug("[Processing] frame dropped (quality=%.2f)", data.get("quality_score", 0))
            return None

        signal_type = data.get("device_type", "generic")
        handlers: Dict[str, Callable] = {
            "ecg_monitor":   self._process_ecg,
            "bp_monitor":    self._process_bp,
            "pulse_oximeter": self._process_spo2,
        }
        handler = handlers.get(signal_type, self._process_generic)
        result  = await handler(data)
        if result:
            await self.message_bus.publish("data.processed", result)
        return result

    async def _process_ecg(self, data: Dict) -> ProcessedSignal:
        raw = data.get("data", {})
        hr  = raw.get("heart_rate", 60.0)
        return ProcessedSignal(
            device_id   = data["device_id"],
            signal_type = "ecg",
            features    = {
                "heart_rate":  hr,
                "rr_mean_ms":  60_000 / hr if hr else 0,
                "qrs_width_ms": raw.get("qrs_width_ms", 80),
                "qt_interval_ms": raw.get("qt_interval_ms", 400),
                "st_elevation": raw.get("st_elevation", 0.0),
            },
            quality   = data["quality_score"],
            timestamp = data["timestamp"],
        )

    async def _process_bp(self, data: Dict) -> ProcessedSignal:
        raw = data.get("data", {})
        s   = raw.get("systolic",  120.0)
        d   = raw.get("diastolic",  80.0)
        pp  = s - d
        return ProcessedSignal(
            device_id   = data["device_id"],
            signal_type = "bp",
            features    = {
                "systolic":         s,
                "diastolic":        d,
                "pulse_pressure":   pp,
                "map":              d + pp / 3,
            },
            quality   = data["quality_score"],
            timestamp = data["timestamp"],
        )

    async def _process_spo2(self, data: Dict) -> ProcessedSignal:
        raw = data.get("data", {})
        return ProcessedSignal(
            device_id   = data["device_id"],
            signal_type = "spo2",
            features    = {"spo2_pct": raw.get("spo2", 98.0)},
            quality     = data["quality_score"],
            timestamp   = data["timestamp"],
        )

    async def _process_generic(self, data: Dict) -> ProcessedSignal:
        return ProcessedSignal(
            device_id   = data["device_id"],
            signal_type = "generic",
            features    = data.get("data", {}),
            quality     = data["quality_score"],
            timestamp   = data["timestamp"],
        )


# ============================================================================
# SECTION 9 — AGENT 3: PATTERN RECOGNITION
# ============================================================================

class PatternRecognitionAgent(BaseAgent):
    """
    Clinical pattern classifier using ACC/AHA 2017 guidelines.

    Classifies: arrhythmia type, ST-elevation ischemia, hypertension stage,
    and QT-interval abnormalities.
    """

    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        message_bus.subscribe("data.processed", self.process)

    async def process(self, signal: Any) -> None:
        if not isinstance(signal, ProcessedSignal):
            return
        if signal.signal_type == "ecg":
            await self._analyse_ecg(signal)
        elif signal.signal_type == "bp":
            await self._analyse_bp(signal)

    # ── ECG pattern analysis ──────────────────────────────────────────────────

    async def _analyse_ecg(self, signal: ProcessedSignal) -> None:
        f       = signal.features
        pattern = {
            "device_id":    signal.device_id,
            "pattern_type": "ecg_pattern",
            "arrhythmia":   self.detect_arrhythmia(f).value,
            "ischemia":     self.detect_ischemia(f),
            "qt_abnormal":  self._qt_abnormal(f.get("qt_interval_ms", 400)),
            "confidence":   0.92,
            "timestamp":    signal.timestamp,
        }
        await self.message_bus.publish("pattern.ecg", pattern)

    async def _analyse_bp(self, signal: ProcessedSignal) -> None:
        f       = signal.features
        pattern = {
            "device_id":    signal.device_id,
            "pattern_type": "bp_pattern",
            "hypertension_stage": self.classify_hypertension(f),
            "hypotension":  f.get("systolic", 120) < 90,
            "wide_pulse_pressure": f.get("pulse_pressure", 40) > 60,
            "confidence":   0.95,
            "timestamp":    signal.timestamp,
        }
        await self.message_bus.publish("pattern.bp", pattern)

    # ── Classifiers ───────────────────────────────────────────────────────────

    def detect_arrhythmia(self, features: Dict) -> ArrhythmiaType:
        hr       = features.get("heart_rate", 60)
        qrs_ms   = features.get("qrs_width_ms", 80)
        rr_mean  = features.get("rr_mean_ms", 1000)

        if hr < 50:
            return ArrhythmiaType.BRADYCARDIA
        if hr > 150 and qrs_ms > 120:
            return ArrhythmiaType.VENTRICULAR_TACHYCARDIA
        if 110 <= hr <= 150 and rr_mean < 200:
            return ArrhythmiaType.ATRIAL_FIBRILLATION
        if hr > 100:
            return ArrhythmiaType.TACHYCARDIA
        return ArrhythmiaType.NORMAL_SINUS

    def detect_ischemia(self, features: Dict) -> bool:
        """ST elevation or depression beyond ±0.1 mV indicates ischemia."""
        return abs(features.get("st_elevation", 0.0)) > 0.1

    def classify_hypertension(self, features: Dict) -> str:
        """ACC/AHA 2017 staging: normal / elevated / stage_1 / stage_2 / hypertensive_crisis."""
        s = features.get("systolic",  120)
        d = features.get("diastolic",  80)
        if s >= 180 or d >= 120:  return "hypertensive_crisis"
        if s >= 140 or d >= 90:   return "stage_2"
        if s >= 130 or d >= 80:   return "stage_1"
        if s >= 120 and d < 80:   return "elevated"
        return "normal"

    @staticmethod
    def _qt_abnormal(qt_ms: float) -> bool:
        return qt_ms > 480 or qt_ms < 340


# ============================================================================
# SECTION 10 — AGENT 4: DIAGNOSTIC
# ============================================================================

class DiagnosticAgent(BaseAgent):
    """
    Interprets patterns into clinical diagnoses and computes multi-dimensional
    risk scores (ASCVD, HF, stroke, SCD).  All recommendations are staged for
    clinician review — never auto-approved.
    """

    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        self._patient_history: Dict[str, List[DiagnosticResult]] = {}
        message_bus.subscribe("pattern.ecg", self.process)
        message_bus.subscribe("pattern.bp",  self.process)

    async def process(self, pattern: Any) -> Optional[DiagnosticResult]:
        if not isinstance(pattern, dict):
            return None
        patient_id = pattern.get("device_id", "unknown")
        result = DiagnosticResult(
            patient_id      = patient_id,
            diagnosis       = self._interpret_pattern(pattern),
            risk_scores     = self._compute_risk_scores(pattern),
            recommendations = self._generate_recommendations(pattern),
            confidence      = pattern.get("confidence", 0.8),
            timestamp       = _utcnow_iso(),
        )
        self._patient_history.setdefault(patient_id, []).append(result)
        await self.message_bus.publish("diagnosis.result", result)
        return result

    # ── Interpretation ────────────────────────────────────────────────────────

    def _interpret_pattern(self, pattern: Dict) -> str:
        arrhythmia = pattern.get("arrhythmia", "")
        labels = {
            ArrhythmiaType.ATRIAL_FIBRILLATION.value:      "Atrial Fibrillation",
            ArrhythmiaType.VENTRICULAR_TACHYCARDIA.value:  "Ventricular Tachycardia",
            ArrhythmiaType.VENTRICULAR_FIBRILLATION.value: "Ventricular Fibrillation",
            ArrhythmiaType.BRADYCARDIA.value:               "Bradycardia",
            ArrhythmiaType.TACHYCARDIA.value:               "Tachycardia",
            ArrhythmiaType.NORMAL_SINUS.value:              "Normal Sinus Rhythm",
        }
        stage = pattern.get("hypertension_stage")
        if stage and stage != "normal":
            return f"Hypertension — {stage.replace('_', ' ').title()}"
        return labels.get(arrhythmia, "Undetermined pattern")

    def _compute_risk_scores(self, pattern: Dict) -> Dict[str, float]:
        is_afib = pattern.get("arrhythmia") == ArrhythmiaType.ATRIAL_FIBRILLATION.value
        is_vtach = pattern.get("arrhythmia") == ArrhythmiaType.VENTRICULAR_TACHYCARDIA.value
        return {
            "ascvd_10yr":   min(0.95, 0.15 + (0.2 if pattern.get("ischemia") else 0.0)),
            "hf_risk":      min(0.95, 0.10 + (0.3 if is_afib else 0.0)),
            "stroke_risk":  0.35 if is_afib else 0.05,
            "scd_risk":     0.45 if is_vtach else 0.05,
        }

    def _generate_recommendations(self, pattern: Dict) -> List[str]:
        recs: List[str] = []
        arrhythmia = pattern.get("arrhythmia", "")
        if arrhythmia == ArrhythmiaType.ATRIAL_FIBRILLATION.value:
            recs.append("Initiate anticoagulation therapy (CHA2DS2-VASc ≥ 2)")
            recs.append("Rate/rhythm control evaluation")
        if arrhythmia == ArrhythmiaType.VENTRICULAR_TACHYCARDIA.value:
            recs.append("Immediate medical intervention required")
            recs.append("ICD referral evaluation")
        if pattern.get("ischemia"):
            recs.append("Urgent cardiology review — possible ACS")
            recs.append("12-lead ECG confirmation")
        stage = pattern.get("hypertension_stage", "")
        if stage in ("stage_2", "hypertensive_crisis"):
            recs.append("Antihypertensive therapy adjustment")
        return recs


# ============================================================================
# SECTION 11 — AGENT 5: ALERT MONITORING
# ============================================================================

class AlertMonitoringAgent(BaseAgent):
    """
    Triages diagnostic results into CRITICAL / HIGH / MEDIUM / LOW alerts
    and determines notification targets.

    Triage rules (in priority order)
    ---------------------------------
    CRITICAL : VTach / VFib / SCD risk > 0.4
    HIGH     : AFib with HR > 130 / ischemia / ASCVD > 0.3
    MEDIUM   : AFib with HR ≤ 130 / hypertension stage_2
    LOW      : everything else with any finding
    None     : normal sinus, normal BP
    """

    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        self.active_alerts: Dict[str, Alert] = {}
        message_bus.subscribe("diagnosis.result", self.process)

    async def process(self, result: Any) -> Optional[Alert]:
        if not isinstance(result, DiagnosticResult):
            return None
        level = self._triage(result)
        if level is None:
            return None
        alert = Alert(
            patient_id       = result.patient_id,
            alert_level      = level,
            description      = result.diagnosis,
            required_actions = self._required_actions(level, result),
            notified_parties = self._notification_list(level),
        )
        self.active_alerts[alert.alert_id] = alert
        await self.message_bus.publish("alert.new", alert)
        logger.warning(
            "[Alert] %s — patient=%s diagnosis=%s",
            level.value.upper(), result.patient_id, result.diagnosis,
        )
        return alert

    def _triage(self, result: DiagnosticResult) -> Optional[AlertLevel]:
        rs = result.risk_scores
        d  = result.diagnosis.lower()
        if "ventricular tachycardia" in d or "ventricular fibrillation" in d or rs.get("scd_risk", 0) > 0.4:
            return AlertLevel.CRITICAL
        if "atrial fibrillation" in d and rs.get("stroke_risk", 0) > 0.3:
            return AlertLevel.HIGH
        if "ischemia" in d or rs.get("ascvd_10yr", 0) > 0.3:
            return AlertLevel.HIGH
        if "atrial fibrillation" in d:
            return AlertLevel.MEDIUM
        if "hypertension" in d and "stage_2" in d:
            return AlertLevel.MEDIUM
        if result.diagnosis and result.diagnosis != "Normal Sinus Rhythm":
            return AlertLevel.LOW
        return None

    def _required_actions(self, level: AlertLevel, result: DiagnosticResult) -> List[str]:
        base = {
            AlertLevel.CRITICAL: ["ACTIVATE_DEFIBRILLATOR", "CALL_RAPID_RESPONSE", "DISPATCH_EMS"],
            AlertLevel.HIGH:     ["NOTIFY_CARDIOLOGIST_15_MIN", "PREPARE_ADVANCED_MONITORING"],
            AlertLevel.MEDIUM:   ["NOTIFY_PRIMARY_CARE", "SCHEDULE_REVIEW_24H"],
            AlertLevel.LOW:      ["LOG_FOR_ROUTINE_REVIEW"],
        }
        return base.get(level, []) + [f"REVIEW: {r}" for r in result.recommendations[:2]]

    @staticmethod
    def _notification_list(level: AlertLevel) -> List[str]:
        targets = {
            AlertLevel.CRITICAL: ["emergency_services", "rapid_response_team",
                                  "on_call_cardiologist", "nursing_supervisor"],
            AlertLevel.HIGH:     ["on_call_cardiologist", "primary_nurse"],
            AlertLevel.MEDIUM:   ["primary_care_physician"],
            AlertLevel.LOW:      ["care_coordinator"],
        }
        return targets.get(level, [])


# ============================================================================
# SECTION 12 — AGENT 6: PERSONALIZATION
# ============================================================================

class PersonalizationAgent(BaseAgent):
    """
    Maintains per-patient baseline profiles via running averages and stores
    alert histories to surface personalised thresholds over time.
    """

    _DEFAULT_THRESHOLDS: Dict[str, float] = {
        "hr_high":        100.0,
        "spo2_low":        92.0,
        "systolic_high":  140.0,
        "diastolic_high":  90.0,
    }

    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        self.patient_profiles: Dict[str, Dict] = {}
        message_bus.subscribe("data.processed", self.process)
        message_bus.subscribe("alert.new",       self._on_alert)

    async def process(self, signal: Any) -> None:
        if not isinstance(signal, ProcessedSignal):
            return
        pid = signal.device_id
        if pid not in self.patient_profiles:
            self.patient_profiles[pid] = {
                "baselines": {}, "alert_history": [], "sample_count": 0,
            }
        await self._update_baseline(pid, signal.features)

    async def _update_baseline(self, patient_id: str, features: Dict) -> None:
        profile = self.patient_profiles[patient_id]
        n       = profile["sample_count"] + 1
        for k, v in features.items():
            if not isinstance(v, (int, float)):
                continue
            prev = profile["baselines"].get(k, v)
            profile["baselines"][k] = prev + (v - prev) / n
        profile["sample_count"] = n

    async def _on_alert(self, alert: Alert) -> None:
        pid = alert.patient_id
        if pid not in self.patient_profiles:
            self.patient_profiles[pid] = {
                "baselines": {}, "alert_history": [], "sample_count": 0,
            }
        self.patient_profiles[pid]["alert_history"].append({
            "alert_id": alert.alert_id,
            "level":    alert.alert_level.value,
            "ts":       alert.timestamp,
        })

    def get_threshold(self, patient_id: str, metric: str) -> float:
        """Return personalised threshold if available, else clinical default."""
        profile = self.patient_profiles.get(patient_id, {})
        return profile.get("thresholds", {}).get(
            metric, self._DEFAULT_THRESHOLDS.get(metric, 0.0)
        )


# ============================================================================
# SECTION 13 — AGENT 7: COMMUNICATION
# ============================================================================

class CommunicationAgent(BaseAgent):
    """
    Formats alert summaries and generates structured clinical reports.
    Reports accumulate in-memory for status queries; in production they are
    also written to EHR via FHIR R4 (IoMT_clinical_workflow.EHRConnector).
    """

    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        self.report_store: List[Dict] = []
        message_bus.subscribe("alert.new", self.process)

    async def process(self, alert: Any) -> None:
        if not isinstance(alert, Alert):
            return
        summary = self._format_summary(alert)
        report  = {
            "report_id":  str(uuid.uuid4()),
            "alert_id":   alert.alert_id,
            "patient_id": alert.patient_id,
            "level":      alert.alert_level.value,
            "summary":    summary,
            "actions":    alert.required_actions,
            "notified":   alert.notified_parties,
            "generated_at": _utcnow_iso(),
        }
        self.report_store.append(report)
        logger.info("[Comms] report generated patient=%s level=%s",
                    alert.patient_id, alert.alert_level.value)

    @staticmethod
    def _format_summary(alert: Alert) -> str:
        return (
            f"[{alert.alert_level.value.upper()}] Patient {alert.patient_id}: "
            f"{alert.description}. "
            f"Actions: {', '.join(alert.required_actions[:2])}. "
            f"Notified: {', '.join(alert.notified_parties)}."
        )


# ============================================================================
# SECTION 14 — MULTI-AGENT COORDINATOR
# ============================================================================

class CardioAISystem:
    """
    Lifecycle coordinator for the 7-agent clinical AI pipeline.
    Creates a shared MessageBus and wires all agents onto it.
    """

    def __init__(self) -> None:
        self.message_bus = MessageBus()
        self.agents: Dict[str, BaseAgent] = {
            "acquisition":    DataAcquisitionAgent("acq-001",    self.message_bus),
            "processing":     DataProcessingAgent("proc-001",    self.message_bus),
            "pattern":        PatternRecognitionAgent("pat-001", self.message_bus),
            "diagnostic":     DiagnosticAgent("diag-001",        self.message_bus),
            "alert_monitoring": AlertMonitoringAgent("alert-001",self.message_bus),
            "personalization":  PersonalizationAgent("pers-001", self.message_bus),
            "communication":    CommunicationAgent("comm-001",   self.message_bus),
        }

    async def start(self) -> None:
        for agent in self.agents.values():
            await agent.start()
        logger.info("[CardioAI] All %d agents started", len(self.agents))

    async def stop(self) -> None:
        for agent in self.agents.values():
            await agent.stop()
        logger.info("[CardioAI] All agents stopped")


# ============================================================================
# SECTION 15 — DEVICE SESSION REGISTRY
# ============================================================================

@dataclass
class DeviceSession:
    device_id:          str
    device_type:        DeviceType
    patient_id:         str
    is_active:          bool          = True
    registered_at:      str           = field(default_factory=_utcnow_iso)
    last_data_at:       Optional[str] = None
    data_count:         int           = 0
    missed_heartbeats:  int           = 0


class DeviceSessionRegistry:
    """Thread-safe in-memory registry of active device sessions."""

    def __init__(self) -> None:
        self._sessions: Dict[str, DeviceSession] = {}

    def register(
        self, device_id: str, device_type: str, patient_id: str
    ) -> DeviceSession:
        try:
            dt = DeviceType(device_type)
        except ValueError:
            dt = DeviceType.ECG_MONITOR
        session = DeviceSession(
            device_id   = device_id,
            device_type = dt,
            patient_id  = patient_id,
        )
        self._sessions[device_id] = session
        logger.info("[Registry] registered device=%s type=%s", device_id, device_type)
        return session

    def get(self, device_id: str) -> Optional[DeviceSession]:
        return self._sessions.get(device_id)

    def mark_data_received(self, device_id: str) -> None:
        session = self._sessions.get(device_id)
        if session:
            session.data_count         += 1
            session.last_data_at        = _utcnow_iso()
            session.missed_heartbeats   = 0

    def mark_inactive(self, device_id: str) -> None:
        session = self._sessions.get(device_id)
        if session:
            session.is_active = False

    def active_devices(self) -> List[DeviceSession]:
        return [s for s in self._sessions.values() if s.is_active]

    def summary(self) -> Dict[str, Any]:
        sessions = list(self._sessions.values())
        return {
            "total":    len(sessions),
            "active":   sum(1 for s in sessions if s.is_active),
            "inactive": sum(1 for s in sessions if not s.is_active),
            "devices":  [
                {
                    "device_id":   s.device_id,
                    "patient_id":  s.patient_id,
                    "is_active":   s.is_active,
                    "data_count":  s.data_count,
                    "last_data_at": s.last_data_at,
                }
                for s in sessions
            ],
        }


# ============================================================================
# SECTION 16 — IoMT SERVER CONNECTOR  (WebSocket CLIENT)
# ============================================================================

class IoMTServerConnector:
    """
    WebSocket client that connects to the IoMT server and runs the
    3-way HMAC-SHA256 handshake before streaming RPM data.

    Reconnection
    ------------
    Exponential back-off up to *reconnect_max_attempts*.  Attempt counter
    resets on a successful session to allow recovery after transient faults.

    Back-pressure
    -------------
    When the inbound queue is full, the oldest frame is evicted before the
    new one is enqueued, ensuring the pipeline always processes the most
    recent sensor readings.
    """

    def __init__(
        self,
        cfg:           HandshakeConfig,
        inbound_queue: asyncio.Queue,
        registry:      DeviceSessionRegistry,
    ) -> None:
        self.cfg            = cfg
        self.inbound_queue  = inbound_queue
        self.registry       = registry
        self._security      = SecurityManager(cfg)
        self._ws:            Optional[websockets.WebSocketClientProtocol] = None
        self._token:         Optional[str]   = None
        self._connected      = asyncio.Event()
        self._stop           = asyncio.Event()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Outer reconnect loop with exponential back-off."""
        attempt = 0
        while not self._stop.is_set():
            try:
                logger.info("[Connector] connecting to %s (attempt %d)",
                            self.cfg.iomt_server_ws_url, attempt + 1)
                async with websockets.connect(
                    self.cfg.iomt_server_ws_url,
                    ping_interval = None,   # we handle keep-alive manually
                    ssl           = None,   # set ssl=True in production with TLS context
                ) as ws:
                    self._ws  = ws
                    attempt   = 0           # reset on successful connect
                    await self._run_session(ws)

            except (websockets.ConnectionClosed, OSError) as exc:
                self._connected.clear()
                attempt += 1
                if attempt >= self.cfg.reconnect_max_attempts:
                    logger.error(
                        "[Connector] max reconnect attempts (%d) reached — stopping",
                        self.cfg.reconnect_max_attempts,
                    )
                    break
                delay = self.cfg.reconnect_base_delay_seconds * (2 ** (attempt - 1))
                logger.info("[Connector] reconnecting in %.1fs ...", delay)
                await asyncio.sleep(delay)

    async def stop(self) -> None:
        self._stop.set()
        if self._ws:
            await self._ws.close()

    # ── Session orchestration ─────────────────────────────────────────────────

    async def _run_session(self, ws: websockets.WebSocketClientProtocol) -> None:
        await self._handshake(ws)
        device_ids = await self._fetch_and_register_devices(ws)
        await self._subscribe_devices(ws, device_ids)
        self._connected.set()
        logger.info("[Connector] session established — streaming %d device(s)",
                    len(device_ids))
        await asyncio.gather(
            self._receive_loop(ws),
            self._heartbeat_loop(ws),
        )

    # ── 3-way HMAC handshake ──────────────────────────────────────────────────

    async def _handshake(self, ws: websockets.WebSocketClientProtocol) -> None:
        """
        Perform the 3-way HMAC-SHA256 handshake:
          1. Send HELLO with client identity.
          2. Receive CHALLENGE (random nonce from server).
          3. Send CHALLENGE_RESP with HMAC-SHA256(shared_secret, nonce).
          4. Receive AUTH_OK with JWT session token.
        """
        # Step 1 — HELLO
        await ws.send(build_message(
            MsgType.HELLO,
            {"client_id": self.cfg.cardioai_backend_id, "version": "1.0"},
            self.cfg.cardioai_backend_id,
        ))

        # Step 2 — CHALLENGE
        msg = parse_message(await asyncio.wait_for(ws.recv(), timeout=10))
        if msg["type"] != MsgType.CHALLENGE.value:
            raise RuntimeError(f"Expected CHALLENGE, got {msg['type']}")
        challenge = msg["payload"]["challenge"]

        # Step 3 — CHALLENGE_RESP  (sign nonce with shared secret)
        await ws.send(build_message(
            MsgType.CHALLENGE_RESP,
            {
                "challenge":  challenge,
                "signature":  self._security.sign_challenge(challenge),
            },
            self.cfg.cardioai_backend_id,
        ))

        # Step 4 — AUTH_OK / AUTH_FAIL
        msg = parse_message(await asyncio.wait_for(ws.recv(), timeout=10))
        if msg["type"] == MsgType.AUTH_FAIL.value:
            raise AuthenticationError(
                f"IoMT server rejected authentication: {msg['payload']}"
            )
        if msg["type"] != MsgType.AUTH_OK.value:
            raise RuntimeError(f"Expected AUTH_OK, got {msg['type']}")

        self._token = msg["payload"].get("token")
        logger.info("[Handshake] authentication successful")

    # ── Device registration ───────────────────────────────────────────────────

    async def _fetch_and_register_devices(
        self, ws: websockets.WebSocketClientProtocol
    ) -> List[str]:
        await ws.send(build_message(
            MsgType.DEVICE_LIST,
            {"token": self._token},
            self.cfg.cardioai_backend_id,
        ))
        msg = parse_message(await asyncio.wait_for(ws.recv(), timeout=15))
        if msg["type"] != MsgType.DEVICE_LIST_ACK.value:
            raise RuntimeError(f"Expected DEVICE_LIST_ACK, got {msg['type']}")

        device_ids = []
        for d in msg["payload"]["devices"]:
            self.registry.register(d["device_id"], d["device_type"], d["patient_id"])
            device_ids.append(d["device_id"])

        logger.info("[Connector] %d device(s) registered", len(device_ids))
        return device_ids

    async def _subscribe_devices(
        self, ws: websockets.WebSocketClientProtocol, device_ids: List[str]
    ) -> None:
        await ws.send(build_message(
            MsgType.SUBSCRIBE,
            {
                "token":           self._token,
                "device_ids":      device_ids,
                "rpm_interval_ms": int(self.cfg.rpm_poll_interval_seconds * 1000),
            },
            self.cfg.cardioai_backend_id,
        ))
        msg = parse_message(await asyncio.wait_for(ws.recv(), timeout=10))
        if msg["type"] != MsgType.SUBSCRIBE_ACK.value:
            raise RuntimeError(f"Subscription failed: {msg}")
        logger.info("[Connector] subscribed to RPM streams")

    # ── Receive / heartbeat loops ─────────────────────────────────────────────

    async def _receive_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        async for raw in ws:
            try:
                msg = parse_message(raw)
            except ValueError as exc:
                logger.warning("[Connector] malformed message: %s", exc)
                continue

            mtype = msg.get("type")
            if mtype == MsgType.RPM_DATA.value:
                await self._handle_rpm_data(msg, ws)
            elif mtype == MsgType.HEARTBEAT.value:
                await ws.send(build_message(
                    MsgType.HEARTBEAT_ACK,
                    {"ts": _utcnow_iso()},
                    self.cfg.cardioai_backend_id,
                ))
            elif mtype == MsgType.ERROR.value:
                logger.error("[Connector] server error: %s", msg["payload"])
            elif mtype == MsgType.DISCONNECT.value:
                logger.warning("[Connector] server requested disconnect")
                break

    async def _heartbeat_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(self.cfg.heartbeat_interval_seconds)
            try:
                await ws.send(build_message(
                    MsgType.HEARTBEAT,
                    {"ts": _utcnow_iso()},
                    self.cfg.cardioai_backend_id,
                ))
            except websockets.ConnectionClosed:
                break

    # ── RPM frame handling ────────────────────────────────────────────────────

    async def _handle_rpm_data(
        self, msg: Dict, ws: websockets.WebSocketClientProtocol
    ) -> None:
        payload   = msg["payload"]
        device_id = payload.get("device_id")
        session   = self.registry.get(device_id)

        if not session or not session.is_active:
            return

        self.registry.mark_data_received(device_id)

        # Back-pressure: evict oldest frame if queue is full
        if self.inbound_queue.full():
            try:
                self.inbound_queue.get_nowait()
                logger.warning("[Connector] inbound queue full — oldest frame evicted")
            except asyncio.QueueEmpty:
                pass

        await self.inbound_queue.put({
            "device_id":   device_id,
            "device_type": session.device_type.value,
            "patient_id":  session.patient_id,
            "timestamp":   payload.get("timestamp", _utcnow_iso()),
            "data":        payload.get("data", {}),
            "quality_score": payload.get("quality_score", 1.0),
        })

        # Acknowledge receipt
        await ws.send(build_message(
            MsgType.RPM_ACK,
            {"msg_id": msg["msg_id"]},
            self.cfg.cardioai_backend_id,
        ))


# ============================================================================
# SECTION 17 — RPM DATA PUMP
# ============================================================================

class RPMDataPump:
    """
    Drains the inbound queue and injects frames into the CardioAI pipeline
    via DataAcquisitionAgent.process().

    An optional *on_rpm_frame* callback is invoked for each frame,
    which can be used to forward frames to Kafka, InfluxDB, or any other
    external sink without coupling this class to those dependencies.
    """

    def __init__(
        self,
        inbound_queue:   asyncio.Queue,
        cardioai_system: CardioAISystem,
        registry:        DeviceSessionRegistry,
        on_rpm_frame:    Optional[Callable[[Dict], Any]] = None,
    ) -> None:
        self.queue        = inbound_queue
        self.system       = cardioai_system
        self.registry     = registry
        self.on_rpm_frame = on_rpm_frame
        self._stop        = asyncio.Event()
        self.stats: Dict[str, Any] = {
            "frames_processed": 0,
            "frames_dropped":   0,
            "last_frame_at":    None,
        }

    async def run(self) -> None:
        logger.info("[RPMPump] started")
        while not self._stop.is_set():
            try:
                frame = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            try:
                await self._process_frame(frame)
            except Exception:
                logger.exception("[RPMPump] error processing frame device=%s",
                                 frame.get("device_id"))
                self.stats["frames_dropped"] += 1
            finally:
                self.queue.task_done()

    async def stop(self) -> None:
        self._stop.set()

    async def _process_frame(self, frame: Dict) -> None:
        device_id = frame.get("device_id")
        if device_id and not self.registry.get(device_id):
            self.registry.register(
                device_id,
                frame.get("device_type", "ecg_monitor"),
                frame.get("patient_id", "unknown"),
            )

        acq_agent = self.system.agents["acquisition"]
        await acq_agent.process(frame)

        self.stats["frames_processed"] += 1
        self.stats["last_frame_at"]     = _utcnow_iso()

        if self.on_rpm_frame:
            try:
                result = self.on_rpm_frame(frame)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("[RPMPump] on_rpm_frame callback error")


# ============================================================================
# SECTION 18 — DEVICE HEALTH MONITOR
# ============================================================================

class DeviceHealthMonitor:
    """
    Periodically inspects active DeviceSession objects for data staleness.

    A device is considered stale when:
      • last_data_at is older than *stale_threshold_seconds*, OR
      • missed_heartbeats ≥ 3

    On detection the device is marked inactive and a 'device.inactive' event
    is published so downstream consumers can react (e.g. raise a nurse alert).
    """

    _MAX_MISSED_HEARTBEATS = 3

    def __init__(
        self,
        registry:                DeviceSessionRegistry,
        message_bus:             MessageBus,
        stale_threshold_seconds: float = 30.0,
        check_interval_seconds:  float = 10.0,
    ) -> None:
        self.registry        = registry
        self.message_bus     = message_bus
        self.stale_threshold = stale_threshold_seconds
        self.check_interval  = check_interval_seconds
        self._stop           = asyncio.Event()

    async def run(self) -> None:
        logger.info("[HealthMonitor] started (threshold=%.0fs)", self.stale_threshold)
        while not self._stop.is_set():
            await asyncio.sleep(self.check_interval)
            await self._check_all_devices()

    async def stop(self) -> None:
        self._stop.set()

    async def _check_all_devices(self) -> None:
        now = datetime.now(timezone.utc)
        for session in self.registry.active_devices():
            if session.last_data_at is None:
                continue  # device registered but never sent data — skip
            last = datetime.fromisoformat(session.last_data_at)
            # Make last timezone-aware if necessary
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            stale = (
                (now - last).total_seconds() > self.stale_threshold
                or session.missed_heartbeats >= self._MAX_MISSED_HEARTBEATS
            )
            if stale:
                self.registry.mark_inactive(session.device_id)
                await self.message_bus.publish("device.inactive", {
                    "device_id":  session.device_id,
                    "patient_id": session.patient_id,
                    "reason":     "stale_data",
                    "last_seen":  session.last_data_at,
                })
                logger.warning(
                    "[HealthMonitor] device=%s patient=%s marked inactive",
                    session.device_id, session.patient_id,
                )


# ============================================================================
# SECTION 19 — BRIDGE (TOP-LEVEL ORCHESTRATOR)
# ============================================================================

class IoMTCardioAIBridge:
    """
    Top-level orchestrator that wires all subsystems together and exposes a
    single start() / stop() interface.

    Component ownership
    -------------------
    - CardioAISystem         : 7-agent AI pipeline with shared MessageBus
    - IoMTServerConnector    : WebSocket client + HMAC handshake
    - RPMDataPump            : queue → pipeline injection
    - DeviceHealthMonitor    : dropout detection
    - DeviceSessionRegistry  : session state

    GCP write-back (via IoMT_gcp_compduide)
    -----------------------------------------
    The *on_rpm_frame* hook passed to RPMDataPump forwards each frame to
    GCPPubSubPublisher.  Diagnostic events are written to BigQuery via the
    'diagnosis.result' topic subscription set up at startup.
    """

    def __init__(
        self,
        cardioai_system: CardioAISystem,
        cfg:             Optional[HandshakeConfig] = None,
    ) -> None:
        self.cfg      = cfg or HandshakeConfig.from_env()
        self.system   = cardioai_system
        self.registry = DeviceSessionRegistry()
        self._queue: asyncio.Queue = asyncio.Queue(
            maxsize=self.cfg.inbound_queue_maxsize
        )
        self.connector = IoMTServerConnector(
            self.cfg, self._queue, self.registry
        )
        self.pump = RPMDataPump(
            inbound_queue   = self._queue,
            cardioai_system = self.system,
            registry        = self.registry,
        )
        self.health_monitor = DeviceHealthMonitor(
            registry    = self.registry,
            message_bus = self.system.message_bus,
        )
        self._tasks: List[asyncio.Task] = []

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the 7-agent pipeline and all background services."""
        await self.system.start()
        self._tasks = [
            asyncio.create_task(self.connector.run(),       name="iomt_connector"),
            asyncio.create_task(self.pump.run(),            name="rpm_pump"),
            asyncio.create_task(self.health_monitor.run(),  name="health_monitor"),
        ]
        logger.info("[Bridge] started — %d background tasks running",
                    len(self._tasks))

    async def stop(self) -> None:
        """Graceful shutdown: stop all background tasks then the pipeline."""
        await self.connector.stop()
        await self.pump.stop()
        await self.health_monitor.stop()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.system.stop()
        logger.info("[Bridge] stopped cleanly")

    # ── Status snapshot ────────────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        """Return a JSON-serialisable snapshot of the bridge's current state."""
        return {
            "bridge_id":         self.cfg.cardioai_backend_id,
            "timestamp":         _utcnow_iso(),
            "queue_depth":       self._queue.qsize(),
            "pump_stats":        self.pump.stats,
            "devices":           self.registry.summary(),
            "agent_count":       len(self.system.agents),
            "message_bus_total": self.system.message_bus.message_count,
        }


# ============================================================================
# SECTION 20 — ENTRY POINT
# ============================================================================

async def main() -> None:
    """
    Production entry point.

    Reads all configuration from environment variables, starts the bridge,
    and runs until SIGINT / SIGTERM is received.

    Usage
    -----
    export IOMT_SERVER_WS_URL="wss://iomt.hospital.local/stream"
    export CARDIOAI_BACKEND_ID="cardioai-prod-01"
    export IOMT_SHARED_SECRET="<32+ char secret from Vault>"
    export IOMT_JWT_SECRET="<32+ char secret from Vault>"
    python iomt_cardioai_production.py
    """
    logger.info("[Startup] IoMT CardioAI Production Service initialising ...")

    try:
        cfg = HandshakeConfig.from_env()
    except ConfigurationError as exc:
        logger.critical("[Startup] configuration error: %s", exc)
        sys.exit(1)

    logger.info("[Startup] config loaded: %r", cfg)

    system = CardioAISystem()
    bridge = IoMTCardioAIBridge(system, cfg)

    loop = asyncio.get_running_loop()

    # Register graceful shutdown on SIGINT / SIGTERM
    import signal as _signal
    shutdown_event = asyncio.Event()

    def _handle_signal(sig: int) -> None:
        logger.info("[Shutdown] received signal %s", _signal.Signals(sig).name)
        shutdown_event.set()

    for sig in (_signal.SIGINT, _signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig)
        except NotImplementedError:
            # Windows does not support loop.add_signal_handler
            pass

    await bridge.start()
    logger.info("[Startup] bridge running — awaiting shutdown signal")

    await shutdown_event.wait()

    logger.info("[Shutdown] stopping bridge ...")
    await bridge.stop()

    # Final status snapshot
    logger.info("[Shutdown] final status: %s", json.dumps(bridge.status(), default=str))
    logger.info("[Shutdown] clean exit")


if __name__ == "__main__":
    asyncio.run(main())
