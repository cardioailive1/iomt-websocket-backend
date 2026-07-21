"""
IoMT CardioAI — Production System
===================================
IoMT Server ↔ CardioAI Backend: HMAC-SHA256 handshake, real-time RPM
streaming, 7-agent clinical AI pipeline, and authenticated HTTP API.
"""

from __future__ import annotations

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

import numpy as np
import websockets
import aiohttp
import jwt

try:
    import bcrypt
except ImportError as _bcrypt_err:
    import subprocess as _subprocess
    print("=" * 78, file=sys.stderr)
    print("FATAL: 'import bcrypt' failed at startup.", file=sys.stderr)
    print(f"Original error: {_bcrypt_err}", file=sys.stderr)
    raise

from aiohttp import web as _web
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

try:
    from db import Database, HospitalUser, UserRole as DBUserRole, LargeDevice  # noqa: E402
except ImportError as _db_import_err:
    print("FATAL: 'from db import ...' failed at startup.", file=sys.stderr)
    print(f"Original error: {_db_import_err}", file=sys.stderr)
    raise

from kafka_bus import (  # noqa: E402
    KafkaEventProducer, KafkaEventConsumer,
    TOPIC_VENDOR_RAW, TOPIC_VENDOR_DEADLETTER,
)
from fhir_client import fhir_client  # noqa: E402
from hl7_server import HL7MLLPServer, AdmissionRegistry, send_oru  # noqa: E402
import subscription_verification as _sub_verify  # noqa: E402

# Shared admission registry — populated by the HL7 MLLP listener (if
# enabled), read by GET /admissions. Not yet wired into alert triage
# logic; see hl7_server.py module docstring for the intended hook point.
_admission_registry = AdmissionRegistry()


def _build_logger() -> logging.Logger:
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
        level=level, format=fmt, datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout, force=True,
    )
    return logging.getLogger("iomt_cardioai")


logger = _build_logger()


class ConfigurationError(RuntimeError):
    pass


def _require_env(name: str, min_length: int = 0) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"Required environment variable '{name}' is not set.")
    if len(value) < min_length:
        raise ConfigurationError(f"'{name}' must be at least {min_length} characters long (got {len(value)}).")
    return value


def _optional_env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip() or default


@dataclass(frozen=True)
class HandshakeConfig:
    iomt_server_ws_url:   str
    iomt_server_rest_url: str
    iomt_server_id:       str
    cardioai_backend_id:  str
    cardioai_ws_host:     str
    cardioai_ws_port:     int
    shared_secret:        str
    jwt_secret:           str
    jwt_algorithm:        str
    token_ttl_seconds:    int
    rpm_poll_interval_seconds:    float
    heartbeat_interval_seconds:   float
    reconnect_max_attempts:       int
    reconnect_base_delay_seconds: float
    inbound_queue_maxsize:        int

    @classmethod
    def from_env(cls) -> "HandshakeConfig":
        return cls(
            iomt_server_ws_url   = _require_env("IOMT_SERVER_WS_URL"),
            iomt_server_rest_url = _optional_env("IOMT_SERVER_REST_URL", "https://iomt-server.hospital.local/api/v1"),
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

    @property
    def api_host(self) -> str:
        return _optional_env("CARDIOAI_API_HOST", "0.0.0.0")

    @property
    def api_port(self) -> int:
        explicit = _optional_env("CARDIOAI_API_PORT", "")
        if explicit:
            return int(explicit)
        platform_port = _optional_env("PORT", "")
        if platform_port:
            return int(platform_port)
        return 8080

    @property
    def refresh_token_ttl(self) -> int:
        return int(_optional_env("REFRESH_TOKEN_TTL_SECONDS", "604800"))

    @property
    def mfa_required(self) -> bool:
        return _optional_env("MFA_REQUIRED", "false").lower() == "true"

    @property
    def allowed_origins(self) -> str:
        return _optional_env("ALLOWED_ORIGINS", "*")

    def __repr__(self) -> str:
        return (
            f"HandshakeConfig(iomt_server_ws_url={self.iomt_server_ws_url!r}, "
            f"cardioai_backend_id={self.cardioai_backend_id!r}, "
            f"shared_secret=<REDACTED>, jwt_secret=<REDACTED>)"
        )


class MsgType(str, Enum):
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


def build_message(msg_type: MsgType, payload: Dict[str, Any], sender_id: str) -> str:
    return json.dumps({
        "msg_id": str(uuid.uuid4()), "type": msg_type.value, "sender_id": sender_id,
        "timestamp": _utcnow_iso(), "payload": payload,
    })


def parse_message(raw: str) -> Dict[str, Any]:
    if not raw:
        raise ValueError("Empty message received")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuthenticationError(PermissionError):
    pass


class SecurityManager:
    _CHALLENGE_BYTES = 32

    def __init__(self, cfg: HandshakeConfig) -> None:
        self._cfg = cfg

    def generate_challenge(self) -> str:
        return base64.b64encode(secrets.token_bytes(self._CHALLENGE_BYTES)).decode()

    def sign_challenge(self, challenge: str) -> str:
        return _hmac.new(self._cfg.shared_secret.encode("utf-8"), challenge.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_challenge(self, challenge: str, signature: str) -> bool:
        expected = self.sign_challenge(challenge)
        return _hmac.compare_digest(expected, signature)

    def issue_token(self, peer_id: str, device_ids: List[str]) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "iss": self._cfg.cardioai_backend_id, "sub": peer_id, "iat": now,
            "exp": now + __import__("datetime").timedelta(seconds=self._cfg.token_ttl_seconds),
            "device_ids": device_ids,
        }
        return jwt.encode(payload, self._cfg.jwt_secret, algorithm=self._cfg.jwt_algorithm)

    def verify_token(self, token: str) -> Dict[str, Any]:
        try:
            return jwt.decode(token, self._cfg.jwt_secret, algorithms=[self._cfg.jwt_algorithm])
        except ExpiredSignatureError as exc:
            raise AuthenticationError("JWT has expired") from exc
        except InvalidTokenError as exc:
            raise AuthenticationError(f"JWT verification failed: {exc}") from exc

    def __repr__(self) -> str:
        return f"SecurityManager(cfg={self._cfg!r})"


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
    device_id: str
    device_type: str
    patient_id: str
    timestamp: str
    data: Dict[str, Any]
    quality_score: float = 1.0


@dataclass
class ProcessedSignal:
    device_id: str
    signal_type: str
    features: Dict[str, Any]
    quality: float
    timestamp: str


@dataclass
class DiagnosticResult:
    patient_id: str
    diagnosis: str
    risk_scores: Dict[str, float]
    recommendations: List[str]
    confidence: float
    timestamp: str


@dataclass
class Alert:
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    patient_id: str = ""
    alert_level: AlertLevel = AlertLevel.LOW
    description: str = ""
    required_actions: List[str] = field(default_factory=list)
    notified_parties: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_utcnow_iso)


class MessageBus:
    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Callable]] = {}
        self._message_history: List[Dict] = []

    def subscribe(self, topic: str, callback: Callable) -> None:
        self._subscribers.setdefault(topic, []).append(callback)
        logger.debug("[Bus] subscribed topic=%s", topic)

    async def publish(self, topic: str, message: Any) -> None:
        self._message_history.append({"topic": topic, "message": message, "timestamp": _utcnow_iso()})
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


class BaseAgent(ABC):
    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        self.agent_id = agent_id
        self.message_bus = message_bus
        self.state: Dict[str, Any] = {}
        self.is_running = False

    @abstractmethod
    async def process(self, data: Any) -> Any: ...

    async def start(self) -> None:
        self.is_running = True
        logger.info("[Agent] %s started", self.agent_id)

    async def stop(self) -> None:
        self.is_running = False
        logger.info("[Agent] %s stopped", self.agent_id)


class DataAcquisitionAgent(BaseAgent):
    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        self._devices: Dict[str, Dict] = {}
        self._stream_queues: Dict[str, asyncio.Queue] = {}
        message_bus.subscribe("device.register", self._on_device_register)

    async def register_device(self, device_id: str, device_type: str, patient_id: str) -> None:
        self._devices[device_id] = {
            "device_id": device_id, "device_type": device_type, "patient_id": patient_id,
            "registered_at": _utcnow_iso(),
        }
        self._stream_queues[device_id] = asyncio.Queue()
        await self.message_bus.publish("device.registered", {"device_id": device_id, "patient_id": patient_id})
        logger.info("[Acquisition] registered device=%s patient=%s", device_id, patient_id)

    async def stream_data(self, device_id: str, data: Dict[str, Any]) -> None:
        if device_id not in self._devices:
            return
        quality = self.validate_data_quality(data.get("data", {}))
        frame = {**data, "quality_score": quality, "timestamp": _utcnow_iso()}
        await self.message_bus.publish("data.raw", frame)

    async def process(self, data: Any) -> None:
        if isinstance(data, dict) and "device_id" in data:
            await self.stream_data(data["device_id"], data)

    def validate_data_quality(self, data: Dict[str, Any]) -> float:
        score = 1.0
        for v in data.values():
            if v is None:
                score *= 0.7
        hr = data.get("heart_rate")
        if hr is not None and (hr < 30 or hr > 250):
            score *= 0.5
        return score

    async def _on_device_register(self, msg: Dict) -> None:
        await self.register_device(msg["device_id"], msg["device_type"], msg["patient_id"])


class DataProcessingAgent(BaseAgent):
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
            "ecg_monitor": self._process_ecg, "bp_monitor": self._process_bp,
            "pulse_oximeter": self._process_spo2,
        }
        handler = handlers.get(signal_type, self._process_generic)
        result = await handler(data)
        if result:
            await self.message_bus.publish("data.processed", result)
        return result

    async def _process_ecg(self, data: Dict) -> ProcessedSignal:
        raw = data.get("data", {})
        hr = raw.get("heart_rate", 60.0)
        return ProcessedSignal(
            device_id=data["device_id"], signal_type="ecg",
            features={
                "heart_rate": hr, "rr_mean_ms": 60_000 / hr if hr else 0,
                "qrs_width_ms": raw.get("qrs_width_ms", 80),
                "qt_interval_ms": raw.get("qt_interval_ms", 400),
                "st_elevation": raw.get("st_elevation", 0.0),
            },
            quality=data["quality_score"], timestamp=data["timestamp"],
        )

    async def _process_bp(self, data: Dict) -> ProcessedSignal:
        raw = data.get("data", {})
        s = raw.get("systolic", 120.0)
        d = raw.get("diastolic", 80.0)
        pp = s - d
        return ProcessedSignal(
            device_id=data["device_id"], signal_type="bp",
            features={"systolic": s, "diastolic": d, "pulse_pressure": pp, "map": d + pp / 3},
            quality=data["quality_score"], timestamp=data["timestamp"],
        )

    async def _process_spo2(self, data: Dict) -> ProcessedSignal:
        raw = data.get("data", {})
        return ProcessedSignal(
            device_id=data["device_id"], signal_type="spo2",
            features={"spo2_pct": raw.get("spo2", 98.0)},
            quality=data["quality_score"], timestamp=data["timestamp"],
        )

    async def _process_generic(self, data: Dict) -> ProcessedSignal:
        return ProcessedSignal(
            device_id=data["device_id"], signal_type="generic", features=data.get("data", {}),
            quality=data["quality_score"], timestamp=data["timestamp"],
        )


class PatternRecognitionAgent(BaseAgent):
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

    async def _analyse_ecg(self, signal: ProcessedSignal) -> None:
        f = signal.features
        pattern = {
            "device_id": signal.device_id, "pattern_type": "ecg_pattern",
            "arrhythmia": self.detect_arrhythmia(f).value, "ischemia": self.detect_ischemia(f),
            "qt_abnormal": self._qt_abnormal(f.get("qt_interval_ms", 400)),
            "confidence": 0.92, "timestamp": signal.timestamp,
        }
        await self.message_bus.publish("pattern.ecg", pattern)

    async def _analyse_bp(self, signal: ProcessedSignal) -> None:
        f = signal.features
        pattern = {
            "device_id": signal.device_id, "pattern_type": "bp_pattern",
            "hypertension_stage": self.classify_hypertension(f),
            "hypotension": f.get("systolic", 120) < 90,
            "wide_pulse_pressure": f.get("pulse_pressure", 40) > 60,
            "confidence": 0.95, "timestamp": signal.timestamp,
        }
        await self.message_bus.publish("pattern.bp", pattern)

    def detect_arrhythmia(self, features: Dict) -> ArrhythmiaType:
        hr = features.get("heart_rate", 60)
        qrs_ms = features.get("qrs_width_ms", 80)
        rr_mean = features.get("rr_mean_ms", 1000)
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
        return abs(features.get("st_elevation", 0.0)) > 0.1

    def classify_hypertension(self, features: Dict) -> str:
        s = features.get("systolic", 120)
        d = features.get("diastolic", 80)
        if s >= 180 or d >= 120: return "hypertensive_crisis"
        if s >= 140 or d >= 90:  return "stage_2"
        if s >= 130 or d >= 80:  return "stage_1"
        if s >= 120 and d < 80:  return "elevated"
        return "normal"

    @staticmethod
    def _qt_abnormal(qt_ms: float) -> bool:
        return qt_ms > 480 or qt_ms < 340


class DiagnosticAgent(BaseAgent):
    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        self._patient_history: Dict[str, List[DiagnosticResult]] = {}
        message_bus.subscribe("pattern.ecg", self.process)
        message_bus.subscribe("pattern.bp", self.process)

    async def process(self, pattern: Any) -> Optional[DiagnosticResult]:
        if not isinstance(pattern, dict):
            return None
        patient_id = pattern.get("device_id", "unknown")
        result = DiagnosticResult(
            patient_id=patient_id, diagnosis=self._interpret_pattern(pattern),
            risk_scores=self._compute_risk_scores(pattern),
            recommendations=self._generate_recommendations(pattern),
            confidence=pattern.get("confidence", 0.8), timestamp=_utcnow_iso(),
        )
        self._patient_history.setdefault(patient_id, []).append(result)
        await self.message_bus.publish("diagnosis.result", result)
        return result

    def _interpret_pattern(self, pattern: Dict) -> str:
        arrhythmia = pattern.get("arrhythmia", "")
        labels = {
            ArrhythmiaType.ATRIAL_FIBRILLATION.value: "Atrial Fibrillation",
            ArrhythmiaType.VENTRICULAR_TACHYCARDIA.value: "Ventricular Tachycardia",
            ArrhythmiaType.VENTRICULAR_FIBRILLATION.value: "Ventricular Fibrillation",
            ArrhythmiaType.BRADYCARDIA.value: "Bradycardia",
            ArrhythmiaType.TACHYCARDIA.value: "Tachycardia",
            ArrhythmiaType.NORMAL_SINUS.value: "Normal Sinus Rhythm",
        }
        stage = pattern.get("hypertension_stage")
        if stage and stage != "normal":
            return f"Hypertension — {stage.replace('_', ' ').title()}"
        return labels.get(arrhythmia, "Undetermined pattern")

    def _compute_risk_scores(self, pattern: Dict) -> Dict[str, float]:
        is_afib = pattern.get("arrhythmia") == ArrhythmiaType.ATRIAL_FIBRILLATION.value
        is_vtach = pattern.get("arrhythmia") == ArrhythmiaType.VENTRICULAR_TACHYCARDIA.value
        return {
            "ascvd_10yr": min(0.95, 0.15 + (0.2 if pattern.get("ischemia") else 0.0)),
            "hf_risk": min(0.95, 0.10 + (0.3 if is_afib else 0.0)),
            "stroke_risk": 0.35 if is_afib else 0.05,
            "scd_risk": 0.45 if is_vtach else 0.05,
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


class AlertMonitoringAgent(BaseAgent):
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

        # HL7 ADT-aware reprioritization (opt-in via
        # HL7_ADMISSION_ALERT_SUPPRESSION_ENABLED). Only ever suppresses
        # LOW-severity findings for patients currently admitted — the
        # rationale being that a patient already under direct inpatient/
        # bedside monitoring doesn't need a redundant LOW-severity IoMT
        # alert. MEDIUM/HIGH/CRITICAL are NEVER suppressed regardless of
        # admission status — this toggle can only reduce noise, never
        # miss something serious. See hl7_server.py module docstring.
        admission = _admission_registry.get(result.patient_id)
        if (
            level == AlertLevel.LOW
            and admission is not None
            and admission.status == "admitted"
            and _optional_env("HL7_ADMISSION_ALERT_SUPPRESSION_ENABLED", "false").lower() == "true"
        ):
            logger.debug(
                "[Alert] suppressed LOW alert for admitted patient_id=%s (location=%s) — "
                "already under direct inpatient monitoring",
                result.patient_id, admission.location,
            )
            return None

        required_actions = self._required_actions(level, result)
        # Additive, always-on: if the patient is currently admitted, prepend
        # their ward/location so nursing staff know where to respond —
        # independent of the suppression toggle above.
        if admission is not None and admission.status == "admitted" and admission.location:
            required_actions = [f"PATIENT CURRENTLY ADMITTED — Location: {admission.location}"] + required_actions

        alert = Alert(
            patient_id=result.patient_id, alert_level=level, description=result.diagnosis,
            required_actions=required_actions,
            notified_parties=self._notification_list(level),
        )
        self.active_alerts[alert.alert_id] = alert
        await self.message_bus.publish("alert.new", alert)
        logger.warning("[Alert] %s — patient=%s diagnosis=%s", level.value.upper(), result.patient_id, result.diagnosis)
        return alert

    def _triage(self, result: DiagnosticResult) -> Optional[AlertLevel]:
        rs = result.risk_scores
        d = result.diagnosis.lower()
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
            AlertLevel.HIGH: ["NOTIFY_CARDIOLOGIST_15_MIN", "PREPARE_ADVANCED_MONITORING"],
            AlertLevel.MEDIUM: ["NOTIFY_PRIMARY_CARE", "SCHEDULE_REVIEW_24H"],
            AlertLevel.LOW: ["LOG_FOR_ROUTINE_REVIEW"],
        }
        return base.get(level, []) + [f"REVIEW: {r}" for r in result.recommendations[:2]]

    @staticmethod
    def _notification_list(level: AlertLevel) -> List[str]:
        targets = {
            AlertLevel.CRITICAL: ["emergency_services", "rapid_response_team", "on_call_cardiologist", "nursing_supervisor"],
            AlertLevel.HIGH: ["on_call_cardiologist", "primary_nurse"],
            AlertLevel.MEDIUM: ["primary_care_physician"],
            AlertLevel.LOW: ["care_coordinator"],
        }
        return targets.get(level, [])


class PersonalizationAgent(BaseAgent):
    _DEFAULT_THRESHOLDS: Dict[str, float] = {
        "hr_high": 100.0, "spo2_low": 92.0, "systolic_high": 140.0, "diastolic_high": 90.0,
    }

    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        self.patient_profiles: Dict[str, Dict] = {}
        message_bus.subscribe("data.processed", self.process)
        message_bus.subscribe("alert.new", self._on_alert)

    async def process(self, signal: Any) -> None:
        if not isinstance(signal, ProcessedSignal):
            return
        pid = signal.device_id
        if pid not in self.patient_profiles:
            self.patient_profiles[pid] = {"baselines": {}, "alert_history": [], "sample_count": 0}
        await self._update_baseline(pid, signal.features)

    async def _update_baseline(self, patient_id: str, features: Dict) -> None:
        profile = self.patient_profiles[patient_id]
        n = profile["sample_count"] + 1
        for k, v in features.items():
            if not isinstance(v, (int, float)):
                continue
            prev = profile["baselines"].get(k, v)
            profile["baselines"][k] = prev + (v - prev) / n
        profile["sample_count"] = n

    async def _on_alert(self, alert: Alert) -> None:
        pid = alert.patient_id
        if pid not in self.patient_profiles:
            self.patient_profiles[pid] = {"baselines": {}, "alert_history": [], "sample_count": 0}
        self.patient_profiles[pid]["alert_history"].append({
            "alert_id": alert.alert_id, "level": alert.alert_level.value, "ts": alert.timestamp,
        })

    def get_threshold(self, patient_id: str, metric: str) -> float:
        profile = self.patient_profiles.get(patient_id, {})
        return profile.get("thresholds", {}).get(metric, self._DEFAULT_THRESHOLDS.get(metric, 0.0))


class CommunicationAgent(BaseAgent):
    def __init__(self, agent_id: str, message_bus: MessageBus) -> None:
        super().__init__(agent_id, message_bus)
        self.report_store: List[Dict] = []
        message_bus.subscribe("alert.new", self.process)

    async def process(self, alert: Any) -> None:
        if not isinstance(alert, Alert):
            return
        summary = self._format_summary(alert)
        report = {
            "report_id": str(uuid.uuid4()), "alert_id": alert.alert_id, "patient_id": alert.patient_id,
            "level": alert.alert_level.value, "summary": summary, "actions": alert.required_actions,
            "notified": alert.notified_parties, "generated_at": _utcnow_iso(),
        }
        self.report_store.append(report)
        logger.info("[Comms] report generated patient=%s level=%s", alert.patient_id, alert.alert_level.value)

        # ── Resolve which organization this alert belongs to, for
        # multi-hospital FHIR/HL7 routing ──────────────────────────────
        #
        # alert.patient_id is actually set from the originating device_id
        # (see DiagnosticAgent.process(), which copies pattern["device_id"]
        # into DiagnosticResult.patient_id) — so we look it up first against
        # large_devices (implants) and then ble_devices (patient-paired
        # wearables) to find both the real clinical patient_id and whichever
        # organization has been assigned to that device. If neither table
        # has an organization set for this device (e.g. a BLE device a
        # patient just paired that no clinician has configured yet), this
        # falls back to the global FHIR_*/HL7_ORU_* environment variables,
        # same as before either device type had organization linking.
        organization = None
        real_patient_id = alert.patient_id
        try:
            device = await _db.get_large_device_by_vendor_id(alert.patient_id)
            if device is not None:
                real_patient_id = device.patient_id
                if device.organization_id:
                    organization = await _db.get_organization_by_id(device.organization_id)
            else:
                ble_device = await _db.get_ble_device_by_device_id(alert.patient_id)
                if ble_device is not None:
                    real_patient_id = ble_device.patient_id
                    await _db.touch_ble_device_last_data(alert.patient_id)
                    if ble_device.organization_id:
                        organization = await _db.get_organization_by_id(ble_device.organization_id)
        except Exception:
            logger.exception("[Comms] error resolving organization for alert=%s", alert.alert_id)

        # FHIR R4 write-back — pushes this alert to the resolved hospital's
        # EHR (or the global default) as Condition + Flag resources.
        # Completely no-op unless FHIR is configured, either per-organization
        # or via the FHIR_* environment variables (see fhir_client.py).
        # Errors are swallowed inside push_alert() itself — a FHIR server
        # being down must never break the clinical alert pipeline, so this
        # is deliberately fire-and-forget with its own internal exception
        # handling, not just a bare await.
        try:
            await fhir_client.push_alert(alert, organization=organization)
        except Exception:
            logger.exception("[Comms] unexpected error calling fhir_client.push_alert")

        # HL7 v2 outbound (ORU^R01) — optional, for EHRs that consume HL7 v2
        # rather than FHIR. Sends the alert description and level as a
        # standard observation-result message. Opt-in via HL7_ORU_ENABLED;
        # no-op otherwise. Single-tenant only for now (one destination
        # interface engine per deployment) — see hl7_server.py.
        if _optional_env("HL7_ORU_ENABLED", "false").lower() == "true":
            oru_host = _optional_env("HL7_ORU_HOST", "")
            oru_port_raw = _optional_env("HL7_ORU_PORT", "")
            if oru_host and oru_port_raw:
                try:
                    await send_oru(
                        host=oru_host, port=int(oru_port_raw),
                        patient_id=real_patient_id, patient_name="",
                        observations=[
                            {"code": "ALERT", "system": "L", "display": "Alert Description", "value": alert.description},
                            {"code": "ALERT-LEVEL", "system": "L", "display": "Alert Level", "value": alert.alert_level.value},
                        ],
                    )
                except Exception:
                    logger.exception("[Comms] unexpected error calling send_oru")
            else:
                logger.warning("[Comms] HL7_ORU_ENABLED=true but HL7_ORU_HOST/HL7_ORU_PORT not set — skipping")

    @staticmethod
    def _format_summary(alert: Alert) -> str:
        return (
            f"[{alert.alert_level.value.upper()}] Patient {alert.patient_id}: {alert.description}. "
            f"Actions: {', '.join(alert.required_actions[:2])}. "
            f"Notified: {', '.join(alert.notified_parties)}."
        )


class CardioAISystem:
    def __init__(self) -> None:
        self.message_bus = MessageBus()
        self.agents: Dict[str, BaseAgent] = {
            "acquisition": DataAcquisitionAgent("acq-001", self.message_bus),
            "processing": DataProcessingAgent("proc-001", self.message_bus),
            "pattern": PatternRecognitionAgent("pat-001", self.message_bus),
            "diagnostic": DiagnosticAgent("diag-001", self.message_bus),
            "alert_monitoring": AlertMonitoringAgent("alert-001", self.message_bus),
            "personalization": PersonalizationAgent("pers-001", self.message_bus),
            "communication": CommunicationAgent("comm-001", self.message_bus),
        }

    async def start(self) -> None:
        for agent in self.agents.values():
            await agent.start()
        logger.info("[CardioAI] All %d agents started", len(self.agents))

    async def stop(self) -> None:
        for agent in self.agents.values():
            await agent.stop()
        logger.info("[CardioAI] All agents stopped")


@dataclass
class DeviceSession:
    device_id: str
    device_type: DeviceType
    patient_id: str
    is_active: bool = True
    registered_at: str = field(default_factory=_utcnow_iso)
    last_data_at: Optional[str] = None
    data_count: int = 0
    missed_heartbeats: int = 0


class DeviceSessionRegistry:
    def __init__(self) -> None:
        self._sessions: Dict[str, DeviceSession] = {}

    def register(self, device_id: str, device_type: str, patient_id: str) -> DeviceSession:
        try:
            dt = DeviceType(device_type)
        except ValueError:
            dt = DeviceType.ECG_MONITOR
        session = DeviceSession(device_id=device_id, device_type=dt, patient_id=patient_id)
        self._sessions[device_id] = session
        logger.info("[Registry] registered device=%s type=%s", device_id, device_type)
        return session

    def get(self, device_id: str) -> Optional[DeviceSession]:
        return self._sessions.get(device_id)

    def mark_data_received(self, device_id: str) -> None:
        session = self._sessions.get(device_id)
        if session:
            session.data_count += 1
            session.last_data_at = _utcnow_iso()
            session.missed_heartbeats = 0

    def mark_inactive(self, device_id: str) -> None:
        session = self._sessions.get(device_id)
        if session:
            session.is_active = False

    def active_devices(self) -> List[DeviceSession]:
        return [s for s in self._sessions.values() if s.is_active]

    def summary(self) -> Dict[str, Any]:
        sessions = list(self._sessions.values())
        return {
            "total": len(sessions),
            "active": sum(1 for s in sessions if s.is_active),
            "inactive": sum(1 for s in sessions if not s.is_active),
            "devices": [
                {
                    "device_id": s.device_id, "patient_id": s.patient_id, "is_active": s.is_active,
                    "data_count": s.data_count, "last_data_at": s.last_data_at,
                    "device_type": s.device_type.value,
                }
                for s in sessions
            ],
        }


class IoMTServerConnector:
    def __init__(self, cfg: HandshakeConfig, inbound_queue: asyncio.Queue, registry: DeviceSessionRegistry) -> None:
        self.cfg = cfg
        self.inbound_queue = inbound_queue
        self.registry = registry
        self._security = SecurityManager(cfg)
        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._token: Optional[str] = None
        self._connected = asyncio.Event()
        self._stop = asyncio.Event()

    async def run(self) -> None:
        attempt = 0
        while not self._stop.is_set():
            try:
                logger.info("[Connector] connecting to %s (attempt %d)", self.cfg.iomt_server_ws_url, attempt + 1)
                async with websockets.connect(self.cfg.iomt_server_ws_url, ping_interval=None, ssl=None) as ws:
                    self._ws = ws
                    attempt = 0
                    await self._run_session(ws)
            except (websockets.ConnectionClosed, OSError):
                self._connected.clear()
                attempt += 1
                if attempt >= self.cfg.reconnect_max_attempts:
                    logger.error("[Connector] max reconnect attempts (%d) reached — stopping", self.cfg.reconnect_max_attempts)
                    break
                delay = self.cfg.reconnect_base_delay_seconds * (2 ** (attempt - 1))
                logger.info("[Connector] reconnecting in %.1fs ...", delay)
                await asyncio.sleep(delay)

    async def stop(self) -> None:
        self._stop.set()
        if self._ws:
            await self._ws.close()

    async def _run_session(self, ws) -> None:
        await self._handshake(ws)
        device_ids = await self._fetch_and_register_devices(ws)
        await self._subscribe_devices(ws, device_ids)
        self._connected.set()
        logger.info("[Connector] session established — streaming %d device(s)", len(device_ids))
        await asyncio.gather(self._receive_loop(ws), self._heartbeat_loop(ws))

    async def _handshake(self, ws) -> None:
        await ws.send(build_message(MsgType.HELLO, {"client_id": self.cfg.cardioai_backend_id, "version": "1.0"}, self.cfg.cardioai_backend_id))
        msg = parse_message(await asyncio.wait_for(ws.recv(), timeout=10))
        if msg["type"] != MsgType.CHALLENGE.value:
            raise RuntimeError(f"Expected CHALLENGE, got {msg['type']}")
        challenge = msg["payload"]["challenge"]
        await ws.send(build_message(MsgType.CHALLENGE_RESP, {"challenge": challenge, "signature": self._security.sign_challenge(challenge)}, self.cfg.cardioai_backend_id))
        msg = parse_message(await asyncio.wait_for(ws.recv(), timeout=10))
        if msg["type"] == MsgType.AUTH_FAIL.value:
            raise AuthenticationError(f"IoMT server rejected authentication: {msg['payload']}")
        if msg["type"] != MsgType.AUTH_OK.value:
            raise RuntimeError(f"Expected AUTH_OK, got {msg['type']}")
        self._token = msg["payload"].get("token")
        logger.info("[Handshake] authentication successful")

    async def _fetch_and_register_devices(self, ws) -> List[str]:
        await ws.send(build_message(MsgType.DEVICE_LIST, {"token": self._token}, self.cfg.cardioai_backend_id))
        msg = parse_message(await asyncio.wait_for(ws.recv(), timeout=15))
        if msg["type"] != MsgType.DEVICE_LIST_ACK.value:
            raise RuntimeError(f"Expected DEVICE_LIST_ACK, got {msg['type']}")
        device_ids = []
        for d in msg["payload"]["devices"]:
            self.registry.register(d["device_id"], d["device_type"], d["patient_id"])
            device_ids.append(d["device_id"])
        logger.info("[Connector] %d device(s) registered", len(device_ids))
        return device_ids

    async def _subscribe_devices(self, ws, device_ids: List[str]) -> None:
        await ws.send(build_message(MsgType.SUBSCRIBE, {
            "token": self._token, "device_ids": device_ids,
            "rpm_interval_ms": int(self.cfg.rpm_poll_interval_seconds * 1000),
        }, self.cfg.cardioai_backend_id))
        msg = parse_message(await asyncio.wait_for(ws.recv(), timeout=10))
        if msg["type"] != MsgType.SUBSCRIBE_ACK.value:
            raise RuntimeError(f"Subscription failed: {msg}")
        logger.info("[Connector] subscribed to RPM streams")

    async def _receive_loop(self, ws) -> None:
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
                await ws.send(build_message(MsgType.HEARTBEAT_ACK, {"ts": _utcnow_iso()}, self.cfg.cardioai_backend_id))
            elif mtype == MsgType.ERROR.value:
                logger.error("[Connector] server error: %s", msg["payload"])
            elif mtype == MsgType.DISCONNECT.value:
                logger.warning("[Connector] server requested disconnect")
                break

    async def _heartbeat_loop(self, ws) -> None:
        while not self._stop.is_set():
            await asyncio.sleep(self.cfg.heartbeat_interval_seconds)
            try:
                await ws.send(build_message(MsgType.HEARTBEAT, {"ts": _utcnow_iso()}, self.cfg.cardioai_backend_id))
            except websockets.ConnectionClosed:
                break

    async def _handle_rpm_data(self, msg: Dict, ws) -> None:
        payload = msg["payload"]
        device_id = payload.get("device_id")
        session = self.registry.get(device_id)
        if not session or not session.is_active:
            return
        self.registry.mark_data_received(device_id)
        if self.inbound_queue.full():
            try:
                self.inbound_queue.get_nowait()
                logger.warning("[Connector] inbound queue full — oldest frame evicted")
            except asyncio.QueueEmpty:
                pass
        await self.inbound_queue.put({
            "device_id": device_id, "device_type": session.device_type.value, "patient_id": session.patient_id,
            "timestamp": payload.get("timestamp", _utcnow_iso()), "data": payload.get("data", {}),
            "quality_score": payload.get("quality_score", 1.0),
        })
        await ws.send(build_message(MsgType.RPM_ACK, {"msg_id": msg["msg_id"]}, self.cfg.cardioai_backend_id))


class RPMDataPump:
    def __init__(self, inbound_queue: asyncio.Queue, cardioai_system: CardioAISystem, registry: DeviceSessionRegistry, on_rpm_frame: Optional[Callable[[Dict], Any]] = None) -> None:
        self.queue = inbound_queue
        self.system = cardioai_system
        self.registry = registry
        self.on_rpm_frame = on_rpm_frame
        self._stop = asyncio.Event()
        self.stats: Dict[str, Any] = {"frames_processed": 0, "frames_dropped": 0, "last_frame_at": None}

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
                logger.exception("[RPMPump] error processing frame device=%s", frame.get("device_id"))
                self.stats["frames_dropped"] += 1
            finally:
                self.queue.task_done()

    async def stop(self) -> None:
        self._stop.set()

    async def _process_frame(self, frame: Dict) -> None:
        device_id = frame.get("device_id")
        if device_id and not self.registry.get(device_id):
            self.registry.register(device_id, frame.get("device_type", "ecg_monitor"), frame.get("patient_id", "unknown"))
        acq_agent = self.system.agents["acquisition"]
        await acq_agent.process(frame)
        self.stats["frames_processed"] += 1
        self.stats["last_frame_at"] = _utcnow_iso()
        if self.on_rpm_frame:
            try:
                result = self.on_rpm_frame(frame)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("[RPMPump] on_rpm_frame callback error")


class DeviceHealthMonitor:
    _MAX_MISSED_HEARTBEATS = 3

    def __init__(self, registry: DeviceSessionRegistry, message_bus: MessageBus, stale_threshold_seconds: float = 30.0, check_interval_seconds: float = 10.0) -> None:
        self.registry = registry
        self.message_bus = message_bus
        self.stale_threshold = stale_threshold_seconds
        self.check_interval = check_interval_seconds
        self._stop = asyncio.Event()

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
                continue
            last = datetime.fromisoformat(session.last_data_at)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            stale = (now - last).total_seconds() > self.stale_threshold or session.missed_heartbeats >= self._MAX_MISSED_HEARTBEATS
            if stale:
                self.registry.mark_inactive(session.device_id)
                await self.message_bus.publish("device.inactive", {
                    "device_id": session.device_id, "patient_id": session.patient_id,
                    "reason": "stale_data", "last_seen": session.last_data_at,
                })
                logger.warning("[HealthMonitor] device=%s patient=%s marked inactive", session.device_id, session.patient_id)


class IoMTCardioAIBridge:
    def __init__(self, cardioai_system: CardioAISystem, cfg: Optional[HandshakeConfig] = None) -> None:
        self.cfg = cfg or HandshakeConfig.from_env()
        self.system = cardioai_system
        self.registry = DeviceSessionRegistry()
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=self.cfg.inbound_queue_maxsize)
        self.connector = IoMTServerConnector(self.cfg, self._queue, self.registry)
        self.pump = RPMDataPump(inbound_queue=self._queue, cardioai_system=self.system, registry=self.registry)
        self.health_monitor = DeviceHealthMonitor(registry=self.registry, message_bus=self.system.message_bus)
        self._tasks: List[asyncio.Task] = []

    async def start(self) -> None:
        await self.system.start()
        self._tasks = [
            asyncio.create_task(self.connector.run(), name="iomt_connector"),
            asyncio.create_task(self.pump.run(), name="rpm_pump"),
            asyncio.create_task(self.health_monitor.run(), name="health_monitor"),
        ]
        logger.info("[Bridge] started — %d background tasks running", len(self._tasks))

    async def stop(self) -> None:
        await self.connector.stop()
        await self.pump.stop()
        await self.health_monitor.stop()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.system.stop()
        logger.info("[Bridge] stopped cleanly")

    def status(self) -> Dict[str, Any]:
        return {
            "bridge_id": self.cfg.cardioai_backend_id, "timestamp": _utcnow_iso(),
            "queue_depth": self._queue.qsize(), "pump_stats": self.pump.stats,
            "devices": self.registry.summary(), "agent_count": len(self.system.agents),
            "message_bus_total": self.system.message_bus.message_count,
        }


import re as _re
import time as _time
from collections import defaultdict as _defaultdict
from datetime import timedelta as _timedelta
from functools import wraps as _wraps

UserRole = DBUserRole
_db = Database()
_kafka_producer = KafkaEventProducer()


async def _load_user_by_email(email: str) -> Optional[HospitalUser]:
    return await _db.get_user_by_email(email)


async def _load_user_by_id(user_id: str) -> Optional[HospitalUser]:
    return await _db.get_user_by_id(user_id)


class RateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._attempts: Dict[str, list[float]] = _defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = _time.time()
        window_start = now - self._window
        attempts = [t for t in self._attempts[key] if t > window_start]
        self._attempts[key] = attempts
        if len(attempts) >= self._max:
            return False
        self._attempts[key].append(now)
        return True

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)


_AUTH_RATE_LIMITER = RateLimiter(max_attempts=5, window_seconds=300)


def _issue_access_token(user: HospitalUser, cfg: "HandshakeConfig") -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({
        "iss": cfg.cardioai_backend_id, "sub": user.id, "email": user.email,
        "role": user.role.value, "patient_id": user.patient_id, "iat": now,
        "exp": now + _timedelta(seconds=cfg.token_ttl_seconds), "token_type": "access",
    }, cfg.jwt_secret, algorithm=cfg.jwt_algorithm)


def _verify_access_token(token: str, cfg: "HandshakeConfig") -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, cfg.jwt_secret, algorithms=[cfg.jwt_algorithm])
    except ExpiredSignatureError as exc:
        raise AuthenticationError("Access token has expired") from exc
    except InvalidTokenError as exc:
        raise AuthenticationError(f"Invalid access token: {exc}") from exc
    if payload.get("token_type") != "access":
        raise AuthenticationError("Token is not an access token")
    return payload


def _cors_middleware(allowed_origins: str):
    @_web.middleware
    async def middleware(request, handler):
        origin = request.headers.get("Origin", "")
        if request.method == "OPTIONS":
            resp = _web.Response(status=204)
        else:
            try:
                resp = await handler(request)
            except _web.HTTPException as exc:
                resp = _web.Response(
                    status=exc.status, content_type="application/json",
                    body=json.dumps({"error": exc.reason}).encode(),
                )
            except Exception:
                # PATCHED: without this branch, any non-HTTPException error
                # (KeyError, asyncpg error, etc.) escapes this middleware
                # entirely. aiohttp then returns a bare 500 with NO CORS
                # headers, the browser blocks that response, and fetch()
                # throws on the client — which looks exactly like "server
                # unreachable" even though the server responded. This also
                # logs the full traceback so the real cause shows up in
                # Render logs instead of vanishing silently.
                logger.exception("[API] unhandled exception in %s %s", request.method, request.path)
                resp = _web.Response(
                    status=500, content_type="application/json",
                    body=json.dumps({
                        "error": "internal_server_error",
                        "message": "An unexpected error occurred. Check server logs.",
                    }).encode(),
                )

        allowed = allowed_origins if allowed_origins == "*" else allowed_origins
        resp.headers["Access-Control-Allow-Origin"] = allowed
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PATCH"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-Vendor-Api-Key"
        resp.headers["Access-Control-Max-Age"] = "86400"
        return resp
    return middleware


def _require_auth(cfg: "HandshakeConfig"):
    def decorator(handler):
        @_wraps(handler)
        async def wrapper(request: _web.Request) -> _web.Response:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                raise _web.HTTPUnauthorized(reason="Missing or malformed Authorization header")
            token = auth_header[7:].strip()
            try:
                payload = _verify_access_token(token, cfg)
            except AuthenticationError as exc:
                raise _web.HTTPUnauthorized(reason=str(exc))
            request["user"] = payload
            return await handler(request)
        return wrapper
    return decorator


def require_role(*allowed_roles: "UserRole"):
    allowed_values = {r.value for r in allowed_roles}

    def decorator(handler):
        @_wraps(handler)
        async def wrapper(request: _web.Request) -> _web.Response:
            user = request.get("user")
            if user is None:
                raise _web.HTTPUnauthorized(reason="Authentication required")
            role = user.get("role")
            if role not in allowed_values:
                logger.warning("[RBAC] forbidden: user_id=%s role=%s attempted endpoint requiring %s", user.get("sub"), role, sorted(allowed_values))
                raise _web.HTTPForbidden(reason=f"This action requires one of: {', '.join(sorted(allowed_values))}")
            return await handler(request)
        return wrapper
    return decorator


# ── Subscription enforcement ─────────────────────────────────────────────
#
# NOTE: this decorator exists but is NOT applied anywhere below as a
# blanket decorator. Every candidate endpoint (devices, alerts, reports,
# admissions, device registration) turned out to be shared between
# patients viewing their own data AND clinical staff viewing/managing
# their patients' data via the web dashboard, using the SAME endpoint
# with internal role-based filtering. A blanket decorator would have
# gated the entire clinical dashboard on each individual clinician's
# personal subscription status — a real bug, caught during
# implementation, not a hypothetical. Each endpoint instead has an
# inline, role-conditional check: only enforced when the calling user's
# role is PATIENT. This decorator is kept available for any genuinely
# patient-only endpoint added later.

def require_active_subscription(handler):
    @_wraps(handler)
    async def wrapper(request: _web.Request) -> _web.Response:
        user = request.get("user")
        if user is None:
            raise _web.HTTPUnauthorized(reason="Authentication required")
        if not await _db.is_subscription_active(user["sub"]):
            raise _web.HTTPPaymentRequired(reason="An active CardioAI Live Premium subscription is required")
        return await handler(request)
    return wrapper


def _require_vendor_api_key(handler):
    @_wraps(handler)
    async def wrapper(request: _web.Request) -> _web.Response:
        api_key = request.headers.get("X-Vendor-Api-Key", "").strip()
        if not api_key:
            raise _web.HTTPUnauthorized(reason="Missing X-Vendor-Api-Key header")
        vendor = await _db.verify_vendor_api_key(api_key)
        if vendor is None:
            logger.warning("[VendorGateway] invalid or inactive API key presented")
            raise _web.HTTPUnauthorized(reason="Invalid or inactive vendor API key")
        request["vendor"] = vendor
        return await handler(request)
    return wrapper


def _normalize_medtronic_payload(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    device_id = raw.get("deviceSerialNumber")
    if not device_id:
        return None
    return {
        "vendor_device_id": device_id, "timestamp": raw.get("recordedAt", _utcnow_iso()),
        "data": {
            "heart_rate": raw.get("heartRateBpm"), "systolic": raw.get("systolicBp"),
            "diastolic": raw.get("diastolicBp"), "spo2": raw.get("spo2Pct"),
        },
        "vendor_episode_type": raw.get("episodeType"),
    }


def _normalize_abbott_payload(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    device_id = raw.get("implantId")
    if not device_id:
        return None
    vitals = raw.get("vitals", {})
    return {
        "vendor_device_id": device_id, "timestamp": raw.get("timestamp", _utcnow_iso()),
        "data": {
            "heart_rate": vitals.get("hr"), "systolic": vitals.get("systolic"),
            "diastolic": vitals.get("diastolic"), "spo2": vitals.get("spo2"),
        },
        "vendor_episode_type": raw.get("alertCode"),
    }


def _normalize_boston_scientific_payload(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    device_id = raw.get("device_id")
    if not device_id:
        return None
    m = raw.get("measurements", {})
    return {
        "vendor_device_id": device_id, "timestamp": raw.get("event_time", _utcnow_iso()),
        "data": {
            "heart_rate": m.get("heart_rate_bpm"), "systolic": m.get("systolic_bp"),
            "diastolic": m.get("diastolic_bp"), "spo2": m.get("spo2_percent"),
        },
        "vendor_episode_type": raw.get("event"),
    }


_VENDOR_NORMALIZERS: Dict[str, Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]] = {
    "medtronic": _normalize_medtronic_payload,
    "abbott": _normalize_abbott_payload,
    "boston_scientific": _normalize_boston_scientific_payload,
}


def normalize_vendor_payload(vendor: str, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    normalizer = _VENDOR_NORMALIZERS.get(vendor)
    if normalizer is None:
        logger.warning("[VendorGateway] no normalizer registered for vendor=%s", vendor)
        return None
    try:
        return normalizer(raw)
    except Exception as exc:
        logger.error("[VendorGateway] normalization error for vendor=%s: %s", vendor, exc)
        return None


async def _consume_vendor_event(bridge: "IoMTCardioAIBridge", event: Dict[str, Any]) -> None:
    vendor_device_id = event.get("vendor_device_id")
    if not vendor_device_id:
        return
    large_device = await _db.get_large_device_by_vendor_id(vendor_device_id)
    if large_device is None or not large_device.is_active:
        logger.warning("[VendorGateway] event for unregistered/inactive device=%s — dropped", vendor_device_id)
        return
    acq_agent = bridge.system.agents["acquisition"]
    await acq_agent.register_device(device_id=vendor_device_id, device_type=large_device.device_type, patient_id=large_device.patient_id)
    await acq_agent.stream_data(vendor_device_id, {"device_id": vendor_device_id, "patient_id": large_device.patient_id, "data": event.get("data", {})})
    await _db.touch_large_device_last_event(vendor_device_id)


def build_http_app(bridge: "IoMTCardioAIBridge") -> _web.Application:
    cfg = bridge.cfg
    app = _web.Application(middlewares=[_cors_middleware(cfg.allowed_origins)])

    async def login(request: _web.Request) -> _web.Response:
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json", "message": "Request body must be valid JSON"}, status=400)

        email = (body.get("email") or "").strip().lower()
        password = (body.get("password") or "").strip()
        mfa_code = (body.get("mfa_code") or "").strip()

        if not email or not password:
            return _web.json_response({"error": "missing_fields", "message": "Both 'email' and 'password' are required"}, status=400)

        if not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return _web.json_response({"error": "invalid_email", "message": "Invalid email format"}, status=400)

        client_ip = request.remote or "unknown"
        if not _AUTH_RATE_LIMITER.is_allowed(client_ip):
            logger.warning("[Auth] rate limited IP=%s email=%s", client_ip, email)
            return _web.json_response({"error": "rate_limited", "message": "Too many login attempts. Try again in 5 minutes."}, status=429)

        user = await _load_user_by_email(email)
        if user is None:
            logger.warning("[Auth] unknown email=%s IP=%s", email, client_ip)
            await _db.log_event("login_failed", ip_address=client_ip, detail=f"unknown email: {email}")
            return _web.json_response({"error": "invalid_credentials", "message": "Email or password is incorrect"}, status=401)

        if not user.is_active:
            logger.warning("[Auth] inactive account login attempt email=%s", email)
            await _db.log_event("login_failed", user_id=user.id, ip_address=client_ip, detail="account inactive")
            return _web.json_response({
                "error": "account_inactive",
                "message": "Your account is not yet active. If you just signed up, an administrator needs to approve your account first.",
            }, status=403)

        if not user.verify_password(password):
            logger.warning("[Auth] wrong password email=%s IP=%s", email, client_ip)
            await _db.log_event("login_failed", user_id=user.id, ip_address=client_ip, detail="wrong password")
            return _web.json_response({"error": "invalid_credentials", "message": "Email or password is incorrect"}, status=401)

        if cfg.mfa_required:
            if not mfa_code:
                return _web.json_response({"error": "mfa_required", "message": "A 6-digit MFA code is required", "next_step": "submit mfa_code"}, status=403)
            if not (_re.match(r"^\d{6}$", mfa_code)):
                return _web.json_response({"error": "invalid_mfa", "message": "Invalid MFA code"}, status=403)

        _AUTH_RATE_LIMITER.reset(client_ip)
        access_token = _issue_access_token(user, cfg)
        refresh_token = await _db.issue_refresh_token(user.id, cfg.refresh_token_ttl)
        await _db.update_last_login(user.id)
        await _db.log_event("login_success", user_id=user.id, ip_address=client_ip)
        logger.info("[Auth] login successful email=%s role=%s IP=%s", email, user.role.value, client_ip)

        return _web.json_response({
            "access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer",
            "expires_in": cfg.token_ttl_seconds,
            "user": {"id": user.id, "name": user.name, "role": user.role.value, "patient_id": user.patient_id},
        })

    async def signup(request: _web.Request) -> _web.Response:
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        email = (body.get("email") or "").strip().lower()
        name = (body.get("name") or "").strip()
        organization = (body.get("organization") or "").strip()
        password = (body.get("password") or "").strip()
        role_str = (body.get("role") or "").strip()

        if not email or not name or not organization or not password or not role_str:
            return _web.json_response({"error": "missing_fields", "message": "email, name, organization, password, and role are all required"}, status=400)

        if not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return _web.json_response({"error": "invalid_email", "message": "Invalid email format"}, status=400)

        client_ip = request.remote or "unknown"
        if not _AUTH_RATE_LIMITER.is_allowed(client_ip):
            logger.warning("[Signup] rate limited IP=%s email=%s", client_ip, email)
            return _web.json_response({"error": "rate_limited", "message": "Too many signup attempts. Try again in 5 minutes."}, status=429)

        try:
            role = UserRole(role_str)
        except ValueError:
            return _web.json_response({"error": "invalid_role", "message": f"'{role_str}' must be one of: nurse, cardiologist, admin"}, status=400)

        if role == UserRole.PATIENT:
            return _web.json_response({"error": "invalid_role", "message": "Patients sign in with Apple — this endpoint is for clinical staff only"}, status=400)

        if len(password) < 8:
            return _web.json_response({"error": "weak_password", "message": "Password must be at least 8 characters"}, status=400)

        existing = await _load_user_by_email(email)
        if existing:
            return _web.json_response({"error": "email_taken", "message": "An account with this email already exists"}, status=409)

        # Organization-domain lock (canonical table first, legacy heuristic
        # as fallback): stops someone from signing up as e.g.
        # "attacker@gmail.com" claiming to be staff at an organization that
        # already has a locked domain list.
        new_domain = email.rsplit("@", 1)[-1].lower()
        org_record = await _db.get_organization_by_name(organization)

        if org_record is not None:
            # Canonical record exists (either admin-created or auto-registered
            # by an earlier signup). If it has any allowed_domains set,
            # enforce them strictly.
            if org_record.allowed_domains and new_domain not in org_record.allowed_domains:
                logger.warning(
                    "[Signup] domain mismatch: org=%s email_domain=%s expected one of %s",
                    organization, new_domain, org_record.allowed_domains,
                )
                return _web.json_response({
                    "error": "organization_domain_mismatch",
                    "message": (
                        f"'{organization}' is already registered with a different "
                        "email domain. If you believe this is an error, contact "
                        "your administrator or use your organization's official "
                        "email address."
                    ),
                }, status=409)
            # If allowed_domains is empty (admin created the org without
            # locking a domain, or it's an older auto-registered record),
            # fall back to the legacy heuristic against existing users.
            elif not org_record.allowed_domains:
                existing_domains = await _db.get_organization_domains(organization)
                if existing_domains and new_domain not in existing_domains:
                    return _web.json_response({
                        "error": "organization_domain_mismatch",
                        "message": (
                            f"'{organization}' is already registered with a different "
                            "email domain. If you believe this is an error, contact "
                            "your administrator or use your organization's official "
                            "email address."
                        ),
                    }, status=409)
        else:
            # Brand-new organization name — nothing to check against yet.
            # Auto-register it now with THIS signup's domain as its founding
            # (and only) allowed domain, so every subsequent signup under
            # this name is locked to it immediately. An admin can broaden
            # this later via PATCH /admin/organizations/{id} if the hospital
            # legitimately uses multiple email domains.
            await _db.create_organization(
                name=organization, allowed_domains=[new_domain], auto_registered=True,
            )
            logger.info(
                "[Signup] auto-registered new organization=%s founding_domain=%s",
                organization, new_domain,
            )

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode()
        new_user = await _db.create_staff_user(email=email, name=name, organization=organization, role=role, password_hash=password_hash, is_active=False)

        await _db.log_event("signup_requested", detail=f"role={role.value} email={email} org={organization}")
        logger.info("[Signup] new pending %s account requested: %s (%s)", role.value, email, organization)

        return _web.json_response({
            "id": new_user.id, "email": new_user.email, "name": new_user.name,
            "organization": new_user.organization, "role": new_user.role.value, "is_active": new_user.is_active,
            "message": "Account created. An administrator must approve it before you can sign in.",
        }, status=201)

    async def refresh(request: _web.Request) -> _web.Response:
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        token_id = (body.get("refresh_token") or "").strip()
        if not token_id:
            return _web.json_response({"error": "missing_fields", "message": "'refresh_token' is required"}, status=400)

        user_id = await _db.consume_refresh_token(token_id)
        if user_id is None:
            logger.warning("[Auth] invalid or expired refresh token")
            return _web.json_response({"error": "invalid_refresh_token", "message": "Refresh token is invalid or has expired. Please sign in again."}, status=401)

        user = await _load_user_by_id(user_id)
        if user is None or not user.is_active:
            return _web.json_response({"error": "user_not_found", "message": "User account no longer exists or has been disabled"}, status=404)

        new_access = _issue_access_token(user, cfg)
        new_refresh = await _db.issue_refresh_token(user.id, cfg.refresh_token_ttl)
        logger.info("[Auth] token refreshed user_id=%s", user_id)

        return _web.json_response({"access_token": new_access, "refresh_token": new_refresh, "token_type": "Bearer", "expires_in": cfg.token_ttl_seconds})

    @_require_auth(cfg)
    async def logout(request: _web.Request) -> _web.Response:
        user_payload = request["user"]
        revoked = await _db.revoke_all_refresh_tokens(user_payload["sub"])
        logger.info("[Auth] logout user_id=%s revoked=%d", user_payload["sub"], revoked)
        return _web.json_response({"message": "Signed out successfully", "tokens_revoked": revoked})

    # ── DELETE /account ──────────────────────────────────────────────────
    #
    # Self-service account deletion — required by both Apple App Store
    # Review Guideline 5.1.1(v) and Google Play's account deletion policy
    # for any app that supports account creation. Any authenticated user
    # (patient or clinical staff) can delete their own account; this is
    # NOT an admin action on someone else's account.
    #
    # See db.delete_account() for the important nuance this implements:
    # credentials are wiped unconditionally (the account can never be
    # signed into again), but clinical data tied to this patient_id is
    # preserved rather than hard-deleted, since medical record retention
    # law in most jurisdictions does not grant an unconditional right to
    # erasure the way it might for a non-healthcare consumer app.

    @_require_auth(cfg)
    async def delete_account(request: _web.Request) -> _web.Response:
        user_payload = request["user"]
        user_id = user_payload["sub"]

        user = await _db.get_user_by_id(user_id)
        if user is None:
            return _web.json_response({"error": "user_not_found"}, status=404)

        await _db.delete_account(user_id)
        await _db.log_event("account_deleted", user_id=user_id, ip_address=request.remote or "unknown", detail=f"role={user.role}")
        logger.info("[Account] user_id=%s (role=%s) deleted their account", user_id, user.role)

        return _web.json_response({
            "message": "Your account has been deleted. You will not be able to sign in again.",
            "clinical_data_note": (
                "Vitals, alerts, and clinical reports associated with your care are retained "
                "as part of the medical record, consistent with healthcare record-keeping "
                "requirements, and are not deleted by this action."
            ),
        })

    # ── POST /subscription/link ──────────────────────────────────────────
    #
    # Called by the app once, immediately after a client-confirmed
    # purchase (StoreKit 2 on iOS, Play Billing on Android). This is what
    # connects a store transaction/purchase token to an internal user —
    # without it, the webhook handlers below have no way to know which
    # user a given Apple/Google notification belongs to, since store
    # notifications identify purchases, not your internal user IDs.
    #
    # Optimistically records status='active' immediately for good UX —
    # the user shouldn't have to wait for a webhook round-trip after
    # paying. The next real webhook notification corrects this if the
    # store's authoritative status actually differs.

    @_require_auth(cfg)
    async def link_subscription(request: _web.Request) -> _web.Response:
        user = request["user"]
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        platform = (body.get("platform") or "").strip().lower()
        transaction_id = (body.get("transaction_id") or "").strip()
        product_id = (body.get("product_id") or "").strip()

        if platform not in ("apple", "google"):
            return _web.json_response({"error": "invalid_platform", "message": "'platform' must be 'apple' or 'google'"}, status=400)
        if not transaction_id or not product_id:
            return _web.json_response({"error": "missing_fields", "message": "'transaction_id' and 'product_id' are required"}, status=400)

        link = await _db.link_subscription(
            user_id=user["sub"], platform=platform, transaction_id=transaction_id, product_id=product_id,
        )
        logger.info("[Subscription] linked user_id=%s platform=%s transaction_id=%s", user["sub"], platform, transaction_id[:16])

        return _web.json_response({
            "status": link.status, "platform": link.platform, "product_id": link.product_id,
        })

    # ── POST /webhooks/apple-subscription ────────────────────────────────
    #
    # Apple App Store Server Notifications V2. Configure this URL in
    # App Store Connect → your app → App Information → App Store Server
    # Notifications. No JWT auth here — Apple authenticates itself via
    # the cryptographically signed payload, verified below.

    async def apple_subscription_webhook(request: _web.Request) -> _web.Response:
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        signed_payload = body.get("signedPayload")
        if not signed_payload:
            return _web.json_response({"error": "missing_signed_payload"}, status=400)

        event = _sub_verify.verify_apple_notification(signed_payload)
        if event is None:
            # Either verification failed, or this notification type
            # doesn't map to an entitlement change (e.g. a TEST
            # notification) — either way, respond 200 so Apple doesn't
            # keep retrying a notification we're deliberately not acting on.
            return _web.json_response({"status": "ignored"})

        updated = await _db.update_subscription_status_by_transaction(
            platform="apple", transaction_id=event.transaction_id, status=event.status,
            expires_at=event.expires_at, auto_renew_status=event.auto_renew_status,
        )
        if updated:
            logger.info("[Subscription] Apple webhook updated transaction_id=%s status=%s", event.transaction_id[:16], event.status)
        return _web.json_response({"status": "processed"})

    # ── POST /webhooks/google-subscription ───────────────────────────────
    #
    # Google Play Real-time Developer Notifications, delivered via a
    # Cloud Pub/Sub push subscription. Configure the push subscription's
    # endpoint URL as:
    #   https://your-backend.com/webhooks/google-subscription?token=<GOOGLE_WEBHOOK_TOKEN>
    # No JWT auth — authenticated via the URL token instead, since Pub/Sub
    # push requests aren't from your app's own users.

    async def google_subscription_webhook(request: _web.Request) -> _web.Response:
        token = request.query.get("token")
        if not _sub_verify.verify_google_webhook_token(token):
            logger.warning("[Subscription] Google webhook called with invalid/missing token")
            return _web.json_response({"error": "unauthorized"}, status=401)

        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        rtdn_payload = _sub_verify.parse_google_pubsub_envelope(body)
        if rtdn_payload is None:
            return _web.json_response({"status": "ignored"})

        event = _sub_verify.normalize_google_notification(rtdn_payload)
        if event is None:
            return _web.json_response({"status": "ignored"})

        updated = await _db.update_subscription_status_by_transaction(
            platform="google", transaction_id=event.transaction_id, status=event.status,
            expires_at=event.expires_at, auto_renew_status=event.auto_renew_status,
        )
        if updated:
            logger.info("[Subscription] Google webhook updated transaction_id=%s status=%s", event.transaction_id[:16], event.status)
        return _web.json_response({"status": "processed"})

    async def root(request: _web.Request) -> _web.Response:
        return _web.json_response({
            "service": "IoMT CardioAI Backend", "status": "running", "bridge_id": cfg.cardioai_backend_id,
            "endpoints": {
                "GET  /dashboard": "Live clinical dashboard (sign in with email/password)",
                "GET  /health": "Liveness probe (no auth)", "GET  /status": "Full bridge status (auth required)",
                "POST /auth/apple": "Sign in with Apple (iOS)", "POST /auth/login": "Email + password login",
                "POST /auth/signup": "Clinical staff self-registration (pending admin approval)",
                "POST /auth/refresh": "Rotate refresh token", "POST /auth/logout": "Revoke session",
                "POST /devices/register": "Register a paired BLE device (auth required)",
                "POST /clinical/devices/register-implant": "Register implant (clinical staff only)",
                "GET  /clinical/devices/implants": "List registered implants (auth required)",
                "POST /vendor-gateway/ingest": "Vendor device gateway ingestion (X-Vendor-Api-Key)",
                "GET  /devices": "Device registry (auth required)", "GET  /alerts": "Active alerts (auth required)",
                "GET  /reports": "Clinical reports (auth required)", "GET  /admin/users": "List user accounts (admin only)",
                "POST /admin/users": "Create a clinician/admin account (admin only)",
                "POST /admin/vendor-keys": "Generate a vendor API key (admin only)",
                "GET  /admin/organizations": "List canonical organizations (admin only)",
                "POST /admin/organizations": "Pre-register an organization with locked email domains (admin only)",
                "PATCH /admin/organizations/{id}": "Update an organization's allowed domains/name (admin only)",
            },
        })

    _DASHBOARD_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "iomt_cardioai_dashboard.html")
    _PRIVACY_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "privacy-policy.html")
    _TERMS_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "terms-of-use.html")

    async def dashboard(request: _web.Request) -> _web.Response:
        try:
            with open(_DASHBOARD_HTML_PATH, "r", encoding="utf-8") as f:
                html = f.read()
        except FileNotFoundError:
            return _web.Response(
                text="<h1>Dashboard file not found</h1><p>iomt_cardioai_dashboard.html is missing from the deploy.</p>",
                content_type="text/html", status=500,
            )
        return _web.Response(text=html, content_type="text/html")

    # ── GET /privacy and GET /terms ──────────────────────────────────────
    #
    # Serves the Privacy Policy and Terms of Use directly from this same
    # Render deployment, at:
    #   https://<your-render-domain>/privacy
    #   https://<your-render-domain>/terms
    # These are the URLs to paste into App Store Connect's Privacy Policy
    # URL field, TestFlight's Test Information Privacy Policy URL field,
    # and the paywall's Terms of Use / Privacy Policy links. No separate
    # hosting needed — the HTML files just need to sit alongside this
    # script in the deployed repo, same as the dashboard file already does.

    async def privacy_policy(request: _web.Request) -> _web.Response:
        try:
            with open(_PRIVACY_HTML_PATH, "r", encoding="utf-8") as f:
                html = f.read()
        except FileNotFoundError:
            return _web.Response(
                text="<h1>Not found</h1><p>privacy-policy.html is missing from the deploy.</p>",
                content_type="text/html", status=500,
            )
        return _web.Response(text=html, content_type="text/html")

    async def terms_of_use(request: _web.Request) -> _web.Response:
        try:
            with open(_TERMS_HTML_PATH, "r", encoding="utf-8") as f:
                html = f.read()
        except FileNotFoundError:
            return _web.Response(
                text="<h1>Not found</h1><p>terms-of-use.html is missing from the deploy.</p>",
                content_type="text/html", status=500,
            )
        return _web.Response(text=html, content_type="text/html")

    async def health(request: _web.Request) -> _web.Response:
        status = bridge.status()
        return _web.json_response({"status": "ok", "bridge_id": status.get("bridge_id"), "timestamp": status.get("timestamp"), "agent_count": status.get("agent_count")})

    @_require_auth(cfg)
    async def full_status(request: _web.Request) -> _web.Response:
        return _web.json_response(bridge.status())

    @_require_auth(cfg)
    async def devices(request: _web.Request) -> _web.Response:
        user = request["user"]
        # Subscription enforcement is role-conditional here, not a
        # blanket decorator — this same endpoint serves the web dashboard
        # for clinical staff (viewing all their patients' devices) using
        # the CLINICIAN's own JWT. Gating it on the calling user's
        # subscription would incorrectly block a nurse/cardiologist's
        # dashboard access over their own personal billing status, which
        # has nothing to do with the patients they're monitoring.
        if user.get("role") == UserRole.PATIENT.value:
            if not await _db.is_subscription_active(user["sub"]):
                raise _web.HTTPPaymentRequired(reason="An active CardioAI Live Premium subscription is required")
        summary = bridge.registry.summary()
        if user.get("role") == UserRole.PATIENT.value:
            pid = user.get("patient_id")
            summary = {**summary, "devices": [d for d in summary["devices"] if d["patient_id"] == pid]}
        return _web.json_response(summary)

    @_require_auth(cfg)
    async def alerts(request: _web.Request) -> _web.Response:
        user = request["user"]
        # Role-conditional, same rationale as /devices above — clinical
        # staff use this endpoint for their dashboard's aggregate alert
        # view; only patients viewing their own alerts are gated.
        if user.get("role") == UserRole.PATIENT.value:
            if not await _db.is_subscription_active(user["sub"]):
                raise _web.HTTPPaymentRequired(reason="An active CardioAI Live Premium subscription is required")
        agent = bridge.system.agents["alert_monitoring"]
        all_alerts = [
            {
                "alert_id": a.alert_id, "patient_id": a.patient_id, "level": a.alert_level.value,
                "description": a.description, "actions": a.required_actions, "notified": a.notified_parties,
                "timestamp": a.timestamp,
            }
            for a in agent.active_alerts.values()
        ]
        if user.get("role") == UserRole.PATIENT.value:
            pid = user.get("patient_id")
            all_alerts = [a for a in all_alerts if a["patient_id"] == pid]
        return _web.json_response(all_alerts)

    @_require_auth(cfg)
    async def reports(request: _web.Request) -> _web.Response:
        user = request["user"]
        # Role-conditional, same rationale as /devices and /alerts above.
        if user.get("role") == UserRole.PATIENT.value:
            if not await _db.is_subscription_active(user["sub"]):
                raise _web.HTTPPaymentRequired(reason="An active CardioAI Live Premium subscription is required")
        store = bridge.system.agents["communication"].report_store
        if user.get("role") == UserRole.PATIENT.value:
            pid = user.get("patient_id")
            store = [r for r in store if r.get("patient_id") == pid]
        return _web.json_response(store[-50:])

    @_require_auth(cfg)
    @require_role(UserRole.ADMIN)
    async def admin_list_users(request: _web.Request) -> _web.Response:
        role_filter = request.query.get("role")
        limit = min(int(request.query.get("limit", "100")), 500)
        offset = max(int(request.query.get("offset", "0")), 0)
        role_enum = None
        if role_filter:
            try:
                role_enum = UserRole(role_filter)
            except ValueError:
                return _web.json_response({"error": "invalid_role", "message": f"'{role_filter}' is not a valid role"}, status=400)
        users = await _db.list_users(role=role_enum, limit=limit, offset=offset)
        return _web.json_response([
            {"id": u.id, "email": u.email, "name": u.name, "organization": u.organization, "role": u.role.value, "patient_id": u.patient_id, "is_active": u.is_active}
            for u in users
        ])

    @_require_auth(cfg)
    @require_role(UserRole.ADMIN)
    async def admin_create_user(request: _web.Request) -> _web.Response:
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        email = (body.get("email") or "").strip().lower()
        name = (body.get("name") or "").strip()
        organization = (body.get("organization") or "").strip()
        password = (body.get("password") or "").strip()
        role_str = (body.get("role") or "").strip()

        if not email or not name or not password or not role_str:
            return _web.json_response({"error": "missing_fields", "message": "email, name, password, and role are all required"}, status=400)

        try:
            role = UserRole(role_str)
        except ValueError:
            return _web.json_response({"error": "invalid_role", "message": f"'{role_str}' must be one of: nurse, cardiologist, admin"}, status=400)

        if role == UserRole.PATIENT:
            return _web.json_response({"error": "invalid_role", "message": "Patient accounts are created via Sign in with Apple, not this endpoint"}, status=400)

        if len(password) < 8:
            return _web.json_response({"error": "weak_password", "message": "Password must be at least 8 characters"}, status=400)

        existing = await _load_user_by_email(email)
        if existing:
            return _web.json_response({"error": "email_taken", "message": "An account with this email already exists"}, status=409)

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode()
        new_user = await _db.create_staff_user(email=email, name=name, organization=organization, role=role, password_hash=password_hash)

        admin_user = request["user"]
        await _db.log_event("user_created", user_id=admin_user.get("sub"), detail=f"created {role.value} account: {email}")
        logger.info("[Admin] user_id=%s created new %s account: %s", admin_user.get("sub"), role.value, email)

        return _web.json_response({"id": new_user.id, "email": new_user.email, "name": new_user.name, "organization": new_user.organization, "role": new_user.role.value}, status=201)

    @_require_auth(cfg)
    @require_role(UserRole.ADMIN)
    async def admin_update_user(request: _web.Request) -> _web.Response:
        target_user_id = request.match_info.get("user_id", "")
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        target = await _load_user_by_id(target_user_id)
        if target is None:
            return _web.json_response({"error": "user_not_found"}, status=404)

        admin_user = request["user"]

        if "is_active" in body:
            new_active = bool(body["is_active"])
            await _db.set_user_active(target_user_id, new_active)
            await _db.log_event("account_disabled" if not new_active else "account_enabled", user_id=admin_user.get("sub"), detail=f"target={target.email}")
            if not new_active:
                await _db.revoke_all_refresh_tokens(target_user_id)

        if "role" in body:
            try:
                new_role = UserRole(body["role"])
            except ValueError:
                return _web.json_response({"error": "invalid_role"}, status=400)
            await _db.set_user_role(target_user_id, new_role)
            await _db.log_event("role_change", user_id=admin_user.get("sub"), detail=f"target={target.email} new_role={new_role.value}")
            logger.info("[Admin] user_id=%s changed role of %s to %s", admin_user.get("sub"), target.email, new_role.value)

        updated = await _load_user_by_id(target_user_id)
        return _web.json_response({"id": updated.id, "email": updated.email, "name": updated.name, "role": updated.role.value, "is_active": updated.is_active})

    async def apple_signin(request: _web.Request) -> _web.Response:
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json", "message": "Request body must be valid JSON"}, status=400)

        identity_token = (body.get("identity_token") or "").strip()
        authorization_code = (body.get("authorization_code") or "").strip()
        first_name = (body.get("first_name") or "").strip()
        last_name = (body.get("last_name") or "").strip()

        if not identity_token or not authorization_code:
            return _web.json_response({"error": "missing_fields", "message": "Both 'identity_token' and 'authorization_code' are required"}, status=400)

        client_ip = request.remote or "unknown"
        if not _AUTH_RATE_LIMITER.is_allowed(client_ip):
            logger.warning("[AppleAuth] rate limited IP=%s", client_ip)
            return _web.json_response({"error": "rate_limited", "message": "Too many sign-in attempts. Try again in 5 minutes."}, status=429)

        verify_tokens = _optional_env("APPLE_VERIFY_TOKENS", "false").lower() == "true"

        try:
            if verify_tokens:
                try:
                    import httpx as _httpx
                    from jose import jwt as _jose_jwt
                    apple_keys = _httpx.get("https://appleid.apple.com/auth/keys", timeout=10).json()
                    apple_payload = _jose_jwt.decode(identity_token, apple_keys, algorithms=["RS256"], audience=_optional_env("APPLE_BUNDLE_ID", "com.cardioai.iomt"))
                except ImportError:
                    logger.error("[AppleAuth] APPLE_VERIFY_TOKENS=true but python-jose / httpx are not installed.")
                    return _web.json_response({"error": "server_configuration", "message": "Apple token verification not configured"}, status=500)
                except Exception as exc:
                    logger.warning("[AppleAuth] token verification failed: %s", exc)
                    return _web.json_response({"error": "invalid_apple_token", "message": "Apple identity token is invalid or expired"}, status=401)
            else:
                import base64 as _b64
                parts = identity_token.split(".")
                if len(parts) != 3:
                    raise ValueError("Not a valid JWT structure")
                padding = "=" * (4 - len(parts[1]) % 4)
                decoded_bytes = _b64.urlsafe_b64decode(parts[1] + padding)
                apple_payload = json.loads(decoded_bytes.decode("utf-8"))
        except Exception as exc:
            logger.warning("[AppleAuth] token decode failed: %s", exc)
            return _web.json_response({"error": "invalid_apple_token", "message": "Could not decode Apple identity token"}, status=401)

        apple_user_id = apple_payload.get("sub", "")
        if not apple_user_id:
            return _web.json_response({"error": "invalid_apple_token", "message": "Apple token missing subject claim"}, status=401)

        apple_email = apple_payload.get("email", "")
        if not apple_email:
            apple_email = f"{apple_user_id[:8].lower()}@privaterelay.appleid.com"

        display_name = f"{first_name} {last_name}".strip()
        if not display_name:
            display_name = apple_email.split("@")[0].replace(".", " ").title()

        existing_user = await _db.get_user_by_apple_id(apple_user_id) or await _load_user_by_email(apple_email)

        if existing_user:
            user = existing_user
            if not user.is_active:
                return _web.json_response({"error": "account_disabled", "message": "Your account has been disabled. Contact your administrator."}, status=403)
        else:
            user = await _db.create_patient_from_apple(apple_user_id=apple_user_id, email=apple_email, name=display_name)
            logger.info("[AppleAuth] auto-provisioned patient apple_id=%s email=%s", apple_user_id[:12], apple_email)

        _AUTH_RATE_LIMITER.reset(client_ip)
        access_token = _issue_access_token(user, cfg)
        refresh_token = await _db.issue_refresh_token(user.id, cfg.refresh_token_ttl)
        await _db.update_last_login(user.id)
        await _db.log_event("login_success", user_id=user.id, ip_address=client_ip, detail="apple_signin")
        logger.info("[AppleAuth] sign-in successful apple_id=%s role=%s IP=%s", apple_user_id[:12], user.role.value, client_ip)

        return _web.json_response({
            "access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer", "expires_in": cfg.token_ttl_seconds,
            "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role.value, "patient_id": user.patient_id},
        })

    # ── POST /auth/google ──────────────────────────────────────────────────
    #
    # Android equivalent of POST /auth/apple. Android has no native platform
    # sign-in tied to this backend, so Android patients sign in with Google
    # instead — auto-provisioned the very first time, exactly like Apple
    # Sign-In does for iOS patients. Verifies the Google ID token against
    # Google's tokeninfo endpoint (simplest correct verification path;
    # equivalent in rigor to Apple's JWKS verification above, just using
    # Google's own hosted verification endpoint instead of manually
    # validating a JWKS signature).

    async def google_signin(request: _web.Request) -> _web.Response:
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json", "message": "Request body must be valid JSON"}, status=400)

        id_token = (body.get("id_token") or "").strip()
        first_name = (body.get("first_name") or "").strip()
        last_name = (body.get("last_name") or "").strip()

        if not id_token:
            return _web.json_response({"error": "missing_fields", "message": "'id_token' is required"}, status=400)

        client_ip = request.remote or "unknown"
        if not _AUTH_RATE_LIMITER.is_allowed(client_ip):
            logger.warning("[GoogleAuth] rate limited IP=%s", client_ip)
            return _web.json_response({"error": "rate_limited", "message": "Too many sign-in attempts. Try again in 5 minutes."}, status=429)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://oauth2.googleapis.com/tokeninfo",
                    params={"id_token": id_token},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        logger.warning("[GoogleAuth] tokeninfo rejected token, status=%s", resp.status)
                        return _web.json_response({"error": "invalid_google_token", "message": "Google ID token is invalid or expired"}, status=401)
                    google_payload = await resp.json()

            expected_client_id = _optional_env("GOOGLE_OAUTH_CLIENT_ID", "")
            if expected_client_id and google_payload.get("aud") != expected_client_id:
                logger.warning("[GoogleAuth] token audience mismatch")
                return _web.json_response({"error": "invalid_google_token", "message": "Token was not issued for this app"}, status=401)
        except Exception as exc:
            logger.warning("[GoogleAuth] token verification failed: %s", exc)
            return _web.json_response({"error": "invalid_google_token", "message": "Could not verify Google ID token"}, status=401)

        google_user_id = google_payload.get("sub", "")
        if not google_user_id:
            return _web.json_response({"error": "invalid_google_token", "message": "Google token missing subject claim"}, status=401)

        google_email = google_payload.get("email", "")
        if not google_email:
            return _web.json_response({"error": "invalid_google_token", "message": "Google token missing email claim"}, status=401)

        display_name = f"{first_name} {last_name}".strip()
        if not display_name:
            display_name = google_payload.get("name", "") or google_email.split("@")[0].replace(".", " ").title()

        existing_user = await _db.get_user_by_google_id(google_user_id) or await _load_user_by_email(google_email)

        if existing_user:
            user = existing_user
            if not user.is_active:
                return _web.json_response({"error": "account_disabled", "message": "Your account has been disabled. Contact your administrator."}, status=403)
        else:
            user = await _db.create_patient_from_google(google_user_id=google_user_id, email=google_email, name=display_name)
            logger.info("[GoogleAuth] auto-provisioned patient google_id=%s email=%s", google_user_id[:12], google_email)

        _AUTH_RATE_LIMITER.reset(client_ip)
        access_token = _issue_access_token(user, cfg)
        refresh_token = await _db.issue_refresh_token(user.id, cfg.refresh_token_ttl)
        await _db.update_last_login(user.id)
        await _db.log_event("login_success", user_id=user.id, ip_address=client_ip, detail="google_signin")
        logger.info("[GoogleAuth] sign-in successful google_id=%s role=%s IP=%s", google_user_id[:12], user.role.value, client_ip)

        return _web.json_response({
            "access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer", "expires_in": cfg.token_ttl_seconds,
            "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role.value, "patient_id": user.patient_id},
        })

    @_require_auth(cfg)
    async def device_register(request: _web.Request) -> _web.Response:
        user = request["user"]

        # NOTE: subscription enforcement here is deliberately role-
        # conditional, not a blanket decorator — this endpoint is shared
        # by both patients self-pairing their own device AND clinical
        # staff registering a bedside device on behalf of a patient who
        # can't use their own phone (e.g. unconscious/incapacitated).
        # Blocking that second path because the CLINICIAN's own personal
        # subscription lapsed would be a real bug, not just an edge case
        # — it would break emergency device registration over a billing
        # technicality that has nothing to do with the patient being
        # monitored.
        if user.get("role") == UserRole.PATIENT.value:
            if not await _db.is_subscription_active(user["sub"]):
                raise _web.HTTPPaymentRequired(reason="An active CardioAI Live Premium subscription is required")
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        device_id = (body.get("device_id") or "").strip()
        device_type = (body.get("device_type") or "ecg_monitor").strip()
        patient_id = (body.get("patient_id") or "").strip()
        device_name = (body.get("device_name") or device_id[:12]).strip()

        if not device_id or not patient_id:
            return _web.json_response({"error": "missing_fields", "message": "Both 'device_id' and 'patient_id' are required"}, status=400)

        if user.get("role") == UserRole.PATIENT.value:
            own_pid = user.get("patient_id") or user.get("sub")
            if patient_id != own_pid:
                logger.warning("[DeviceRegister] patient_id mismatch user=%s attempted=%s", own_pid, patient_id)
                return _web.json_response({"error": "patient_id_mismatch", "message": "You can only register devices for your own patient ID"}, status=403)
        # NOTE: when a clinician registers on a patient's behalf, patient_id
        # is treated as clinician-supplied free text (e.g. a hospital MRN)
        # — same as the existing implant registration path. It is
        # deliberately NOT validated against an existing `users` record,
        # because a patient may be unconscious/incapacitated and have
        # never signed into the app before (no Apple Sign-In yet means no
        # users row exists at all). Requiring a pre-existing account would
        # block exactly the emergency scenario this feature exists for.

        existing = bridge.registry.get(device_id)
        if existing:
            existing.is_active = True
            logger.info("[DeviceRegister] re-activated device=%s patient=%s", device_id, patient_id)
        else:
            bridge.registry.register(device_id, device_type, patient_id)
            logger.info("[DeviceRegister] registered device=%s type=%s patient=%s name=%s", device_id, device_type, patient_id, device_name)

        # If a CLINICIAN (not the patient) is registering this device —
        # e.g. attaching a bedside ECG monitor to an unconscious patient
        # who can't use their own phone to pair it — resolve the
        # clinician's own organization and assign it immediately. This
        # means no separate "configure" step is needed afterward, unlike
        # a patient's own self-pairing (which intentionally leaves
        # organization_id unset until a clinician configures it later).
        organization_id = None
        configured_by_user_id = None
        is_clinical_registration = user.get("role") in (
            UserRole.NURSE.value, UserRole.CARDIOLOGIST.value, UserRole.ADMIN.value,
        )
        if is_clinical_registration:
            try:
                clinician_user = await _load_user_by_id(user.get("sub"))
                if clinician_user and clinician_user.organization:
                    org = await _db.get_organization_by_name(clinician_user.organization)
                    if org:
                        organization_id = org.id
                        configured_by_user_id = user.get("sub")
            except Exception:
                logger.exception("[DeviceRegister] error resolving organization for clinician_id=%s", user.get("sub"))

        # Persist to the database so this pairing survives restarts and is
        # visible to clinical staff for configuration (assigning it to
        # their hospital's organization). Previously this only lived in
        # bridge.registry (in-memory) — a redeploy would silently lose
        # every patient's paired-device record.
        try:
            await _db.upsert_ble_device(
                device_id=device_id, device_type=device_type, patient_id=patient_id,
                device_name=device_name, paired_by_user_id=user.get("sub"),
                organization_id=organization_id, configured_by_user_id=configured_by_user_id,
            )
        except Exception:
            logger.exception("[DeviceRegister] failed to persist BLE device=%s to database", device_id)

        acq_agent = bridge.system.agents["acquisition"]
        import asyncio as _asyncio
        _asyncio.create_task(acq_agent.register_device(device_id, device_type, patient_id))

        return _web.json_response({
            "device_id": device_id, "patient_id": patient_id, "status": "registered",
            "organization_configured": organization_id is not None,
        })

    @_require_auth(cfg)
    @require_role(UserRole.NURSE, UserRole.CARDIOLOGIST, UserRole.ADMIN)
    async def register_implant(request: _web.Request) -> _web.Response:
        user = request["user"]
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        vendor_device_id = (body.get("vendor_device_id") or "").strip()
        vendor = (body.get("vendor") or "").strip().lower()
        device_type = (body.get("device_type") or "").strip().lower()
        patient_id = (body.get("patient_id") or "").strip()
        model_number = (body.get("model_number") or "").strip() or None
        implanted_at = (body.get("implanted_at") or "").strip() or None
        notes = (body.get("notes") or "").strip() or None

        if not vendor_device_id or not vendor or not device_type or not patient_id:
            return _web.json_response({"error": "missing_fields", "message": "vendor_device_id, vendor, device_type, and patient_id are all required"}, status=400)

        valid_vendors = {"medtronic", "abbott", "boston_scientific", "biotronik", "other"}
        if vendor not in valid_vendors:
            return _web.json_response({"error": "invalid_vendor", "message": f"vendor must be one of: {', '.join(sorted(valid_vendors))}"}, status=400)

        valid_types = {"pacemaker", "icd", "crt_d", "crt_p", "implantable_loop_recorder", "other"}
        if device_type not in valid_types:
            return _web.json_response({"error": "invalid_device_type", "message": f"device_type must be one of: {', '.join(sorted(valid_types))}"}, status=400)

        existing = await _db.get_large_device_by_vendor_id(vendor_device_id)
        if existing is not None and existing.is_active:
            return _web.json_response({"error": "already_registered", "message": f"Device {vendor_device_id} is already registered"}, status=409)

        # Resolve the registering clinician's organization so this device
        # (and every alert it later generates) can be routed to that
        # hospital's own FHIR/HL7 configuration, rather than only the
        # global single-tenant FHIR_*/HL7_ORU_* environment variables.
        # If the clinician's user record has no organization set, or it
        # doesn't match a canonical organizations row, organization_id is
        # simply left null — the device still registers normally and
        # falls back to global config, exactly as before this feature.
        organization_id = None
        try:
            clinician_user = await _load_user_by_id(user.get("sub"))
            if clinician_user and clinician_user.organization:
                org = await _db.get_organization_by_name(clinician_user.organization)
                if org:
                    organization_id = org.id
        except Exception:
            logger.exception("[Implant] error resolving organization for clinician_id=%s", user.get("sub"))

        large_device = await _db.register_large_device(
            vendor_device_id=vendor_device_id, vendor=vendor, device_type=device_type, patient_id=patient_id,
            model_number=model_number, implanted_at=implanted_at,
            implanting_clinician_id=user.get("sub"), registered_by_user_id=user.get("sub"), notes=notes,
            organization_id=organization_id,
        )

        await _db.log_event("implant_registered", user_id=user.get("sub"), detail=f"vendor={vendor} device={vendor_device_id} patient={patient_id}")
        logger.info("[Implant] clinician=%s registered %s device=%s for patient=%s", user.get("sub"), vendor, vendor_device_id, patient_id)

        return _web.json_response({
            "id": large_device.id, "vendor_device_id": large_device.vendor_device_id, "vendor": large_device.vendor,
            "device_type": large_device.device_type, "patient_id": large_device.patient_id, "is_active": large_device.is_active,
        }, status=201)

    @_require_auth(cfg)
    async def list_implants(request: _web.Request) -> _web.Response:
        user = request["user"]
        patient_id = request.query.get("patient_id")
        vendor = request.query.get("vendor")
        if user.get("role") == UserRole.PATIENT.value:
            patient_id = user.get("patient_id") or user.get("sub")
        devices_ = await _db.list_large_devices(patient_id=patient_id, vendor=vendor)
        return _web.json_response([
            {
                "id": d.id, "vendor_device_id": d.vendor_device_id, "vendor": d.vendor, "device_type": d.device_type,
                "model_number": d.model_number, "patient_id": d.patient_id, "implanted_at": d.implanted_at,
                "is_active": d.is_active, "last_event_at": d.last_event_at,
            }
            for d in devices_
        ])

    # ── GET /clinical/devices/ble ─────────────────────────────────────────
    #
    # Clinical staff: list patient-paired BLE devices, optionally filtered
    # to only those NOT yet configured (organization_id is null) — this is
    # the "needs attention" queue for a nurse/admin to work through after
    # patients pair devices from the app on their own.

    @_require_auth(cfg)
    @require_role(UserRole.NURSE, UserRole.CARDIOLOGIST, UserRole.ADMIN)
    async def list_ble_devices(request: _web.Request) -> _web.Response:
        patient_id = request.query.get("patient_id")
        unconfigured_only = request.query.get("unconfigured", "").lower() == "true"
        devices_ = await _db.list_ble_devices(patient_id=patient_id, unconfigured_only=unconfigured_only)
        return _web.json_response([
            {
                "id": d.id, "device_id": d.device_id, "device_type": d.device_type,
                "device_name": d.device_name, "patient_id": d.patient_id,
                "organization_id": d.organization_id, "is_configured": d.is_configured,
                "configured_at": d.configured_at, "is_active": d.is_active,
                "last_data_at": d.last_data_at, "created_at": d.created_at,
            }
            for d in devices_
        ])

    # ── PATCH /clinical/devices/ble/{device_id} ──────────────────────────
    #
    # Clinical staff: assign a patient-paired BLE device to their
    # organization, so its future alerts route to that hospital's FHIR/HL7
    # configuration instead of falling back to the global default. This is
    # the "register/config" step requested — the patient already paired
    # the device from the app; this is the hospital-side acknowledgment
    # that links it to their care.

    @_require_auth(cfg)
    @require_role(UserRole.NURSE, UserRole.CARDIOLOGIST, UserRole.ADMIN)
    async def configure_ble_device(request: _web.Request) -> _web.Response:
        device_id = request.match_info.get("device_id", "")
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        organization_id = (body.get("organization_id") or "").strip()
        if not organization_id:
            return _web.json_response({"error": "missing_fields", "message": "'organization_id' is required"}, status=400)

        existing = await _db.get_ble_device_by_device_id(device_id)
        if existing is None:
            return _web.json_response({"error": "device_not_found", "message": f"No BLE device found with device_id={device_id}"}, status=404)

        org = await _db.get_organization_by_id(organization_id)
        if org is None:
            return _web.json_response({"error": "organization_not_found"}, status=404)

        user = request["user"]
        updated = await _db.configure_ble_device(
            device_id=device_id, organization_id=organization_id, configured_by_user_id=user.get("sub"),
        )
        await _db.log_event(
            "ble_device_configured", user_id=user.get("sub"),
            detail=f"device_id={device_id} organization={org.name} patient_id={existing.patient_id}",
        )
        logger.info("[BLEConfig] clinician=%s assigned device=%s to organization=%s", user.get("sub"), device_id, org.name)

        return _web.json_response({
            "id": updated.id, "device_id": updated.device_id, "patient_id": updated.patient_id,
            "organization_id": updated.organization_id, "is_configured": updated.is_configured,
            "configured_at": updated.configured_at,
        })

    @_require_vendor_api_key
    async def vendor_gateway_ingest(request: _web.Request) -> _web.Response:
        vendor = request["vendor"]
        try:
            raw_payload = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        normalized = normalize_vendor_payload(vendor, raw_payload)
        vendor_device_id = normalized.get("vendor_device_id") if normalized else \
            raw_payload.get("deviceSerialNumber") or raw_payload.get("implantId") or raw_payload.get("device_id")

        large_device = None
        if vendor_device_id:
            large_device = await _db.get_large_device_by_vendor_id(vendor_device_id)

        matched = large_device is not None and large_device.is_active

        await _db.log_vendor_event(
            vendor=vendor, raw_payload=raw_payload, vendor_device_id=vendor_device_id,
            large_device_id=large_device.id if large_device else None, matched=matched,
            kafka_published=bool(normalized and matched),
        )

        if normalized is None:
            logger.warning("[VendorGateway] vendor=%s payload failed normalization", vendor)
            await _kafka_producer.publish(TOPIC_VENDOR_DEADLETTER, key=vendor_device_id or "unknown", value={"vendor": vendor, "raw": raw_payload, "reason": "normalization_failed"})
            return _web.json_response({"error": "normalization_failed", "message": "Payload could not be normalized for this vendor"}, status=422)

        if not matched:
            logger.warning("[VendorGateway] vendor=%s device=%s not registered or inactive — dead-lettered", vendor, vendor_device_id)
            await _kafka_producer.publish(TOPIC_VENDOR_DEADLETTER, key=vendor_device_id or "unknown", value={"vendor": vendor, "raw": raw_payload, "reason": "device_not_registered"})
            return _web.json_response({"error": "device_not_registered", "message": f"Device {vendor_device_id} is not registered or is inactive."}, status=404)

        await _kafka_producer.publish(TOPIC_VENDOR_RAW, key=vendor_device_id, value=normalized)
        return _web.json_response({"status": "accepted"}, status=202)

    @_require_auth(cfg)
    @require_role(UserRole.ADMIN)
    async def admin_create_vendor_key(request: _web.Request) -> _web.Response:
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        vendor = (body.get("vendor") or "").strip().lower()
        label = (body.get("label") or "").strip()

        valid_vendors = {"medtronic", "abbott", "boston_scientific", "biotronik", "other"}
        if vendor not in valid_vendors:
            return _web.json_response({"error": "invalid_vendor", "message": f"vendor must be one of: {', '.join(sorted(valid_vendors))}"}, status=400)

        raw_key, key_id = await _db.create_vendor_api_key(vendor=vendor, label=label)

        admin_user = request["user"]
        await _db.log_event("vendor_key_created", user_id=admin_user.get("sub"), detail=f"vendor={vendor} key_id={key_id}")
        logger.info("[Admin] user_id=%s created vendor API key for vendor=%s", admin_user.get("sub"), vendor)

        return _web.json_response({"key_id": key_id, "vendor": vendor, "api_key": raw_key, "warning": "This key is shown only once and cannot be recovered. Store it securely now."}, status=201)

    # ── GET /admin/organizations ─────────────────────────────────────────
    #
    # Admin-only: list all canonical organizations, including ones that
    # were auto-registered by a first-time signup (auto_registered=true)
    # versus ones an admin explicitly created ahead of time.

    # ── GET /clinical/organizations ──────────────────────────────────────
    #
    # Any clinical staff role (not just admin): a minimal id+name listing
    # for populating the "assign this device to an organization" dropdown
    # when configuring a patient-paired BLE device. Deliberately does NOT
    # include fhir_enabled/fhir_base_url/etc — those stay admin-only via
    # GET /admin/organizations, since a nurse configuring a device doesn't
    # need visibility into another hospital's FHIR integration status.

    @_require_auth(cfg)
    @require_role(UserRole.NURSE, UserRole.CARDIOLOGIST, UserRole.ADMIN)
    async def list_organizations_minimal(request: _web.Request) -> _web.Response:
        orgs = await _db.list_organizations()
        return _web.json_response([{"id": o.id, "name": o.name} for o in orgs])

    @_require_auth(cfg)
    @require_role(UserRole.ADMIN)
    async def admin_list_organizations(request: _web.Request) -> _web.Response:
        orgs = await _db.list_organizations()
        return _web.json_response([
            {
                "id": o.id, "name": o.name, "allowed_domains": o.allowed_domains,
                "auto_registered": o.auto_registered, "created_at": o.created_at,
                "fhir_enabled": o.fhir_enabled, "fhir_base_url": o.fhir_base_url,
                "fhir_min_alert_level": o.fhir_min_alert_level,
                # fhir_client_secret is intentionally never returned in any response.
            }
            for o in orgs
        ])

    # ── POST /admin/organizations ────────────────────────────────────────
    #
    # Admin-only: pre-register an organization with a locked domain list
    # BEFORE any of its staff sign up. Recommended for onboarding a known
    # hospital customer, so the first real signup is already domain-locked
    # instead of relying on auto-registration from whichever email happens
    # to sign up first.

    @_require_auth(cfg)
    @require_role(UserRole.ADMIN)
    async def admin_create_organization(request: _web.Request) -> _web.Response:
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        name = (body.get("name") or "").strip()
        allowed_domains = body.get("allowed_domains") or []

        if not name:
            return _web.json_response({"error": "missing_fields", "message": "'name' is required"}, status=400)
        if not isinstance(allowed_domains, list) or not all(isinstance(d, str) for d in allowed_domains):
            return _web.json_response({"error": "invalid_domains", "message": "'allowed_domains' must be a list of domain strings, e.g. [\"hospital.org\"]"}, status=400)

        existing = await _db.get_organization_by_name(name)
        if existing is not None:
            return _web.json_response({"error": "organization_exists", "message": f"'{name}' is already registered"}, status=409)

        admin_user = request["user"]
        org = await _db.create_organization(
            name=name, allowed_domains=allowed_domains, created_by=admin_user.get("sub"), auto_registered=False,
        )
        await _db.log_event("organization_created", user_id=admin_user.get("sub"), detail=f"name={name} domains={allowed_domains}")
        logger.info("[Admin] user_id=%s created organization=%s domains=%s", admin_user.get("sub"), name, allowed_domains)

        return _web.json_response({
            "id": org.id, "name": org.name, "allowed_domains": org.allowed_domains, "auto_registered": org.auto_registered,
        }, status=201)

    # ── PATCH /admin/organizations/{org_id} ──────────────────────────────
    #
    # Admin-only: update an organization's allowed domain list (e.g. add a
    # second legitimate domain a hospital uses) and/or fix its canonical
    # name. Body: { "allowed_domains": [...] } and/or { "name": "..." }

    @_require_auth(cfg)
    @require_role(UserRole.ADMIN)
    async def admin_update_organization(request: _web.Request) -> _web.Response:
        org_id = request.match_info.get("org_id", "")
        try:
            body = await request.json()
        except Exception:
            return _web.json_response({"error": "invalid_json"}, status=400)

        org = await _db.get_organization_by_id(org_id)
        if org is None:
            return _web.json_response({"error": "organization_not_found"}, status=404)

        allowed_domains = body.get("allowed_domains")
        name = body.get("name")
        fhir_enabled = body.get("fhir_enabled")
        fhir_base_url = body.get("fhir_base_url")
        fhir_token_url = body.get("fhir_token_url")
        fhir_client_id = body.get("fhir_client_id")
        fhir_client_secret = body.get("fhir_client_secret")
        fhir_patient_identifier_system = body.get("fhir_patient_identifier_system")
        fhir_min_alert_level = body.get("fhir_min_alert_level")

        if allowed_domains is not None and (not isinstance(allowed_domains, list) or not all(isinstance(d, str) for d in allowed_domains)):
            return _web.json_response({"error": "invalid_domains", "message": "'allowed_domains' must be a list of domain strings"}, status=400)

        if fhir_min_alert_level is not None and fhir_min_alert_level not in ("low", "medium", "high", "critical"):
            return _web.json_response({"error": "invalid_fhir_min_alert_level", "message": "must be one of: low, medium, high, critical"}, status=400)

        updated = await _db.update_organization(
            org_id, allowed_domains=allowed_domains, name=name,
            fhir_enabled=fhir_enabled, fhir_base_url=fhir_base_url, fhir_token_url=fhir_token_url,
            fhir_client_id=fhir_client_id, fhir_client_secret=fhir_client_secret,
            fhir_patient_identifier_system=fhir_patient_identifier_system, fhir_min_alert_level=fhir_min_alert_level,
        )

        admin_user = request["user"]
        await _db.log_event(
            "organization_updated", user_id=admin_user.get("sub"),
            # Deliberately exclude fhir_client_secret from the audit log detail.
            detail=f"org_id={org_id} domains={allowed_domains} name={name} fhir_enabled={fhir_enabled}",
        )
        logger.info("[Admin] user_id=%s updated organization=%s", admin_user.get("sub"), org_id)

        return _web.json_response({
            "id": updated.id, "name": updated.name, "allowed_domains": updated.allowed_domains,
            "auto_registered": updated.auto_registered, "fhir_enabled": updated.fhir_enabled,
            "fhir_base_url": updated.fhir_base_url, "fhir_min_alert_level": updated.fhir_min_alert_level,
            # fhir_client_secret is intentionally never returned in any response.
        })

    # ── GET /admissions ───────────────────────────────────────────────────
    #
    # Read-only view of current admission status, populated by the HL7 v2
    # MLLP listener (hl7_server.py) if HL7_MLLP_ENABLED=true. Returns an
    # empty list if HL7 isn't configured — this endpoint is always safe
    # to call regardless of whether HL7 is set up. Patients see only their
    # own admission record, matching the pattern used for /devices and
    # /alerts.

    @_require_auth(cfg)
    async def admissions(request: _web.Request) -> _web.Response:
        user = request["user"]
        # Role-conditional, same rationale as /devices, /alerts, /reports.
        if user.get("role") == UserRole.PATIENT.value:
            if not await _db.is_subscription_active(user["sub"]):
                raise _web.HTTPPaymentRequired(reason="An active CardioAI Live Premium subscription is required")
        summary = _admission_registry.summary()
        if user.get("role") == UserRole.PATIENT.value:
            pid = user.get("patient_id")
            summary = {**summary, "patients": [p for p in summary["patients"] if p["patient_id"] == pid]}
        return _web.json_response(summary)

    app.router.add_get("/", root)
    app.router.add_get("/dashboard", dashboard)
    app.router.add_get("/privacy", privacy_policy)
    app.router.add_get("/terms", terms_of_use)
    app.router.add_post("/auth/apple", apple_signin)
    app.router.add_post("/auth/google", google_signin)
    app.router.add_post("/auth/login", login)
    app.router.add_post("/auth/signup", signup)
    app.router.add_post("/auth/refresh", refresh)
    app.router.add_post("/auth/logout", logout)
    app.router.add_delete("/account", delete_account)
    app.router.add_post("/subscription/link", link_subscription)
    app.router.add_post("/webhooks/apple-subscription", apple_subscription_webhook)
    app.router.add_post("/webhooks/google-subscription", google_subscription_webhook)
    app.router.add_post("/devices/register", device_register)
    app.router.add_post("/clinical/devices/register-implant", register_implant)
    app.router.add_get("/clinical/devices/implants", list_implants)
    app.router.add_get("/clinical/devices/ble", list_ble_devices)
    app.router.add_patch("/clinical/devices/ble/{device_id}", configure_ble_device)
    app.router.add_get("/clinical/organizations", list_organizations_minimal)
    app.router.add_post("/vendor-gateway/ingest", vendor_gateway_ingest)
    app.router.add_get("/health", health)
    app.router.add_get("/status", full_status)
    app.router.add_get("/devices", devices)
    app.router.add_get("/alerts", alerts)
    app.router.add_get("/reports", reports)
    app.router.add_get("/admin/users", admin_list_users)
    app.router.add_post("/admin/users", admin_create_user)
    app.router.add_patch("/admin/users/{user_id}", admin_update_user)
    app.router.add_post("/admin/vendor-keys", admin_create_vendor_key)
    app.router.add_get("/admin/organizations", admin_list_organizations)
    app.router.add_post("/admin/organizations", admin_create_organization)
    app.router.add_patch("/admin/organizations/{org_id}", admin_update_organization)
    app.router.add_get("/admissions", admissions)

    return app


async def start_http_api(bridge: "IoMTCardioAIBridge", host: str = "0.0.0.0", port: int = 8080) -> Tuple["_web.AppRunner", "KafkaEventConsumer"]:
    await _db.connect()
    logger.info("[API] PostgreSQL connection pool established")

    await _kafka_producer.start()

    kafka_consumer = KafkaEventConsumer(producer=_kafka_producer, on_event=lambda event: _consume_vendor_event(bridge, event))
    await kafka_consumer.start()
    logger.info("[API] Kafka vendor-event consumer started")

    app = build_http_app(bridge)
    runner = _web.AppRunner(app)
    await runner.setup()
    site = _web.TCPSite(runner, host, port)
    await site.start()
    logger.info("[API] HTTP server listening on http://%s:%d", host, port)
    return runner, kafka_consumer


async def stop_http_api(runner: "_web.AppRunner", kafka_consumer: Optional["KafkaEventConsumer"] = None) -> None:
    if kafka_consumer is not None:
        await kafka_consumer.stop()
    await _kafka_producer.stop()
    await runner.cleanup()
    await _db.disconnect()


async def main() -> None:
    logger.info("[Startup] IoMT CardioAI Production Service initialising ...")

    run_mode = _optional_env("CARDIOAI_RUN_MODE", "all").lower()
    if run_mode not in ("all", "api", "bridge"):
        logger.critical("[Startup] invalid CARDIOAI_RUN_MODE=%r — must be 'all', 'api', or 'bridge'", run_mode)
        sys.exit(1)
    logger.info("[Startup] run mode: %s", run_mode)

    try:
        cfg = HandshakeConfig.from_env()
    except ConfigurationError as exc:
        logger.critical("[Startup] configuration error: %s", exc)
        sys.exit(1)

    logger.info("[Startup] config loaded: %r", cfg)

    system = CardioAISystem()
    bridge = IoMTCardioAIBridge(system, cfg)

    loop = asyncio.get_running_loop()

    import signal as _signal
    shutdown_event = asyncio.Event()

    def _handle_signal(sig: int) -> None:
        logger.info("[Shutdown] received signal %s", _signal.Signals(sig).name)
        shutdown_event.set()

    for sig in (_signal.SIGINT, _signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig)
        except NotImplementedError:
            pass

    api_runner = None
    kafka_consumer = None
    hl7_server = None

    if run_mode in ("all", "api"):
        api_runner, kafka_consumer = await start_http_api(bridge, host=cfg.api_host, port=cfg.api_port)
        logger.info("[Startup] HTTP API listening on http://%s:%d", cfg.api_host, cfg.api_port)

        # HL7 v2 MLLP listener — separate TCP port from the HTTP API, since
        # HL7 v2/MLLP is not an HTTP protocol. Only starts if HL7_MLLP_ENABLED
        # is set; on Render this requires a TCP-capable service (a Private
        # Service or a paid plan with a non-HTTP port exposed), since the
        # free web service tier only routes HTTP traffic to $PORT.
        if _optional_env("HL7_MLLP_ENABLED", "false").lower() == "true":
            hl7_server = HL7MLLPServer(_admission_registry)
            await hl7_server.start()
            logger.info("[Startup] HL7 v2 MLLP listener started")
        else:
            logger.info("[Startup] HL7_MLLP_ENABLED not set — HL7 ADT listener not started")

    if run_mode in ("all", "bridge"):
        await bridge.start()
        logger.info("[Startup] bridge running — outbound connection to %s", cfg.iomt_server_ws_url)
    else:
        logger.info("[Startup] run_mode=api — skipping outbound IoMT bridge connector.")

    logger.info("[Startup] awaiting shutdown signal")
    await shutdown_event.wait()

    logger.info("[Shutdown] stopping services ...")
    if run_mode in ("all", "bridge"):
        await bridge.stop()
    if hl7_server is not None:
        await hl7_server.stop()
    if api_runner is not None:
        await stop_http_api(api_runner, kafka_consumer)

    logger.info("[Shutdown] final status: %s", json.dumps(bridge.status(), default=str))
    logger.info("[Shutdown] clean exit")


if __name__ == "__main__":
    asyncio.run(main())
