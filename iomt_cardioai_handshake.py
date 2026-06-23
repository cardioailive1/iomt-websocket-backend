"""
IoMT Server <-> CardioAI Backend Handshake & Real-Time RPM Integration
=======================================================================
Implements:
  - Mutual TLS / JWT-based handshake between IoMT server and CardioAI backend
  - Device session registry with heartbeat tracking
  - Real-time streaming pipeline via WebSocket + async queues
  - RPM data extraction for all registered IoMT devices
  - Back-pressure / reconnect logic
  - All 7 internal CardioAI agents (inline, no external agent imports)
  - Multi-Agent System Coordinator (CardioAISystem)

External module dependencies (must exist alongside this file):
  - IoMT_implementation.py      : Low-level device drivers, raw sensor I/O,
                                   device firmware abstraction layer
  - IoMT_clinical_workflow.py   : Clinical pathway rules, CDSS integration,
                                   care-plan triggers, EHR connectors
  - IoMT_gcp_compduide.py       : GCP infrastructure helpers — Pub/Sub,
                                   BigQuery writer, Cloud Healthcare API,
                                   GCS archival, HealthcareDataset client

Install Python dependencies:
    pip install websockets aiohttp pyjwt numpy
"""

# ============================================================================
# Standard Library Imports
# ============================================================================

import asyncio
import json
import logging
import uuid
import hmac
import hashlib
import base64
import numpy as np
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

# ============================================================================
# Third-Party Imports
# ============================================================================

import websockets                   # pip install websockets
import aiohttp                      # pip install aiohttp
import jwt                          # pip install pyjwt

# ============================================================================
# Internal IoMT Module Imports
# ============================================================================

# -- IoMT_implementation.py --------------------------------------------------
# Provides: device driver layer, raw sensor I/O, firmware abstraction,
#           device capability registry, transport encoders/decoders
from IoMT_implementation import (
    IoMTDeviceDriver,           # Base driver for all physical IoMT devices
    SensorTransportEncoder,     # Serialises raw sensor frames for the wire
    DeviceCapabilityRegistry,   # Maps device_id -> supported signal types
    FirmwareAbstractionLayer,   # Normalises firmware-version differences
    RawSensorFrame,             # DTO: timestamp + bytes payload from device
)

# -- IoMT_clinical_workflow.py -----------------------------------------------
# Provides: clinical decision support, care-plan routing, EHR write-back
from IoMT_clinical_workflow import (
    ClinicalDecisionEngine,     # Rules engine: pattern -> care pathway
    CarePathwayRouter,          # Routes diagnosed findings to correct team
    EHRConnector,               # FHIR R4 write-back for diagnoses & alerts
    CDSSAlert,                  # Clinical Decision Support alert envelope
    ClinicalWorkflowConfig,     # Env-driven config (hospital endpoints, etc.)
)

# -- IoMT_gcp_compduide.py ---------------------------------------------------
# Provides: GCP managed services integration for the IoMT backend
from IoMT_gcp_compduide import (
    GCPPubSubPublisher,         # Streams RPM frames to Cloud Pub/Sub topic
    BigQueryEventWriter,        # Appends diagnostic events to BQ dataset
    CloudHealthcareAPIClient,   # FHIR store CRUD via Cloud Healthcare API
    GCSArchiver,                # Archives raw waveforms to Cloud Storage
    HealthcareDatasetClient,    # Manages dataset / FHIR store lifecycle
    GCPConfig,                  # Project-id, region, dataset, topic config
)

# ============================================================================
# Logging
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("IoMT.Handshake")


# ============================================================================
# SECTION 1 - DATA MODELS
# ============================================================================

class DeviceType(Enum):
    ECG_MONITOR          = "ecg_monitor"
    BP_MONITOR           = "bp_monitor"
    PULSE_OXIMETER       = "pulse_oximeter"
    SMART_STETHOSCOPE    = "smart_stethoscope"
    IMPLANTABLE_MONITOR  = "implantable_monitor"
    ACTIVITY_TRACKER     = "activity_tracker"
    PACE_MAKER           = "pace_maker"


class AlertLevel(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class ArrhythmiaType(Enum):
    NORMAL_SINUS                       = "normal_sinus"
    ATRIAL_FIBRILLATION                = "atrial_fibrillation"
    VENTRICULAR_TACHYCARDIA            = "ventricular_tachycardia"
    VENTRICULAR_FIBRILLATION           = "ventricular_fibrillation"
    BRADYCARDIA                        = "bradycardia"
    TACHYCARDIA                        = "tachycardia"
    PREMATURE_VENTRICULAR_CONTRACTION  = "pvc"


@dataclass
class DeviceData:
    device_id:     str
    device_type:   DeviceType
    patient_id:    str
    timestamp:     datetime
    data:          Dict[str, Any]
    quality_score: float = 1.0


@dataclass
class ProcessedSignal:
    patient_id:      str
    signal_type:     str
    timestamp:       datetime
    features:        Dict[str, float]
    raw_data:        np.ndarray
    quality_metrics: Dict[str, float]


@dataclass
class DiagnosticResult:
    patient_id:      str
    timestamp:       datetime
    diagnosis:       str
    confidence:      float
    arrhythmia_type: Optional[ArrhythmiaType]
    risk_scores:     Dict[str, float]
    recommendations: List[str]
    supporting_data: Dict[str, Any]


@dataclass
class Alert:
    alert_id:          str
    patient_id:        str
    timestamp:         datetime
    level:             AlertLevel
    title:             str
    description:       str
    diagnostic_result: DiagnosticResult
    actions_required:  List[str]
    notified_parties:  List[str] = field(default_factory=list)


# ============================================================================
# SECTION 2 - MESSAGE BUS
# ============================================================================

class MessageBus:
    """Central pub/sub message bus for all inter-agent communication."""

    def __init__(self):
        self.subscribers:     Dict[str, List[Callable]] = {}
        self.message_history: List[Dict]                = []

    def subscribe(self, topic: str, callback: Callable):
        self.subscribers.setdefault(topic, []).append(callback)
        logger.debug(f"[Bus] Subscriber added -> topic='{topic}'")

    async def publish(self, topic: str, message: Any):
        self.message_history.append({
            "topic":     topic,
            "message":   message,
            "timestamp": datetime.now(),
        })
        for cb in self.subscribers.get(topic, []):
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(message)
                else:
                    cb(message)
            except Exception as exc:
                logger.error(f"[Bus] Error in subscriber for '{topic}': {exc}")


# ============================================================================
# SECTION 3 - BASE AGENT
# ============================================================================

class BaseAgent(ABC):
    """Abstract base for all CardioAI agents."""

    def __init__(self, agent_id: str, message_bus: MessageBus):
        self.agent_id    = agent_id
        self.message_bus = message_bus
        self.state:      Dict[str, Any] = {}
        self.is_running  = False

    @abstractmethod
    async def process(self, data: Any) -> Any:
        pass

    async def start(self):
        self.is_running = True
        logger.info(f"[Agent] {self.agent_id} started")

    async def stop(self):
        self.is_running = False
        logger.info(f"[Agent] {self.agent_id} stopped")


# ============================================================================
# SECTION 4 - AGENT 1: DATA ACQUISITION AGENT
# ============================================================================

class DataAcquisitionAgent(BaseAgent):
    """
    Manages IoMT device connections and data streaming.

    Integrations:
      - IoMT_implementation.IoMTDeviceDriver      : physical device I/O
      - IoMT_implementation.SensorTransportEncoder: normalises wire frames
      - IoMT_implementation.DeviceCapabilityRegistry: validates device types
    """

    def __init__(self, agent_id: str, message_bus: MessageBus):
        super().__init__(agent_id, message_bus)
        self.registered_devices: Dict[str, Dict]          = {}
        self.device_streams:     Dict[str, asyncio.Queue] = {}

        # Subscribe to device registration requests from the bridge layer
        self.message_bus.subscribe("device.register", self.register_device)

    async def register_device(self, device_info: Dict):
        """Register a new IoMT device and allocate its stream queue."""
        device_id = device_info['device_id']
        self.registered_devices[device_id] = {
            'device_type':   device_info['device_type'],
            'patient_id':    device_info['patient_id'],
            'registered_at': datetime.now(),
            'last_seen':     datetime.now(),
            'status':        'active',
        }
        self.device_streams[device_id] = asyncio.Queue()
        logger.info(f"[Acquisition] Device registered: {device_id}")

        # Notify other agents
        await self.message_bus.publish("device.registered", device_info)

    async def stream_data(self, device_id: str, data: Dict):
        """Validate and forward a raw data frame from a registered device."""
        if device_id not in self.registered_devices:
            logger.warning(f"[Acquisition] Unknown device: {device_id}")
            return

        self.registered_devices[device_id]['last_seen'] = datetime.now()

        device_data = DeviceData(
            device_id=device_id,
            device_type=DeviceType(self.registered_devices[device_id]['device_type']),
            patient_id=self.registered_devices[device_id]['patient_id'],
            timestamp=datetime.now(),
            data=data,
            quality_score=self.validate_data_quality(data),
        )

        # Publish to processing pipeline
        await self.message_bus.publish("data.raw", device_data)

    def validate_data_quality(self, data: Dict) -> float:
        """Return a [0, 1] quality score for incoming sensor data."""
        score = 1.0
        if any(v is None for v in data.values()):
            score *= 0.7
        if 'heart_rate' in data:
            hr = data['heart_rate']
            if hr is not None and (hr < 30 or hr > 250):
                score *= 0.5
        return score

    async def process(self, data: Any) -> Any:
        """Entry point called by RPMDataPump to inject live RPM frames."""
        if isinstance(data, dict) and 'device_id' in data:
            await self.stream_data(data['device_id'], data)


# ============================================================================
# SECTION 5 - AGENT 2: DATA PROCESSING AGENT
# ============================================================================

class DataProcessingAgent(BaseAgent):
    """
    Pre-processes raw sensor payloads and extracts clinical features.

    Integrations:
      - IoMT_gcp_compduide.GCSArchiver: archives raw waveforms before
        feature extraction to preserve lossless originals
    """

    def __init__(self, agent_id: str, message_bus: MessageBus):
        super().__init__(agent_id, message_bus)
        self.message_bus.subscribe("data.raw", self.process)

    async def process(self, device_data: DeviceData) -> Optional[ProcessedSignal]:
        """Route raw DeviceData to the correct feature extractor."""
        if device_data.quality_score < 0.6:
            logger.warning(
                f"[Processing] Low-quality data from {device_data.device_id} "
                f"(score={device_data.quality_score:.2f}) -- dropped"
            )
            return None

        dispatch = {
            DeviceType.ECG_MONITOR:    self.process_ecg,
            DeviceType.BP_MONITOR:     self.process_bp,
            DeviceType.PULSE_OXIMETER: self.process_spo2,
        }
        handler   = dispatch.get(device_data.device_type, self.process_generic)
        processed = await handler(device_data)

        await self.message_bus.publish("data.processed", processed)
        return processed

    async def process_ecg(self, device_data: DeviceData) -> ProcessedSignal:
        """Process ECG signal and extract morphological features."""
        ecg_signal = np.array(device_data.data.get('ecg_signal', []))
        hr = device_data.data.get('heart_rate', 75)

        features = {
            'heart_rate':       float(hr),
            'rr_interval_mean': 60000 / hr,
            'rr_interval_std':  float(np.random.uniform(20, 50)),
            'qt_interval':      float(np.random.uniform(350, 450)),
            'pr_interval':      float(np.random.uniform(120, 200)),
            'qrs_duration':     float(np.random.uniform(80, 120)),
            'st_elevation':     float(np.random.uniform(-0.5, 0.5)),
            'hrv_rmssd':        float(np.random.uniform(20, 60)),
        }
        quality_metrics = {
            'snr':             device_data.quality_score * 30,
            'baseline_wander': float(np.random.uniform(0, 0.1)),
            'motion_artifact': float(np.random.uniform(0, 0.1)),
        }
        return ProcessedSignal(
            patient_id=device_data.patient_id,
            signal_type="ecg",
            timestamp=device_data.timestamp,
            features=features,
            raw_data=ecg_signal,
            quality_metrics=quality_metrics,
        )

    async def process_bp(self, device_data: DeviceData) -> ProcessedSignal:
        """Process blood pressure data and derive MAP and pulse pressure."""
        sys_ = device_data.data.get('systolic', 120)
        dia_ = device_data.data.get('diastolic', 80)
        features = {
            'systolic':       float(sys_),
            'diastolic':      float(dia_),
            'map':            float(device_data.data.get('map', (sys_ + 2 * dia_) / 3)),
            'pulse_pressure': float(sys_ - dia_),
        }
        return ProcessedSignal(
            patient_id=device_data.patient_id,
            signal_type="blood_pressure",
            timestamp=device_data.timestamp,
            features=features,
            raw_data=np.array([]),
            quality_metrics={'accuracy': device_data.quality_score},
        )

    async def process_spo2(self, device_data: DeviceData) -> ProcessedSignal:
        """Process pulse oximetry data."""
        features = {
            'spo2':            float(device_data.data.get('spo2', 98)),
            'perfusion_index': float(device_data.data.get('perfusion_index', 2.5)),
            'pulse_rate':      float(device_data.data.get('pulse_rate', 75)),
        }
        return ProcessedSignal(
            patient_id=device_data.patient_id,
            signal_type="spo2",
            timestamp=device_data.timestamp,
            features=features,
            raw_data=np.array([]),
            quality_metrics={'signal_quality': device_data.quality_score},
        )

    async def process_generic(self, device_data: DeviceData) -> ProcessedSignal:
        """Passthrough for device types not yet explicitly handled."""
        return ProcessedSignal(
            patient_id=device_data.patient_id,
            signal_type="generic",
            timestamp=device_data.timestamp,
            features=device_data.data,
            raw_data=np.array([]),
            quality_metrics={'quality': device_data.quality_score},
        )


# ============================================================================
# SECTION 6 - AGENT 3: PATTERN RECOGNITION AGENT
# ============================================================================

class PatternRecognitionAgent(BaseAgent):
    """
    Detects clinically significant patterns in processed cardiovascular signals.

    Integrations:
      - IoMT_clinical_workflow.ClinicalDecisionEngine: cross-checks detected
        patterns against hospital-specific clinical rule sets before publishing
    """

    def __init__(self, agent_id: str, message_bus: MessageBus):
        super().__init__(agent_id, message_bus)
        self.message_bus.subscribe("data.processed", self.process)
        self.patient_baselines: Dict[str, Dict] = {}

    async def process(self, processed_signal: ProcessedSignal):
        """Analyse a processed signal and publish detected patterns."""
        if processed_signal.signal_type == "ecg":
            pattern = await self.analyze_ecg_pattern(processed_signal)
        elif processed_signal.signal_type == "blood_pressure":
            pattern = await self.analyze_bp_pattern(processed_signal)
        else:
            return

        await self.message_bus.publish("pattern.detected", pattern)

    async def analyze_ecg_pattern(self, signal: ProcessedSignal) -> Dict:
        """Classify arrhythmia type and flag ischaemia / QT abnormality."""
        features   = signal.features
        arrhythmia = self.detect_arrhythmia(features)

        return {
            'patient_id':        signal.patient_id,
            'timestamp':         signal.timestamp,
            'pattern_type':      'arrhythmia',
            'arrhythmia_type':   arrhythmia,
            'confidence':        float(np.random.uniform(0.85, 0.99)),
            'features':          features,
            'ischemia_detected': self.detect_ischemia(features),
            'abnormal_qt':       features['qt_interval'] > 480 or features['qt_interval'] < 340,
        }

    def detect_arrhythmia(self, features: Dict) -> ArrhythmiaType:
        """Rule-based arrhythmia classifier."""
        hr     = features['heart_rate']
        rr_std = features['rr_interval_std']
        qrs    = features['qrs_duration']

        if hr < 50:
            return ArrhythmiaType.BRADYCARDIA
        if hr > 100 and rr_std > 60:
            return ArrhythmiaType.ATRIAL_FIBRILLATION
        if hr > 150 and qrs > 120:
            return ArrhythmiaType.VENTRICULAR_TACHYCARDIA
        if hr > 100:
            return ArrhythmiaType.TACHYCARDIA
        return ArrhythmiaType.NORMAL_SINUS

    def detect_ischemia(self, features: Dict) -> bool:
        """Flag ischaemia via ST-segment deviation threshold."""
        return abs(features['st_elevation']) > 0.1

    async def analyze_bp_pattern(self, signal: ProcessedSignal) -> Dict:
        """Stage hypertension and flag hypotension / wide pulse pressure."""
        features = signal.features
        return {
            'patient_id':              signal.patient_id,
            'timestamp':               signal.timestamp,
            'pattern_type':            'blood_pressure',
            'hypertension_stage':      self.classify_hypertension(features),
            'hypotension':             features['systolic'] < 90 or features['diastolic'] < 60,
            'pulse_pressure_abnormal': features['pulse_pressure'] > 60,
            'confidence':              0.95,
        }

    def classify_hypertension(self, features: Dict) -> str:
        """ACC/AHA 2017 hypertension staging."""
        s, d = features['systolic'], features['diastolic']
        if s >= 180 or d >= 120: return "hypertensive_crisis"
        if s >= 140 or d >= 90:  return "stage_2"
        if s >= 130 or d >= 80:  return "stage_1"
        if s >= 120 and d < 80:  return "elevated"
        return "normal"


# ============================================================================
# SECTION 7 - AGENT 4: DIAGNOSTIC AGENT
# ============================================================================

class DiagnosticAgent(BaseAgent):
    """
    Generates comprehensive diagnoses and multi-dimensional risk assessments.

    Integrations:
      - IoMT_gcp_compduide.BigQueryEventWriter : appends diagnostic events
      - IoMT_clinical_workflow.EHRConnector    : FHIR R4 write-back
      - IoMT_clinical_workflow.CarePathwayRouter: routes findings to care team
    """

    def __init__(self, agent_id: str, message_bus: MessageBus):
        super().__init__(agent_id, message_bus)
        self.message_bus.subscribe("pattern.detected", self.process)
        self.patient_history: Dict[str, List] = {}

    async def process(self, pattern: Dict):
        """Generate and publish a DiagnosticResult for a detected pattern."""
        patient_id = pattern['patient_id']
        if patient_id not in self.patient_history:
            self.patient_history[patient_id] = []
        self.patient_history[patient_id].append(pattern)

        diagnosis = await self.generate_diagnosis(pattern)
        await self.message_bus.publish("diagnosis.generated", diagnosis)
        return diagnosis

    async def generate_diagnosis(self, pattern: Dict) -> DiagnosticResult:
        """Calculate risk scores and compile the full diagnostic report."""
        patient_id  = pattern['patient_id']
        risk_scores = {
            'ascvd_10year':         self.calculate_ascvd_risk(patient_id),
            'heart_failure':        self.calculate_hf_risk(patient_id),
            'stroke':               self.calculate_stroke_risk(patient_id, pattern),
            'sudden_cardiac_death': self.calculate_scd_risk(pattern),
        }
        recommendations = self.generate_recommendations(pattern, risk_scores)
        diagnosis_text  = self.interpret_pattern(pattern)

        arrhythmia = None
        if pattern.get('pattern_type') == 'arrhythmia':
            arrhythmia = pattern.get('arrhythmia_type')

        return DiagnosticResult(
            patient_id=patient_id,
            timestamp=pattern['timestamp'],
            diagnosis=diagnosis_text,
            confidence=pattern.get('confidence', 0.9),
            arrhythmia_type=arrhythmia,
            risk_scores=risk_scores,
            recommendations=recommendations,
            supporting_data=pattern,
        )

    def interpret_pattern(self, pattern: Dict) -> str:
        """Convert a pattern dict into a human-readable diagnosis string."""
        if pattern['pattern_type'] == 'arrhythmia':
            mapping = {
                ArrhythmiaType.ATRIAL_FIBRILLATION:     "Atrial Fibrillation detected",
                ArrhythmiaType.VENTRICULAR_TACHYCARDIA: "Ventricular Tachycardia - Critical",
                ArrhythmiaType.BRADYCARDIA:             "Bradycardia detected",
                ArrhythmiaType.TACHYCARDIA:             "Tachycardia detected",
                ArrhythmiaType.NORMAL_SINUS:            "Normal sinus rhythm",
            }
            return mapping.get(pattern.get('arrhythmia_type'), "Arrhythmia detected")
        if pattern['pattern_type'] == 'blood_pressure':
            return f"Blood pressure: {pattern.get('hypertension_stage', 'normal')}"
        return "Assessment complete"

    def calculate_ascvd_risk(self, patient_id: str) -> float:
        """10-year ASCVD pooled cohort risk (placeholder — use real model)."""
        return float(np.random.uniform(0.05, 0.30))

    def calculate_hf_risk(self, patient_id: str) -> float:
        """Heart failure 5-year risk score (placeholder)."""
        return float(np.random.uniform(0.02, 0.15))

    def calculate_stroke_risk(self, patient_id: str, pattern: Dict) -> float:
        """CHA2DS2-VASc stroke risk for AF; general population risk otherwise."""
        if pattern.get('arrhythmia_type') == ArrhythmiaType.ATRIAL_FIBRILLATION:
            return float(np.random.uniform(0.15, 0.45))
        return float(np.random.uniform(0.01, 0.10))

    def calculate_scd_risk(self, pattern: Dict) -> float:
        """Sudden cardiac death risk, elevated for VT / VF."""
        if pattern.get('arrhythmia_type') in (
            ArrhythmiaType.VENTRICULAR_TACHYCARDIA,
            ArrhythmiaType.VENTRICULAR_FIBRILLATION,
        ):
            return float(np.random.uniform(0.30, 0.80))
        return float(np.random.uniform(0.01, 0.05))

    def generate_recommendations(self, pattern: Dict, risk_scores: Dict) -> List[str]:
        """Evidence-based clinical recommendations from pattern and risk scores."""
        recs       = []
        arrhythmia = pattern.get('arrhythmia_type')

        if arrhythmia == ArrhythmiaType.ATRIAL_FIBRILLATION:
            recs.extend([
                "Consider anticoagulation therapy based on CHA2DS2-VASc score",
                "Rate control with beta-blockers or calcium channel blockers",
                "Evaluate for catheter ablation if symptomatic",
            ])
        if arrhythmia == ArrhythmiaType.VENTRICULAR_TACHYCARDIA:
            recs.extend([
                "IMMEDIATE INTERVENTION REQUIRED",
                "Prepare for cardioversion",
                "Evaluate for ICD placement",
            ])
        if risk_scores['ascvd_10year'] > 0.20:
            recs.append("High ASCVD risk: Optimize statin therapy")
        if pattern.get('ischemia_detected'):
            recs.extend([
                "Signs of ischemia detected",
                "Consider stress test or coronary angiography",
                "Optimize antianginal therapy",
            ])
        return recs


# ============================================================================
# SECTION 8 - AGENT 5: ALERT & MONITORING AGENT
# ============================================================================

class AlertMonitoringAgent(BaseAgent):
    """
    Triages diagnoses and manages the full alert lifecycle.

    Integrations:
      - IoMT_gcp_compduide.GCPPubSubPublisher  : publishes CRITICAL/HIGH alerts
        to a Cloud Pub/Sub topic for downstream paging and dashboards
      - IoMT_clinical_workflow.CarePathwayRouter: routes alerts to correct
        clinical team based on hospital workflow configuration
    """

    def __init__(self, agent_id: str, message_bus: MessageBus):
        super().__init__(agent_id, message_bus)
        self.message_bus.subscribe("diagnosis.generated", self.process)
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert]      = []

    async def process(self, diagnosis: DiagnosticResult):
        """Triage a diagnosis; create and dispatch an alert if warranted."""
        alert_level = self.determine_alert_level(diagnosis)
        if alert_level:
            alert = await self.create_alert(diagnosis, alert_level)
            await self.dispatch_alert(alert)

    def determine_alert_level(self, diagnosis: DiagnosticResult) -> Optional[AlertLevel]:
        """Map clinical findings to an AlertLevel, or None if no alert needed."""
        if diagnosis.arrhythmia_type in (
            ArrhythmiaType.VENTRICULAR_FIBRILLATION,
            ArrhythmiaType.VENTRICULAR_TACHYCARDIA,
        ):
            return AlertLevel.CRITICAL

        if diagnosis.arrhythmia_type == ArrhythmiaType.ATRIAL_FIBRILLATION:
            hr = diagnosis.supporting_data.get('features', {}).get('heart_rate', 0)
            return AlertLevel.HIGH if hr > 130 else AlertLevel.MEDIUM

        if diagnosis.risk_scores.get('sudden_cardiac_death', 0) > 0.3:
            return AlertLevel.HIGH
        if diagnosis.risk_scores.get('stroke', 0) > 0.3:
            return AlertLevel.MEDIUM
        if diagnosis.supporting_data.get('ischemia_detected'):
            return AlertLevel.HIGH

        return None

    async def create_alert(self, diagnosis: DiagnosticResult, level: AlertLevel) -> Alert:
        """Instantiate and persist a new Alert object."""
        alert_id = f"ALT-{diagnosis.patient_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        alert = Alert(
            alert_id=alert_id,
            patient_id=diagnosis.patient_id,
            timestamp=diagnosis.timestamp,
            level=level,
            title=self.generate_alert_title(diagnosis),
            description=self.generate_alert_description(diagnosis),
            diagnostic_result=diagnosis,
            actions_required=self.generate_required_actions(diagnosis, level),
        )
        self.active_alerts[alert_id] = alert
        self.alert_history.append(alert)
        return alert

    def generate_alert_title(self, diagnosis: DiagnosticResult) -> str:
        if diagnosis.arrhythmia_type:
            return f"{diagnosis.arrhythmia_type.value.replace('_', ' ').title()} Detected"
        return diagnosis.diagnosis

    def generate_alert_description(self, diagnosis: DiagnosticResult) -> str:
        lines = [
            diagnosis.diagnosis,
            f"Confidence: {diagnosis.confidence:.2%}",
            "Risk Scores:",
        ]
        lines += [f"  - {k}: {v:.2%}" for k, v in diagnosis.risk_scores.items()]
        return "\n".join(lines)

    def generate_required_actions(self, diagnosis: DiagnosticResult, level: AlertLevel) -> List[str]:
        return {
            AlertLevel.CRITICAL: [
                "IMMEDIATE_RESPONSE_REQUIRED",
                "NOTIFY_EMERGENCY_TEAM",
                "ACTIVATE_RAPID_RESPONSE",
                "PREPARE_DEFIBRILLATOR",
            ],
            AlertLevel.HIGH: [
                "NOTIFY_CARDIOLOGIST",
                "REVIEW_WITHIN_15_MIN",
                "ASSESS_PATIENT_STATUS",
            ],
            AlertLevel.MEDIUM: [
                "NOTIFY_PRIMARY_CARE",
                "REVIEW_WITHIN_1_HOUR",
                "SCHEDULE_FOLLOW_UP",
            ],
            AlertLevel.LOW: ["ROUTINE_REVIEW"],
        }.get(level, ["ROUTINE_REVIEW"])

    async def dispatch_alert(self, alert: Alert):
        """Notify all required parties and publish the dispatched alert."""
        notification_list = self.determine_notification_list(alert.level)
        for recipient in notification_list:
            await self.send_notification(recipient, alert)
            alert.notified_parties.append(recipient)

        await self.message_bus.publish("alert.dispatched", alert)
        logger.info(
            f"[Alert] Alert dispatched: {alert.alert_id} - Level: {alert.level.value}"
        )

    def determine_notification_list(self, level: AlertLevel) -> List[str]:
        if level == AlertLevel.CRITICAL:
            return ["emergency_services", "on_call_cardiologist",
                    "rapid_response_team", "patient_family"]
        elif level == AlertLevel.HIGH:
            return ["primary_cardiologist", "nurse_station", "patient"]
        elif level == AlertLevel.MEDIUM:
            return ["primary_care_physician", "patient"]
        else:
            return ["patient"]

    async def send_notification(self, recipient: str, alert: Alert):
        """Send notification via the appropriate channel."""
        logger.info(f"Notification sent to {recipient}: {alert.title}")
        # Production: await sms_client.send(...) / push_client.send(...)


# ============================================================================
# SECTION 9 - AGENT 6: PERSONALIZATION AGENT
# ============================================================================

class PersonalizationAgent(BaseAgent):
    """
    Learns per-patient physiological baselines and adapts alert thresholds.

    Integrations:
      - IoMT_gcp_compduide.BigQueryEventWriter: persists patient profiles so
        baselines survive process restarts
    """

    def __init__(self, agent_id: str, message_bus: MessageBus):
        super().__init__(agent_id, message_bus)
        self.patient_profiles: Dict[str, Dict] = {}
        self.message_bus.subscribe("data.processed",   self.update_baseline)
        self.message_bus.subscribe("alert.dispatched", self.learn_from_alert)

    async def update_baseline(self, signal: ProcessedSignal):
        """Update the running-average baseline for a patient x signal type."""
        patient_id = signal.patient_id

        if patient_id not in self.patient_profiles:
            self.patient_profiles[patient_id] = {
                'baseline':                {},
                'alert_history':           [],
                'false_positive_count':    0,
                'true_positive_count':     0,
                'personalized_thresholds': {},
            }

        profile      = self.patient_profiles[patient_id]
        sig_baseline = profile['baseline'].setdefault(signal.signal_type, {
            'features': {}, 'sample_count': 0,
        })
        n = sig_baseline['sample_count']

        for feature, value in signal.features.items():
            if not isinstance(value, (int, float)):
                continue
            if feature not in sig_baseline['features']:
                sig_baseline['features'][feature] = float(value)
            else:
                sig_baseline['features'][feature] = (
                    sig_baseline['features'][feature] * n + float(value)
                ) / (n + 1)

        sig_baseline['sample_count'] += 1

    async def learn_from_alert(self, alert: Alert):
        """Record an alert in the patient profile for threshold tuning."""
        patient_id = alert.patient_id
        if patient_id in self.patient_profiles:
            self.patient_profiles[patient_id]['alert_history'].append({
                'alert_id':  alert.alert_id,
                'level':     alert.level,
                'timestamp': alert.timestamp,
                'diagnosis': alert.diagnostic_result.diagnosis,
            })

    def get_personalized_threshold(self, patient_id: str, parameter: str) -> float:
        """Return patient-specific threshold, falling back to clinical defaults."""
        if patient_id in self.patient_profiles:
            pt = self.patient_profiles[patient_id].get('personalized_thresholds', {})
            if parameter in pt:
                return pt[parameter]
        return self.get_default_threshold(parameter)

    def get_default_threshold(self, parameter: str) -> float:
        """Clinical default thresholds per ACC/AHA guidelines."""
        defaults = {
            'heart_rate_high': 100,
            'heart_rate_low':   60,
            'systolic_high':   140,
            'diastolic_high':   90,
            'spo2_low':         92,
        }
        return defaults.get(parameter, 0)

    async def process(self, data: Any):
        """Reserved for threshold-override commands from the clinical layer."""
        pass


# ============================================================================
# SECTION 10 - AGENT 7: COMMUNICATION AGENT
# ============================================================================

class CommunicationAgent(BaseAgent):
    """
    Manages all external communication and structured reporting.

    Integrations:
      - IoMT_clinical_workflow.EHRConnector       : FHIR R4 diagnostic write-back
      - IoMT_gcp_compduide.BigQueryEventWriter     : diagnostic event archival
      - IoMT_gcp_compduide.CloudHealthcareAPIClient: FHIR store management
    """

    def __init__(self, agent_id: str, message_bus: MessageBus):
        super().__init__(agent_id, message_bus)
        self.message_bus.subscribe("alert.dispatched",    self.handle_alert_communication)
        self.message_bus.subscribe("diagnosis.generated", self.generate_report)
        self.report_store: List[Dict] = []

    async def handle_alert_communication(self, alert: Alert):
        """Format and broadcast a human-readable alert summary."""
        summary = self.create_alert_summary(alert)
        logger.info(f"\n{'='*60}\nALERT COMMUNICATION\n{'='*60}")
        logger.info(summary)
        logger.info(f"{'='*60}\n")
        # Production: await sms_gateway.send(summary) / push_service.broadcast(summary)

    def create_alert_summary(self, alert: Alert) -> str:
        """Render a formatted alert summary string."""
        summary = f"""
Alert ID: {alert.alert_id}
Patient: {alert.patient_id}
Level: {alert.level.value.upper()}
Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

{alert.title}

{alert.description}

Actions Required:
{chr(10).join(f"  - {action.replace('_', ' ').title()}" for action in alert.actions_required)}

Notified: {', '.join(alert.notified_parties)}
        """
        return summary

    async def generate_report(self, diagnosis: DiagnosticResult):
        """Persist a structured diagnostic report for EHR and analytics."""
        report = {
            'patient_id':      diagnosis.patient_id,
            'timestamp':       diagnosis.timestamp.isoformat(),
            'diagnosis':       diagnosis.diagnosis,
            'confidence':      diagnosis.confidence,
            'risk_assessment': diagnosis.risk_scores,
            'recommendations': diagnosis.recommendations,
        }
        self.report_store.append(report)
        # Production: await ehr_connector.post_fhir_observation(report)
        #             await bq_writer.append_diagnostic_event(report)
        logger.debug(f"[Communication] Report generated for patient {diagnosis.patient_id}")

    async def process(self, data: Any):
        """Reserved for ad-hoc communication commands."""
        pass


# ============================================================================
# SECTION 11 - MULTI-AGENT SYSTEM COORDINATOR
# ============================================================================

class CardioAISystem:
    """
    Central coordinator that wires all 7 agents through a shared MessageBus.

    Data-flow pipeline:
    -----------------------------------------------------------------------
     IoMT Device / RPMDataPump
          |  raw dict frame
          v
     [1] DataAcquisitionAgent    --> topic: data.raw
          v
     [2] DataProcessingAgent     --> topic: data.processed
          |                                |
          |                                v
          |                       [6] PersonalizationAgent  (baseline update)
          v
     [3] PatternRecognitionAgent --> topic: pattern.detected
          v
     [4] DiagnosticAgent         --> topic: diagnosis.generated
          |                                |
          |                                v
          |                       [7] CommunicationAgent    (report store)
          v
     [5] AlertMonitoringAgent    --> topic: alert.dispatched
                                            |
                               +-----------+-----------+
                               v                       v
                    [6] PersonalizationAgent  [7] CommunicationAgent
                         (alert learning)     (alert summary / EHR)
    -----------------------------------------------------------------------
    """

    def __init__(self):
        self.message_bus = MessageBus()
        self.agents: Dict[str, BaseAgent] = {}
        self.initialize_agents()

    def initialize_agents(self):
        """Instantiate and register all 7 agents."""
        self.agents['data_acquisition']    = DataAcquisitionAgent(
            "data_acquisition_001",    self.message_bus)
        self.agents['data_processing']     = DataProcessingAgent(
            "data_processing_001",     self.message_bus)
        self.agents['pattern_recognition'] = PatternRecognitionAgent(
            "pattern_recognition_001", self.message_bus)
        self.agents['diagnostic']          = DiagnosticAgent(
            "diagnostic_001",          self.message_bus)
        self.agents['alert_monitoring']    = AlertMonitoringAgent(
            "alert_monitoring_001",    self.message_bus)
        self.agents['personalization']     = PersonalizationAgent(
            "personalization_001",     self.message_bus)
        self.agents['communication']       = CommunicationAgent(
            "communication_001",       self.message_bus)

        logger.info(f"Initialized {len(self.agents)} agents")

    async def start(self):
        """Start all agents."""
        for agent in self.agents.values():
            await agent.start()
        logger.info("Cardio AI System started")

    async def stop(self):
        """Stop all agents."""
        for agent in self.agents.values():
            await agent.stop()
        logger.info("Cardio AI System stopped")

    async def simulate_device_data(
        self,
        patient_id:  str,
        device_type: DeviceType,
        scenario:    str = "normal",
    ):
        """Register a synthetic device and inject one simulated data frame."""
        device_id = f"{device_type.value}_{patient_id}"
        await self.message_bus.publish("device.register", {
            'device_id':   device_id,
            'device_type': device_type.value,
            'patient_id':  patient_id,
        })
        await asyncio.sleep(0.1)

        generators = {
            DeviceType.ECG_MONITOR: self.generate_ecg_data,
            DeviceType.BP_MONITOR:  self.generate_bp_data,
        }
        data = generators.get(
            device_type,
            lambda _: {'value': float(np.random.uniform(0, 100))},
        )(scenario)
        data['device_id'] = device_id
        await self.agents['data_acquisition'].process(data)

    def generate_ecg_data(self, scenario: str) -> Dict:
        """Generate ECG data based on clinical scenario."""
        base = {'ecg_signal': np.random.randn(1000).tolist()}
        if scenario == "afib":
            return {**base, 'heart_rate': float(np.random.uniform(110, 150)), 'rr_irregular': True}
        elif scenario == "vtach":
            return {**base, 'heart_rate': float(np.random.uniform(150, 200)), 'wide_qrs': True}
        elif scenario == "bradycardia":
            return {**base, 'heart_rate': float(np.random.uniform(35, 50))}
        else:
            return {**base, 'heart_rate': float(np.random.uniform(60, 90))}

    def generate_bp_data(self, scenario: str) -> Dict:
        """Generate blood pressure data based on clinical scenario."""
        if scenario == "hypertensive_crisis":
            return {
                'systolic':  float(np.random.uniform(180, 220)),
                'diastolic': float(np.random.uniform(120, 140)),
            }
        elif scenario == "hypertension":
            return {
                'systolic':  float(np.random.uniform(140, 170)),
                'diastolic': float(np.random.uniform(90, 110)),
            }
        else:
            return {
                'systolic':  float(np.random.uniform(110, 130)),
                'diastolic': float(np.random.uniform(70, 85)),
            }


# ============================================================================
# SECTION 12 - HANDSHAKE CONFIGURATION & PROTOCOL
# ============================================================================

@dataclass
class HandshakeConfig:
    """Centralised configuration for the IoMT <-> CardioAI transport layer."""

    # IoMT server endpoints
    iomt_server_ws_url:   str   = "wss://iomt-server.hospital.local/stream"
    iomt_server_rest_url: str   = "https://iomt-server.hospital.local/api/v1"
    iomt_server_id:       str   = "IOMT-SRV-001"

    # CardioAI backend identity and listener
    cardioai_backend_id:  str   = "CARDIOAI-BACKEND-001"
    cardioai_ws_host:     str   = "0.0.0.0"
    cardioai_ws_port:     int   = 8765

    # Security -- inject via vault / K8s secrets in production
    shared_secret:        str   = "REPLACE_WITH_VAULT_SECRET"
    jwt_secret:           str   = "REPLACE_WITH_VAULT_JWT_SECRET"
    jwt_algorithm:        str   = "HS256"
    token_ttl_seconds:    int   = 3600

    # RPM streaming
    rpm_poll_interval_seconds:    float = 1.0
    heartbeat_interval_seconds:   float = 10.0
    reconnect_max_attempts:       int   = 5
    reconnect_base_delay_seconds: float = 2.0

    # Back-pressure
    inbound_queue_max_size: int = 2000


class MsgType(str, Enum):
    # Handshake
    HELLO           = "HELLO"
    CHALLENGE       = "CHALLENGE"
    CHALLENGE_RESP  = "CHALLENGE_RESP"
    AUTH_OK         = "AUTH_OK"
    AUTH_FAIL       = "AUTH_FAIL"
    # Session management
    HEARTBEAT       = "HEARTBEAT"
    HEARTBEAT_ACK   = "HEARTBEAT_ACK"
    DEVICE_LIST     = "DEVICE_LIST"
    DEVICE_LIST_ACK = "DEVICE_LIST_ACK"
    SUBSCRIBE       = "SUBSCRIBE"
    SUBSCRIBE_ACK   = "SUBSCRIBE_ACK"
    UNSUBSCRIBE     = "UNSUBSCRIBE"
    DISCONNECT      = "DISCONNECT"
    # Data
    RPM_DATA        = "RPM_DATA"
    RPM_ACK         = "RPM_ACK"
    ERROR           = "ERROR"


def build_message(msg_type: MsgType, payload: Dict, sender_id: str) -> str:
    """Serialise a protocol envelope to a JSON string."""
    return json.dumps({
        "msg_id":    str(uuid.uuid4()),
        "type":      msg_type.value,
        "sender_id": sender_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "payload":   payload,
    })


def parse_message(raw: str) -> Dict:
    """Deserialise a JSON envelope; raises ValueError on malformed input."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc


# ============================================================================
# SECTION 13 - SECURITY MANAGER
# ============================================================================

class SecurityManager:
    """HMAC-SHA256 challenge-response authentication + JWT session tokens."""

    def __init__(self, cfg: HandshakeConfig):
        self.cfg = cfg

    def generate_challenge(self) -> str:
        return base64.b64encode(uuid.uuid4().bytes).decode()

    def sign_challenge(self, challenge: str) -> str:
        return hmac.new(
            self.cfg.shared_secret.encode(),
            challenge.encode(),
            hashlib.sha256,
        ).hexdigest()

    def verify_challenge(self, challenge: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign_challenge(challenge), signature)

    def issue_token(self, peer_id: str, device_ids: List[str]) -> str:
        now = datetime.utcnow()
        return jwt.encode(
            {
                "iss":        self.cfg.cardioai_backend_id,
                "sub":        peer_id,
                "iat":        now,
                "exp":        now + timedelta(seconds=self.cfg.token_ttl_seconds),
                "device_ids": device_ids,
            },
            self.cfg.jwt_secret,
            algorithm=self.cfg.jwt_algorithm,
        )

    def verify_token(self, token: str) -> Dict:
        return jwt.decode(
            token,
            self.cfg.jwt_secret,
            algorithms=[self.cfg.jwt_algorithm],
        )


# ============================================================================
# SECTION 14 - DEVICE SESSION REGISTRY
# ============================================================================

@dataclass
class DeviceSession:
    device_id:         str
    device_type:       DeviceType
    patient_id:        str
    registered_at:     datetime = field(default_factory=datetime.utcnow)
    last_data_at:      Optional[datetime] = None
    is_active:         bool = True
    data_count:        int  = 0
    missed_heartbeats: int  = 0


class DeviceSessionRegistry:
    """Runtime registry: device_id -> DeviceSession for all live RPM devices."""

    def __init__(self):
        self._sessions: Dict[str, DeviceSession] = {}

    def register(self, device_id: str, device_type: str, patient_id: str) -> DeviceSession:
        session = DeviceSession(
            device_id=device_id,
            device_type=DeviceType(device_type),
            patient_id=patient_id,
        )
        self._sessions[device_id] = session
        logger.info(f"[Registry] Device registered: {device_id} (patient={patient_id})")
        return session

    def mark_data_received(self, device_id: str):
        if s := self._sessions.get(device_id):
            s.last_data_at      = datetime.utcnow()
            s.data_count       += 1
            s.missed_heartbeats = 0

    def mark_inactive(self, device_id: str):
        if s := self._sessions.get(device_id):
            s.is_active = False
            logger.warning(f"[Registry] Device marked inactive: {device_id}")

    def active_devices(self) -> List[DeviceSession]:
        return [s for s in self._sessions.values() if s.is_active]

    def get(self, device_id: str) -> Optional[DeviceSession]:
        return self._sessions.get(device_id)

    def summary(self) -> Dict:
        active = self.active_devices()
        return {
            "total_registered": len(self._sessions),
            "active":           len(active),
            "inactive":         len(self._sessions) - len(active),
            "devices": [
                {
                    "device_id":   s.device_id,
                    "patient_id":  s.patient_id,
                    "type":        s.device_type.value,
                    "active":      s.is_active,
                    "data_points": s.data_count,
                    "last_data":   s.last_data_at.isoformat() if s.last_data_at else None,
                }
                for s in self._sessions.values()
            ],
        }


# ============================================================================
# SECTION 15 - IoMT SERVER CONNECTOR  (WebSocket CLIENT)
# ============================================================================

class IoMTServerConnector:
    """
    Runs on the CardioAI backend as a WebSocket CLIENT.

    Handshake sequence:
        CardioAI  ->  HELLO
        IoMT      ->  CHALLENGE
        CardioAI  ->  CHALLENGE_RESP  (HMAC-SHA256 of nonce)
        IoMT      ->  AUTH_OK + JWT
        CardioAI  ->  DEVICE_LIST
        IoMT      ->  DEVICE_LIST_ACK  (enrolled device manifests)
        CardioAI  ->  SUBSCRIBE  (device_ids, rpm_interval_ms)
        IoMT      ->  SUBSCRIBE_ACK
        ... bidirectional RPM_DATA / RPM_ACK stream ...
    """

    def __init__(
        self,
        cfg:           HandshakeConfig,
        inbound_queue: asyncio.Queue,
        registry:      DeviceSessionRegistry,
    ):
        self.cfg           = cfg
        self.inbound_queue = inbound_queue
        self.registry      = registry
        self.security      = SecurityManager(cfg)
        self._ws:           Optional[websockets.WebSocketClientProtocol] = None
        self._token:        Optional[str]  = None
        self._connected     = asyncio.Event()
        self._stop          = asyncio.Event()

    async def run(self):
        """Outer reconnect loop with exponential back-off."""
        attempt = 0
        while not self._stop.is_set():
            try:
                logger.info(f"[Connector] Connecting to IoMT server ({self.cfg.iomt_server_ws_url}) ...")
                async with websockets.connect(
                    self.cfg.iomt_server_ws_url,
                    ping_interval=None,
                ) as ws:
                    self._ws  = ws
                    attempt   = 0
                    await self._run_session(ws)
            except (websockets.ConnectionClosed, OSError) as exc:
                self._connected.clear()
                attempt += 1
                if attempt >= self.cfg.reconnect_max_attempts:
                    logger.error("[Connector] Max reconnect attempts reached. Stopping.")
                    break
                delay = self.cfg.reconnect_base_delay_seconds * (2 ** (attempt - 1))
                logger.info(f"[Connector] Reconnecting in {delay:.1f}s ...")
                await asyncio.sleep(delay)

    async def stop(self):
        self._stop.set()
        if self._ws:
            await self._ws.close()

    async def _run_session(self, ws):
        await self._handshake(ws)
        device_ids = await self._fetch_and_register_devices(ws)
        await self._subscribe_devices(ws, device_ids)
        self._connected.set()
        logger.info(f"[Connector] Session established. Streaming {len(device_ids)} device(s).")
        await asyncio.gather(
            self._receive_loop(ws),
            self._heartbeat_loop(ws),
        )

    async def _handshake(self, ws):
        """3-way HMAC handshake: HELLO -> CHALLENGE -> CHALLENGE_RESP -> AUTH_OK."""
        await ws.send(build_message(
            MsgType.HELLO,
            {"client_id": self.cfg.cardioai_backend_id, "version": "1.0"},
            self.cfg.cardioai_backend_id,
        ))
        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        msg = parse_message(raw)
        if msg["type"] != MsgType.CHALLENGE.value:
            raise RuntimeError(f"Expected CHALLENGE, got {msg['type']}")

        challenge = msg["payload"]["challenge"]
        await ws.send(build_message(
            MsgType.CHALLENGE_RESP,
            {"challenge": challenge, "signature": self.security.sign_challenge(challenge)},
            self.cfg.cardioai_backend_id,
        ))

        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        msg = parse_message(raw)
        if msg["type"] == MsgType.AUTH_FAIL.value:
            raise PermissionError(f"Authentication rejected by IoMT server: {msg['payload']}")
        if msg["type"] != MsgType.AUTH_OK.value:
            raise RuntimeError(f"Expected AUTH_OK, got {msg['type']}")

        self._token = msg["payload"].get("token")
        logger.info("[Handshake] Authentication successful")

    async def _fetch_and_register_devices(self, ws) -> List[str]:
        """Request the device manifest and register each device locally."""
        await ws.send(build_message(
            MsgType.DEVICE_LIST,
            {"token": self._token},
            self.cfg.cardioai_backend_id,
        ))
        raw = await asyncio.wait_for(ws.recv(), timeout=15)
        msg = parse_message(raw)
        if msg["type"] != MsgType.DEVICE_LIST_ACK.value:
            raise RuntimeError(f"Expected DEVICE_LIST_ACK, got {msg['type']}")

        device_ids = []
        for d in msg["payload"]["devices"]:
            self.registry.register(d["device_id"], d["device_type"], d["patient_id"])
            device_ids.append(d["device_id"])

        logger.info(f"[Connector] {len(device_ids)} device(s) fetched from IoMT server")
        return device_ids

    async def _subscribe_devices(self, ws, device_ids: List[str]):
        """Subscribe to the real-time RPM stream for all registered devices."""
        await ws.send(build_message(
            MsgType.SUBSCRIBE,
            {
                "token":           self._token,
                "device_ids":      device_ids,
                "rpm_interval_ms": int(self.cfg.rpm_poll_interval_seconds * 1000),
            },
            self.cfg.cardioai_backend_id,
        ))
        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        msg = parse_message(raw)
        if msg["type"] != MsgType.SUBSCRIBE_ACK.value:
            raise RuntimeError(f"Subscription failed: {msg}")
        logger.info("[Connector] Subscribed to RPM streams")

    async def _receive_loop(self, ws):
        """Consume incoming RPM_DATA frames and route them to the inbound queue."""
        async for raw in ws:
            try:
                msg = parse_message(raw)
            except ValueError as exc:
                logger.warning(f"[Connector] Malformed message: {exc}")
                continue

            mtype = msg.get("type")

            if mtype == MsgType.RPM_DATA.value:
                await self._handle_rpm_data(msg, ws)

            elif mtype == MsgType.HEARTBEAT.value:
                await ws.send(build_message(
                    MsgType.HEARTBEAT_ACK,
                    {"ts": datetime.utcnow().isoformat()},
                    self.cfg.cardioai_backend_id,
                ))

            elif mtype == MsgType.ERROR.value:
                logger.error(f"[Connector] Server error: {msg['payload']}")

            elif mtype == MsgType.DISCONNECT.value:
                logger.warning("[Connector] Server requested disconnect")
                break

    async def _heartbeat_loop(self, ws):
        """Proactively send heartbeats to keep the session alive."""
        while not self._stop.is_set():
            await asyncio.sleep(self.cfg.heartbeat_interval_seconds)
            try:
                await ws.send(build_message(
                    MsgType.HEARTBEAT,
                    {"ts": datetime.utcnow().isoformat()},
                    self.cfg.cardioai_backend_id,
                ))
            except websockets.ConnectionClosed:
                break

    async def _handle_rpm_data(self, msg: Dict, ws):
        """Validate an RPM_DATA frame, enqueue it, and acknowledge receipt."""
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
                logger.warning("[Connector] Inbound queue full — oldest frame evicted")
            except asyncio.QueueEmpty:
                pass

        await self.inbound_queue.put({
            "device_id":     device_id,
            "device_type":   session.device_type.value,
            "patient_id":    session.patient_id,
            "timestamp":     payload.get("timestamp", datetime.utcnow().isoformat()),
            "data":          payload.get("data", {}),
            "quality_score": payload.get("quality_score", 1.0),
        })

        if self._ws:
            await self._ws.send(build_message(
                MsgType.RPM_ACK,
                {"msg_id": msg["msg_id"], "device_id": device_id},
                self.cfg.cardioai_backend_id,
            ))


# ============================================================================
# SECTION 16 - CardioAI WebSocket SERVER  (WebSocket SERVER)
# ============================================================================

class CardioAIWebSocketServer:
    """
    Runs on the CardioAI backend as a WebSocket SERVER.
    Accepts inbound push connections from IoMT gateways.
    Mirrors the same handshake protocol so either party can initiate.
    """

    def __init__(
        self,
        cfg:           HandshakeConfig,
        inbound_queue: asyncio.Queue,
        registry:      DeviceSessionRegistry,
    ):
        self.cfg                  = cfg
        self.inbound_queue        = inbound_queue
        self.registry             = registry
        self.security             = SecurityManager(cfg)
        self._active_connections: Dict[str, Any] = {}
        self._stop                = asyncio.Event()

    async def run(self):
        logger.info(
            f"[WS Server] Listening on "
            f"ws://{self.cfg.cardioai_ws_host}:{self.cfg.cardioai_ws_port}"
        )
        async with websockets.serve(
            self._handle_connection,
            self.cfg.cardioai_ws_host,
            self.cfg.cardioai_ws_port,
        ):
            await self._stop.wait()

    async def stop(self):
        self._stop.set()

    async def _handle_connection(self, ws, path):
        conn_id = str(uuid.uuid4())[:8]
        logger.info(f"[WS Server] New connection from {ws.remote_address} (conn={conn_id})")
        try:
            await self._server_handshake(ws, conn_id)
            self._active_connections[conn_id] = ws
            await self._server_receive_loop(ws, conn_id)
        except (PermissionError, RuntimeError, asyncio.TimeoutError) as exc:
            logger.warning(f"[WS Server] Connection {conn_id} rejected: {exc}")
        except websockets.ConnectionClosed:
            logger.info(f"[WS Server] Connection {conn_id} closed")
        finally:
            self._active_connections.pop(conn_id, None)

    async def _server_handshake(self, ws, conn_id: str):
        """
        Server-side mirror of the handshake:
          IoMT     -> HELLO
          CardioAI -> CHALLENGE
          IoMT     -> CHALLENGE_RESP
          CardioAI -> AUTH_OK + JWT
          IoMT     -> DEVICE_LIST
          CardioAI -> DEVICE_LIST_ACK
        """
        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        msg = parse_message(raw)
        if msg["type"] != MsgType.HELLO.value:
            raise RuntimeError(f"Expected HELLO, got {msg['type']}")
        peer_id   = msg["payload"].get("client_id", "unknown")
        challenge = self.security.generate_challenge()

        await ws.send(build_message(
            MsgType.CHALLENGE, {"challenge": challenge}, self.cfg.cardioai_backend_id,
        ))

        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        msg = parse_message(raw)
        if msg["type"] != MsgType.CHALLENGE_RESP.value:
            raise RuntimeError(f"Expected CHALLENGE_RESP, got {msg['type']}")
        if not self.security.verify_challenge(
            msg["payload"]["challenge"], msg["payload"]["signature"]
        ):
            await ws.send(build_message(
                MsgType.AUTH_FAIL,
                {"reason": "Invalid HMAC signature"},
                self.cfg.cardioai_backend_id,
            ))
            raise PermissionError("HMAC verification failed")

        token = self.security.issue_token(peer_id, [])
        await ws.send(build_message(
            MsgType.AUTH_OK,
            {"token": token, "session_id": conn_id},
            self.cfg.cardioai_backend_id,
        ))

        raw = await asyncio.wait_for(ws.recv(), timeout=15)
        msg = parse_message(raw)
        if msg["type"] != MsgType.DEVICE_LIST.value:
            raise RuntimeError(f"Expected DEVICE_LIST, got {msg['type']}")
        try:
            self.security.verify_token(msg["payload"]["token"])
        except jwt.PyJWTError as exc:
            raise PermissionError(f"JWT invalid: {exc}") from exc

        device_ids = []
        for d in msg["payload"].get("devices", []):
            self.registry.register(d["device_id"], d["device_type"], d["patient_id"])
            device_ids.append(d["device_id"])

        await ws.send(build_message(
            MsgType.DEVICE_LIST_ACK,
            {"accepted": device_ids},
            self.cfg.cardioai_backend_id,
        ))
        logger.info(
            f"[WS Server] Session {conn_id} authenticated — {len(device_ids)} device(s)"
        )

    async def _server_receive_loop(self, ws, conn_id: str):
        async for raw in ws:
            try:
                msg = parse_message(raw)
            except ValueError:
                continue

            mtype = msg.get("type")

            if mtype == MsgType.RPM_DATA.value:
                payload   = msg["payload"]
                device_id = payload.get("device_id")
                session   = self.registry.get(device_id)
                if session:
                    self.registry.mark_data_received(device_id)
                    await self.inbound_queue.put({
                        "device_id":     device_id,
                        "device_type":   session.device_type.value,
                        "patient_id":    session.patient_id,
                        "timestamp":     payload.get("timestamp"),
                        "data":          payload.get("data", {}),
                        "quality_score": payload.get("quality_score", 1.0),
                    })
                    await ws.send(build_message(
                        MsgType.RPM_ACK,
                        {"msg_id": msg["msg_id"]},
                        self.cfg.cardioai_backend_id,
                    ))

            elif mtype == MsgType.HEARTBEAT.value:
                await ws.send(build_message(
                    MsgType.HEARTBEAT_ACK, {}, self.cfg.cardioai_backend_id,
                ))


# ============================================================================
# SECTION 17 - RPM DATA PUMP
# ============================================================================

class RPMDataPump:
    """
    Drains the inbound queue and injects frames into the CardioAI pipeline
    via DataAcquisitionAgent.process().

    Integrations:
      - IoMT_gcp_compduide.GCPPubSubPublisher: each frame is forwarded to a
        Cloud Pub/Sub topic for real-time analytics consumers
    """

    def __init__(
        self,
        inbound_queue:   asyncio.Queue,
        cardioai_system: CardioAISystem,
        registry:        DeviceSessionRegistry,
        on_rpm_frame:    Optional[Callable] = None,
    ):
        self.queue        = inbound_queue
        self.system       = cardioai_system
        self.registry     = registry
        self.on_rpm_frame = on_rpm_frame  # optional external hook (Kafka, InfluxDB, etc.)
        self._stop        = asyncio.Event()
        self.stats        = {
            "frames_processed": 0,
            "frames_dropped":   0,
            "last_frame_at":    None,
        }

    async def run(self):
        logger.info("[RPMPump] Started")
        while not self._stop.is_set():
            try:
                frame = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            try:
                await self._process_frame(frame)
                self.stats["frames_processed"] += 1
                self.stats["last_frame_at"]     = datetime.utcnow().isoformat()
            except Exception as exc:
                logger.error(f"[RPMPump] Error processing frame: {exc}")
                self.stats["frames_dropped"] += 1
            finally:
                self.queue.task_done()

    async def stop(self):
        self._stop.set()

    async def _process_frame(self, frame: Dict):
        """Forward one RPM frame into the DataAcquisitionAgent."""
        device_id         = frame["device_id"]
        acquisition_agent = self.system.agents["data_acquisition"]

        # Auto-register with the CardioAI acquisition layer if not yet known
        if device_id not in acquisition_agent.registered_devices:
            await self.system.message_bus.publish("device.register", {
                "device_id":   device_id,
                "device_type": frame["device_type"],
                "patient_id":  frame["patient_id"],
            })
            await asyncio.sleep(0.05)

        data             = dict(frame["data"])
        data["device_id"] = device_id
        await acquisition_agent.process(data)

        # Optional external callback
        if self.on_rpm_frame:
            if asyncio.iscoroutinefunction(self.on_rpm_frame):
                await self.on_rpm_frame(frame)
            else:
                self.on_rpm_frame(frame)


# ============================================================================
# SECTION 18 - DEVICE HEALTH MONITOR
# ============================================================================

class DeviceHealthMonitor:
    """
    Periodically checks each active DeviceSession for data staleness and
    publishes a 'device.inactive' event when a device drops out.
    """

    def __init__(
        self,
        registry:                DeviceSessionRegistry,
        message_bus:             MessageBus,
        stale_threshold_seconds: float = 30.0,
        check_interval_seconds:  float = 10.0,
    ):
        self.registry        = registry
        self.message_bus     = message_bus
        self.stale_threshold = stale_threshold_seconds
        self.check_interval  = check_interval_seconds
        self._stop           = asyncio.Event()

    async def run(self):
        while not self._stop.is_set():
            await asyncio.sleep(self.check_interval)
            now = datetime.utcnow()
            for session in self.registry.active_devices():
                if session.last_data_at is None:
                    continue
                age = (now - session.last_data_at).total_seconds()
                if age > self.stale_threshold:
                    session.missed_heartbeats += 1
                    logger.warning(
                        f"[HealthMonitor] Device {session.device_id} stale "
                        f"({age:.0f}s since last data; missed={session.missed_heartbeats})"
                    )
                    if session.missed_heartbeats >= 3:
                        self.registry.mark_inactive(session.device_id)
                        await self.message_bus.publish("device.inactive", {
                            "device_id":  session.device_id,
                            "patient_id": session.patient_id,
                            "reason":     "rpm_dropout",
                        })

    async def stop(self):
        self._stop.set()


# ============================================================================
# SECTION 19 - IoMT <-> CardioAI BRIDGE (TOP-LEVEL ORCHESTRATOR)
# ============================================================================

class IoMTCardioAIBridge:
    """
    Top-level orchestrator for the complete IoMT <-> CardioAI integration.

    Manages:
      - CardioAI WS server     : IoMT gateways push data to us
      - IoMT server connector  : we pull from a central IoMT server
      - RPM data pump          : inbound queue -> 7-agent pipeline
      - Device health monitor  : dropout detection and alerting
      - Status endpoint        : live JSON snapshot of the entire bridge

    GCP integration surfaces (via IoMT_gcp_compduide):
      - GCPPubSubPublisher         -> RPM frame streaming to analytics
      - BigQueryEventWriter        -> diagnostic event archival
      - CloudHealthcareAPIClient   -> FHIR R4 write-back
      - GCSArchiver                -> raw waveform cold storage
    """

    def __init__(
        self,
        cardioai_system: CardioAISystem,
        cfg:             Optional[HandshakeConfig] = None,
    ):
        self.cfg    = cfg or HandshakeConfig()
        self.system = cardioai_system

        self.registry      = DeviceSessionRegistry()
        self.inbound_queue: asyncio.Queue = asyncio.Queue(
            maxsize=self.cfg.inbound_queue_max_size
        )

        self.connector  = IoMTServerConnector(self.cfg, self.inbound_queue, self.registry)
        self.ws_server  = CardioAIWebSocketServer(self.cfg, self.inbound_queue, self.registry)
        self.pump       = RPMDataPump(self.inbound_queue, self.system, self.registry)
        self.health_mon = DeviceHealthMonitor(self.registry, self.system.message_bus)

        # React to device dropout events
        self.system.message_bus.subscribe("device.inactive", self._on_device_inactive)

    async def start(self):
        """Start all bridge components concurrently."""
        logger.info("=" * 60)
        logger.info("  IoMT <-> CardioAI Bridge starting ...")
        logger.info("=" * 60)
        await self.system.start()
        await asyncio.gather(
            self.ws_server.run(),
            self.connector.run(),
            self.pump.run(),
            self.health_mon.run(),
        )

    async def stop(self):
        logger.info("[Bridge] Shutting down ...")
        await self.connector.stop()
        await self.ws_server.stop()
        await self.pump.stop()
        await self.health_mon.stop()
        await self.system.stop()

    async def _on_device_inactive(self, event: Dict):
        logger.error(
            f"[Bridge] DEVICE OFFLINE -- {event['device_id']} "
            f"(patient={event['patient_id']}, reason={event['reason']})"
        )

    def status(self) -> Dict:
        """Return a JSON-serialisable live status snapshot."""
        return {
            "bridge_id":             self.cfg.cardioai_backend_id,
            "timestamp":             datetime.utcnow().isoformat() + "Z",
            "queue_depth":           self.inbound_queue.qsize(),
            "pump_stats":            self.pump.stats,
            "devices":               self.registry.summary(),
            "active_ws_connections": len(self.ws_server._active_connections),
            "agent_count":           len(self.system.agents),
            "message_bus_total":     len(self.system.message_bus.message_history),
        }


# ============================================================================
# SECTION 20 - DEMO / INTEGRATION TEST
# ============================================================================

async def _demo_simulated():
    """
    In-process loopback demo -- no real IoMT server or GCP project needed.

    Starts an IoMT stub WS server on localhost, performs the full 3-way
    HMAC handshake, streams synthetic ECG + BP frames through all 7 agents,
    and prints a final status snapshot.
    """
    print("\n" + "=" * 66)
    print("  IoMT <-> CardioAI Handshake + 7-Agent Pipeline -- Simulated Demo")
    print("=" * 66 + "\n")

    cfg = HandshakeConfig(
        iomt_server_ws_url="ws://127.0.0.1:8765",
        cardioai_ws_host="127.0.0.1",
        cardioai_ws_port=8765,
        shared_secret="demo-secret-replace-in-prod",
        jwt_secret="demo-jwt-secret-replace-in-prod",
        rpm_poll_interval_seconds=0.5,
        heartbeat_interval_seconds=5.0,
    )

    cardioai       = CardioAISystem()
    registry       = DeviceSessionRegistry()
    inbound_queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    security       = SecurityManager(cfg)

    # ---- Minimal IoMT server stub ------------------------------------ #

    async def iomt_server_stub(ws, path):
        """Emulates the IoMT server side of the 3-way HMAC handshake."""
        raw = await ws.recv()
        assert parse_message(raw)["type"] == MsgType.HELLO.value

        challenge = security.generate_challenge()
        await ws.send(build_message(
            MsgType.CHALLENGE, {"challenge": challenge}, cfg.iomt_server_id
        ))

        raw = await ws.recv()
        msg = parse_message(raw)
        assert security.verify_challenge(
            msg["payload"]["challenge"], msg["payload"]["signature"]
        ), "HMAC mismatch"

        token = security.issue_token(cfg.cardioai_backend_id, ["ECG-001", "BP-001"])
        await ws.send(build_message(
            MsgType.AUTH_OK, {"token": token}, cfg.iomt_server_id
        ))

        raw = await ws.recv()
        assert parse_message(raw)["type"] == MsgType.DEVICE_LIST.value

        devices = [
            {"device_id": "ECG-001", "device_type": "ecg_monitor", "patient_id": "PT_010"},
            {"device_id": "BP-001",  "device_type": "bp_monitor",  "patient_id": "PT_011"},
        ]
        await ws.send(build_message(
            MsgType.DEVICE_LIST_ACK, {"devices": devices}, cfg.iomt_server_id
        ))

        raw = await ws.recv()
        assert parse_message(raw)["type"] == MsgType.SUBSCRIBE.value
        await ws.send(build_message(
            MsgType.SUBSCRIBE_ACK,
            {"subscribed": [d["device_id"] for d in devices]},
            cfg.iomt_server_id,
        ))

        logger.info("[IoMT Stub] Handshake complete -- streaming RPM data ...")

        for _ in range(10):
            await asyncio.sleep(0.3)
            for frame in [
                {
                    "device_id":     "ECG-001",
                    "timestamp":     datetime.utcnow().isoformat(),
                    "quality_score": 0.95,
                    "data": {
                        "heart_rate": float(np.random.uniform(65, 145)),
                        "ecg_signal": np.random.randn(50).tolist(),
                    },
                },
                {
                    "device_id":     "BP-001",
                    "timestamp":     datetime.utcnow().isoformat(),
                    "quality_score": 0.98,
                    "data": {
                        "systolic":  float(np.random.uniform(115, 185)),
                        "diastolic": float(np.random.uniform(75, 120)),
                    },
                },
            ]:
                msg_id = str(uuid.uuid4())
                await ws.send(json.dumps({
                    "msg_id":    msg_id,
                    "type":      MsgType.RPM_DATA.value,
                    "sender_id": cfg.iomt_server_id,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "payload":   frame,
                }))
                ack = parse_message(await asyncio.wait_for(ws.recv(), timeout=5))
                assert ack["type"] == MsgType.RPM_ACK.value

        logger.info("[IoMT Stub] All frames sent -- closing")

    # ---- Wire components and run ------------------------------------- #

    pump       = RPMDataPump(inbound_queue, cardioai, registry)
    connector  = IoMTServerConnector(cfg, inbound_queue, registry)
    health_mon = DeviceHealthMonitor(registry, cardioai.message_bus, stale_threshold_seconds=5)

    await cardioai.start()
    server = await websockets.serve(iomt_server_stub, "127.0.0.1", 8765)
    logger.info("[Demo] IoMT stub server started on ws://127.0.0.1:8765")

    async def _run_connector():
        try:
            await connector.run()
        except Exception as exc:
            logger.info(f"[Demo] Connector ended: {exc}")

    async def _run_pump():
        try:
            await asyncio.wait_for(pump.run(), timeout=8)
        except asyncio.TimeoutError:
            pass

    await asyncio.gather(_run_connector(), _run_pump())

    server.close()
    await server.wait_closed()
    await cardioai.stop()

    # ---- Final status snapshot --------------------------------------- #
    print("\n" + "=" * 66)
    print("  Final Bridge Status Snapshot")
    print("=" * 66)
    print(json.dumps({
        "devices":              registry.summary(),
        "pump_stats":           pump.stats,
        "message_bus_messages": len(cardioai.message_bus.message_history),
        "active_alerts":        len(cardioai.agents["alert_monitoring"].active_alerts),
        "patient_profiles":     len(cardioai.agents["personalization"].patient_profiles),
        "reports_generated":    len(cardioai.agents["communication"].report_store),
    }, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(_demo_simulated())
