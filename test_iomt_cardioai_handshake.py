"""
test_iomt_cardioai_handshake.py
=================================
Pytest suite for iomt_cardioai_handshake.py

Covers:
  - Data models (DeviceData, ProcessedSignal, DiagnosticResult, Alert)
  - MessageBus  (subscribe, publish, multi-subscriber, error isolation)
  - BaseAgent   (start / stop lifecycle)
  - Agent 1 - DataAcquisitionAgent
  - Agent 2 - DataProcessingAgent (ECG, BP, SpO2, generic, quality gate)
  - Agent 3 - PatternRecognitionAgent (arrhythmia classifier, BP staging)
  - Agent 4 - DiagnosticAgent (risk scores, recommendations, interpretation)
  - Agent 5 - AlertMonitoringAgent (triage logic, action lists, notification)
  - Agent 6 - PersonalizationAgent (baseline updates, alert learning)
  - Agent 7 - CommunicationAgent (summaries, report store)
  - CardioAISystem coordinator (init, start/stop, 7-agent wiring, simulation)
  - HandshakeConfig defaults and overrides
  - SecurityManager (HMAC challenge, JWT issue/verify, replay protection)
  - build_message / parse_message protocol helpers
  - DeviceSessionRegistry (register, mark_data_received, mark_inactive, summary)
  - RPMDataPump (frame injection, auto-registration, stats, back-pressure)
  - DeviceHealthMonitor (stale detection, inactive publication)
  - End-to-end pipeline: ECG frame -> alert generation
  - End-to-end pipeline: BP frame -> hypertensive crisis alert
  - End-to-end WebSocket handshake (full 3-way HMAC loopback)

Run:
    pytest test_iomt_cardioai_handshake.py -v
    pytest test_iomt_cardioai_handshake.py -v --tb=short -q   # quiet mode
"""

import asyncio
import json
import sys
import os
import uuid
import types
from datetime import datetime, timedelta
from typing import Dict, List
from unittest.mock import MagicMock

import numpy as np
import pytest
import jwt

# ---------------------------------------------------------------------------
# PATH SETUP  –  resolve the outputs directory relative to this file
# ---------------------------------------------------------------------------

OUTPUTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "user-data", "outputs",
)
sys.path.insert(0, os.path.abspath(OUTPUTS_DIR))


# ---------------------------------------------------------------------------
# STUB the three proprietary external modules so imports succeed in CI/CD
# ---------------------------------------------------------------------------

def _make_stub(module_name: str, names: List[str]):
    mod = types.ModuleType(module_name)
    for name in names:
        setattr(mod, name, MagicMock())
    sys.modules[module_name] = mod


_make_stub("IoMT_implementation", [
    "IoMTDeviceDriver", "SensorTransportEncoder",
    "DeviceCapabilityRegistry", "FirmwareAbstractionLayer", "RawSensorFrame",
])
_make_stub("IoMT_clinical_workflow", [
    "ClinicalDecisionEngine", "CarePathwayRouter", "EHRConnector",
    "CDSSAlert", "ClinicalWorkflowConfig",
])
_make_stub("IoMT_gcp_compduide", [
    "GCPPubSubPublisher", "BigQueryEventWriter", "CloudHealthcareAPIClient",
    "GCSArchiver", "HealthcareDatasetClient", "GCPConfig",
])

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------

from iomt_cardioai_handshake import (   # noqa: E402
    DeviceType, AlertLevel, ArrhythmiaType,
    DeviceData, ProcessedSignal, DiagnosticResult, Alert,
    MessageBus,
    DataAcquisitionAgent,
    DataProcessingAgent,
    PatternRecognitionAgent,
    DiagnosticAgent,
    AlertMonitoringAgent,
    PersonalizationAgent,
    CommunicationAgent,
    CardioAISystem,
    HandshakeConfig, MsgType, build_message, parse_message,
    SecurityManager,
    DeviceSession, DeviceSessionRegistry,
    RPMDataPump, DeviceHealthMonitor,
    IoMTServerConnector,
)


# ===========================================================================
# SHARED FIXTURES & FACTORIES
# ===========================================================================

@pytest.fixture
def cfg() -> HandshakeConfig:
    return HandshakeConfig(
        shared_secret="test-secret-abc",
        jwt_secret="test-jwt-secret-xyz",
        token_ttl_seconds=3600,
        cardioai_backend_id="TEST-BACKEND",
        iomt_server_id="TEST-IOMT",
        reconnect_max_attempts=2,
        reconnect_base_delay_seconds=0.01,
        heartbeat_interval_seconds=0.1,
        rpm_poll_interval_seconds=0.1,
    )


@pytest.fixture
def security(cfg):
    return SecurityManager(cfg)


@pytest.fixture
def bus():
    return MessageBus()


@pytest.fixture
def registry():
    return DeviceSessionRegistry()


@pytest.fixture
def cardioai():
    return CardioAISystem()


def make_device_data(
    device_type: DeviceType = DeviceType.ECG_MONITOR,
    patient_id:  str        = "PT_001",
    data:        Dict       = None,
    quality:     float      = 1.0,
) -> DeviceData:
    return DeviceData(
        device_id    = f"{device_type.value}_PT_001",
        device_type  = device_type,
        patient_id   = patient_id,
        timestamp    = datetime.now(),
        data         = data or {"heart_rate": 72, "ecg_signal": [0.1] * 50},
        quality_score= quality,
    )


def make_ecg_signal(
    heart_rate: float = 72,
    rr_std:     float = 30,
    qrs:        float = 100,
    qt:         float = 400,
    st:         float = 0.0,
    patient_id: str   = "PT_001",
) -> ProcessedSignal:
    return ProcessedSignal(
        patient_id      = patient_id,
        signal_type     = "ecg",
        timestamp       = datetime.now(),
        features        = {
            "heart_rate":       heart_rate,
            "rr_interval_mean": 60000 / heart_rate,
            "rr_interval_std":  rr_std,
            "qt_interval":      qt,
            "pr_interval":      160.0,
            "qrs_duration":     qrs,
            "st_elevation":     st,
            "hrv_rmssd":        35.0,
        },
        raw_data        = np.array([]),
        quality_metrics = {"snr": 28.0},
    )


def make_bp_signal(systolic: float = 120, diastolic: float = 80) -> ProcessedSignal:
    return ProcessedSignal(
        patient_id      = "PT_001",
        signal_type     = "blood_pressure",
        timestamp       = datetime.now(),
        features        = {
            "systolic":       systolic,
            "diastolic":      diastolic,
            "map":            (systolic + 2 * diastolic) / 3,
            "pulse_pressure": systolic - diastolic,
        },
        raw_data        = np.array([]),
        quality_metrics = {"accuracy": 1.0},
    )


def make_diagnostic_result(
    arrhythmia: ArrhythmiaType = ArrhythmiaType.NORMAL_SINUS,
    risk_scores: Dict          = None,
    supporting:  Dict          = None,
) -> DiagnosticResult:
    return DiagnosticResult(
        patient_id      = "PT_001",
        timestamp       = datetime.now(),
        diagnosis       = "Test diagnosis",
        confidence      = 0.92,
        arrhythmia_type = arrhythmia,
        risk_scores     = risk_scores or {
            "ascvd_10year": 0.10,
            "heart_failure": 0.05,
            "stroke": 0.05,
            "sudden_cardiac_death": 0.02,
        },
        recommendations = [],
        supporting_data = supporting or {},
    )


# ===========================================================================
# 1. DATA MODEL TESTS
# ===========================================================================

class TestDataModels:

    def test_device_data_default_quality(self):
        dd = DeviceData(
            device_id="ECG-1", device_type=DeviceType.ECG_MONITOR,
            patient_id="PT_X", timestamp=datetime.now(), data={},
        )
        assert dd.quality_score == 1.0

    def test_alert_notified_parties_starts_empty(self):
        alert = Alert(
            alert_id="A1", patient_id="PT_X", timestamp=datetime.now(),
            level=AlertLevel.HIGH, title="Test", description="Desc",
            diagnostic_result=make_diagnostic_result(),
            actions_required=["ACT"],
        )
        assert alert.notified_parties == []

    def test_device_type_enum_values(self):
        assert DeviceType.ECG_MONITOR.value  == "ecg_monitor"
        assert DeviceType.BP_MONITOR.value   == "bp_monitor"
        assert DeviceType.PULSE_OXIMETER.value == "pulse_oximeter"

    def test_alert_level_enum_values(self):
        assert AlertLevel.CRITICAL.value == "critical"
        assert AlertLevel.HIGH.value     == "high"
        assert AlertLevel.MEDIUM.value   == "medium"
        assert AlertLevel.LOW.value      == "low"

    def test_all_arrhythmia_types_present(self):
        values = {e.value for e in ArrhythmiaType}
        for expected in ("atrial_fibrillation", "ventricular_tachycardia",
                         "ventricular_fibrillation", "normal_sinus", "bradycardia"):
            assert expected in values


# ===========================================================================
# 2. MESSAGE BUS TESTS
# ===========================================================================

class TestMessageBus:

    @pytest.mark.asyncio
    async def test_subscribe_and_receive(self, bus):
        received = []
        bus.subscribe("topic.a", lambda msg: received.append(msg))
        await bus.publish("topic.a", "hello")
        assert received == ["hello"]

    @pytest.mark.asyncio
    async def test_async_subscriber(self, bus):
        received = []
        async def async_cb(msg):
            received.append(msg)
        bus.subscribe("topic.b", async_cb)
        await bus.publish("topic.b", 42)
        assert received == [42]

    @pytest.mark.asyncio
    async def test_multiple_subscribers_same_topic(self, bus):
        results = []
        bus.subscribe("topic.c", lambda m: results.append(f"A:{m}"))
        bus.subscribe("topic.c", lambda m: results.append(f"B:{m}"))
        await bus.publish("topic.c", "ping")
        assert "A:ping" in results
        assert "B:ping" in results

    @pytest.mark.asyncio
    async def test_no_bleed_between_topics(self, bus):
        received = []
        bus.subscribe("topic.d", lambda m: received.append(m))
        await bus.publish("topic.e", "stray")
        assert received == []

    @pytest.mark.asyncio
    async def test_message_history_appended(self, bus):
        await bus.publish("hist.topic", {"key": "val"})
        assert len(bus.message_history) == 1
        assert bus.message_history[0]["topic"] == "hist.topic"

    @pytest.mark.asyncio
    async def test_subscriber_exception_does_not_crash_bus(self, bus):
        """A faulty subscriber must not prevent other subscribers from running."""
        def bad_cb(m):
            raise RuntimeError("deliberate failure")
        good_cb = []
        bus.subscribe("err.topic", bad_cb)
        bus.subscribe("err.topic", lambda m: good_cb.append(m))
        await bus.publish("err.topic", "test")
        assert good_cb == ["test"]

    @pytest.mark.asyncio
    async def test_publish_to_topic_with_no_subscribers(self, bus):
        # Should not raise
        await bus.publish("empty.topic", "data")
        assert len(bus.message_history) == 1


# ===========================================================================
# 3. BASE AGENT TESTS
# ===========================================================================

class TestBaseAgent:

    @pytest.mark.asyncio
    async def test_start_sets_running_true(self, bus):
        agent = DataAcquisitionAgent("acq-001", bus)
        assert not agent.is_running
        await agent.start()
        assert agent.is_running

    @pytest.mark.asyncio
    async def test_stop_sets_running_false(self, bus):
        agent = DataAcquisitionAgent("acq-001", bus)
        await agent.start()
        await agent.stop()
        assert not agent.is_running

    def test_agent_id_stored(self, bus):
        agent = DataAcquisitionAgent("my-unique-id", bus)
        assert agent.agent_id == "my-unique-id"


# ===========================================================================
# 4. DATA ACQUISITION AGENT TESTS
# ===========================================================================

class TestDataAcquisitionAgent:

    @pytest.fixture
    def agent(self, bus):
        return DataAcquisitionAgent("acq-test", bus)

    @pytest.mark.asyncio
    async def test_register_device_stores_entry(self, agent):
        await agent.register_device({
            "device_id": "ECG-01", "device_type": "ecg_monitor", "patient_id": "PT_A",
        })
        assert "ECG-01" in agent.registered_devices
        assert agent.registered_devices["ECG-01"]["patient_id"] == "PT_A"

    @pytest.mark.asyncio
    async def test_register_creates_stream_queue(self, agent):
        await agent.register_device({
            "device_id": "BP-01", "device_type": "bp_monitor", "patient_id": "PT_B",
        })
        assert "BP-01" in agent.device_streams
        assert isinstance(agent.device_streams["BP-01"], asyncio.Queue)

    @pytest.mark.asyncio
    async def test_register_publishes_device_registered(self, agent, bus):
        published = []
        bus.subscribe("device.registered", lambda m: published.append(m))
        await agent.register_device({
            "device_id": "SPO-01", "device_type": "pulse_oximeter", "patient_id": "PT_C",
        })
        assert len(published) == 1
        assert published[0]["device_id"] == "SPO-01"

    @pytest.mark.asyncio
    async def test_stream_data_unknown_device_silent(self, agent, bus):
        published = []
        bus.subscribe("data.raw", lambda m: published.append(m))
        await agent.stream_data("UNKNOWN-DEVICE", {"hr": 72})
        assert published == []

    @pytest.mark.asyncio
    async def test_stream_data_publishes_data_raw(self, agent, bus):
        published = []
        bus.subscribe("data.raw", lambda m: published.append(m))
        await agent.register_device({
            "device_id": "ECG-02", "device_type": "ecg_monitor", "patient_id": "PT_D",
        })
        await agent.stream_data("ECG-02", {"heart_rate": 80})
        assert len(published) == 1
        assert isinstance(published[0], DeviceData)
        assert published[0].patient_id == "PT_D"

    @pytest.mark.asyncio
    async def test_stream_data_updates_last_seen(self, agent):
        await agent.register_device({
            "device_id": "ECG-03", "device_type": "ecg_monitor", "patient_id": "PT_E",
        })
        before = agent.registered_devices["ECG-03"]["last_seen"]
        await asyncio.sleep(0.01)
        await agent.stream_data("ECG-03", {"heart_rate": 75})
        after = agent.registered_devices["ECG-03"]["last_seen"]
        assert after >= before

    # ---- validate_data_quality ----

    def test_quality_normal_data(self, agent):
        assert agent.validate_data_quality({"heart_rate": 72, "spo2": 98}) == 1.0

    def test_quality_penalises_none_value(self, agent):
        assert agent.validate_data_quality({"heart_rate": None}) < 1.0

    def test_quality_penalises_extreme_hr_high(self, agent):
        assert agent.validate_data_quality({"heart_rate": 300}) < 1.0

    def test_quality_penalises_extreme_hr_low(self, agent):
        assert agent.validate_data_quality({"heart_rate": 20}) < 1.0

    def test_quality_boundary_hr_exactly_30(self, agent):
        assert agent.validate_data_quality({"heart_rate": 30}) == 1.0

    def test_quality_boundary_hr_exactly_250(self, agent):
        assert agent.validate_data_quality({"heart_rate": 250}) == 1.0

    @pytest.mark.asyncio
    async def test_process_dispatches_stream(self, agent, bus):
        published = []
        bus.subscribe("data.raw", lambda m: published.append(m))
        await agent.register_device({
            "device_id": "ECG-10", "device_type": "ecg_monitor", "patient_id": "PT_F",
        })
        await agent.process({"device_id": "ECG-10", "heart_rate": 75})
        assert len(published) == 1

    @pytest.mark.asyncio
    async def test_process_ignores_non_dict(self, agent, bus):
        published = []
        bus.subscribe("data.raw", lambda m: published.append(m))
        await agent.process("not-a-dict")
        assert published == []

    @pytest.mark.asyncio
    async def test_bus_device_register_topic_triggers_register(self, bus):
        agent = DataAcquisitionAgent("acq-bus-test", bus)
        await bus.publish("device.register", {
            "device_id": "AUTO-01", "device_type": "ecg_monitor", "patient_id": "PT_Z",
        })
        assert "AUTO-01" in agent.registered_devices


# ===========================================================================
# 5. DATA PROCESSING AGENT TESTS
# ===========================================================================

class TestDataProcessingAgent:

    @pytest.fixture
    def agent(self, bus):
        return DataProcessingAgent("proc-test", bus)

    @pytest.mark.asyncio
    async def test_low_quality_dropped(self, agent, bus):
        published = []
        bus.subscribe("data.processed", lambda m: published.append(m))
        result = await agent.process(make_device_data(quality=0.5))
        assert result is None
        assert published == []

    @pytest.mark.asyncio
    async def test_quality_threshold_boundary_accepted(self, agent):
        result = await agent.process(make_device_data(quality=0.6))
        assert result is not None

    @pytest.mark.asyncio
    async def test_ecg_signal_type(self, agent):
        result = await agent.process_ecg(make_device_data(
            data={"heart_rate": 75, "ecg_signal": [0.1, 0.2]}
        ))
        assert result.signal_type == "ecg"

    @pytest.mark.asyncio
    async def test_ecg_features_populated(self, agent):
        result = await agent.process_ecg(make_device_data(
            data={"heart_rate": 80, "ecg_signal": []}
        ))
        for key in ("heart_rate", "qt_interval", "st_elevation", "qrs_duration"):
            assert key in result.features
        assert result.features["heart_rate"] == 80.0

    @pytest.mark.asyncio
    async def test_ecg_rr_mean_from_hr(self, agent):
        result = await agent.process_ecg(make_device_data(
            data={"heart_rate": 60, "ecg_signal": []}
        ))
        assert abs(result.features["rr_interval_mean"] - 1000.0) < 1e-6

    @pytest.mark.asyncio
    async def test_bp_signal_type(self, agent):
        result = await agent.process_bp(make_device_data(
            device_type=DeviceType.BP_MONITOR,
            data={"systolic": 130, "diastolic": 85},
        ))
        assert result.signal_type == "blood_pressure"

    @pytest.mark.asyncio
    async def test_bp_features_correct(self, agent):
        result = await agent.process_bp(make_device_data(
            device_type=DeviceType.BP_MONITOR,
            data={"systolic": 130, "diastolic": 85},
        ))
        assert result.features["systolic"]       == 130.0
        assert result.features["diastolic"]      == 85.0
        assert result.features["pulse_pressure"] == 45.0

    @pytest.mark.asyncio
    async def test_bp_map_formula(self, agent):
        result = await agent.process_bp(make_device_data(
            device_type=DeviceType.BP_MONITOR,
            data={"systolic": 120, "diastolic": 80},
        ))
        expected = (120 + 2 * 80) / 3
        assert abs(result.features["map"] - expected) < 0.01

    @pytest.mark.asyncio
    async def test_spo2_features(self, agent):
        result = await agent.process_spo2(make_device_data(
            device_type=DeviceType.PULSE_OXIMETER,
            data={"spo2": 98, "perfusion_index": 2.0, "pulse_rate": 70},
        ))
        assert result.signal_type          == "spo2"
        assert result.features["spo2"]     == 98.0
        assert result.features["pulse_rate"] == 70.0

    @pytest.mark.asyncio
    async def test_generic_passthrough(self, agent):
        result = await agent.process_generic(make_device_data(
            device_type=DeviceType.SMART_STETHOSCOPE,
            data={"audio_rms": 0.3},
        ))
        assert result.signal_type == "generic"

    @pytest.mark.asyncio
    async def test_dispatch_routes_ecg(self, agent, bus):
        published = []
        bus.subscribe("data.processed", lambda m: published.append(m))
        await agent.process(make_device_data(quality=0.9))
        assert published[0].signal_type == "ecg"

    @pytest.mark.asyncio
    async def test_dispatch_routes_bp(self, agent, bus):
        published = []
        bus.subscribe("data.processed", lambda m: published.append(m))
        await agent.process(make_device_data(
            device_type=DeviceType.BP_MONITOR,
            data={"systolic": 120, "diastolic": 80},
        ))
        assert published[0].signal_type == "blood_pressure"


# ===========================================================================
# 6. PATTERN RECOGNITION AGENT TESTS
# ===========================================================================

class TestPatternRecognitionAgent:

    @pytest.fixture
    def agent(self, bus):
        return PatternRecognitionAgent("pat-test", bus)

    # ---- detect_arrhythmia ----

    @pytest.mark.parametrize("hr,rr_std,qrs,expected", [
        (40,  30, 100, ArrhythmiaType.BRADYCARDIA),
        (72,  30, 95,  ArrhythmiaType.NORMAL_SINUS),
        (115, 80, 90,  ArrhythmiaType.ATRIAL_FIBRILLATION),
        (160, 20, 135, ArrhythmiaType.VENTRICULAR_TACHYCARDIA),
        (110, 25, 90,  ArrhythmiaType.TACHYCARDIA),
    ])
    def test_arrhythmia_detection(self, agent, hr, rr_std, qrs, expected):
        result = agent.detect_arrhythmia({
            "heart_rate": hr, "rr_interval_std": rr_std, "qrs_duration": qrs,
        })
        assert result == expected

    def test_bradycardia_priority_over_wide_qrs(self, agent):
        """HR < 50 must be bradycardia regardless of other features."""
        result = agent.detect_arrhythmia(
            {"heart_rate": 40, "rr_interval_std": 90, "qrs_duration": 140}
        )
        assert result == ArrhythmiaType.BRADYCARDIA

    # ---- detect_ischemia ----

    @pytest.mark.parametrize("st,expected", [
        (0.2,   True),
        (-0.15, True),
        (0.05,  False),
        (0.1,   False),   # boundary: not strictly >0.1
        (0.101, True),
    ])
    def test_ischemia_detection(self, agent, st, expected):
        assert agent.detect_ischemia({"st_elevation": st}) is expected

    # ---- classify_hypertension ----

    @pytest.mark.parametrize("systolic,diastolic,expected", [
        (115, 75,  "normal"),
        (122, 79,  "elevated"),
        (132, 82,  "stage_1"),
        (145, 92,  "stage_2"),
        (185, 125, "hypertensive_crisis"),
        (200, 110, "hypertensive_crisis"),
        (120, 80,  "stage_1"),   # ACC/AHA 2017: d>=80 is stage_1
        (130, 80,  "stage_1"),
    ])
    def test_hypertension_staging(self, agent, systolic, diastolic, expected):
        assert agent.classify_hypertension(
            {"systolic": systolic, "diastolic": diastolic}
        ) == expected

    # ---- analyze_ecg_pattern ----

    @pytest.mark.asyncio
    async def test_ecg_pattern_required_keys(self, agent):
        pattern = await agent.analyze_ecg_pattern(make_ecg_signal())
        for k in ("patient_id", "pattern_type", "arrhythmia_type",
                  "confidence", "ischemia_detected", "abnormal_qt"):
            assert k in pattern

    @pytest.mark.asyncio
    async def test_ecg_pattern_type_label(self, agent):
        assert (await agent.analyze_ecg_pattern(make_ecg_signal()))["pattern_type"] == "arrhythmia"

    @pytest.mark.asyncio
    async def test_ecg_confidence_range(self, agent):
        for _ in range(5):
            p = await agent.analyze_ecg_pattern(make_ecg_signal())
            assert 0.85 <= p["confidence"] <= 0.99

    @pytest.mark.asyncio
    async def test_abnormal_qt_high(self, agent):
        assert (await agent.analyze_ecg_pattern(make_ecg_signal(qt=490)))["abnormal_qt"] is True

    @pytest.mark.asyncio
    async def test_abnormal_qt_low(self, agent):
        assert (await agent.analyze_ecg_pattern(make_ecg_signal(qt=330)))["abnormal_qt"] is True

    @pytest.mark.asyncio
    async def test_normal_qt(self, agent):
        assert (await agent.analyze_ecg_pattern(make_ecg_signal(qt=400)))["abnormal_qt"] is False

    # ---- analyze_bp_pattern ----

    @pytest.mark.asyncio
    async def test_bp_pattern_type(self, agent):
        p = await agent.analyze_bp_pattern(make_bp_signal())
        assert p["pattern_type"] == "blood_pressure"

    @pytest.mark.asyncio
    async def test_bp_hypotension_flag(self, agent):
        p = await agent.analyze_bp_pattern(make_bp_signal(systolic=85, diastolic=55))
        assert p["hypotension"] is True

    @pytest.mark.asyncio
    async def test_bp_no_hypotension_normal(self, agent):
        p = await agent.analyze_bp_pattern(make_bp_signal(120, 80))
        assert p["hypotension"] is False

    @pytest.mark.asyncio
    async def test_bp_wide_pulse_pressure(self, agent):
        p = await agent.analyze_bp_pattern(make_bp_signal(180, 80))
        assert p["pulse_pressure_abnormal"] is True

    @pytest.mark.asyncio
    async def test_bp_publishes_to_bus(self, agent, bus):
        published = []
        bus.subscribe("pattern.detected", lambda m: published.append(m))
        await agent.process(make_bp_signal(145, 95))
        assert len(published) == 1


# ===========================================================================
# 7. DIAGNOSTIC AGENT TESTS
# ===========================================================================

class TestDiagnosticAgent:

    @pytest.fixture
    def agent(self, bus):
        return DiagnosticAgent("diag-test", bus)

    def _pattern(self, arrhythmia=ArrhythmiaType.ATRIAL_FIBRILLATION, patient="PT_001"):
        return {
            "patient_id":        patient,
            "timestamp":         datetime.now(),
            "pattern_type":      "arrhythmia",
            "arrhythmia_type":   arrhythmia,
            "confidence":        0.95,
            "ischemia_detected": False,
            "features":          {"heart_rate": 110},
        }

    # ---- interpret_pattern ----

    @pytest.mark.parametrize("arrhythmia,expected_fragment", [
        (ArrhythmiaType.ATRIAL_FIBRILLATION,     "Atrial Fibrillation"),
        (ArrhythmiaType.VENTRICULAR_TACHYCARDIA, "Critical"),
        (ArrhythmiaType.NORMAL_SINUS,            "Normal"),
        (ArrhythmiaType.BRADYCARDIA,             "Bradycardia"),
        (ArrhythmiaType.TACHYCARDIA,             "Tachycardia"),
    ])
    def test_interpret_pattern_arrhythmia(self, agent, arrhythmia, expected_fragment):
        text = agent.interpret_pattern(
            {"pattern_type": "arrhythmia", "arrhythmia_type": arrhythmia}
        )
        assert expected_fragment.lower() in text.lower()

    def test_interpret_pattern_bp_includes_stage(self, agent):
        text = agent.interpret_pattern({
            "pattern_type": "blood_pressure", "hypertension_stage": "stage_2",
        })
        assert "stage_2" in text

    # ---- risk calculators ----

    def test_ascvd_in_range(self, agent):
        for _ in range(20):
            assert 0.05 <= agent.calculate_ascvd_risk("PT_X") <= 0.30

    def test_hf_risk_in_range(self, agent):
        for _ in range(20):
            assert 0.02 <= agent.calculate_hf_risk("PT_X") <= 0.15

    def test_stroke_risk_elevated_for_afib(self, agent):
        risk = agent.calculate_stroke_risk("PT", {"arrhythmia_type": ArrhythmiaType.ATRIAL_FIBRILLATION})
        assert risk >= 0.15

    def test_stroke_risk_low_without_afib(self, agent):
        risk = agent.calculate_stroke_risk("PT", {"arrhythmia_type": ArrhythmiaType.NORMAL_SINUS})
        assert risk <= 0.10

    def test_scd_high_for_vtach(self, agent):
        risk = agent.calculate_scd_risk({"arrhythmia_type": ArrhythmiaType.VENTRICULAR_TACHYCARDIA})
        assert risk >= 0.30

    def test_scd_low_for_normal(self, agent):
        risk = agent.calculate_scd_risk({"arrhythmia_type": ArrhythmiaType.NORMAL_SINUS})
        assert risk <= 0.05

    # ---- recommendations ----

    def test_afib_anticoagulation_recommended(self, agent):
        recs = agent.generate_recommendations(
            {"arrhythmia_type": ArrhythmiaType.ATRIAL_FIBRILLATION, "ischemia_detected": False},
            {"ascvd_10year": 0.05},
        )
        assert any("anticoagulation" in r.lower() for r in recs)

    def test_vtach_immediate_intervention(self, agent):
        recs = agent.generate_recommendations(
            {"arrhythmia_type": ArrhythmiaType.VENTRICULAR_TACHYCARDIA, "ischemia_detected": False},
            {"ascvd_10year": 0.05},
        )
        assert any("IMMEDIATE" in r for r in recs)
        assert any("ICD" in r for r in recs)

    def test_high_ascvd_statin(self, agent):
        recs = agent.generate_recommendations(
            {"arrhythmia_type": None, "ischemia_detected": False},
            {"ascvd_10year": 0.25},
        )
        assert any("statin" in r.lower() for r in recs)

    def test_ischemia_recommendations(self, agent):
        recs = agent.generate_recommendations(
            {"arrhythmia_type": None, "ischemia_detected": True},
            {"ascvd_10year": 0.05},
        )
        assert any("ischemia" in r.lower() for r in recs)

    def test_normal_no_recommendations(self, agent):
        recs = agent.generate_recommendations(
            {"arrhythmia_type": ArrhythmiaType.NORMAL_SINUS, "ischemia_detected": False},
            {"ascvd_10year": 0.05},
        )
        assert recs == []

    # ---- generate_diagnosis / process ----

    @pytest.mark.asyncio
    async def test_generate_diagnosis_type(self, agent):
        result = await agent.generate_diagnosis(self._pattern())
        assert isinstance(result, DiagnosticResult)

    @pytest.mark.asyncio
    async def test_generate_diagnosis_risk_scores_present(self, agent):
        result = await agent.generate_diagnosis(self._pattern())
        for k in ("ascvd_10year", "heart_failure", "stroke", "sudden_cardiac_death"):
            assert k in result.risk_scores

    @pytest.mark.asyncio
    async def test_process_stores_patient_history(self, agent):
        await agent.process(self._pattern(patient="PT_HIST"))
        assert "PT_HIST" in agent.patient_history
        assert len(agent.patient_history["PT_HIST"]) == 1

    @pytest.mark.asyncio
    async def test_process_publishes_to_bus(self, agent, bus):
        published = []
        bus.subscribe("diagnosis.generated", lambda m: published.append(m))
        await agent.process(self._pattern())
        assert len(published) == 1
        assert isinstance(published[0], DiagnosticResult)


# ===========================================================================
# 8. ALERT MONITORING AGENT TESTS
# ===========================================================================

class TestAlertMonitoringAgent:

    @pytest.fixture
    def agent(self, bus):
        return AlertMonitoringAgent("alert-test", bus)

    # ---- determine_alert_level ----

    @pytest.mark.parametrize("arrhythmia,supporting,expected_level", [
        (ArrhythmiaType.VENTRICULAR_TACHYCARDIA, {},                        AlertLevel.CRITICAL),
        (ArrhythmiaType.VENTRICULAR_FIBRILLATION, {},                       AlertLevel.CRITICAL),
        (ArrhythmiaType.ATRIAL_FIBRILLATION, {"features": {"heart_rate": 140}}, AlertLevel.HIGH),
        (ArrhythmiaType.ATRIAL_FIBRILLATION, {"features": {"heart_rate": 90}},  AlertLevel.MEDIUM),
    ])
    def test_alert_level_arrhythmia(self, agent, arrhythmia, supporting, expected_level):
        diag = make_diagnostic_result(arrhythmia=arrhythmia, supporting=supporting)
        assert agent.determine_alert_level(diag) == expected_level

    def test_alert_level_high_scd_risk(self, agent):
        diag = make_diagnostic_result(risk_scores={
            "ascvd_10year": 0.10, "heart_failure": 0.05,
            "stroke": 0.05, "sudden_cardiac_death": 0.40,
        })
        assert agent.determine_alert_level(diag) == AlertLevel.HIGH

    def test_alert_level_high_stroke_is_medium(self, agent):
        diag = make_diagnostic_result(risk_scores={
            "ascvd_10year": 0.10, "heart_failure": 0.05,
            "stroke": 0.35, "sudden_cardiac_death": 0.02,
        })
        assert agent.determine_alert_level(diag) == AlertLevel.MEDIUM

    def test_alert_level_ischemia_is_high(self, agent):
        diag = make_diagnostic_result(supporting={"ischemia_detected": True})
        assert agent.determine_alert_level(diag) == AlertLevel.HIGH

    def test_alert_level_normal_is_none(self, agent):
        assert agent.determine_alert_level(make_diagnostic_result()) is None

    # ---- generate_required_actions ----

    @pytest.mark.parametrize("level,expected_action", [
        (AlertLevel.CRITICAL, "PREPARE_DEFIBRILLATOR"),
        (AlertLevel.CRITICAL, "ACTIVATE_RAPID_RESPONSE"),
        (AlertLevel.HIGH,     "NOTIFY_CARDIOLOGIST"),
        (AlertLevel.HIGH,     "REVIEW_WITHIN_15_MIN"),
        (AlertLevel.MEDIUM,   "NOTIFY_PRIMARY_CARE"),
        (AlertLevel.LOW,      "ROUTINE_REVIEW"),
    ])
    def test_required_actions(self, agent, level, expected_action):
        actions = agent.generate_required_actions(make_diagnostic_result(), level)
        assert expected_action in actions

    # ---- notification list ----

    @pytest.mark.parametrize("level,expected_recipient", [
        (AlertLevel.CRITICAL, "emergency_services"),
        (AlertLevel.CRITICAL, "rapid_response_team"),
        (AlertLevel.HIGH,     "primary_cardiologist"),
        (AlertLevel.MEDIUM,   "primary_care_physician"),
    ])
    def test_notification_list(self, agent, level, expected_recipient):
        assert expected_recipient in agent.determine_notification_list(level)

    # ---- create_alert / dispatch_alert ----

    @pytest.mark.asyncio
    async def test_create_alert_stored(self, agent):
        diag  = make_diagnostic_result(ArrhythmiaType.VENTRICULAR_TACHYCARDIA)
        alert = await agent.create_alert(diag, AlertLevel.CRITICAL)
        assert alert.alert_id in agent.active_alerts
        assert alert in agent.alert_history

    @pytest.mark.asyncio
    async def test_create_alert_correct_level(self, agent):
        diag  = make_diagnostic_result()
        alert = await agent.create_alert(diag, AlertLevel.HIGH)
        assert alert.level == AlertLevel.HIGH
        assert alert.patient_id == "PT_001"

    @pytest.mark.asyncio
    async def test_dispatch_publishes_to_bus(self, agent, bus):
        published = []
        bus.subscribe("alert.dispatched", lambda m: published.append(m))
        diag  = make_diagnostic_result(ArrhythmiaType.VENTRICULAR_FIBRILLATION)
        alert = await agent.create_alert(diag, AlertLevel.CRITICAL)
        await agent.dispatch_alert(alert)
        assert len(published) == 1
        assert published[0].level == AlertLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_dispatch_populates_notified_parties(self, agent, bus):
        bus.subscribe("alert.dispatched", lambda _: None)
        diag  = make_diagnostic_result(ArrhythmiaType.VENTRICULAR_TACHYCARDIA)
        alert = await agent.create_alert(diag, AlertLevel.CRITICAL)
        await agent.dispatch_alert(alert)
        assert len(alert.notified_parties) > 0


# ===========================================================================
# 9. PERSONALIZATION AGENT TESTS
# ===========================================================================

class TestPersonalizationAgent:

    @pytest.fixture
    def agent(self, bus):
        return PersonalizationAgent("pers-test", bus)

    @pytest.mark.asyncio
    async def test_new_patient_profile_created(self, agent):
        await agent.update_baseline(make_ecg_signal())
        assert "PT_001" in agent.patient_profiles

    @pytest.mark.asyncio
    async def test_sample_count_increments(self, agent):
        for _ in range(3):
            await agent.update_baseline(make_ecg_signal())
        assert agent.patient_profiles["PT_001"]["baseline"]["ecg"]["sample_count"] == 3

    @pytest.mark.asyncio
    async def test_running_average_stable_on_constant_input(self, agent):
        for _ in range(5):
            await agent.update_baseline(make_ecg_signal(heart_rate=75.0))
        avg = agent.patient_profiles["PT_001"]["baseline"]["ecg"]["features"]["heart_rate"]
        assert abs(avg - 75.0) < 0.01

    @pytest.mark.asyncio
    async def test_learn_from_alert_stores_entry(self, agent):
        diag = make_diagnostic_result()
        alert = Alert(
            alert_id="A999", patient_id="PT_001", timestamp=datetime.now(),
            level=AlertLevel.HIGH, title="T", description="D",
            diagnostic_result=diag, actions_required=[],
        )
        await agent.update_baseline(make_ecg_signal())
        await agent.learn_from_alert(alert)
        assert len(agent.patient_profiles["PT_001"]["alert_history"]) == 1
        assert agent.patient_profiles["PT_001"]["alert_history"][0]["alert_id"] == "A999"

    @pytest.mark.parametrize("param,expected", [
        ("heart_rate_high", 100),
        ("spo2_low",         92),
        ("systolic_high",   140),
        ("diastolic_high",   90),
        ("unknown_param",     0),
    ])
    def test_default_thresholds(self, agent, param, expected):
        assert agent.get_default_threshold(param) == expected

    def test_personalized_threshold_falls_back_to_default(self, agent):
        assert agent.get_personalized_threshold("NO_PATIENT", "heart_rate_high") == 100

    @pytest.mark.asyncio
    async def test_non_numeric_features_skipped(self, agent):
        sig = ProcessedSignal(
            patient_id="PT_001", signal_type="generic", timestamp=datetime.now(),
            features={"label": "bad", "value": 3.0},
            raw_data=np.array([]), quality_metrics={},
        )
        await agent.update_baseline(sig)
        features = agent.patient_profiles["PT_001"]["baseline"]["generic"]["features"]
        assert "value" in features
        assert "label" not in features


# ===========================================================================
# 10. COMMUNICATION AGENT TESTS
# ===========================================================================

class TestCommunicationAgent:

    @pytest.fixture
    def agent(self, bus):
        return CommunicationAgent("comm-test", bus)

    def _make_alert(self, level=AlertLevel.CRITICAL):
        return Alert(
            alert_id="COMM-001", patient_id="PT_001",
            timestamp=datetime.now(), level=level,
            title="VTach Detected", description="Critical arrhythmia",
            diagnostic_result=make_diagnostic_result(ArrhythmiaType.VENTRICULAR_TACHYCARDIA),
            actions_required=["PREPARE_DEFIBRILLATOR"],
            notified_parties=["emergency_services"],
        )

    def test_summary_contains_patient_id(self, agent):
        assert "PT_001" in agent.create_alert_summary(self._make_alert())

    def test_summary_contains_level(self, agent):
        assert "CRITICAL" in agent.create_alert_summary(self._make_alert())

    def test_summary_contains_action(self, agent):
        summary = agent.create_alert_summary(self._make_alert())
        assert "Defibrillator" in summary or "PREPARE_DEFIBRILLATOR" in summary

    def test_summary_contains_notified(self, agent):
        assert "emergency_services" in agent.create_alert_summary(self._make_alert())

    @pytest.mark.asyncio
    async def test_generate_report_stored(self, agent):
        await agent.generate_report(make_diagnostic_result())
        assert len(agent.report_store) == 1

    @pytest.mark.asyncio
    async def test_report_structure(self, agent):
        await agent.generate_report(make_diagnostic_result())
        r = agent.report_store[0]
        for key in ("patient_id", "diagnosis", "risk_assessment", "recommendations"):
            assert key in r

    @pytest.mark.asyncio
    async def test_multiple_reports_accumulate(self, agent):
        for _ in range(5):
            await agent.generate_report(make_diagnostic_result())
        assert len(agent.report_store) == 5

    @pytest.mark.asyncio
    async def test_handle_alert_no_exception(self, agent):
        await agent.handle_alert_communication(self._make_alert())


# ===========================================================================
# 11. CARDIOAI SYSTEM COORDINATOR TESTS
# ===========================================================================

class TestCardioAISystem:

    def test_seven_agents_initialised(self, cardioai):
        assert len(cardioai.agents) == 7

    def test_all_expected_agent_keys(self, cardioai):
        for key in ("data_acquisition", "data_processing", "pattern_recognition",
                    "diagnostic", "alert_monitoring", "personalization", "communication"):
            assert key in cardioai.agents

    @pytest.mark.asyncio
    async def test_start_all_running(self, cardioai):
        await cardioai.start()
        for agent in cardioai.agents.values():
            assert agent.is_running
        await cardioai.stop()

    @pytest.mark.asyncio
    async def test_stop_all_stopped(self, cardioai):
        await cardioai.start()
        await cardioai.stop()
        for agent in cardioai.agents.values():
            assert not agent.is_running

    @pytest.mark.parametrize("scenario,hr_min,hr_max", [
        ("normal",      60, 90),
        ("afib",       110, 150),
        ("vtach",      150, 200),
        ("bradycardia", 35, 50),
    ])
    def test_ecg_data_generator(self, cardioai, scenario, hr_min, hr_max):
        for _ in range(10):
            data = cardioai.generate_ecg_data(scenario)
            assert hr_min <= data["heart_rate"] <= hr_max

    @pytest.mark.parametrize("scenario,sys_min,sys_max", [
        ("normal",              110, 130),
        ("hypertension",        140, 170),
        ("hypertensive_crisis", 180, 220),
    ])
    def test_bp_data_generator(self, cardioai, scenario, sys_min, sys_max):
        for _ in range(10):
            data = cardioai.generate_bp_data(scenario)
            assert sys_min <= data["systolic"] <= sys_max

    @pytest.mark.asyncio
    async def test_simulate_ecg_registers_device(self, cardioai):
        await cardioai.start()
        await cardioai.simulate_device_data("PT_SIM", DeviceType.ECG_MONITOR, "normal")
        assert "ecg_monitor_PT_SIM" in cardioai.agents["data_acquisition"].registered_devices
        await cardioai.stop()

    @pytest.mark.asyncio
    async def test_all_agents_share_same_bus(self, cardioai):
        bus = cardioai.message_bus
        for agent in cardioai.agents.values():
            assert agent.message_bus is bus


# ===========================================================================
# 12. PROTOCOL HELPER TESTS
# ===========================================================================

class TestProtocolHelpers:

    def test_build_message_fields(self):
        msg = json.loads(build_message(MsgType.HELLO, {"k": "v"}, "SENDER"))
        assert msg["type"]      == "HELLO"
        assert msg["sender_id"] == "SENDER"
        assert msg["payload"]   == {"k": "v"}
        assert "msg_id"    in msg
        assert "timestamp" in msg

    def test_build_message_unique_ids(self):
        ids = {json.loads(build_message(MsgType.HEARTBEAT, {}, "S"))["msg_id"]
               for _ in range(10)}
        assert len(ids) == 10

    def test_parse_message_valid(self):
        msg = parse_message('{"type": "HELLO", "payload": {}}')
        assert msg["type"] == "HELLO"

    def test_parse_message_invalid_json(self):
        with pytest.raises(ValueError):
            parse_message("{not-json}")

    def test_parse_message_empty_string(self):
        with pytest.raises(ValueError):
            parse_message("")

    def test_all_msg_types_roundtrip(self):
        for mt in MsgType:
            msg = json.loads(build_message(mt, {}, "S"))
            assert msg["type"] == mt.value


# ===========================================================================
# 13. HANDSHAKE CONFIG TESTS
# ===========================================================================

class TestHandshakeConfig:

    def test_default_port(self):
        assert HandshakeConfig().cardioai_ws_port == 8765

    def test_default_queue_size(self):
        assert HandshakeConfig().inbound_queue_max_size == 2000

    def test_default_reconnect_attempts(self):
        assert HandshakeConfig().reconnect_max_attempts == 5

    def test_default_jwt_algorithm(self):
        assert HandshakeConfig().jwt_algorithm == "HS256"

    def test_override_values(self, cfg):
        assert cfg.shared_secret          == "test-secret-abc"
        assert cfg.reconnect_max_attempts == 2


# ===========================================================================
# 14. SECURITY MANAGER TESTS
# ===========================================================================

class TestSecurityManager:

    def test_challenge_decodes_to_16_bytes(self, security):
        import base64
        assert len(base64.b64decode(security.generate_challenge())) == 16

    def test_challenge_unique(self, security):
        assert len({security.generate_challenge() for _ in range(20)}) == 20

    def test_sign_is_deterministic(self, security):
        c = security.generate_challenge()
        assert security.sign_challenge(c) == security.sign_challenge(c)

    def test_verify_correct_signature(self, security):
        c = security.generate_challenge()
        assert security.verify_challenge(c, security.sign_challenge(c)) is True

    def test_verify_wrong_signature(self, security):
        c = security.generate_challenge()
        assert security.verify_challenge(c, "bad-sig") is False

    def test_verify_tampered_challenge(self, security):
        c   = security.generate_challenge()
        sig = security.sign_challenge(c)
        assert security.verify_challenge("tampered", sig) is False

    def test_token_is_string(self, security):
        assert isinstance(security.issue_token("peer", []), str)

    def test_token_correct_sub(self, security):
        assert security.verify_token(security.issue_token("peer-1", []))["sub"] == "peer-1"

    def test_token_device_ids(self, security):
        payload = security.verify_token(security.issue_token("p", ["A", "B"]))
        assert "A" in payload["device_ids"]
        assert "B" in payload["device_ids"]

    def test_expired_token_rejected(self, cfg):
        sec = SecurityManager(HandshakeConfig(
            shared_secret=cfg.shared_secret,
            jwt_secret=cfg.jwt_secret,
            token_ttl_seconds=-1,
        ))
        with pytest.raises(jwt.ExpiredSignatureError):
            sec.verify_token(sec.issue_token("p", []))

    def test_wrong_jwt_secret_rejected(self, security, cfg):
        token = security.issue_token("peer", [])
        wrong = SecurityManager(HandshakeConfig(
            jwt_secret="wrong", shared_secret=cfg.shared_secret
        ))
        with pytest.raises(jwt.InvalidSignatureError):
            wrong.verify_token(token)

    def test_different_secrets_different_sigs(self, cfg):
        s1 = SecurityManager(cfg)
        s2 = SecurityManager(HandshakeConfig(shared_secret="other", jwt_secret=cfg.jwt_secret))
        c = "challenge"
        assert s1.sign_challenge(c) != s2.sign_challenge(c)


# ===========================================================================
# 15. DEVICE SESSION REGISTRY TESTS
# ===========================================================================

class TestDeviceSessionRegistry:

    def test_register_returns_session(self, registry):
        s = registry.register("ECG-1", "ecg_monitor", "PT_A")
        assert isinstance(s, DeviceSession)
        assert s.device_id == "ECG-1"
        assert s.is_active is True
        assert s.data_count == 0

    def test_get_registered(self, registry):
        registry.register("BP-1", "bp_monitor", "PT_B")
        assert registry.get("BP-1").device_type == DeviceType.BP_MONITOR

    def test_get_unknown_returns_none(self, registry):
        assert registry.get("GHOST") is None

    def test_mark_data_increments_count(self, registry):
        registry.register("ECG-2", "ecg_monitor", "PT_C")
        registry.mark_data_received("ECG-2")
        registry.mark_data_received("ECG-2")
        assert registry.get("ECG-2").data_count == 2

    def test_mark_data_sets_last_data_at(self, registry):
        registry.register("ECG-3", "ecg_monitor", "PT_D")
        assert registry.get("ECG-3").last_data_at is None
        registry.mark_data_received("ECG-3")
        assert registry.get("ECG-3").last_data_at is not None

    def test_mark_data_resets_missed_heartbeats(self, registry):
        registry.register("ECG-4", "ecg_monitor", "PT_E")
        registry.get("ECG-4").missed_heartbeats = 5
        registry.mark_data_received("ECG-4")
        assert registry.get("ECG-4").missed_heartbeats == 0

    def test_mark_inactive(self, registry):
        registry.register("ECG-5", "ecg_monitor", "PT_F")
        registry.mark_inactive("ECG-5")
        assert registry.get("ECG-5").is_active is False

    def test_active_devices_excludes_inactive(self, registry):
        registry.register("D1", "ecg_monitor", "P1")
        registry.register("D2", "ecg_monitor", "P2")
        registry.mark_inactive("D1")
        active_ids = [s.device_id for s in registry.active_devices()]
        assert "D1" not in active_ids
        assert "D2" in active_ids

    def test_summary_counts(self, registry):
        registry.register("D1", "ecg_monitor", "P1")
        registry.register("D2", "bp_monitor",  "P2")
        registry.register("D3", "ecg_monitor", "P3")
        registry.mark_inactive("D3")
        s = registry.summary()
        assert s["total_registered"] == 3
        assert s["active"]           == 2
        assert s["inactive"]         == 1

    def test_summary_device_entry_fields(self, registry):
        registry.register("D10", "ecg_monitor", "PT_10")
        dev = registry.summary()["devices"][0]
        assert dev["device_id"]   == "D10"
        assert dev["active"]      is True
        assert dev["data_points"] == 0

    def test_mark_data_on_unknown_is_silent(self, registry):
        registry.mark_data_received("GHOST")  # should not raise

    def test_mark_inactive_on_unknown_is_silent(self, registry):
        registry.mark_inactive("GHOST")


# ===========================================================================
# 16. RPM DATA PUMP TESTS
# ===========================================================================

def _make_frame(device_id="ECG-01", device_type="ecg_monitor", patient_id="PT_001"):
    return {
        "device_id":    device_id,
        "device_type":  device_type,
        "patient_id":   patient_id,
        "timestamp":    datetime.utcnow().isoformat(),
        "data":         {"heart_rate": 75.0},
        "quality_score": 1.0,
    }


class TestRPMDataPump:

    @pytest.mark.asyncio
    async def test_pump_processes_frame(self):
        system = CardioAISystem()
        registry = DeviceSessionRegistry()
        queue = asyncio.Queue()
        pump = RPMDataPump(queue, system, registry)

        await system.start()
        await system.message_bus.publish("device.register", {
            "device_id": "ECG-01", "device_type": "ecg_monitor", "patient_id": "PT_001",
        })
        await asyncio.sleep(0.05)
        await queue.put(_make_frame())
        task = asyncio.create_task(pump.run())
        await asyncio.sleep(0.2)
        pump._stop.set()
        await task
        assert pump.stats["frames_processed"] == 1
        await system.stop()

    @pytest.mark.asyncio
    async def test_stats_start_at_zero(self):
        pump = RPMDataPump(asyncio.Queue(), CardioAISystem(), DeviceSessionRegistry())
        assert pump.stats["frames_processed"] == 0
        assert pump.stats["frames_dropped"]   == 0
        assert pump.stats["last_frame_at"]    is None

    @pytest.mark.asyncio
    async def test_auto_register_unknown_device(self):
        system = CardioAISystem()
        registry = DeviceSessionRegistry()
        queue = asyncio.Queue()
        pump = RPMDataPump(queue, system, registry)
        await system.start()
        await queue.put(_make_frame(device_id="NEW-DEV", patient_id="PT_NEW"))
        task = asyncio.create_task(pump.run())
        await asyncio.sleep(0.3)
        pump._stop.set()
        await task
        assert "NEW-DEV" in system.agents["data_acquisition"].registered_devices
        await system.stop()

    @pytest.mark.asyncio
    async def test_optional_callback_invoked(self):
        system = CardioAISystem()
        registry = DeviceSessionRegistry()
        queue = asyncio.Queue()
        captured = []

        async def hook(frame):
            captured.append(frame)

        pump = RPMDataPump(queue, system, registry, on_rpm_frame=hook)
        await system.start()
        await system.message_bus.publish("device.register", {
            "device_id": "CB-DEV", "device_type": "ecg_monitor", "patient_id": "PT_CB",
        })
        await asyncio.sleep(0.05)
        await queue.put(_make_frame("CB-DEV"))
        task = asyncio.create_task(pump.run())
        await asyncio.sleep(0.2)
        pump._stop.set()
        await task
        assert len(captured) == 1
        await system.stop()

    @pytest.mark.asyncio
    async def test_stop_event_exits_run(self):
        system = CardioAISystem()
        pump = RPMDataPump(asyncio.Queue(), system, DeviceSessionRegistry())
        pump._stop.set()
        await system.start()
        await asyncio.wait_for(pump.run(), timeout=2.0)
        await system.stop()


# ===========================================================================
# 17. DEVICE HEALTH MONITOR TESTS
# ===========================================================================

class TestDeviceHealthMonitor:

    @pytest.mark.asyncio
    async def test_stale_device_marked_inactive_and_event_published(self):
        bus      = MessageBus()
        registry = DeviceSessionRegistry()
        session  = registry.register("STALE-01", "ecg_monitor", "PT_S")
        session.last_data_at      = datetime.utcnow() - timedelta(seconds=60)
        session.missed_heartbeats = 2  # one away from threshold (>=3)

        events = []
        bus.subscribe("device.inactive", lambda m: events.append(m))

        monitor = DeviceHealthMonitor(
            registry, bus,
            stale_threshold_seconds=5.0,
            check_interval_seconds=0.05,
        )
        task = asyncio.create_task(monitor.run())
        await asyncio.sleep(0.15)
        monitor._stop.set()
        await task

        assert not session.is_active
        assert any(e["device_id"] == "STALE-01" for e in events)

    @pytest.mark.asyncio
    async def test_fresh_device_stays_active(self):
        bus      = MessageBus()
        registry = DeviceSessionRegistry()
        session  = registry.register("FRESH-01", "bp_monitor", "PT_F")
        session.last_data_at = datetime.utcnow()

        monitor = DeviceHealthMonitor(
            registry, bus,
            stale_threshold_seconds=30.0,
            check_interval_seconds=0.05,
        )
        task = asyncio.create_task(monitor.run())
        await asyncio.sleep(0.15)
        monitor._stop.set()
        await task

        assert session.is_active is True

    @pytest.mark.asyncio
    async def test_device_never_sent_data_not_flagged(self):
        """Devices with last_data_at == None must be skipped."""
        bus      = MessageBus()
        registry = DeviceSessionRegistry()
        session  = registry.register("NEW-01", "ecg_monitor", "PT_N")

        events = []
        bus.subscribe("device.inactive", lambda m: events.append(m))

        monitor = DeviceHealthMonitor(
            registry, bus,
            stale_threshold_seconds=0.01,
            check_interval_seconds=0.05,
        )
        task = asyncio.create_task(monitor.run())
        await asyncio.sleep(0.2)
        monitor._stop.set()
        await task

        assert session.is_active is True
        assert events == []


# ===========================================================================
# 18. END-TO-END PIPELINE TESTS
# ===========================================================================

class TestEndToEndPipeline:

    @pytest.mark.asyncio
    async def test_vtach_produces_critical_alert(self):
        """
        Inject a VTach ProcessedSignal directly and verify a CRITICAL alert
        is published through the full agent chain.
        """
        system = CardioAISystem()
        await system.start()

        critical = []
        system.message_bus.subscribe(
            "alert.dispatched",
            lambda a: critical.append(a) if a.level == AlertLevel.CRITICAL else None,
        )
        vtach = make_ecg_signal(heart_rate=170, rr_std=20, qrs=130)
        await system.message_bus.publish("data.processed", vtach)
        await asyncio.sleep(0.1)

        assert len(critical) >= 1
        await system.stop()

    @pytest.mark.asyncio
    async def test_afib_produces_medium_or_high_alert(self):
        system = CardioAISystem()
        await system.start()

        alerts = []
        system.message_bus.subscribe("alert.dispatched", lambda a: alerts.append(a))
        afib = make_ecg_signal(heart_rate=120, rr_std=80, qrs=90)
        await system.message_bus.publish("data.processed", afib)
        await asyncio.sleep(0.1)

        assert any(a.level in (AlertLevel.HIGH, AlertLevel.MEDIUM) for a in alerts)
        await system.stop()

    @pytest.mark.asyncio
    async def test_hypertensive_crisis_diagnosis_text(self):
        system = CardioAISystem()
        await system.start()

        diagnoses = []
        system.message_bus.subscribe("diagnosis.generated", lambda d: diagnoses.append(d))
        await system.message_bus.publish("data.processed", make_bp_signal(190, 125))
        await asyncio.sleep(0.1)

        assert any("hypertensive_crisis" in d.diagnosis for d in diagnoses)
        await system.stop()

    @pytest.mark.asyncio
    async def test_personalization_updated_after_signal(self):
        system = CardioAISystem()
        await system.start()

        pers = system.agents["personalization"]
        await system.message_bus.publish("data.processed", make_ecg_signal())
        await asyncio.sleep(0.05)

        assert "PT_001" in pers.patient_profiles
        await system.stop()

    @pytest.mark.asyncio
    async def test_communication_report_stored(self):
        system = CardioAISystem()
        await system.start()

        comm = system.agents["communication"]
        await system.message_bus.publish("data.processed",
                                         make_ecg_signal(heart_rate=170, rr_std=20, qrs=130))
        await asyncio.sleep(0.1)

        assert len(comm.report_store) >= 1
        await system.stop()

    @pytest.mark.asyncio
    async def test_acquisition_to_diagnosis_full_path(self):
        """
        Raw dict -> DataAcquisitionAgent.process() -> MessageBus chain ->
        at least one diagnosis.generated event.
        """
        system = CardioAISystem()
        await system.start()

        acq = system.agents["data_acquisition"]
        await acq.register_device({
            "device_id": "ECG-FA", "device_type": "ecg_monitor", "patient_id": "PT_FA",
        })
        await acq.process({"device_id": "ECG-FA", "heart_rate": 135, "ecg_signal": [0.1] * 50})
        await asyncio.sleep(0.2)

        diag_events = [m for m in system.message_bus.message_history
                       if m["topic"] == "diagnosis.generated"]
        assert len(diag_events) >= 1
        await system.stop()

    @pytest.mark.asyncio
    async def test_normal_ecg_does_not_produce_critical(self):
        """Normal sinus ECG should never generate a CRITICAL alert."""
        system = CardioAISystem()
        await system.start()

        critical = []
        system.message_bus.subscribe(
            "alert.dispatched",
            lambda a: critical.append(a) if a.level == AlertLevel.CRITICAL else None,
        )
        normal = make_ecg_signal(heart_rate=72, rr_std=30, qrs=95, st=0.0)
        await system.message_bus.publish("data.processed", normal)
        await asyncio.sleep(0.1)

        assert critical == []
        await system.stop()


# ===========================================================================
# 19. WEBSOCKET HANDSHAKE LOOPBACK
# ===========================================================================

class TestWebSocketHandshakeLoopback:

    @pytest.mark.asyncio
    async def test_full_3way_hmac_handshake(self, cfg):
        """
        Loopback: stub IoMT server performs the 3-way challenge,
        connector authenticates, devices are registered in the registry.
        """
        import websockets as _ws

        PORT = 19100
        cfg.iomt_server_ws_url = f"ws://127.0.0.1:{PORT}"
        security  = SecurityManager(cfg)
        registry  = DeviceSessionRegistry()
        queue     = asyncio.Queue(maxsize=50)
        connector = IoMTServerConnector(cfg, queue, registry)
        auth_done = asyncio.Event()

        async def stub(ws):
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            assert parse_message(raw)["type"] == MsgType.HELLO.value

            challenge = security.generate_challenge()
            await ws.send(build_message(MsgType.CHALLENGE,
                                        {"challenge": challenge}, cfg.iomt_server_id))

            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            msg = parse_message(raw)
            assert msg["type"] == MsgType.CHALLENGE_RESP.value
            assert security.verify_challenge(
                msg["payload"]["challenge"], msg["payload"]["signature"]
            )

            token = security.issue_token(cfg.cardioai_backend_id, ["HS-1"])
            await ws.send(build_message(MsgType.AUTH_OK,
                                        {"token": token}, cfg.iomt_server_id))

            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            assert parse_message(raw)["type"] == MsgType.DEVICE_LIST.value
            await ws.send(build_message(
                MsgType.DEVICE_LIST_ACK,
                {"devices": [{"device_id": "HS-1", "device_type": "ecg_monitor",
                               "patient_id": "PT_HS"}]},
                cfg.iomt_server_id,
            ))
            auth_done.set()

            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            assert parse_message(raw)["type"] == MsgType.SUBSCRIBE.value
            await ws.send(build_message(
                MsgType.SUBSCRIBE_ACK, {"subscribed": ["HS-1"]}, cfg.iomt_server_id,
            ))
            await asyncio.sleep(0.3)

        server = await _ws.serve(stub, "127.0.0.1", PORT)

        async def run_connector():
            try:
                await asyncio.wait_for(connector.run(), timeout=3)
            except (asyncio.TimeoutError, Exception):
                pass

        task = asyncio.create_task(run_connector())
        await asyncio.wait_for(auth_done.wait(), timeout=5)
        connector._stop.set()
        await task
        server.close()
        await server.wait_closed()

        assert registry.get("HS-1") is not None
        assert registry.get("HS-1").patient_id == "PT_HS"

    @pytest.mark.asyncio
    async def test_wrong_secret_fails_auth(self, cfg):
        """Connector with a bad shared secret must not complete authentication."""
        import websockets as _ws

        PORT = 19101
        server_sec = SecurityManager(cfg)
        bad_cfg = HandshakeConfig(
            shared_secret="WRONG",
            jwt_secret=cfg.jwt_secret,
            iomt_server_ws_url=f"ws://127.0.0.1:{PORT}",
            reconnect_max_attempts=1,
            reconnect_base_delay_seconds=0.01,
        )
        registry  = DeviceSessionRegistry()
        queue     = asyncio.Queue()
        connector = IoMTServerConnector(bad_cfg, queue, registry)
        failed    = asyncio.Event()

        async def stub(ws):
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5)
                assert parse_message(raw)["type"] == MsgType.HELLO.value
                ch = server_sec.generate_challenge()
                await ws.send(build_message(MsgType.CHALLENGE, {"challenge": ch},
                                            cfg.iomt_server_id))
                raw = await asyncio.wait_for(ws.recv(), timeout=5)
                msg = parse_message(raw)
                if not server_sec.verify_challenge(
                    msg["payload"]["challenge"], msg["payload"]["signature"]
                ):
                    await ws.send(build_message(
                        MsgType.AUTH_FAIL, {"reason": "bad hmac"}, cfg.iomt_server_id
                    ))
                    failed.set()
            except Exception:
                failed.set()

        server = await _ws.serve(stub, "127.0.0.1", PORT)

        async def run():
            try:
                await asyncio.wait_for(connector.run(), timeout=3)
            except Exception:
                pass

        task = asyncio.create_task(run())
        await asyncio.wait_for(failed.wait(), timeout=5)
        connector._stop.set()
        await task
        server.close()
        await server.wait_closed()

        assert registry.get("HS-1") is None  # nothing registered


# ===========================================================================
# 20. BACK-PRESSURE TEST
# ===========================================================================

class TestBackPressure:

    @pytest.mark.asyncio
    async def test_full_queue_evicts_oldest_frame(self):
        """
        When the inbound queue is at capacity, _handle_rpm_data must
        evict the oldest entry before appending the new one.
        """
        registry = DeviceSessionRegistry()
        session  = registry.register("BP-FULL", "bp_monitor", "PT_BP")
        session.last_data_at = datetime.utcnow()

        queue = asyncio.Queue(maxsize=3)
        for i in range(3):
            await queue.put({"seq": i})
        assert queue.full()

        connector = IoMTServerConnector(HandshakeConfig(), queue, registry)
        connector._ws = None  # prevent network send

        msg = {
            "msg_id": str(uuid.uuid4()),
            "type":   MsgType.RPM_DATA.value,
            "payload": {
                "device_id":    "BP-FULL",
                "timestamp":    datetime.utcnow().isoformat(),
                "data":         {"systolic": 150},
                "quality_score": 1.0,
            }
        }
        await connector._handle_rpm_data(msg, None)
        assert queue.qsize() == 3  # evicted one, added one => still at max


# ===========================================================================
# MAIN
# ===========================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
