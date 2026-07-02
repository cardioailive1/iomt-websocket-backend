"""
hl7_server.py — HL7 v2 MLLP listener for ADT feeds
=====================================================
Receives HL7 v2 ADT (Admit/Discharge/Transfer) messages over MLLP
(Minimal Lower Layer Protocol — the standard TCP framing for HL7 v2)
from a hospital's ADT feed / interface engine (Mirth Connect, Rhapsody,
Cloverleaf, or the EHR's native HL7 interface).

Why this matters for CardioAI
------------------------------
Knowing which patients are CURRENTLY admitted (and where) lets you:
  - Suppress or reprioritize alerts for patients who've been discharged
  - Attach ward/unit context to alerts so nursing staff know where to go
  - Correlate RPM/implant data with inpatient encounters

This module only PARSES and TRACKS admission state — it does not yet
feed that state into the alerting pipeline's decision logic. See
AdmissionRegistry.get(patient_id) for where to hook that in later
(e.g. in AlertMonitoringAgent._triage()).

Scope
-----
Handles the ADT message types that matter for this use case:
  ADT^A01  Admit / visit notification
  ADT^A02  Transfer
  ADT^A03  Discharge
  ADT^A04  Register (outpatient/ED) — treated like an admit
  ADT^A08  Update patient information — updates name/location only
Anything else is acknowledged (AA) but otherwise ignored — better to
ACK-and-ignore unhandled message types than to NAK and make the sending
interface engine retry indefinitely.

No external HL7 parsing library is used — HL7 v2's pipe/^-delimited
segment structure is simple enough to parse directly, keeping this
self-contained like the rest of the codebase.

Required environment variables (optional — omit to disable entirely)
------------------------------------------------------------------------
  HL7_MLLP_ENABLED   "true" to start the listener (default: "false")
  HL7_MLLP_HOST      bind host (default: "0.0.0.0")
  HL7_MLLP_PORT      bind port (default: "2575" — the conventional HL7 MLLP port)
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger("IoMT.HL7")

# MLLP framing bytes
_START_BLOCK = b"\x0b"
_END_BLOCK = b"\x1c"
_CARRIAGE_RETURN = b"\x0d"

_ADMIT_LIKE = {"A01", "A04"}
_DISCHARGE_LIKE = {"A03"}
_TRANSFER_LIKE = {"A02"}
_UPDATE_LIKE = {"A08"}


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AdmissionRecord:
    patient_id: str
    patient_name: str = ""
    status: str = "unknown"      # admitted | discharged | transferred
    location: str = ""           # PV1-3 assigned patient location, if present
    patient_class: str = ""      # PV1-2 (I=inpatient, O=outpatient, E=emergency, ...)
    last_event_type: str = ""    # e.g. "A01"
    updated_at: str = field(default_factory=_utcnow_iso)


class AdmissionRegistry:
    """In-memory registry of current admission status per patient_id."""

    def __init__(self) -> None:
        self._records: Dict[str, AdmissionRecord] = {}

    def apply_event(self, event: Dict[str, Any]) -> AdmissionRecord:
        pid = event["patient_id"]
        existing = self._records.get(pid, AdmissionRecord(patient_id=pid))

        event_type = event.get("event_type", "")
        if event_type in _ADMIT_LIKE:
            existing.status = "admitted"
        elif event_type in _DISCHARGE_LIKE:
            existing.status = "discharged"
        elif event_type in _TRANSFER_LIKE:
            existing.status = "transferred"
        # A08 (update) intentionally does not change status

        if event.get("patient_name"):
            existing.patient_name = event["patient_name"]
        if event.get("location"):
            existing.location = event["location"]
        if event.get("patient_class"):
            existing.patient_class = event["patient_class"]
        existing.last_event_type = event_type
        existing.updated_at = _utcnow_iso()

        self._records[pid] = existing
        return existing

    def get(self, patient_id: str) -> Optional[AdmissionRecord]:
        return self._records.get(patient_id)

    def is_admitted(self, patient_id: str) -> bool:
        rec = self._records.get(patient_id)
        return rec is not None and rec.status == "admitted"

    def summary(self) -> Dict[str, Any]:
        records = list(self._records.values())
        return {
            "total_known_patients": len(records),
            "currently_admitted": sum(1 for r in records if r.status == "admitted"),
            "patients": [
                {
                    "patient_id": r.patient_id, "patient_name": r.patient_name,
                    "status": r.status, "location": r.location,
                    "patient_class": r.patient_class, "last_event_type": r.last_event_type,
                    "updated_at": r.updated_at,
                }
                for r in records
            ],
        }


# ============================================================================
# Minimal HL7 v2 parsing
# ============================================================================

def _parse_hl7_message(raw: str) -> Dict[str, list[list[str]]]:
    """
    Parse a raw HL7 v2 message into {segment_name: [fields...]} per segment,
    keyed by segment type with a list of occurrences (some segments like
    OBX can repeat; ADT parsing here only ever uses the first occurrence).

    Field separator is whatever character follows "MSH" (conventionally '|').
    Component separator ('^') is NOT expanded further here — ADT fields we
    care about (patient ID, name, location) are extracted with simple
    component splitting inline where needed.
    """
    raw = raw.replace("\r\n", "\r").replace("\n", "\r")
    segments = [s for s in raw.split("\r") if s.strip()]
    if not segments or not segments[0].startswith("MSH"):
        raise ValueError("Message does not start with MSH segment")

    field_sep = segments[0][3]  # character immediately after 'MSH'
    parsed: Dict[str, list[list[str]]] = {}
    for seg in segments:
        fields = seg.split(field_sep)
        seg_name = fields[0]
        parsed.setdefault(seg_name, []).append(fields)
    return parsed


def _component(field_value: str, index: int = 0, comp_sep: str = "^") -> str:
    parts = field_value.split(comp_sep)
    return parts[index] if index < len(parts) else ""


def parse_adt_message(raw: str) -> Dict[str, Any]:
    """
    Parse an ADT message into a flat event dict:
      {event_type, patient_id, patient_name, location, patient_class,
       message_control_id, raw_message_type}

    Raises ValueError on anything that isn't parseable as HL7 v2 with an
    MSH segment — callers should catch this and NAK the message.
    """
    segments = _parse_hl7_message(raw)

    msh = segments.get("MSH", [[]])[0]
    # MSH-9 = message type, e.g. "ADT^A01" — but MSH-1 (field sep) shifts
    # indices by one since fields[0] is literally "MSH".
    message_type_field = msh[8] if len(msh) > 8 else ""
    event_type = _component(message_type_field, 1) or "UNKNOWN"
    message_control_id = msh[9] if len(msh) > 9 else ""

    pid = segments.get("PID", [[]])[0]
    patient_id = _component(pid[3], 0) if len(pid) > 3 else ""
    patient_name_field = pid[5] if len(pid) > 5 else ""
    # PID-5 components: FamilyName^GivenName^Middle^Suffix^Prefix
    family = _component(patient_name_field, 0)
    given = _component(patient_name_field, 1)
    patient_name = f"{given} {family}".strip()

    pv1 = segments.get("PV1", [[]])[0]
    patient_class = pv1[2] if len(pv1) > 2 else ""
    location_field = pv1[3] if len(pv1) > 3 else ""
    # PV1-3 components: PointOfCare^Room^Bed^Facility
    location = "^".join(p for p in location_field.split("^")[:3] if p)

    if not patient_id:
        raise ValueError("PID segment missing or has no patient identifier (PID-3)")

    return {
        "event_type": event_type,
        "patient_id": patient_id,
        "patient_name": patient_name,
        "location": location,
        "patient_class": patient_class,
        "message_control_id": message_control_id,
        "raw_message_type": message_type_field,
    }


def _build_ack(message_control_id: str, ack_code: str = "AA", text: str = "") -> bytes:
    """Build a minimal HL7 v2 ACK/NAK response, MLLP-framed and ready to send."""
    now = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    msh = f"MSH|^~\\&|CARDIOAI|CARDIOAI|||{now}||ACK|{message_control_id}-ACK|P|2.5"
    msa = f"MSA|{ack_code}|{message_control_id}|{text}"
    body = f"{msh}\r{msa}\r".encode("utf-8")
    return _START_BLOCK + body + _END_BLOCK + _CARRIAGE_RETURN


# ============================================================================
# MLLP TCP server
# ============================================================================

class HL7MLLPServer:
    """
    Async TCP server speaking MLLP framing for inbound HL7 v2 ADT messages.
    Each connection is handled independently; multiple interface engines
    (or one engine with multiple connections) can send concurrently.
    """

    def __init__(self, registry: AdmissionRegistry, host: Optional[str] = None, port: Optional[int] = None) -> None:
        self.registry = registry
        self.host = host or _env("HL7_MLLP_HOST", "0.0.0.0")
        self.port = port or int(_env("HL7_MLLP_PORT", "2575"))
        self._server: Optional[asyncio.base_events.Server] = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_connection, self.host, self.port)
        logger.info("[HL7] MLLP listener started on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("[HL7] MLLP listener stopped")

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        logger.info("[HL7] connection opened from %s", peer)
        buffer = b""
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buffer += chunk

                while _START_BLOCK in buffer and (_END_BLOCK + _CARRIAGE_RETURN) in buffer:
                    start = buffer.index(_START_BLOCK) + 1
                    end = buffer.index(_END_BLOCK + _CARRIAGE_RETURN, start)
                    message_bytes = buffer[start:end]
                    buffer = buffer[end + 2:]

                    ack = await self._process_message(message_bytes)
                    writer.write(ack)
                    await writer.drain()
        except Exception:
            logger.exception("[HL7] connection error from %s", peer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("[HL7] connection closed from %s", peer)

    async def _process_message(self, message_bytes: bytes) -> bytes:
        control_id = "UNKNOWN"
        try:
            raw = message_bytes.decode("utf-8", errors="replace")
            event = parse_adt_message(raw)
            control_id = event.get("message_control_id") or control_id

            record = self.registry.apply_event(event)
            logger.info(
                "[HL7] ADT^%s patient_id=%s status=%s location=%s",
                event["event_type"], record.patient_id, record.status, record.location,
            )
            return _build_ack(control_id, "AA")

        except ValueError as exc:
            logger.warning("[HL7] rejected malformed message: %s", exc)
            return _build_ack(control_id, "AE", str(exc)[:200])
        except Exception:
            logger.exception("[HL7] unexpected error processing message")
            return _build_ack(control_id, "AE", "internal error")
