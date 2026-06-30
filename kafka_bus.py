# kafka_bus.py
# ==============================================================================
# IoMT CardioAI — Kafka Integration for Large/Implanted Device Events
# ==============================================================================
#
# This module is ONLY for the large-device (pacemaker/ICD) vendor gateway
# path. It does NOT touch the existing BLE patient-pairing flow at all —
# that continues to use the in-process MessageBus exactly as before.
#
# Why Kafka here specifically
# -----------------------------
# Vendor gateways (Medtronic CareLink, Abbott Merlin.net, Boston Scientific
# LATITUDE, etc.) can push bursts of events for thousands of implanted
# devices across a hospital network simultaneously — at a different scale
# and reliability profile than one patient's BLE wearable. Kafka gives:
#   - Durable buffering if the 7-agent pipeline is temporarily slow/down
#   - Replay capability for audit/debugging a specific device's history
#   - A clean boundary so vendor-specific HTTP ingestion never blocks
#     directly on pipeline processing time
#
# Topics
# ------
#   iomt.vendor.raw         — every normalized event, keyed by vendor_device_id
#   iomt.vendor.deadletter  — events that failed normalization, for review
#
# Required environment variables
# --------------------------------
#   KAFKA_BOOTSTRAP_SERVERS   e.g. "your-cluster.upstash.io:9092"
#   KAFKA_SASL_USERNAME        (if your provider requires SASL auth)
#   KAFKA_SASL_PASSWORD
#   KAFKA_SECURITY_PROTOCOL    "SASL_SSL" (Upstash/Confluent Cloud) or
#                               "PLAINTEXT" (local testing only)
#
# If KAFKA_BOOTSTRAP_SERVERS is unset, this module degrades gracefully to
# a no-op in-memory queue so the rest of the system keeps working in local
# dev / testing without requiring a live Kafka cluster.
# ==============================================================================

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections import deque
from typing import Any, Awaitable, Callable, Deque, Dict, Optional

logger = logging.getLogger("cardioai.kafka")

TOPIC_VENDOR_RAW        = "iomt.vendor.raw"
TOPIC_VENDOR_DEADLETTER = "iomt.vendor.deadletter"


def _kafka_configured() -> bool:
    return bool(os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "").strip())


# ============================================================================
# Producer
# ============================================================================

class KafkaEventProducer:
    """
    Publishes normalized vendor device events. Falls back to an in-memory
    deque (capped, FIFO) if Kafka is not configured, so local development
    and tests don't require a live cluster.
    """

    def __init__(self) -> None:
        self._producer = None
        self._fallback_queue: Deque[Dict[str, Any]] = deque(maxlen=5000)
        self._enabled = _kafka_configured()

    async def start(self) -> None:
        if not self._enabled:
            logger.warning(
                "[Kafka] KAFKA_BOOTSTRAP_SERVERS not set — using in-memory "
                "fallback queue. Vendor events will NOT survive a restart. "
                "Set KAFKA_BOOTSTRAP_SERVERS for production."
            )
            return

        from aiokafka import AIOKafkaProducer  # imported lazily — optional dep

        kwargs: Dict[str, Any] = {
            "bootstrap_servers": os.environ["KAFKA_BOOTSTRAP_SERVERS"],
            "value_serializer":  lambda v: json.dumps(v).encode("utf-8"),
        }

        security_protocol = os.environ.get("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
        if security_protocol != "PLAINTEXT":
            kwargs["security_protocol"] = security_protocol
            kwargs["sasl_mechanism"]    = os.environ.get("KAFKA_SASL_MECHANISM", "SCRAM-SHA-256")
            kwargs["sasl_plain_username"] = os.environ.get("KAFKA_SASL_USERNAME", "")
            kwargs["sasl_plain_password"] = os.environ.get("KAFKA_SASL_PASSWORD", "")

        self._producer = AIOKafkaProducer(**kwargs)
        await self._producer.start()
        logger.info("[Kafka] producer connected to %s",
                    os.environ["KAFKA_BOOTSTRAP_SERVERS"])

    async def stop(self) -> None:
        if self._producer is not None:
            await self._producer.stop()
            logger.info("[Kafka] producer stopped")

    async def publish(self, topic: str, key: str, value: Dict[str, Any]) -> None:
        if self._producer is not None:
            await self._producer.send_and_wait(
                topic, value=value, key=key.encode("utf-8"),
            )
        else:
            # Fallback path — local dev / Kafka not configured
            self._fallback_queue.append({"topic": topic, "key": key, "value": value})
            logger.debug("[Kafka:fallback] queued event for key=%s (queue depth=%d)",
                        key, len(self._fallback_queue))

    def fallback_queue_snapshot(self) -> list:
        """For diagnostics / the /status endpoint when Kafka isn't configured."""
        return list(self._fallback_queue)


# ============================================================================
# Consumer
# ============================================================================

class KafkaEventConsumer:
    """
    Consumes normalized vendor events and forwards them into the 7-agent
    pipeline via the provided callback. If Kafka is not configured, this
    drains the producer's in-memory fallback queue instead, on a timer —
    giving the exact same end-to-end behavior locally without a real cluster.
    """

    def __init__(
        self,
        producer:    KafkaEventProducer,
        on_event:    Callable[[Dict[str, Any]], Awaitable[None]],
        group_id:    str = "cardioai-pipeline",
    ) -> None:
        self._producer  = producer
        self._on_event  = on_event
        self._group_id  = group_id
        self._consumer  = None
        self._stop      = asyncio.Event()
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="kafka_consumer")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._consumer is not None:
            await self._consumer.stop()

    async def _run(self) -> None:
        if _kafka_configured():
            await self._run_kafka()
        else:
            await self._run_fallback()

    async def _run_kafka(self) -> None:
        from aiokafka import AIOKafkaConsumer

        kwargs: Dict[str, Any] = {
            "bootstrap_servers": os.environ["KAFKA_BOOTSTRAP_SERVERS"],
            "group_id":          self._group_id,
            "value_deserializer": lambda v: json.loads(v.decode("utf-8")),
            "auto_offset_reset": "latest",
        }
        security_protocol = os.environ.get("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")
        if security_protocol != "PLAINTEXT":
            kwargs["security_protocol"] = security_protocol
            kwargs["sasl_mechanism"]    = os.environ.get("KAFKA_SASL_MECHANISM", "SCRAM-SHA-256")
            kwargs["sasl_plain_username"] = os.environ.get("KAFKA_SASL_USERNAME", "")
            kwargs["sasl_plain_password"] = os.environ.get("KAFKA_SASL_PASSWORD", "")

        self._consumer = AIOKafkaConsumer(TOPIC_VENDOR_RAW, **kwargs)
        await self._consumer.start()
        logger.info("[Kafka] consumer subscribed to %s (group=%s)",
                    TOPIC_VENDOR_RAW, self._group_id)
        try:
            async for msg in self._consumer:
                if self._stop.is_set():
                    break
                try:
                    await self._on_event(msg.value)
                except Exception as exc:
                    logger.error("[Kafka] handler error for key=%s: %s",
                                msg.key, exc)
        finally:
            await self._consumer.stop()

    async def _run_fallback(self) -> None:
        """Drain the producer's in-memory queue every 250ms."""
        logger.info("[Kafka:fallback] consumer running against in-memory queue")
        while not self._stop.is_set():
            queue = self._producer._fallback_queue
            while queue:
                item = queue.popleft()
                try:
                    await self._on_event(item["value"])
                except Exception as exc:
                    logger.error("[Kafka:fallback] handler error: %s", exc)
            await asyncio.sleep(0.25)


# ============================================================================
# Module-level singletons
# ============================================================================

producer = KafkaEventProducer()
