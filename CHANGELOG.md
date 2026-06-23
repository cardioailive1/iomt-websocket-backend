# Changelog

## v1.0.0 — 2025-10-15

### Added
- 7-agent AI clinical pipeline (Acquisition → Processing → Pattern → Diagnostic → Alert → Personalization → Communication)
- 3-way HMAC-SHA256 challenge/response authentication
- JWT HS256 session tokens with expiry enforcement
- IoMT server WebSocket connector with exponential back-off reconnect
- Back-pressure inbound queue (maxsize configurable, oldest-frame eviction)
- Device session registry with health monitoring (30s stale threshold)
- ACC/AHA 2017 hypertension staging
- Arrhythmia detection: normal sinus, AFib, VTach, VFib, bradycardia, tachycardia
- ST-elevation ischemia detection (±0.1 mV threshold)
- Multi-risk scoring: ASCVD 10-yr, HF, stroke, SCD
- Interactive clinical dashboard (4 views: Overview, Agents, Handshake Protocol, Test Suite)
- Clinical workflow integration guide (8 sections: EHR/FHIR R4, Emergency Response, CDS, etc.)
- Production deployment: Docker, docker-compose, Kubernetes (kustomize), systemd
- Nginx TLS reverse proxy for unified wss:// + https:// on single domain
- 200-test pytest suite (100% pass rate)

### Security
- Secrets loaded exclusively from environment variables (no defaults in code)
- HandshakeConfig frozen dataclass — immutable after startup
- `secrets.token_bytes(32)` for challenge generation (CSPRNG)
- `hmac.compare_digest()` for constant-time signature comparison
- `datetime.now(timezone.utc)` throughout (deprecated `utcnow()` removed)
- Non-root Docker container (uid 1001)
- K8s: least-privilege RBAC, NetworkPolicy, read-only root filesystem
- Systemd: NoNewPrivileges, PrivateTmp, ProtectSystem=strict

### Bug Fixes
- `validate_data_quality`: None HR no longer raises TypeError before penalty
- `classify_hypertension(120, 80)` correctly returns "stage_1" per ACC/AHA 2017
- WebSocket stub handlers updated for websockets library ≥12.0 API
