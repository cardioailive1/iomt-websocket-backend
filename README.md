# IoMT CardioAI — Backend

Real-time cardiac monitoring backend with a 7-agent clinical AI pipeline,
HMAC-secured device ingestion, PostgreSQL-backed authentication with RBAC,
and two permanent, independent device data paths: patient-paired BLE
wearables for remote patient monitoring (RPM), and clinician-registered
implanted devices (pacemakers, ICDs) fed through a vendor gateway + Kafka
pipeline.

---

## Architecture overview

```
                        ┌─────────────────────────────┐
   Patient (iOS app)    │                             │
   BLE wearable ────────┼──▶ POST /devices/register    │
   (ECG patch, BP cuff, │    (patient self-pairs)      │
   pulse oximeter)      │         │                     │
                        │         ▼                     │
                        │   In-process MessageBus        │
                        │         │                       │
   Clinician            │         ▼                        │
   registers implant ───┼──▶ DataAcquisitionAgent ──┐        │
   POST /clinical/      │         │                  │        │
   devices/             │         ▼                  │        │
   register-implant     │   DataProcessingAgent       │        │
                        │         │                    │        │
   Vendor cloud gateway │         ▼                     │        │
   (Medtronic/Abbott/   │   PatternRecognitionAgent      ▼ 7-agent
   Boston Scientific) ──┼──▶ POST /vendor-gateway/         pipeline
                        │    ingest → Kafka → consumer  │        │
                        │         │                      │        │
                        │         ▼                       │        │
                        │   DiagnosticAgent                │        │
                        │         │                         │        │
                        │         ▼                          │        │
                        │   AlertMonitoringAgent                      │
                        │         │                                   │
                        │         ▼                                   │
                        │   PersonalizationAgent ──▶ CommunicationAgent
                        │                                     │
                        └─────────────────────────────────────┼────────
                                                                ▼
                                              GET /health /status /devices
                                              /alerts /reports
                                              (consumed by iOS app + dashboard)
```

Both device paths — BLE and implanted — feed the **same** 7-agent pipeline
through the same `DataAcquisitionAgent` entry points, so pattern
recognition, diagnosis, and alerting behave identically regardless of
which path the data arrived through.

---

## The two device paths — both permanent, both active

| | BLE wearables (RPM) | Large/implanted devices |
|---|---|---|
| **Who registers it** | Patient, via the iOS app | Clinician (nurse/cardiologist/admin), at implant time |
| **Where** | Anywhere — patient self-pairs at home | Hospital (implant) or home follow-up visit |
| **Examples** | ECG patch, BP cuff, pulse oximeter | Pacemaker, ICD, CRT-D, loop recorder |
| **Registration endpoint** | `POST /devices/register` | `POST /clinical/devices/register-implant` |
| **Ongoing data path** | iOS app → WebSocket bridge → MessageBus | Vendor's cloud gateway → `POST /vendor-gateway/ingest` → Kafka → pipeline |
| **RBAC** | Patient registers their own only | Clinical staff only — patients cannot self-register an implant |

A single patient can have both at once: a self-paired BLE wearable for
daily RPM, and a clinician-registered pacemaker reporting through their
vendor's gateway. Neither path depends on or interferes with the other.

---

## 7-agent clinical pipeline

| Agent | Responsibility |
|---|---|
| `DataAcquisitionAgent` | Registers devices, validates incoming frame quality, publishes raw frames |
| `DataProcessingAgent` | Cleans/normalizes signal data for downstream agents |
| `PatternRecognitionAgent` | Detects arrhythmia patterns (AFib, VTach, bradycardia, etc.) |
| `DiagnosticAgent` | Maps detected patterns to clinical diagnoses |
| `AlertMonitoringAgent` | Raises alerts based on diagnosis severity and thresholds |
| `PersonalizationAgent` | Adapts thresholds per patient based on baseline history |
| `CommunicationAgent` | Formats and dispatches clinician-facing reports/notifications |

---

## Authentication & RBAC

- **Patients** — Sign in with Apple (iOS) or email/password; auto-provisioned on first Apple sign-in
- **Clinical staff** (nurse, cardiologist, admin) — email/password, created by an admin via `POST /admin/users`
- All sessions backed by real PostgreSQL `users` + `refresh_tokens` tables — survive restarts and redeploys
- Every login, role change, and account status change is recorded in `audit_log`
- RBAC enforced per-route via a `require_role(*roles)` decorator stacked on top of JWT auth

---

## Files in this repo

| File | Purpose |
|---|---|
| `iomt_cardioai_production.py` | Main backend — HTTP API, 7-agent pipeline, BLE bridge connector, large-device + vendor gateway routes |
| `db.py` | PostgreSQL layer — users, refresh tokens, audit log, `LargeDevice`, vendor API keys, vendor event audit |
| `kafka_bus.py` | Kafka producer/consumer for the vendor gateway pipeline (with in-memory fallback if Kafka isn't configured) |
| `migrations/001_create_users.sql` | Users, refresh tokens, audit log schema |
| `migrations/002_create_large_devices.sql` | Large device registry, vendor keys, vendor event audit schema |
| `render.yaml` | Render.com Blueprint — provisions PostgreSQL + the API service |
| `requirements.txt` | Python dependencies (`aiohttp`, `asyncpg`, `aiokafka`, `bcrypt`, etc.) |

---

# Deployment Guide

## Step 1 — Choose a Kafka provider

Render does not host Kafka natively. **Upstash Kafka** (free tier,
serverless, standard Kafka protocol) is the easiest fit for getting
started:

1. Sign up at https://upstash.com → create a Kafka cluster
2. Copy the bootstrap endpoint, username, and password it gives you

Any provider speaking the standard Kafka wire protocol works (Confluent
Cloud, AWS MSK, self-hosted) — just adjust `KAFKA_SECURITY_PROTOCOL` /
`KAFKA_SASL_MECHANISM` in `render.yaml` to match.

**If you don't have Kafka credentials yet**, leave `KAFKA_BOOTSTRAP_SERVERS`
unset — the system automatically falls back to an in-memory queue so
everything still works for testing. Events just won't survive a process
restart until you add real Kafka credentials.

---

## Step 2 — Push everything and deploy

```bash
git add iomt_cardioai_production.py db.py kafka_bus.py \
        render.yaml requirements.txt migrations/

git commit -m "Add large-device registration + Kafka vendor gateway pipeline"
git push origin main
```

In the Render Dashboard: **New + → Blueprint → connect this repo.**
Render reads `render.yaml` and provisions the PostgreSQL database and the
API service automatically, wiring `DATABASE_URL` for you.

---

## Step 3 — Run BOTH migrations (in order)

```bash
psql "<connection-string>" -f migrations/001_create_users.sql
psql "<connection-string>" -f migrations/002_create_large_devices.sql
```

The first migration seeds three test accounts (`patient@hospital.local`,
`nurse@hospital.local`, `cardio@hospital.local`, all password
`changeme_in_prod` — **change these before going live**).

The second migration creates `large_devices`, `vendor_api_keys`, and
`vendor_events_raw`, and seeds one **test** vendor API key (Medtronic,
value `test-vendor-key-do-not-use-in-production`) so you can exercise the
ingestion endpoint immediately without waiting on a real vendor.

---

## Step 4 — Fill in secrets

**On `cardioai-api`** (Dashboard → Environment):
```
IOMT_SHARED_SECRET      = <32+ char random string>
IOMT_JWT_SECRET          = <32+ char random string>
KAFKA_BOOTSTRAP_SERVERS  = <your Upstash/Confluent bootstrap endpoint>
KAFKA_SASL_USERNAME       = <from your Kafka provider>
KAFKA_SASL_PASSWORD       = <from your Kafka provider>
```

Generate the two random secrets with:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## Step 5 — Register a clinician account, then a test implant

Use the seeded test cardiologist account, then:

```bash
# 1. Log in as the clinician
curl -X POST https://your-app.onrender.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"cardio@hospital.local","password":"changeme_in_prod"}'
# → copy the access_token from the response

# 2. Register a test pacemaker against a patient
curl -X POST https://your-app.onrender.com/clinical/devices/register-implant \
  -H "Authorization: Bearer <clinician-access-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "vendor_device_id": "MDT-TEST-001",
    "vendor": "medtronic",
    "device_type": "pacemaker",
    "patient_id": "PT_12345",
    "model_number": "Azure XT DR MRI",
    "implanted_at": "2026-01-15"
  }'
```

---

## Step 6 — Simulate a vendor gateway push

```bash
curl -X POST https://your-app.onrender.com/vendor-gateway/ingest \
  -H "X-Vendor-Api-Key: test-vendor-key-do-not-use-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "deviceSerialNumber": "MDT-TEST-001",
    "heartRateBpm": 145,
    "episodeType": "AF",
    "recordedAt": "2026-01-01T12:00:00Z"
  }'
```

You should get back `{"status": "accepted"}` with HTTP 202. Within a second
or two, check `GET /devices` and `GET /alerts` (with the clinician's
Bearer token) — `MDT-TEST-001` should appear as a registered, active
device, and an AFib-related alert should appear if the HR/pattern crosses
the pipeline's thresholds.

---

## API reference — large device & vendor gateway endpoints

### `POST /clinical/devices/register-implant`
**Role required:** nurse, cardiologist, or admin
Registers a pacemaker/ICD/etc. against a patient. Full request/response
shapes are in the docstring inside `iomt_cardioai_production.py`.

### `GET /clinical/devices/implants?patient_id=...&vendor=...`
**Role required:** any authenticated user (patients see only their own)
Lists registered implants.

### `POST /vendor-gateway/ingest`
**Auth:** `X-Vendor-Api-Key` header — NOT a JWT. Machine-to-machine
endpoint for vendor gateways only; never called by the iOS app or a
clinician directly.

Returns:
- `202 accepted` — normalized, matched to a registered device, published to Kafka
- `404 device_not_registered` — `vendor_device_id` isn't registered or is inactive; a clinician must register it first
- `422 normalization_failed` — payload didn't match the expected shape for that vendor

Every payload — matched or not — is recorded in `vendor_events_raw` for audit.

### `POST /admin/vendor-keys`
**Role required:** admin only
Generates a new vendor API key. The raw key value is returned **exactly
once** in the response — store it immediately, it cannot be recovered
afterward (only its SHA-256 hash is kept).

```bash
curl -X POST https://your-app.onrender.com/admin/vendor-keys \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"vendor": "abbott", "label": "Abbott Merlin.net production gateway"}'
```

---

## Connecting a REAL vendor (when you have a contract)

The three normalizer functions in `iomt_cardioai_production.py`
(`_normalize_medtronic_payload`, `_normalize_abbott_payload`,
`_normalize_boston_scientific_payload`) are **best-guess implementations**
based on each vendor's publicly documented export formats — not verified
against an actual signed integration contract, since none exists yet.

Before connecting a real vendor:

1. Get their actual gateway payload schema from their integration team
2. Update the corresponding `_normalize_*_payload` function to match the real field names exactly
3. Generate a real API key via `POST /admin/vendor-keys` and hand it to the vendor's integration team
4. Test with their sandbox/staging gateway before going live

---

## Core API reference (auth, devices, alerts)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | None | Liveness probe |
| `GET` | `/status` | Bearer | Full bridge/pipeline status |
| `POST` | `/auth/apple` | None | iOS Sign in with Apple |
| `POST` | `/auth/login` | None | Email/password login |
| `POST` | `/auth/refresh` | None | Rotate refresh token |
| `POST` | `/auth/logout` | Bearer | Revoke session |
| `POST` | `/devices/register` | Bearer | Patient self-pairs a BLE device |
| `GET` | `/devices` | Bearer | List devices (patients see only their own) |
| `GET` | `/alerts` | Bearer | List active alerts |
| `GET` | `/reports` | Bearer | List clinical reports |
| `GET` | `/admin/users` | Bearer (admin) | List user accounts |
| `POST` | `/admin/users` | Bearer (admin) | Create a clinician/admin account |
| `PATCH` | `/admin/users/{id}` | Bearer (admin) | Update role/status |

---

## Environment variables reference

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string (auto-wired by `render.yaml`) |
| `IOMT_SHARED_SECRET` | Yes | HMAC secret for the BLE device handshake protocol |
| `IOMT_JWT_SECRET` | Yes | Signs JWT access/refresh tokens |
| `KAFKA_BOOTSTRAP_SERVERS` | Recommended | Kafka cluster endpoint for vendor gateway pipeline (falls back to in-memory queue if unset) |
| `KAFKA_SASL_USERNAME` / `KAFKA_SASL_PASSWORD` | If using SASL auth | Kafka credentials |
| `KAFKA_SECURITY_PROTOCOL` | If not PLAINTEXT | e.g. `SASL_SSL` for Upstash/Confluent |
| `CARDIOAI_BACKEND_ID` | Yes | Identifier for this backend instance |
| `IOMT_SERVER_WS_URL` | For BLE hardware gateway | Outbound WebSocket target for `IoMTServerConnector` |
| `APPLE_VERIFY_TOKENS` | iOS only | Whether to verify Apple Sign In tokens against Apple's servers |
| `ALLOWED_ORIGINS` | Production | CORS allowed origins — set to your real domain before going live |
