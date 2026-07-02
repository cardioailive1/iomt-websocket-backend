# IoMT CardioAI — Backend

Real-time cardiac monitoring backend with a 7-agent clinical AI pipeline, HMAC-secured device ingestion, PostgreSQL-backed authentication with RBAC, self-service clinical staff signup with organization-domain locking, admin approval workflow, and two permanent, independent device data paths: patient-paired BLE wearables for remote patient monitoring (RPM), and clinician-registered implanted devices (pacemakers, ICDs) fed through a vendor gateway + Kafka pipeline. Also includes optional FHIR R4 write-back and HL7 v2 ADT integration for hospital EHR interoperability.

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
   (or via dashboard)   │         │                    │        │
                        │         ▼                     │        │
   Vendor cloud gateway │   PatternRecognitionAgent      ▼ 7-agent
   (Medtronic/Abbott/   │         │                        pipeline
   Boston Scientific) ──┼──▶ POST /vendor-gateway/         │        │
                        │    ingest → Kafka → consumer      │        │
                        │         │                          │        │
                        │         ▼                           │        │
                        │   DiagnosticAgent                    │        │
                        │         │                             │        │
                        │         ▼                              │        │
                        │   AlertMonitoringAgent                          │
                        │         │                                       │
                        │         ▼                                       │
                        │   PersonalizationAgent ──▶ CommunicationAgent ──┼──▶ FHIR R4 write-back
                        │                                     │            │   (Condition + Flag)
   Hospital interface   │                                     │            │
   engine (ADT feed) ───┼──▶ HL7 v2 MLLP listener             │            │
   Mirth/Rhapsody/etc.  │    (admit/discharge/transfer)        │            │
                        └─────────────────────────────────────┼────────────┘
                                                                ▼
                                              GET /health /status /devices
                                              /alerts /reports /admissions
                                              (consumed by iOS app + dashboard)
```

Both device paths — BLE and implanted — feed the same 7-agent pipeline through the same `DataAcquisitionAgent` entry points, so pattern recognition, diagnosis, and alerting behave identically regardless of which path the data arrived through.

## The two device paths — both permanent, both active

| | BLE wearables (RPM) | Large/implanted devices |
|---|---|---|
| Who registers it | Patient, via the iOS app | Clinician (nurse/cardiologist/admin), at implant time — either via API or the dashboard's "+ Register Implant Device" button |
| Where | Anywhere — patient self-pairs at home | Hospital (implant) or home follow-up visit |
| Examples | ECG patch, BP cuff, pulse oximeter | Pacemaker, ICD, CRT-D, loop recorder |
| Registration endpoint | `POST /devices/register` | `POST /clinical/devices/register-implant` |
| Ongoing data path | iOS app → WebSocket bridge → MessageBus | Vendor's cloud gateway → `POST /vendor-gateway/ingest` → Kafka → pipeline |
| RBAC | Patient registers their own only | Clinical staff only — patients cannot self-register an implant |
| Dashboard visibility | "BLE Wearables — Patient Self-Paired" table | "Implanted Devices — Clinician-Registered" table |

A single patient can have both at once: a self-paired BLE wearable for daily RPM, and a clinician-registered pacemaker reporting through their vendor's gateway. Neither path depends on or interferes with the other.

## 7-agent clinical pipeline

| Agent | Responsibility |
|---|---|
| `DataAcquisitionAgent` | Registers devices, validates incoming frame quality, publishes raw frames |
| `DataProcessingAgent` | Cleans/normalizes signal data for downstream agents |
| `PatternRecognitionAgent` | Detects arrhythmia patterns (AFib, VTach, bradycardia, etc.) |
| `DiagnosticAgent` | Maps detected patterns to clinical diagnoses |
| `AlertMonitoringAgent` | Raises alerts based on diagnosis severity and thresholds |
| `PersonalizationAgent` | Adapts thresholds per patient based on baseline history |
| `CommunicationAgent` | Formats and dispatches clinician-facing reports/notifications, and pushes alerts to FHIR (if configured) |

## Authentication & RBAC

* **Patients** — Sign in with Apple (iOS) or email/password; auto-provisioned on first Apple sign-in
* **Clinical staff (nurse, cardiologist, admin)** — self-service signup via `POST /auth/signup` (dashboard's "Create one" screen), OR created directly by an admin via `POST /admin/users`
* Self-service signups start **inactive** and require admin approval — see "Real-world login & account creation" below
* **Organization-domain locking**: the first signup under a given organization name "founds" that organization's allowed email domain(s). Every subsequent signup claiming the same organization name must use a matching email domain, or it's rejected with `organization_domain_mismatch`. Admins can also pre-register an organization with explicit allowed domains via `POST /admin/organizations` before any of its staff sign up.
* All sessions backed by real PostgreSQL `users` + `refresh_tokens` tables — survive restarts and redeploys
* Every login, role change, account status change, and organization change is recorded in `audit_log`
* RBAC enforced per-route via a `require_role(*roles)` decorator stacked on top of JWT auth
* Any non-HTTP exception in a request handler is caught by the CORS middleware, logged with a full traceback, and returned as a proper JSON 500 response with CORS headers attached — this ensures backend bugs always surface as a real, debuggable error in both the browser and Render logs, never as a misleading "could not reach the backend" message

## Admin approval workflow (dashboard)

The dashboard has a dedicated **Admin** tab (visible only to `role: admin`) with:
* **Pending Approval** — every inactive account, with a one-click **Approve** button
* **All Accounts** — every account, with a toggle to Activate/Deactivate

This calls the same `GET /admin/users` / `PATCH /admin/users/{id}` endpoints available via the API — the dashboard just wraps them in a UI so approving staff no longer requires raw API calls or direct database access.

## Files in this repo

| File | Purpose |
|---|---|
| `iomt_cardioai_production.py` | Main backend — HTTP API, 7-agent pipeline, BLE bridge connector, large-device + vendor gateway routes, organization management, FHIR/HL7 wiring |
| `db.py` | PostgreSQL layer — users, refresh tokens, audit log, `LargeDevice`, `Organization`, vendor API keys, vendor event audit |
| `kafka_bus.py` | Kafka producer/consumer for the vendor gateway pipeline (with in-memory fallback if Kafka isn't configured) |
| `fhir_client.py` | FHIR R4 write-back client — pushes alerts to a hospital's EHR as `Condition` + `Flag` resources. Fully opt-in; no-op unless `FHIR_ENABLED=true` |
| `hl7_server.py` | HL7 v2 MLLP listener for ADT (admit/discharge/transfer) feeds. Fully opt-in; no-op unless `HL7_MLLP_ENABLED=true` |
| `iomt_cardioai_dashboard.html` | Static clinical dashboard — served at `/dashboard`. Includes sign-in/signup, live monitoring, device registry (split BLE/implant views), alerts, admin approvals panel, and implant registration form |
| `migrations/001_create_users.sql` | Users, refresh tokens, audit log schema |
| `migrations/002_create_large_devices.sql` | Large device registry, vendor keys, vendor event audit schema |
| `migrations/003_create_organizations.sql` | Canonical organization registry with admin-managed allowed email domains |
| `migrations/004_add_organization_to_users.sql` | Adds the `organization` column to `users` (required by staff signup and the domain-lock feature) |
| `migrations/005_add_fhir_config_and_device_org_link.sql` | Adds per-organization FHIR config columns and links `large_devices` to `organizations`, enabling multi-hospital FHIR routing |
| `render.yaml` | Render.com Blueprint — provisions PostgreSQL + the API service |
| `requirements.txt` | Python dependencies (`aiohttp`, `asyncpg`, `aiokafka`, `bcrypt`, etc.) |

## Deployment Guide

### Step 1 — Choose a Kafka provider

Render does not host Kafka natively. Upstash Kafka (free tier, serverless, standard Kafka protocol) is the easiest fit for getting started:

1. Sign up at https://upstash.com → create a Kafka cluster
2. Copy the bootstrap endpoint, username, and password it gives you

Any provider speaking the standard Kafka wire protocol works (Confluent Cloud, AWS MSK, self-hosted) — just adjust `KAFKA_SECURITY_PROTOCOL` / `KAFKA_SASL_MECHANISM` in `render.yaml` to match.

If you don't have Kafka credentials yet, leave `KAFKA_BOOTSTRAP_SERVERS` unset — the system automatically falls back to an in-memory queue so everything still works for testing. Events just won't survive a process restart until you add real Kafka credentials.

### Step 2 — Push everything and deploy

```bash
git add iomt_cardioai_production.py db.py kafka_bus.py fhir_client.py hl7_server.py \
        iomt_cardioai_dashboard.html render.yaml requirements.txt migrations/

git commit -m "Deploy IoMT CardioAI with signup, admin approvals, FHIR/HL7 integration"
git push origin main
```

In the Render Dashboard: New + → Blueprint → connect this repo. Render reads `render.yaml` and provisions the PostgreSQL database and the API service automatically, wiring `DATABASE_URL` for you.

**Important:** `fhir_client.py` and `hl7_server.py` must be present at the project root (same folder as `iomt_cardioai_production.py`) — the app imports from both at startup and will crash with `ModuleNotFoundError` on boot if either is missing, even if you never enable FHIR or HL7 (`FHIR_ENABLED`/`HL7_MLLP_ENABLED` default to disabled, but the files themselves must still exist so the imports succeed).

### Step 3 — Run all five migrations, in order

```bash
psql "<connection-string>" -f migrations/001_create_users.sql
psql "<connection-string>" -f migrations/002_create_large_devices.sql
psql "<connection-string>" -f migrations/003_create_organizations.sql
psql "<connection-string>" -f migrations/004_add_organization_to_users.sql
psql "<connection-string>" -f migrations/005_add_fhir_config_and_device_org_link.sql
```

* Migration 001 seeds three test accounts (`patient@hospital.local`, `nurse@hospital.local`, `cardio@hospital.local`, all password `changeme_in_prod` — change these before going live, or delete them and use the real signup flow instead).
* Migration 002 creates `large_devices`, `vendor_api_keys`, and `vendor_events_raw`, and seeds one test vendor API key (Medtronic, value `test-vendor-key-do-not-use-in-production`).
* Migration 003 creates the `organizations` table used for the email-domain lock on staff signup.
* Migration 004 adds the `organization` column to `users` — **required**, since `create_staff_user()` and the signup flow write to this column; without it, every signup attempt fails with a raw database error (`UndefinedColumnError`).
* Migration 005 adds per-organization FHIR config columns and links `large_devices` to `organizations`, enabling multi-hospital FHIR routing and admission-aware alerting.

If you're adding these migrations to an existing deployment that already has `001`/`002` applied, you only need to run `003`, `004`, and `005` — they're additive and don't touch existing data.

### Step 4 — Fill in secrets

On `cardioai-api` (Dashboard → Environment):

```
IOMT_SHARED_SECRET       = <32+ char random string>
IOMT_JWT_SECRET          = <32+ char random string>
KAFKA_BOOTSTRAP_SERVERS  = <your Upstash/Confluent bootstrap endpoint>
KAFKA_SASL_USERNAME      = <from your Kafka provider>
KAFKA_SASL_PASSWORD      = <from your Kafka provider>
```

Generate the two random secrets with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Optional — FHIR R4 write-back** (leave unset to disable entirely):

```
FHIR_ENABLED                    = true
FHIR_BASE_URL                   = https://fhir.hospital.org/api/FHIR/R4
FHIR_TOKEN_URL                  = https://hospital.org/oauth2/token
FHIR_CLIENT_ID                  = <from the hospital's app registration>
FHIR_CLIENT_SECRET              = <from the hospital's app registration>
FHIR_PATIENT_IDENTIFIER_SYSTEM  = <identifier system URI matching your patient_id values>
FHIR_MIN_ALERT_LEVEL            = medium   # optional, default "medium" — low alerts stay internal
```

Get `FHIR_BASE_URL`, `FHIR_TOKEN_URL`, and app credentials from the hospital's EHR integration team (Epic App Orchard, Cerner Code Console, etc.) — there's no way to test against a real instance without their sandbox access. `FHIR_PATIENT_IDENTIFIER_SYSTEM` is critical: your internal `patient_id` is not the same as the hospital's FHIR `Patient.id`, so this tells the client which identifier system to search by to resolve the two.

**Optional — HL7 v2 ADT integration** (leave unset to disable entirely):

```
HL7_MLLP_ENABLED = true
HL7_MLLP_HOST    = 0.0.0.0
HL7_MLLP_PORT    = 2575
```

**Render-specific limitation:** HL7/MLLP is raw TCP, not HTTP. Render's standard web services only route HTTP traffic to the public `$PORT` — an external interface engine cannot reach an MLLP port on a normal Render web service. To actually receive ADT feeds, you need either a Render **Private Service** (reachable only from other services inside Render's network) or a host/plan that exposes a raw TCP port. Confirm reachability with whoever manages the hospital's interface engine (Mirth/Rhapsody/Cloverleaf) before relying on this in production.

### Step 5 — Register a clinician account, then a test implant

Use the seeded test cardiologist account, then:

```bash
# 1. Log in as the clinician
curl -X POST https://your-app.onrender.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"cardio@hospital.local","password":"changeme_in_prod"}'
# → copy the access_token from the response

# 2. Register a test pacemaker against a patient (or use the dashboard's
#    "+ Register Implant Device" button on the Devices tab instead)
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

### Step 6 — Simulate a vendor gateway push

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

You should get back `{"status": "accepted"}` with HTTP 202. Within a second or two, check `GET /devices` and `GET /alerts` — `MDT-TEST-001` should appear under the "Implanted Devices" table on the dashboard, and an AFib-related alert should appear if the HR/pattern crosses the pipeline's thresholds. If `FHIR_ENABLED=true`, the alert also gets pushed to your configured FHIR server as `Condition` + `Flag` resources.

## Real-world login & account creation

The migration seeds three test accounts so you can verify the system works immediately — but for real use, clinical staff create their own accounts through the dashboard's Sign Up screen, and patients sign in with Apple.

### Patients

Sign in with Apple via the iOS app (`POST /auth/apple`). The first successful sign-in auto-provisions a patient account — no admin action needed, no signup form.

### Clinical staff (nurse / cardiologist / admin)

1. Open the dashboard (`https://your-app.onrender.com/dashboard`)
2. Click "Create one" under the Sign In form
3. Fill in name, organization, hospital email, password, and role
4. Submit — the account is created but starts **inactive**
   * If this is the first signup for a brand-new organization name, that organization is auto-registered with this email's domain as its founding allowed domain
   * If the organization already has a locked domain (either from an earlier signup or admin pre-registration), the email domain must match, or the signup is rejected
5. An existing admin approves it — either through the dashboard's **Admin** tab (Pending Approval → Approve), or via `PATCH /admin/users/{id}` with `{"is_active": true}`
6. Once approved, the new user can sign in normally

### The bootstrap problem — your very first admin account

A brand-new deployment has no existing admin to approve the first signup. Activate the first admin account directly in the database, once:

```sql
UPDATE users SET is_active = true WHERE email = 'your-real-admin-email@hospital.local';
```

After that one manual step, your first admin can sign in and approve every subsequent signup through the dashboard's Admin tab — no more direct SQL needed for anyone after the first account.

## API reference

### Auth

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/auth/apple` | None | iOS Sign in with Apple |
| `POST` | `/auth/login` | None | Email/password login |
| `POST` | `/auth/signup` | None | Clinical staff self-registration (pending admin approval; enforces organization-domain lock) |
| `POST` | `/auth/refresh` | None | Rotate refresh token |
| `POST` | `/auth/logout` | Bearer | Revoke session |

### Devices & clinical data

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/devices/register` | Bearer | Patient self-pairs a BLE device |
| `GET` | `/devices` | Bearer | List devices, with `device_type` (patients see only their own) |
| `POST` | `/clinical/devices/register-implant` | Bearer (nurse/cardiologist/admin) | Registers a pacemaker/ICD/etc. against a patient |
| `GET` | `/clinical/devices/implants?patient_id=...&vendor=...` | Bearer | Lists registered implants (patients see only their own) |
| `POST` | `/vendor-gateway/ingest` | `X-Vendor-Api-Key` | Machine-to-machine vendor device ingestion |
| `GET` | `/alerts` | Bearer | List active alerts |
| `GET` | `/reports` | Bearer | List clinical reports |
| `GET` | `/admissions` | Bearer | Current admission status from HL7 ADT feed (patients see only their own; empty if HL7 not configured) |

### Admin

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/admin/users` | Bearer (admin) | List user accounts |
| `POST` | `/admin/users` | Bearer (admin) | Create a clinician/admin account directly (active immediately) |
| `PATCH` | `/admin/users/{id}` | Bearer (admin) | Approve/deactivate an account, or change its role |
| `POST` | `/admin/vendor-keys` | Bearer (admin) | Generate a new vendor API key (shown once) |
| `GET` | `/admin/organizations` | Bearer (admin) | List canonical organizations and their allowed domains |
| `POST` | `/admin/organizations` | Bearer (admin) | Pre-register an organization with a locked domain list |
| `PATCH` | `/admin/organizations/{id}` | Bearer (admin) | Update an organization's allowed domains, name, or per-hospital FHIR configuration |

### Infrastructure

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | None | Liveness probe |
| `GET` | `/status` | Bearer | Full bridge/pipeline status |
| `GET` | `/dashboard` | None | Serves the static clinical dashboard |

### `POST /vendor-gateway/ingest` responses

* `202 accepted` — normalized, matched to a registered device, published to Kafka
* `404 device_not_registered` — `vendor_device_id` isn't registered or is inactive; a clinician must register it first
* `422 normalization_failed` — payload didn't match the expected shape for that vendor

Every payload — matched or not — is recorded in `vendor_events_raw` for audit.

## Connecting a REAL vendor (when you have a contract)

The three normalizer functions in `iomt_cardioai_production.py` (`_normalize_medtronic_payload`, `_normalize_abbott_payload`, `_normalize_boston_scientific_payload`) are best-guess implementations based on each vendor's publicly documented export formats — not verified against an actual signed integration contract.

Before connecting a real vendor:

1. Get their actual gateway payload schema from their integration team
2. Update the corresponding `_normalize_*_payload` function to match the real field names exactly
3. Generate a real API key via `POST /admin/vendor-keys` and hand it to the vendor's integration team
4. Test with their sandbox/staging gateway before going live

## What's not built yet

* **Multi-hospital routing for BLE-sourced alerts**: organization-based FHIR/HL7 routing (migration 005) works for **implant-sourced** alerts, since implants are linked to the registering clinician's organization at registration time. BLE wearables have no such link yet — their alerts always use the global `FHIR_*`/`HL7_ORU_*` environment variables. Linking BLE devices to an organization (e.g. via the patient's care team) would close this gap.
* **HL7 v2 outbound beyond ORU**: only ORU^R01 (observation result) is implemented for outbound. Other outbound message types (e.g. MDM for documents) are not built.

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
| `FHIR_ENABLED` | Optional | `true` to activate the global (single-tenant) FHIR R4 write-back (default: disabled). Organizations with their own FHIR config (via `PATCH /admin/organizations/{id}`) don't need this. |
| `FHIR_BASE_URL` | If FHIR enabled | Hospital's FHIR R4 base URL (global fallback) |
| `FHIR_TOKEN_URL` | If FHIR enabled | OAuth2 token endpoint for client-credentials grant (global fallback) |
| `FHIR_CLIENT_ID` / `FHIR_CLIENT_SECRET` | If FHIR enabled | Registered app credentials (global fallback) |
| `FHIR_PATIENT_IDENTIFIER_SYSTEM` | If FHIR enabled | Identifier system URI matching your internal `patient_id` values (global fallback) |
| `FHIR_MIN_ALERT_LEVEL` | Optional | Minimum alert level pushed to FHIR: `low`\|`medium`\|`high`\|`critical` (default: `medium`) |
| `HL7_MLLP_ENABLED` | Optional | `true` to start the inbound HL7 v2 MLLP listener (ADT) (default: disabled) |
| `HL7_MLLP_HOST` | Optional | Bind host for the inbound MLLP listener (default: `0.0.0.0`) |
| `HL7_MLLP_PORT` | Optional | Bind port for the inbound MLLP listener (default: `2575`) |
| `HL7_ADMISSION_ALERT_SUPPRESSION_ENABLED` | Optional | `true` to suppress redundant LOW-severity alerts for currently-admitted patients (default: disabled). Never affects MEDIUM/HIGH/CRITICAL alerts. |
| `HL7_ORU_ENABLED` | Optional | `true` to send outbound HL7 v2 ORU^R01 messages for each alert (default: disabled) |
| `HL7_ORU_HOST` / `HL7_ORU_PORT` | If ORU enabled | Destination interface engine host/port for outbound ORU messages |
