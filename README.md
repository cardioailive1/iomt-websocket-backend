# IoMT CardioAI — Production Release v1.0.0

Real-time cardiac monitoring system with HMAC-SHA256 authentication,
7-agent AI clinical pipeline, and live dashboard.

---

## Repository Layout

```
iomt_cardioai/
├── README.md                        ← This file
├── backend/
│   ├── iomt_cardioai_production.py  ← Main production service (1,720 lines)
│   ├── iomt_cardioai_handshake.py   ← Full system with all agents
│   ├── requirements.txt
│   ├── .env.example                 ← Copy to .env, fill secrets
│   ├── Dockerfile                   ← Multi-stage, non-root
│   ├── docker-compose.yml           ← Backend + Nginx stack
│   ├── cardioai.service             ← Systemd unit
│   ├── Makefile
│   ├── .gitignore
│   ├── .dockerignore
│   ├── nginx/
│   │   └── nginx.conf               ← TLS reverse proxy config
│   └── k8s/
│       ├── kustomization.yaml
│       ├── namespace.yaml
│       ├── rbac.yaml
│       ├── secret.yaml              ← Populate via Vault before applying
│       ├── configmap.yaml
│       ├── deployment.yaml          ← 2 replicas, rolling update, HPA
│       ├── service.yaml
│       ├── hpa.yaml                 ← Auto-scales 2→8 pods
│       ├── networkpolicy.yaml
│       └── cardioai-nginx.yaml
├── frontend/
│   ├── iomt_cardioai_dashboard.html ← Interactive clinical dashboard
│   ├── test_preview.html            ← Test suite visual preview
│   ├── index.html                   ← Entry redirect
│   ├── config.js                    ← API URL configuration
│   ├── nginx-static.conf            ← Nginx config for static serving
│   └── Dockerfile                   ← Nginx-based frontend container
├── tests/
│   ├── test_iomt_cardioai_handshake.py  ← 200 pytest tests (100% pass)
│   ├── requirements-test.txt
│   ├── pytest.ini
│   └── run_tests.sh
└── deploy/
    └── deploy_iomt_cardioai.sh      ← Single-file deployment script
```

---

## Quick Start

### 1. Configure secrets

```bash
cp backend/.env.example backend/.env
# Edit backend/.env — fill in IOMT_SHARED_SECRET, IOMT_JWT_SECRET,
# IOMT_SERVER_WS_URL, and CARDIOAI_BACKEND_ID
```

### 2a. Docker Compose (recommended for single-server deployments)

```bash
cd backend
docker-compose up -d --build
```

Exposes:
- `wss://your-host/stream` — WebSocket (iOS app + IoMT devices)
- `https://your-host/api/` — REST API (dashboard live data)
- `https://your-host/`     — Frontend dashboard

### 2b. Kubernetes

```bash
# Populate secrets via Vault first
kubectl create secret generic cardioai-secrets \
  --namespace=cardioai \
  --from-literal=shared_secret="$(vault kv get -field=shared_secret secret/cardioai)" \
  --from-literal=jwt_secret="$(vault kv get -field=jwt_secret secret/cardioai)"

kubectl apply -k backend/k8s/
kubectl rollout status deployment/cardioai-backend -n cardioai
```

### 2c. Bare metal / VM (systemd)

```bash
sudo useradd --system --no-create-home --shell /bin/false cardioai
sudo mkdir -p /opt/cardioai
sudo cp backend/*.py /opt/cardioai/
sudo cp backend/.env /opt/cardioai/.env
sudo chmod 600 /opt/cardioai/.env
sudo pip3 install -r backend/requirements.txt
sudo cp backend/cardioai.service /etc/systemd/system/
sudo systemctl enable --now cardioai
```

### 2d. Use the deployment script

```bash
chmod +x deploy/deploy_iomt_cardioai.sh
deploy/deploy_iomt_cardioai.sh help
```

### 3. Run tests

```bash
cd tests && ./run_tests.sh
# Expected: 200 passed
```

### 4. Open the dashboard

```
https://your-host/
```

Or locally:
```bash
open frontend/iomt_cardioai_dashboard.html
```

---

## Architecture

```
iOS App  ──wss── ┐
IoMT Devices ─── ┤
                 │  HMAC-SHA256 handshake + JWT
                 ▼
           IoMTServerConnector (port 8765)
                 │
           RPMDataPump
                 │
     ┌───────────▼───────────┐
     │   7-Agent AI Pipeline  │
     │  1. DataAcquisition    │
     │  2. DataProcessing     │
     │  3. PatternRecognition │
     │  4. Diagnostic         │
     │  5. AlertMonitoring    │
     │  6. Personalization    │
     │  7. Communication      │
     └───────────┬───────────┘
                 │
        REST API (port 8080)
                 │
     HTML Dashboard ← polling every 5s
```

---

## Security

| Layer               | Implementation                                      |
|---------------------|-----------------------------------------------------|
| Transport           | TLS 1.2/1.3 via Nginx (wss:// + https://)          |
| Authentication      | 3-way HMAC-SHA256 challenge/response                |
| Session             | JWT HS256, 1-hour TTL, timezone-aware expiry        |
| Secrets             | Environment variables only — never in source code   |
| Container           | Non-root (uid 1001), read-only filesystem           |
| K8s                 | Least-privilege RBAC, NetworkPolicy, no privilege   |
| Systemd             | NoNewPrivileges, PrivateTmp, ProtectSystem          |

---

## Environment Variables

| Variable                  | Required | Default               | Description                    |
|---------------------------|----------|-----------------------|--------------------------------|
| `IOMT_SHARED_SECRET`      | ✅       | —                     | HMAC key (min 32 chars)        |
| `IOMT_JWT_SECRET`         | ✅       | —                     | JWT signing key (min 32 chars) |
| `IOMT_SERVER_WS_URL`      | ✅       | —                     | wss://host/stream              |
| `CARDIOAI_BACKEND_ID`     | ✅       | —                     | Unique service identifier      |
| `CARDIOAI_WS_PORT`        | ❌       | 8765                  | WebSocket listener port        |
| `CARDIOAI_HEALTH_PORT`    | ❌       | 8080                  | REST API / health port         |
| `TOKEN_TTL_SECONDS`       | ❌       | 3600                  | JWT session duration           |
| `INBOUND_QUEUE_MAXSIZE`   | ❌       | 2000                  | Back-pressure queue cap        |
| `LOG_LEVEL`               | ❌       | INFO                  | DEBUG\|INFO\|WARNING\|ERROR    |
| `LOG_FORMAT`              | ❌       | text                  | json (prod) or text (dev)      |

---

## Test Coverage

200 tests · 100% pass rate · 20 test suites

| Suite                      | Tests |
|----------------------------|-------|
| PatternRecognitionAgent     | 30    |
| AlertMonitoringAgent        | 22    |
| DiagnosticAgent             | 21    |
| DataAcquisitionAgent        | 15    |
| CardioAISystem              | 13    |
| SecurityManager             | 12    |
| DataProcessingAgent         | 12    |
| DeviceSessionRegistry       | 12    |
| PersonalizationAgent        | 11    |
| End-to-End Pipeline         | 7     |
| MessageBus                  | 7     |
| + 9 more suites             | 37    |

---

**Version**: 1.0.0 · **Python**: 3.12+ · **License**: Proprietary
