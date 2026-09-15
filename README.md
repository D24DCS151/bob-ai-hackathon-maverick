<div align="center">

# THREATICAP

### Threat Intelligence Correlation & Alert Prioritisation System

**From sensor noise to command decision.**

Multi-source threat correlation, MITRE ATT&CK mapping, mission-aware risk scoring, and commander-ready BLUF reporting — engineered for defence and intelligence SOC environments.

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-OpenAPI%20documented-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063)](https://docs.pydantic.dev/)
[![Docker](https://img.shields.io/badge/Docker-containerised-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/status-production--oriented-success)]()
[![License](https://img.shields.io/badge/license-Proprietary-lightgrey)]()

</div>

---

## Table of Contents

1. [Mission](#mission)
2. [Operational Capability Matrix](#operational-capability-matrix)
3. [Architecture Overview](#architecture-overview)
4. [Data Flow](#data-flow)
5. [Module Map](#module-map)
6. [Quick Start — Local Development](#quick-start--local-development)
7. [Running with Docker](#running-with-docker)
8. [API Reference](#api-reference)
9. [Configuration Reference](#configuration-reference)
10. [MITRE ATT&CK Knowledge Base](#mitre-attck-knowledge-base)
11. [Sample Data & Demo Scenario](#sample-data--demo-scenario)
12. [Testing](#testing)
13. [Extension Points](#extension-points)
14. [Security & Operational Considerations](#security--operational-considerations)
15. [Kubernetes Deployment](#kubernetes-deployment)
16. [Roadmap](#roadmap)
17. [Development & Contributing](#development--contributing)
18. [Team](#team)

---

## Mission

Modern SOCs — national, military, and coalition — are saturated with alerts arriving from disconnected sensors: SIEM platforms, EDR agents, satellite and ISR feeds, HUMINT and SIGINT reporting, and STIX/TAXII intelligence exchanges. Analysts spend the majority of their time triaging this volume rather than acting on it, and a critical alert hitting a live command-and-control (C2) asset can be indistinguishable from noise hitting an idle workstation — unless the system understands the mission context in which it is operating.

**THREATICAP exists to close that gap.**

It ingests alerts from heterogeneous sources, correlates related activity into coherent threats, maps observed behaviour to MITRE ATT&CK, applies an explainable and mission-aware risk score, and produces a structured **BLUF (Bottom Line Up Front)** report tailored to the reader — commander, watch officer, or analyst — so that the right decision reaches the right person in seconds, not hours.

Every scoring decision, correlation, and report is written to an immutable audit trail. Every threshold, weight, and connector is configuration-driven. Nothing in the scoring or correlation logic is hard-coded, and every output is explainable back to its source evidence — a requirement for any system intended to inform command decisions.

---

## Operational Capability Matrix

| Capability | Detail |
|---|---|
| **Multi-source ingestion** | SIEM (JSON / CEF / LEEF), EDR and network telemetry, HUMINT / SIGINT / OSINT reporting, STIX 2.1 / TAXII 2.1 feeds |
| **Correlation engine** | IOC matching, temporal proximity, asset overlap, and behavioural / MITRE pattern analysis, unified via Union-Find clustering |
| **False-positive reduction** | Heuristic FP scoring with configurable whitelists and multi-source corroboration weighting |
| **MITRE ATT&CK mapping** | Technique, sub-technique, and tactic enrichment from a maintainable YAML knowledge base |
| **Risk-based prioritisation** | Explainable 5-factor weighted scoring with configurable tiers — CRITICAL / HIGH / MEDIUM / LOW |
| **BLUF report generation** | Commander-ready output: bottom line, supporting evidence, recommended actions, investigation steps |
| **REST API** | Full OpenAPI-documented FastAPI service |
| **Air-gapped operation** | Offline CLI execution via `python -m threaticap`, no external dependencies required |
| **Immutable audit trail** | Every correlation decision, score, and report is permanently and traceably logged |

---

## Architecture Overview

<img width="1852" height="839" alt="THREATICAP architecture diagram" src="https://github.com/user-attachments/assets/6a27343f-6e44-4eab-ac85-76d93134d69b" />

THREATICAP is organised as a linear, auditable pipeline. Each stage consumes and produces only canonical, validated data models — there is no implicit coupling between stages, which keeps the system testable, extensible, and safe to modify in isolation.

---

## Data Flow

<img width="1915" height="354" alt="THREATICAP data flow diagram" src="https://github.com/user-attachments/assets/a41d1633-780a-4b81-832a-07fc2876c525" />

**Key invariant:** every component receives and returns only canonical model types. Raw source data is preserved in `Alert.raw_payload` for forensic reference but is never consumed downstream — all correlation, scoring, and reporting logic operates exclusively on validated, normalised models.

---

## Module Map

```text
threaticap/
├── __init__.py             # Package version
├── __main__.py             # python -m threaticap entry point
├── pipeline.py             # ThreatPipeline orchestrator
├── cli.py                  # Click CLI
├── logging_config.py       # Structured JSON / console logging
│
├── models/                 # Canonical Pydantic v2 data models
│   ├── alert.py             # Alert, Observable, AssetContext
│   ├── correlated_threat.py # CorrelatedThreat, EvidenceLink
│   ├── mitre.py             # MitreMapping, MitreTechnique
│   ├── priority.py          # PriorityScore, ScoreComponent
│   ├── bluf.py               # BlufReport, ActionItem
│   └── audit.py              # AuditRecord (immutable, append-only)
│
├── ingestion/               # Multi-source ingestion layer
│   ├── base_connector.py    # Abstract BaseConnector interface
│   ├── normaliser.py        # Schema enforcement + IOC extraction
│   ├── deduplicator.py      # LRU-cached deduplication
│   ├── enricher.py          # Asset registry + TLP assignment
│   ├── pipeline.py          # IngestionPipeline orchestrator
│   └── connectors/
│       ├── siem_connector.py           # SIEM (JSON/CEF/LEEF/HTTP)
│       ├── edr_connector.py            # EDR/network (JSON/CSV/syslog)
│       ├── intel_report_connector.py   # HUMINT/SIGINT/OSINT
│       └── stix_connector.py           # STIX 2.1 / TAXII 2.1
│
├── correlation/             # Correlation engine
│   ├── engine.py             # CorrelationEngine (Union-Find clustering)
│   ├── ioc_correlator.py     # Shared observable matching
│   ├── temporal_correlator.py    # Time-window grouping
│   ├── asset_correlator.py   # Asset/hostname/segment overlap
│   ├── behaviour_correlator.py   # MITRE technique/campaign matching
│   └── fp_filter.py          # False-positive probability scoring
│
├── mapping/
│   └── mitre_mapper.py       # ATT&CK technique enrichment
│
├── scoring/
│   └── prioritisation_engine.py  # 5-factor weighted scoring
│
├── reporting/
│   └── bluf_generator.py     # BLUF report generation
│
├── storage/
│   └── repositories.py       # Abstract repos + in-memory implementations
│
└── api/
    ├── app.py                 # FastAPI application + all endpoints
    ├── schemas.py              # API request/response schemas
    └── dependencies.py         # FastAPI dependency injection
```

---

## Quick Start — Local Development

### Prerequisites

- Python 3.11+
- `pip`

### Install

```bash
git clone https://github.com/defence-org/threaticap.git
cd threaticap
pip install -e ".[dev]"
```

### Run the demo (no server required)

```bash
python -m threaticap demo --data-dir data/sample
```

Ingests all sample data files, runs the full pipeline end to end, and prints BLUF reports to the terminal — suitable for air-gapped demonstration.

### Start the API server

```bash
python -m threaticap serve --host 0.0.0.0 --port 8080
# API docs: http://localhost:8080/api/v1/docs
```

### Run the test suite

```bash
pytest tests/ -v --tb=short
```

---

## Running with Docker

### Build and run

```bash
docker build -t threaticap:latest .
docker run -p 8080:8080 \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/data:/app/data:ro \
  threaticap:latest
```

### Docker Compose — full stack (PostgreSQL + Redis)

```bash
# Copy and edit environment config
cp .env.example .env

# Start all services
docker compose up -d

# View logs
docker compose logs -f threaticap-api

# Run the demo inside the container
docker compose run --rm threaticap-api python -m threaticap demo

# Stop all services
docker compose down
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `THREATICAP_CONFIG` | `config/config.yaml` | Path to configuration file |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG` / `INFO` / `WARNING` / `ERROR`) |
| `JSON_LOGS` | `false` | Emit structured JSON logs |
| `HOST` | `0.0.0.0` | API bind address |
| `PORT` | `8080` | API port |
| `DB_PASSWORD` | `changeme-in-production` | PostgreSQL password |
| `REDIS_PASSWORD` | `changeme-in-production` | Redis password |

> Default credentials are placeholders for local development only. See [Security & Operational Considerations](#security--operational-considerations) before any deployment beyond a workstation.

---

## API Reference

Full OpenAPI documentation is served at `http://localhost:8080/api/v1/docs`.

### Ingest

```http
POST /api/v1/ingest/alerts
Content-Type: application/json

{
  "alerts": [ { "...": "alert fields" } ],
  "run_pipeline": false
}
```

### Run pipeline

```http
POST /api/v1/pipeline/run
Content-Type: application/json

{ "alert_limit": 1000 }
```

### Query threats

```http
GET /api/v1/threats?tier=CRITICAL&limit=50
GET /api/v1/threats/{threat_id}
GET /api/v1/threats/{threat_id}/bluf?format=text
```

### Reports

```http
GET /api/v1/reports
GET /api/v1/reports/{report_id}?format=json
```

### System

```http
GET /api/v1/health
GET /api/v1/metrics
GET /api/v1/audit?threat_id=<id>
```

---

## Configuration Reference

`config/config.yaml` drives all runtime behaviour — there are no hard-coded parameters in code, which keeps scoring and correlation logic auditable and tunable per deployment.

### Correlation

```yaml
correlation:
  ioc_enabled: true
  temporal_enabled: true
  asset_enabled: true
  behaviour_enabled: true
  temporal_window_seconds: 3600   # 1-hour correlation window
  min_group_confidence: 0.30      # Minimum confidence to group alerts
  whitelist_ips: []                # IPs known to generate benign alerts
  whitelist_hostnames: []
  whitelist_domains: []
```

### Scoring

```yaml
scoring:
  weights:
    severity: 0.30              # Weights must sum to 1.0
    confidence: 0.25
    source_reliability: 0.15
    asset_criticality: 0.20
    temporal_urgency: 0.10
  thresholds:
    critical: 80.0               # Score ≥ 80 → CRITICAL
    high: 60.0                   # Score ≥ 60 → HIGH
    medium: 35.0                 # Score ≥ 35 → MEDIUM
    # Below 35 → LOW
  urgency_max_age_hours: 72.0
```

### Asset Registry

```yaml
asset_registry:
  "10.0.1.50":
    asset_id: "DC-001"
    hostname: "dc01.corp.internal"
    criticality: 0.95            # 0.0–1.0 mission criticality
    classification: "SECRET"
    network_segment: "CORP-MGMT"
    tags: ["domain-controller"]
```

---

## MITRE ATT&CK Knowledge Base

`config/mitre_attack_kb.yaml` contains technique definitions loaded at startup:

```yaml
techniques:
  - id: T1059.001
    name: "Command and Scripting Interpreter: PowerShell"
    tactic_ids: ["TA0002"]
    description: "..."
    detection_notes: "..."
    mitigations: ["Enable Script Block Logging", "..."]
    platforms: ["Windows"]
    data_sources: ["..."]
```

**For production deployment**, replace the bundled knowledge base with data derived from the official MITRE ATT&CK STIX bundle:

```bash
# Download enterprise-attack.json from:
# https://github.com/mitre/cti/tree/master/enterprise-attack
# Then point the configuration to the bundle:
mitre:
  stix_bundle_path: "config/enterprise-attack.json"
```

---

## Sample Data & Demo Scenario

`data/sample/` contains a realistic, multi-source dataset built around a simulated APT campaign:

| File | Description | Scenario |
|---|---|---|
| `siem_alerts.json` | 8 SIEM alerts | APT-X campaign activity + 2 false positives |
| `edr_events.json` | 5 EDR detections | Credential dumping, persistence, C2 |
| `intel_reports.json` | 2 intelligence reports | HUMINT advance warning + OSINT C2 analysis |
| `stix_bundle.json` | STIX 2.1 bundle | C2 IP/domain indicators + threat actor profile |

The dataset is deliberately constructed to exercise three critical evaluation paths:

- **True-positive path** — the APT-X "OP-PHANTOM-2024" multi-stage attack, which should resolve to a CRITICAL or HIGH correlated threat
- **False-positive path** — an AV update event and an authorised IT RDP session, which should score LOW
- **Multi-source corroboration** — identical IOCs appearing across SIEM, EDR, HUMINT, and STIX simultaneously

---

## Testing

```bash
# Full suite
pytest tests/ -v

# With coverage
pytest tests/ --cov=threaticap --cov-report=term-missing

# Targeted modules
pytest tests/test_correlation.py -v
pytest tests/test_scoring_bluf.py -v
pytest tests/test_pipeline.py -v
pytest tests/test_api.py -v
```

### Test coverage by area

| File | Coverage |
|---|---|
| `test_models.py` | Pydantic validation, frozen fields, constraint enforcement |
| `test_ingestion.py` | Normalisation, IOC extraction, deduplication, enrichment, connectors |
| `test_correlation.py` | All correlators, FP filter, engine clustering, audit callbacks |
| `test_scoring_bluf.py` | Scoring weights, tier assignment, BLUF structure and content |
| `test_pipeline.py` | End-to-end execution against sample data and synthetic integration cases |
| `test_api.py` | All FastAPI endpoints — ingest, pipeline, threats, reports, audit, health |

---

## Extension Points

THREATICAP is built to be extended without modifying its core pipeline, correlation, or API layers.

### Add a new connector

1. Create `threaticap/ingestion/connectors/my_connector.py`
2. Subclass `BaseConnector`
3. Implement `connect()`, `disconnect()`, `fetch_raw()`, `normalise()`
4. Register it in `IngestionPipeline.register_connector()`

```python
class MyConnector(BaseConnector):
    def connect(self): ...
    def disconnect(self): ...
    def fetch_raw(self) -> Iterator[dict]: ...
    def normalise(self, raw: dict) -> Alert | None: ...
```

### Replace the storage backend with PostgreSQL

1. Implement `PostgreSQLAlertRepository(BaseAlertRepository)` in `threaticap/storage/`
2. Pass it to `ThreatPipeline(alert_repo=PostgreSQLAlertRepository(dsn))`
3. No changes are required to the pipeline, correlation, or API layers

### Integrate a classified threat intelligence platform

1. Create a connector that fetches from the classified API (STIX or proprietary format)
2. Set `source_reliability` appropriately for the source
3. Set `tlp="TLP:RED"` on produced alerts
4. The audit trail will record every correlation decision involving classified data

### Add a machine-learning false-positive classifier

Replace `FalsePositiveFilter.compute_fp_probability()` with a trained model:

```python
class MLFalsePositiveFilter(FalsePositiveFilter):
    def __init__(self, model_path: str):
        self._model = joblib.load(model_path)

    def compute_fp_probability(self, alerts, correlation_confidence, reasons=None):
        features = self._extract_features(alerts, correlation_confidence)
        return float(self._model.predict_proba([features])[0][0])
```

### Integrate a graph database

Replace `InMemoryThreatRepository` with a Neo4j-backed implementation:

- Threats and alerts become nodes
- Correlation links become directed, confidence-weighted edges
- Enables complex relationship queries — attack paths, actor attribution, lateral-movement reconstruction

### Connect to a national threat intelligence platform

```yaml
# config.yaml
connectors:
  - type: taxii
    url: "https://national-tip.example.gov/taxii2/"
    collection: "national-indicators"
    source_reliability: 0.95
    tlp: "TLP:RED"
```

---

## Security & Operational Considerations

### Secrets management

- Credentials must **never** be stored in `config.yaml` or committed to source control
- Use Docker secrets, Kubernetes secrets, or a vault (HashiCorp Vault, AWS Secrets Manager) in any shared environment
- Database passwords, API keys, and TAXII credentials must be injected at runtime, not baked into images

### Network security

- Deploy behind a reverse proxy (nginx, Envoy) with TLS termination
- Use mutual TLS (mTLS) for service-to-service communication in production
- Restrict API access via network policy; expose only `/api/v1/health` publicly
- For air-gapped environments, operate exclusively through the CLI (`python -m threaticap demo`)

### Least privilege

- The API container runs as a non-root user (uid 1000)
- The database user should hold `INSERT` / `SELECT` only on required tables; `DELETE` must be forbidden on audit tables
- Connector service accounts should be provisioned with read-only access to source systems

### Input validation

- All inbound data passes through Pydantic v2 validation before entering the pipeline
- Raw payloads are preserved but isolated in `Alert.raw_payload` and never consumed downstream
- Maximum field lengths are enforced at the model level (description ≤ 8192 characters)
- MITRE technique IDs are validated by regex before use

### Audit trail

- Every correlation decision, score, and BLUF report is recorded as an `AuditRecord`
- Audit records are frozen (immutable) at creation time
- In production, the audit table should enforce row-level security to prevent tampering
- Audit records are never deleted — implement archival rotation rather than deletion if retention limits apply

### Classified data handling

- Alerts originating from classified sources (`HUMINT`, `SIGINT`, `SATELLITE_ISR`) are automatically assigned `TLP:RED`
- TLP propagation follows a most-restrictive-wins rule across correlated threats
- Within a SCIF, confirm the system is operating on an appropriately classified network before ingesting classified data
- The asset registry `classification` field is propagated into scores and reports — review it for accuracy before deployment

### False-positive management

- The FP filter is conservative by default: it downweights scores but never silently suppresses threats
- Tune `whitelist_ips` and `whitelist_hostnames` for the specific operating environment
- Monitor `false_positive_probability` in generated reports; ground-truth analyst feedback should feed future model training

---

## Kubernetes Deployment

```yaml
# threaticap-deployment.yaml (abbreviated)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threaticap-api
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: threaticap-api
        image: threaticap:latest
        ports:
        - containerPort: 8080
        env:
        - name: THREATICAP_CONFIG
          value: "/app/config/config.yaml"
        - name: JSON_LOGS
          value: "true"
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: threaticap-secrets
              key: db-password
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 8080
          initialDelaySeconds: 15
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /api/v1/health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: threaticap-config
```

**For horizontal scaling:**

- Replace in-memory repositories with the PostgreSQL backend
- Replace the in-memory deduplication cache with a Redis backend
- Introduce a message queue (Kafka / RabbitMQ) between connectors and the pipeline to decouple ingestion throughput from processing capacity

---

## Roadmap

| Horizon | Focus |
|---|---|
| **Immediate** | Self-hosted Docker deployment to a national SOC; live MISP federation and TAXII 2.1 collection; SIEM integration (Splunk/QRadar) via streaming ingestion |
| **Medium term** | Promotion to a classified network via the air-gapped transfer architecture; analyst feedback loop into a fine-tuned FP classification model; real-time mission-context integration with operational systems |
| **Strategic** | National threat intelligence hub for aggregation and redistribution to sector partners; certified cross-domain solution for classification handling; national-grade FP reduction model trained on accumulated analyst verdicts |

---

## Development & Contributing

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests with coverage
pytest tests/ --cov=threaticap --cov-report=html

# Type checking (optional)
pip install mypy
mypy threaticap/ --ignore-missing-imports

# Formatting
pip install black
black threaticap/ tests/
```

### Adding a new correlator

1. Create `threaticap/correlation/my_correlator.py`
2. Implement a class with `correlate(self, alerts: list[Alert]) -> list[dict]`, returning link dictionaries
3. Register it in `CorrelationEngine.__init__()` when enabled via configuration
4. Add corresponding tests in `tests/test_correlation.py`

### Versioning

- `Alert.schema_version` enables forward-compatible data migrations
- `CorrelatedThreat.correlation_version` records which configuration produced a given threat
- `PriorityScore.scoring_version` and `threshold_used` enable score auditing and regression detection over time

---

## Team

### Team Maverick

| Enrollment No. | Name |
|---|---|
| D24DCS151 | Vatsal Sapovadiya |
| D24DCS150 | Pratham Jadwani |
| D24DCS159 | Krunal Mistry |
| D24DCS156 | Hitanshu Varia |

---


**THREATICAP — designed for hardening into live defence environments.**

*From sensor noise to command decision.*

</div>
