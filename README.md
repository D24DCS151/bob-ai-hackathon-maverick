# THREATICAP
## Threat Intelligence Correlation & Alert Prioritisation System

> **Production-grade** multi-source threat intelligence correlation, MITRE ATT&CK mapping, risk-based prioritisation, and commander-ready BLUF report generation — designed for deployment in defence and intelligence SOC environments.

---

## Table of Contents

1. [Mission & Capabilities](#mission--capabilities)
2. [Architecture Overview](#architecture-overview)
3. [Data Flow](#data-flow)
4. [Quick Start — Local Development](#quick-start--local-development)
5. [Running with Docker](#running-with-docker)
6. [API Reference](#api-reference)
7. [Configuration Reference](#configuration-reference)
8. [MITRE ATT&CK Knowledge Base](#mitre-attck-knowledge-base)
9. [Sample Data & Demo](#sample-data--demo)
10. [Testing](#testing)
11. [Extension Points](#extension-points)
12. [Security & Operational Considerations](#security--operational-considerations)
13. [Kubernetes Deployment](#kubernetes-deployment)
14. [Development & Contributing](#development--contributing)

---

## Mission & Capabilities

THREATICAP addresses the core SOC challenge of **alert fatigue and prioritisation** in high-volume, multi-source threat environments.

| Capability | Description |
|---|---|
| **Multi-source ingestion** | SIEM (JSON/CEF/LEEF), EDR/network telemetry, HUMINT/SIGINT/OSINT reports, STIX/TAXII feeds |
| **Correlation** | IOC matching, temporal proximity, asset overlap, behavioural/MITRE pattern analysis |
| **False-positive reduction** | Heuristic FP scoring with configurable whitelist and multi-source corroboration weighting |
| **MITRE ATT&CK mapping** | Technique, sub-technique, tactic enrichment from maintainable YAML knowledge base |
| **Risk-based scoring** | Explainable 5-factor weighted scoring with configurable tiers (CRITICAL/HIGH/MEDIUM/LOW) |
| **BLUF generation** | Commander-ready reports with bottom line, evidence, recommended actions, and investigation steps |
| **REST API** | Full OpenAPI-documented FastAPI service |
| **CLI** | Air-gapped / offline operation via `python -m threaticap` |
| **Full audit trail** | Every correlation decision, score, and report is immutably logged |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          THREATICAP                                 │
│                                                                     │
│  ┌──────────────┐   ┌─────────────────────────────────────────┐    │
│  │   FastAPI    │   │           IngestionPipeline             │    │
│  │   REST API   │   │  ┌──────────┐ ┌───────────┐ ┌───────┐  │    │
│  │  /api/v1/    │   │  │Normaliser│ │Deduplicator│ │Enrich.│  │    │
│  └──────┬───────┘   │  └──────────┘ └───────────┘ └───────┘  │    │
│         │           │         ▲ Connectors                    │    │
│  ┌──────▼───────────▼──────┐  │  SIEM / EDR / Intel / STIX   │    │
│  │     ThreatPipeline      │  └─────────────────────────────  │    │
│  │  (Orchestrator)         │                                   │    │
│  └─┬────────┬────────┬─────┘                                  │    │
│    │        │        │                                         │    │
│    ▼        ▼        ▼                                         │    │
│  ┌───────┐ ┌──────┐ ┌───────────┐  ┌───────────┐             │    │
│  │Correl.│ │MITRE │ │Prioritisa-│  │   BLUF    │             │    │
│  │Engine │ │Mapper│ │tion Engine│  │ Generator │             │    │
│  └───────┘ └──────┘ └───────────┘  └─────┬─────┘             │    │
│                                           │                    │    │
│  ┌────────────────────────────────────────▼──────────────────┐│    │
│  │                    Storage Layer                          ││    │
│  │  AlertRepo / ThreatRepo / ReportRepo / AuditRepo          ││    │
│  │  (In-Memory → SQLite → PostgreSQL — same interface)        ││    │
│  └───────────────────────────────────────────────────────────┘│    │
└─────────────────────────────────────────────────────────────────────┘
```

### Module Map

```
threaticap/
├── __init__.py             # Package version
├── __main__.py             # python -m threaticap entry point
├── pipeline.py             # ThreatPipeline orchestrator
├── cli.py                  # Click CLI
├── logging_config.py       # Structured JSON / console logging
│
├── models/                 # Canonical Pydantic v2 data models
│   ├── alert.py            # Alert, Observable, AssetContext
│   ├── correlated_threat.py # CorrelatedThreat, EvidenceLink
│   ├── mitre.py            # MitreMapping, MitreTechnique
│   ├── priority.py         # PriorityScore, ScoreComponent
│   ├── bluf.py             # BlufReport, ActionItem
│   └── audit.py            # AuditRecord (immutable, append-only)
│
├── ingestion/              # Multi-source ingestion layer
│   ├── base_connector.py   # Abstract BaseConnector interface
│   ├── normaliser.py       # Schema enforcement + IOC extraction
│   ├── deduplicator.py     # LRU-cached deduplication
│   ├── enricher.py         # Asset registry + TLP assignment
│   ├── pipeline.py         # IngestionPipeline orchestrator
│   └── connectors/
│       ├── siem_connector.py      # SIEM (JSON/CEF/LEEF/HTTP)
│       ├── edr_connector.py       # EDR/network (JSON/CSV/syslog)
│       ├── intel_report_connector.py  # HUMINT/SIGINT/OSINT
│       └── stix_connector.py      # STIX 2.1 / TAXII 2.1
│
├── correlation/            # Correlation engine
│   ├── engine.py           # CorrelationEngine (Union-Find clustering)
│   ├── ioc_correlator.py   # Shared observable matching
│   ├── temporal_correlator.py  # Time-window grouping
│   ├── asset_correlator.py # Asset/hostname/segment overlap
│   ├── behaviour_correlator.py  # MITRE technique/campaign matching
│   └── fp_filter.py        # False-positive probability scoring
│
├── mapping/
│   └── mitre_mapper.py     # ATT&CK technique enrichment
│
├── scoring/
│   └── prioritisation_engine.py  # 5-factor weighted scoring
│
├── reporting/
│   └── bluf_generator.py   # BLUF report generation
│
├── storage/
│   └── repositories.py     # Abstract repos + in-memory implementations
│
└── api/
    ├── app.py              # FastAPI application + all endpoints
    ├── schemas.py          # API request/response schemas
    └── dependencies.py     # FastAPI dependency injection
```

---

## Data Flow

```
Source Data                 Ingestion               Correlation
─────────────               ────────────────        ───────────────────
SIEM JSON/CEF  ──►  Connector.normalise()  ──►  IOCCorrelator
EDR telemetry  ──►  AlertNormaliser        ──►  TemporalCorrelator  ──►  CorrelatedThreat
Intel reports  ──►  AlertDeduplicator      ──►  AssetCorrelator
STIX/TAXII     ──►  AlertEnricher         ──►  BehaviourCorrelator
                                           ──►  FPFilter

Correlation           MITRE            Scoring             BLUF
────────────────      ────────         ──────────────       ──────────────
CorrelatedThreat ──►  MitreMapper ──►  Prioritisation ──►  BlufGenerator ──►  BlufReport
                      MitreMapping     Engine                              ──►  AuditRecord
                      (YAML KB)        PriorityScore
                                       (5 components)
```

**Key invariant**: every component receives and returns only canonical model types.
Raw source data is preserved in `Alert.raw_payload` but never consumed downstream.

---

## Quick Start — Local Development

### Prerequisites

- Python 3.11+
- pip

### Install

```bash
# Clone and install in development mode
git clone https://github.com/defence-org/threaticap.git
cd threaticap
pip install -e ".[dev]"
```

### Run the demo (no server required)

```bash
python -m threaticap demo --data-dir data/sample
```

This ingests all sample data files, runs the full pipeline, and prints BLUF reports to the terminal.

### Start the API server

```bash
python -m threaticap serve --host 0.0.0.0 --port 8080
# API docs: http://localhost:8080/api/v1/docs
```

### Run tests

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

### Docker Compose (full stack with PostgreSQL + Redis)

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
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `JSON_LOGS` | `false` | Emit structured JSON logs |
| `HOST` | `0.0.0.0` | API bind address |
| `PORT` | `8080` | API port |
| `DB_PASSWORD` | `changeme-in-production` | PostgreSQL password |
| `REDIS_PASSWORD` | `changeme-in-production` | Redis password |

---

## API Reference

Full OpenAPI documentation: `http://localhost:8080/api/v1/docs`

### Ingest

```http
POST /api/v1/ingest/alerts
Content-Type: application/json

{
  "alerts": [ { <alert fields> } ],
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

`config/config.yaml` — all parameters configurable, no hard-coded values in code.

### Correlation

```yaml
correlation:
  ioc_enabled: true
  temporal_enabled: true
  asset_enabled: true
  behaviour_enabled: true
  temporal_window_seconds: 3600   # 1-hour correlation window
  min_group_confidence: 0.30      # Minimum confidence to group alerts
  whitelist_ips: []               # IPs known to generate benign alerts
  whitelist_hostnames: []
  whitelist_domains: []
```

### Scoring

```yaml
scoring:
  weights:
    severity: 0.30          # Must sum to 1.0
    confidence: 0.25
    source_reliability: 0.15
    asset_criticality: 0.20
    temporal_urgency: 0.10
  thresholds:
    critical: 80.0          # Score ≥ 80 → CRITICAL
    high: 60.0              # Score ≥ 60 → HIGH
    medium: 35.0            # Score ≥ 35 → MEDIUM
    # Below 35 → LOW
  urgency_max_age_hours: 72.0
```

### Asset Registry

```yaml
asset_registry:
  "10.0.1.50":
    asset_id: "DC-001"
    hostname: "dc01.corp.internal"
    criticality: 0.95         # 0.0–1.0 mission criticality
    classification: "SECRET"
    network_segment: "CORP-MGMT"
    tags: ["domain-controller"]
```

---

## MITRE ATT&CK Knowledge Base

`config/mitre_attack_kb.yaml` contains technique definitions loaded at startup.

```yaml
techniques:
  - id: T1059.001
    name: "Command and Scripting Interpreter: PowerShell"
    tactic_ids: ["TA0002"]
    description: "..."
    detection_notes: "..."
    mitigations: ["Enable Script Block Logging", ...]
    platforms: ["Windows"]
    data_sources: [...]
```

**For production**: Replace with data derived from the official MITRE ATT&CK STIX bundle:
```bash
# Download enterprise-attack.json from:
# https://github.com/mitre/cti/tree/master/enterprise-attack
# Then point config to the bundle:
mitre:
  stix_bundle_path: "config/enterprise-attack.json"
```

---

## Sample Data & Demo

`data/sample/` contains realistic multi-source data for a simulated APT campaign:

| File | Description | Scenario |
|---|---|---|
| `siem_alerts.json` | 8 SIEM alerts | APT-X campaign + 2 false positives |
| `edr_events.json` | 5 EDR detections | Credential dumping, persistence, C2 |
| `intel_reports.json` | 2 intel reports | HUMINT advance warning + OSINT C2 analysis |
| `stix_bundle.json` | STIX 2.1 bundle | C2 IP/domain indicators + threat actor profile |

The sample data is designed to exercise:
- **True positive path**: APT-X OP-PHANTOM-2024 multi-stage attack (should produce CRITICAL/HIGH correlated threat)
- **False positive path**: AV update event, authorised IT RDP session (should score LOW)
- **Multi-source corroboration**: Same IOCs appear in SIEM + EDR + HUMINT + STIX

---

## Testing

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=threaticap --cov-report=term-missing

# Specific module
pytest tests/test_correlation.py -v
pytest tests/test_scoring_bluf.py -v
pytest tests/test_pipeline.py -v
pytest tests/test_api.py -v
```

### Test categories

| File | What it tests |
|---|---|
| `test_models.py` | Pydantic validation, frozen fields, constraint enforcement |
| `test_ingestion.py` | Normalisation, IOC extraction, deduplication, enrichment, connectors |
| `test_correlation.py` | All correlators, FP filter, engine clustering, audit callbacks |
| `test_scoring_bluf.py` | Scoring weights, tier assignment, BLUF structure and content |
| `test_pipeline.py` | End-to-end with sample data + synthetic data integration tests |
| `test_api.py` | All FastAPI endpoints (ingest, pipeline, threats, reports, audit, health) |

---

## Extension Points

### Add a new connector

1. Create `threaticap/ingestion/connectors/my_connector.py`
2. Subclass `BaseConnector`
3. Implement `connect()`, `disconnect()`, `fetch_raw()`, `normalise()`
4. Register in `IngestionPipeline.register_connector()`

```python
class MyConnector(BaseConnector):
    def connect(self): ...
    def disconnect(self): ...
    def fetch_raw(self) -> Iterator[dict]: ...
    def normalise(self, raw: dict) -> Alert | None: ...
```

### Replace storage backend with PostgreSQL

1. Implement `PostgreSQLAlertRepository(BaseAlertRepository)` in `threaticap/storage/`
2. Pass it to `ThreatPipeline(alert_repo=PostgreSQLAlertRepository(dsn))`
3. No changes required to pipeline, correlation, or API layers

### Integrate a classified threat intelligence platform

1. Create a connector that fetches from the classified API (STIX or proprietary format)
2. Set `source_reliability` appropriately
3. Set `tlp="TLP:RED"` on produced alerts
4. The audit trail will record all correlation decisions involving classified data

### Add an ML false-positive classifier

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
- Correlation links become directed edges with confidence weights
- Enables complex relationship queries (attack paths, actor attribution)

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

- **Never** store credentials in `config.yaml` or environment variables in production
- Use Docker secrets, Kubernetes secrets, or a vault (HashiCorp Vault, AWS Secrets Manager)
- Database passwords, API keys, and TAXII credentials must be injected at runtime

### Network security

- Deploy behind a reverse proxy (nginx, Envoy) with TLS termination
- Use mutual TLS (mTLS) for service-to-service communication in production
- Restrict API access with network policies; expose only `/api/v1/health` publicly
- For air-gapped environments, use the CLI (`python -m threaticap demo`)

### Least privilege

- The API container runs as non-root user (uid 1000)
- Database user should have `INSERT/SELECT` only on required tables; `DELETE` forbidden on audit tables
- Connector service accounts should have read-only access to source systems

### Input validation

- All inbound data passes through Pydantic v2 validation before processing
- Raw payloads are preserved but isolated in `Alert.raw_payload`
- Maximum field lengths enforced at model level (description ≤ 8192 chars)
- MITRE technique IDs validated by regex before use

### Audit trail

- Every correlation decision, score, and BLUF is recorded as an `AuditRecord`
- Audit records are frozen (immutable) after creation
- In production, the audit database table should use row-level security to prevent modification
- Audit records are not deleted — implement archival rotation if needed

### Classified data handling

- Alerts from classified sources (`HUMINT`, `SIGINT`, `SATELLITE_ISR`) are automatically set to `TLP:RED`
- TLP propagation follows most-restrictive-wins rule
- In SCIFs, ensure the system is on an appropriately classified network before ingesting classified data
- Review the asset registry `classification` field — it is propagated into scores and reports

### False positive management

- The FP filter is conservative by default — it reduces scores but does not suppress threats
- Review and tune `whitelist_ips` and `whitelist_hostnames` for your environment
- Monitor `false_positive_probability` in reports; ground-truth feedback should feed ML model training

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

For **horizontal scaling**:
- Replace in-memory repositories with PostgreSQL backend
- Replace in-memory dedup cache with Redis backend
- Use a message queue (Kafka/RabbitMQ) between connectors and pipeline

---

## Development & Contributing

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests with coverage
pytest tests/ --cov=threaticap --cov-report=html

# Type checking (optional)
pip install mypy
mypy threaticap/ --ignore-missing-imports

# Format
pip install black
black threaticap/ tests/
```

### Adding a new correlator

1. Create `threaticap/correlation/my_correlator.py`
2. Implement a class with `correlate(self, alerts: list[Alert]) -> list[dict]` returning link dicts
3. Register it in `CorrelationEngine.__init__()` if enabled in config
4. Add tests in `tests/test_correlation.py`

### Versioning

- `Alert.schema_version` enables forward-compatible migrations
- `CorrelatedThreat.correlation_version` tracks which config version produced the threat
- `PriorityScore.scoring_version` and `threshold_used` enable score audit and regression detection

---

*THREATICAP — Designed for hardening into live defence environments.*
