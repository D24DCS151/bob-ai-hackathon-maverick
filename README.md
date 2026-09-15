# THREATICAP — v3.0
## Threat Intelligence Correlation & Alert Prioritisation System

> **Production-grade** multi-source threat intelligence correlation, MITRE ATT&CK mapping, risk-based prioritisation, and commander-ready BLUF report generation — designed for national-level defence and intelligence SOC environments.

**Phase 2 production hardening adds:** PostgreSQL persistence, Redis Streams near-real-time ingestion, graph-based attack path reconstruction (NetworkX), official MITRE ATT&CK STIX bundle loading, pluggable live enrichment with circuit breakers, API-key + JWT authentication, RBAC, TLP enforcement, analyst feedback loop, Prometheus metrics, Satellite/ISR connector, and a hardened container stack.

**Phase 3 — National Defence SOC Edition adds:** Mission-aware threat prioritisation, multi-stage kill chain campaign reconstruction, feedback-driven closed-loop FP reduction, national classification & coalition intelligence handling (TLP 2.0, NOFORN, RELTO, STIX 2.1 export), cross-domain and air-gapped operation with tamper-evident transfer packages, MISP and TAXII 2.1 connectors, role-specific commander BLUF (COMMANDER / WATCH_OFFICER / INTEL_OFFICER / COALITION), and full NATO Admiralty Scale feed quality management with radioactive-decay confidence aging.

---

## Table of Contents

1. [Mission & Capabilities](#mission--capabilities)
2. [Architecture Overview](#architecture-overview)
3. [Phase 2 New Components](#phase-2-new-components)
4. [Data Flow](#data-flow)
5. [Quick Start — Local Development](#quick-start--local-development)
6. [Running with Docker Compose](#running-with-docker-compose)
7. [Authentication & RBAC](#authentication--rbac)
8. [API Reference](#api-reference)
9. [Configuration Reference](#configuration-reference)
10. [MITRE ATT&CK Knowledge Base](#mitre-attck-knowledge-base)
11. [Streaming Ingestion (Redis Streams)](#streaming-ingestion-redis-streams)
12. [Graph Correlation](#graph-correlation)
13. [Enrichment](#enrichment)
14. [Analyst Feedback](#analyst-feedback)
15. [Observability](#observability)
16. [Sample Data & Demo](#sample-data--demo)
17. [Testing](#testing)
18. [Extension Points](#extension-points)
19. [Security & Operational Considerations](#security--operational-considerations)
20. [Kubernetes Deployment](#kubernetes-deployment)
21. [Roadmap for Classified Environments](#roadmap-for-classified-environments)

---

## Mission & Capabilities

THREATICAP addresses the core SOC challenge of **alert fatigue and prioritisation** in high-volume, multi-source threat environments.

| Capability | Status | Description |
|---|---|---|
| **Multi-source ingestion** | v1 | SIEM (JSON/CEF/LEEF), EDR/network telemetry, HUMINT/SIGINT/OSINT reports, STIX/TAXII feeds, Satellite/ISR |
| **Streaming ingestion** | v2 | Redis Streams near-real-time path with at-least-once delivery and back-pressure |
| **Correlation** | v1+v2 | IOC matching, temporal proximity, asset overlap, behavioural/MITRE pattern analysis + graph-based attack path reconstruction |
| **False-positive reduction** | v1+v3 | Heuristic FP scoring + closed-loop analyst feedback learning (EMA, per-rule / per-source adjustment) |
| **MITRE ATT&CK mapping** | v1+v2 | YAML knowledge base + official STIX bundle loading; technique, sub-technique, tactic level |
| **Risk-based scoring** | v1+v3 | Explainable 5-factor weighted scoring + **mission impact multiplier** (up to 3×) |
| **Mission-aware prioritisation** | v3 | Dynamic mission context injection; active missions amplify threat scores on affected C2/ISR/COMMS assets |
| **Kill chain reconstruction** | v3 | Maps MITRE tactics to Unified Kill Chain phases; identifies APT multi-stage campaigns; narrative for BLUF |
| **BLUF generation** | v1+v3 | Commander-ready reports with role-specific formats (COMMANDER / WATCH_OFFICER / INTEL_OFFICER / COALITION) |
| **Authentication** | v2 | API keys (SHA-256 hashed) + JWT (HS256/RS256), bcrypt-ready interface |
| **RBAC** | v2 | reader / analyst / operator / admin role hierarchy with TLP clearance enforcement |
| **Enrichment** | v2 | Pluggable reputation / CMDB / CVE enrichers with circuit breakers and TTL cache |
| **Analyst feedback** | v2 | TP/FP/Benign/NeedsReview verdicts stored and linked to audit trail |
| **Intel quality management** | v3 | Per-source reliability tracking (NATO Admiralty Scale A–F), radioactive-decay confidence aging, staleness retirement |
| **Classification handling** | v3 | UNCLASSIFIED → TOP SECRET//SCI levels, TLP 2.0, NOFORN/RELTO/ORCON caveats, STIX 2.1 coalition export |
| **Cross-domain / air-gapped** | v3 | CrossDomainGuard policy enforcement, tamper-evident HMAC-signed transfer packages (.tigpkg), disconnected mode queue |
| **MISP connector** | v3 | Bidirectional MISP integration — pull events + push sightings; cache fallback for air-gapped ops |
| **TAXII 2.1 connector** | v3 | Standard TAXII 2.1 collection polling for national TIP / CISP / AIS feeds |
| **PostgreSQL backend** | v2 | Full connection-pooled PostgreSQL repository implementations with versioned migrations |
| **Observability** | v2 | Prometheus metrics endpoint, structured logging, enricher health, uptime |
| **REST API** | v1+v2 | Full OpenAPI-documented FastAPI service; all endpoints auth-protected |
| **CLI** | v1 | Air-gapped / offline operation via `python -m threaticap` |
| **Full audit trail** | v1+v2 | Every correlation decision, score, report, feedback, and auth event immutably logged |

---

## Architecture Overview

```
                           ┌─────────────────────────────────────────────────────────┐
                           │                     THREATICAP v2                       │
                           │                                                         │
  External Sources         │  ┌──────────────────────────────────────────────────┐  │
  ─────────────────        │  │               Ingestion Layer                    │  │
  SIEM / CEF / LEEF ──────►│  │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │  │
  EDR / CSV / JSON  ──────►│  │  │SIEMConn. │ │EDRConn.  │ │IntelReportConn.  │ │  │
  Intel Reports    ──────► │  │  └────┬─────┘ └────┬─────┘ └──────┬───────────┘ │  │
  STIX Bundles     ──────► │  │  ┌────┴─────┐ ┌────┴─────┐ ┌──────┴────────────┐│  │
  Satellite / ISR  ──────► │  │  │STIXConn. │ │SatISRConn│ │   Normaliser      ││  │
                           │  │  └──────────┘ └──────────┘ └──────┬────────────┘│  │
  Redis Streams    ──────► │  │  ┌──────────────────────────────── │────────────┐│  │
  (near-real-time)         │  │  │  Deduplicator → Enricher → AlertRepo        ││  │
                           │  └──┴───────────────────────────────────────────── ┘│  │
                           │                         │                            │  │
                           │  ┌──────────────────────▼─────────────────────────┐ │  │
                           │  │              ThreatPipeline (Orchestrator)      │ │  │
                           │  └──┬─────────────┬─────────────┬──────────────── ┘ │  │
                           │     │             │             │                    │  │
                           │  ┌──▼──────┐ ┌───▼────┐ ┌──────▼──────┐            │  │
                           │  │Correlat.│ │MITRE   │ │Prioritisat. │            │  │
                           │  │Engine   │ │Mapper  │ │Engine       │            │  │
                           │  │+AttackGr│ │+STIX   │ │             │            │  │
                           │  └──┬──────┘ └───┬────┘ └──────┬──────┘            │  │
                           │     └────────────┴─────────────┘                   │  │
                           │                         │                           │  │
                           │  ┌──────────────────────▼─────────────────────────┐│  │
                           │  │               BLUF Generator                   ││  │
                           │  └──────────────────────┬──────────────────────── ┘│  │
                           │                         │                           │  │
                           │  ┌──────────────────────▼─────────────────────────┐│  │
                           │  │               Storage Layer                    ││  │
                           │  │  AlertRepo / ThreatRepo / ReportRepo / Audit   ││  │
                           │  │  FeedbackRepo / EnrichmentCache                ││  │
                           │  │  InMemory (dev) ──► PostgreSQL (production)    ││  │
                           │  └──────────────────────────────────────────────── ┘│  │
                           │                                                      │  │
                           │  ┌──────────────────────────────────────────────┐    │  │
                           │  │  FastAPI (REST + OpenAPI)                    │    │  │
                           │  │  Auth: API Key + JWT | RBAC | TLP            │    │  │
                           │  │  Metrics: /api/v1/metrics/prometheus         │    │  │
                           │  └──────────────────────────────────────────────┘    │  │
                           └──────────────────────────────────────────────────────┘  │
                                                                                      │
```

### Module Map

```
threaticap/
├── __init__.py                  # Package version
├── __main__.py                  # python -m threaticap entry point
├── pipeline.py                  # ThreatPipeline orchestrator
├── cli.py                       # Click CLI (batch / air-gapped)
├── logging_config.py            # Structured JSON / console logging
│
├── models/                      # Canonical Pydantic v2 data models
│   ├── alert.py                 # Alert, Observable, AssetContext, GeoLocation
│   ├── correlated_threat.py     # CorrelatedThreat, EvidenceLink
│   ├── mitre.py                 # MitreMapping, MitreTechnique
│   ├── priority.py              # PriorityScore, ScoreComponent
│   ├── bluf.py                  # BlufReport, ActionItem
│   ├── audit.py                 # AuditRecord (immutable, append-only)
│   └── feedback.py              # AnalystFeedback, Verdict [v2]
│
├── ingestion/                   # Multi-source ingestion layer
│   ├── base_connector.py        # Abstract BaseConnector interface
│   ├── normaliser.py            # Schema enforcement + IOC extraction
│   ├── deduplicator.py          # LRU-cached deduplication
│   ├── enricher.py              # Asset registry + TLP assignment
│   ├── pipeline.py              # IngestionPipeline orchestrator
│   ├── stream_consumer.py       # Redis Streams consumer [v2]
│   └── connectors/
│       ├── siem_connector.py    # SIEM (JSON/CEF/LEEF)
│       ├── edr_connector.py     # EDR / network telemetry
│       ├── intel_report_connector.py  # HUMINT/SIGINT/OSINT reports
│       ├── stix_connector.py    # STIX 2.x bundles
│       └── satellite_connector.py    # Satellite/ISR/SIGINT/ELINT [v2]
│
├── correlation/                 # Correlation engine
│   ├── engine.py                # CorrelationEngine (Union-Find + graph)
│   ├── ioc_correlator.py        # Shared IOC / observable matching
│   ├── temporal_correlator.py   # Time-window proximity
│   ├── asset_correlator.py      # Shared assets / network segments
│   ├── behaviour_correlator.py  # MITRE technique sequence matching
│   ├── fp_filter.py             # False-positive heuristic filter
│   └── graph_correlator.py      # NetworkX attack path reconstruction [v2]
│
├── mapping/
│   └── mitre_mapper.py          # MITRE ATT&CK mapper (YAML + STIX [v2])
│
├── scoring/
│   └── prioritisation_engine.py # 5-factor weighted scoring
│
├── reporting/
│   └── bluf_generator.py        # BLUF generator (JSON + plain text)
│
├── enrichment/                  # Pluggable live enrichment [v2]
│   ├── broker.py                # EnrichmentBroker + circuit breakers
│   └── __init__.py
│
├── observability/               # Metrics and monitoring [v2]
│   ├── metrics.py               # Prometheus-compatible counters + gauges
│   └── __init__.py
│
├── storage/                     # Persistence layer
│   ├── repositories.py          # Abstract interfaces + in-memory implementations
│   ├── postgres_repositories.py # PostgreSQL implementations [v2]
│   ├── migrations.py            # Migration runner [v2]
│   ├── feedback_repository.py   # Analyst feedback storage [v2]
│   └── __init__.py
│
└── api/
    ├── app.py                   # FastAPI application (all endpoints)
    ├── auth.py                  # API key + JWT auth + RBAC [v2]
    ├── dependencies.py          # FastAPI DI: pipeline, feedback repo
    ├── schemas.py               # Request/response Pydantic schemas
    └── __init__.py
```

---

## Phase 2 New Components

### 1. PostgreSQL Backend (`storage/postgres_repositories.py`)
Full implementations of all four repository interfaces backed by PostgreSQL via `psycopg2`. Features:
- Connection pool (`PostgresConnectionPool`) with configurable min/max size
- All queries parameterised (no string interpolation — SQL injection safe)
- JSONB storage for flexible model fields with GIN indexes
- Transactional writes with rollback on failure
- `create_postgres_repositories(dsn)` factory function for clean DI

Activate with `storage.backend=postgresql` in `config.yaml` and set `POSTGRES_DSN` env var.

### 2. Redis Streams (`ingestion/stream_consumer.py`)
Near-real-time streaming ingestion path alongside the existing batch mode:
- `StreamingIngestionManager` wraps the existing `IngestionPipeline`
- Consumer groups for load-balanced multi-worker deployments
- At-least-once delivery with manual ACK
- Pending Entry List (PEL) recovery — reclaims stuck messages from failed workers
- Dead-letter stream for messages exceeding max retry count
- Back-pressure: pauses polling when downstream is overloaded

### 3. Graph Correlation (`correlation/graph_correlator.py`)
NetworkX-based directed attack graph built alongside existing Union-Find clusters:
- Each alert becomes a node with rich attributes
- Correlation signals become weighted directed edges
- Attack path detection via topological sort of directed subgraphs
- Betweenness centrality scoring — hub alerts (high connectivity) get priority boost
- Community detection (Louvain / greedy modularity) for cluster analysis
- Cytoscape.js / D3.js-compatible JSON export via `GET /api/v1/threats/{id}/graph`

### 4. Authentication & RBAC (`api/auth.py`)
- API keys: SHA-256 hashed at rest (bcrypt interface ready); stored in `_DEV_API_KEYS` (dev) or `api_keys` DB table (production)
- JWT: HS256 signed (RS256 upgrade path documented); 8-hour expiry by default
- Roles: `reader < analyst < operator < admin` (hierarchical has_role check)
- TLP clearance: most-restrictive-wins; users only see data at or below their clearance
- Every successful auth event is logged with actor, role, path, and method
- Dev bypass: `THREATICAP_AUTH_DISABLED=true` — **never in production**

### 5. Enrichment Broker (`enrichment/broker.py`)
- `ReputationEnricher` — IP/domain/hash reputation (stub → VirusTotal/MISP/AbuseIPDB)
- `CMDBEnricher` — asset criticality + owner (stub → ServiceNow/Device42, with static registry fallback)
- `CVEEnricher` — vulnerability context (stub → NVD API v2)
- `CircuitBreaker` — CLOSED → OPEN → HALF_OPEN state machine per enricher
- `_TTLCache` — in-process TTL cache to protect external APIs from repeated calls

### 6. Satellite/ISR Connector (`ingestion/connectors/satellite_connector.py`)
Dedicated connector for overhead imagery, SIGINT, ELINT, and space-based surveillance:
- Normalises geolocation (lat/lon → GEO observable + GeoLocation model)
- Extracts maritime vessel IDs (MMSI), aircraft ICAO codes, vehicle IDs as custom observables
- Classifies all ISR data as TLP:RED by default
- Free-text IOC extraction using the same patterns as Intel Report connector
- Activity-type based MITRE technique mapping
- Extensible to Link 16, VMF, national imagery exploitation APIs

### 7. Analyst Feedback (`models/feedback.py`, `storage/feedback_repository.py`)
- `AnalystFeedback` model with `Verdict` enum: TRUE_POSITIVE / FALSE_POSITIVE / BENIGN / NEEDS_REVIEW
- Confidence field for analyst certainty weighting
- `POST /api/v1/threats/{id}/feedback` endpoint (analyst role required)
- Every feedback action creates an `AuditRecord` (who decided what, when)
- `InMemoryFeedbackRepository` (dev) → `PostgresFeedbackRepository` (production path)

### 8. Prometheus Metrics (`observability/metrics.py`)
- Counters: alerts ingested, threats created, BLUF reports generated, API requests by method/status
- Gauges: stored alert/threat counts, system uptime
- Optional `prometheus-client` integration; falls back to `_SimpleMetrics` if not installed
- `GET /api/v1/metrics/prometheus` — text exposition format, no auth required (standard practice)
- `GET /api/v1/metrics` — JSON summary for dashboards and health checks

---

## Data Flow

```
1. INGEST
   External source → Connector.fetch_raw()
                   → Normaliser (schema enforcement, IOC extraction)
                   → Deduplicator (LRU cache, dedup_hash comparison)
                   → AlertEnricher (asset registry, TLP assignment, optional live enrichment)
                   → AlertRepository.save()

   OR (streaming):
   Redis Stream → StreamConsumer.consume() → IngestionPipeline (same path)

2. CORRELATE
   AlertRepository.list_recent()
   → IOCCorrelator     → shared observable pairs
   → TemporalCorrelator → time-window pairs
   → AssetCorrelator   → shared asset/segment pairs
   → BehaviourCorrelator → MITRE technique sequence matches
   → UnionFind         → merge pairs into groups
   → AttackGraph       → build directed graph, detect paths, compute centrality [v2]
   → FalsePositiveFilter → score FP probability per group
   → build CorrelatedThreat objects

3. MAP
   CorrelatedThreat → MitreMapper → attach technique details, tactic names, mitigations
                                    (YAML KB or official STIX bundle [v2])

4. SCORE
   CorrelatedThreat + MitreMapping → PrioritisationEngine
   → 5-factor weighted score:
       severity × 0.30
       confidence × 0.25
       source_reliability × 0.15
       asset_criticality × 0.20
       temporal_urgency × 0.10
   → graph centrality boost [v2]
   → PriorityScore (CRITICAL / HIGH / MEDIUM / LOW)

5. REPORT
   CorrelatedThreat + PriorityScore + MitreMapping → BlufGenerator
   → BlufReport (JSON + plain text)
   → ThreatRepository.save() + AuditRepository.append()

6. SERVE
   FastAPI: authenticated (API key / JWT), role-checked, TLP-filtered
   → /api/v1/threats      — prioritised threat list
   → /api/v1/threats/{id} — threat detail + score + audit
   → /api/v1/threats/{id}/bluf   — BLUF report (json / text)
   → /api/v1/threats/{id}/graph  — attack graph (Cytoscape JSON) [v2]
   → /api/v1/threats/{id}/feedback — analyst verdict [v2]
```

---

## Quick Start — Local Development

### Prerequisites

- Python 3.11+
- `pip install -e ".[dev]"`
- (Optional) `pip install -e ".[production]"` for PostgreSQL, Redis, NetworkX, Prometheus

```bash
# Clone / enter directory
cd threaticap

# Install with dev extras
pip install -e ".[dev]"

# Run demo (in-memory, no external services required)
python -m threaticap demo

# Start API server (dev mode, auth disabled)
THREATICAP_AUTH_DISABLED=true python -m threaticap serve

# API documentation
open http://localhost:8080/api/v1/docs
```

### Install all production extras

```bash
pip install -e ".[full]"
```

This installs: `psycopg2-binary`, `redis`, `networkx`, `prometheus-client`, `python-jose[cryptography]`, `stix2`, `scikit-learn`.

---

## Running with Docker Compose

```bash
# Copy and customise secrets (do NOT commit .env)
cp .env.example .env
# Edit .env: set DB_PASSWORD, REDIS_PASSWORD, THREATICAP_MASTER_KEY, JWT_SECRET_KEY

# Build and start all services
docker compose up --build

# Or start without Docker, using local Python against Docker backing services:
POSTGRES_DSN="postgresql://threaticap:changeme@localhost:5432/threaticap" \
REDIS_URL="redis://:changeme@localhost:6379/0" \
THREATICAP_AUTH_DISABLED=true \
python -m threaticap serve
```

### Environment Variable Reference

| Variable | Default | Description |
|---|---|---|
| `THREATICAP_CONFIG` | `config/config.yaml` | Path to YAML config file |
| `POSTGRES_DSN` | — | PostgreSQL connection string (required for postgresql backend) |
| `REDIS_URL` | — | Redis connection URL (required for streaming) |
| `THREATICAP_MASTER_KEY` | insecure dev key | Admin API key (override immediately in production) |
| `JWT_SECRET_KEY` | insecure dev secret | JWT signing secret (random 256-bit hex in production) |
| `THREATICAP_AUTH_DISABLED` | `false` | **DEVELOPMENT ONLY** — bypasses all auth |
| `LOG_LEVEL` | `INFO` | Python log level |
| `JSON_LOGS` | `false` | Emit structured JSON logs (use `true` in production) |
| `ENVIRONMENT` | `development` | `development` or `production` (affects JWT secret enforcement) |
| `THREATICAP_API_KEY_1..4` | — | Additional API keys to register at startup |
| `THREATICAP_API_ROLE_1..4` | `reader` | Role for corresponding API key |
| `THREATICAP_API_ACTOR_1..4` | `user1..4` | Actor label for corresponding API key |

### First-time PostgreSQL setup

The migrations are applied automatically via the Docker Compose `docker-entrypoint-initdb.d` volume mount on first container start. For a pre-existing database:

```bash
# Apply migrations manually
python -c "
from threaticap.storage.migrations import run_migrations
run_migrations('postgresql://threaticap:password@localhost:5432/threaticap')
"
```

---

## Authentication & RBAC

All API endpoints (except `/api/v1/health`, `/api/v1/metrics/prometheus`, and `/`) require authentication.

### API Key authentication

```bash
# Provide in X-API-Key header
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/threats
```

### JWT Bearer authentication

```bash
# Create a JWT (requires python-jose)
python -c "
from threaticap.api.auth import create_jwt_token, Role
token = create_jwt_token('my-id', 'analyst-alice', Role.ANALYST, 'TLP:AMBER')
print(token)
"

# Use in Authorization header
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/threats
```

### Creating a new API key (admin required)

```bash
curl -X POST -H "X-API-Key: $ADMIN_KEY" \
  "http://localhost:8080/api/v1/admin/api-keys?actor=soc-tool&role=operator&clearance=TLP%3AAMBER"
```

### Role permissions

| Role | Can do |
|---|---|
| `reader` | View threats, BLUF reports, alerts, audit trail, metrics |
| `analyst` | Reader + submit feedback, run pipeline |
| `operator` | Analyst + ingest alerts, manage some settings |
| `admin` | Full access including key management |

### TLP clearance

Users are assigned a clearance level (TLP:WHITE / GREEN / AMBER / RED). Data tagged at a higher TLP than the user's clearance is not returned. The most-restrictive-wins rule applies when aggregating multi-source alerts.

---

## API Reference

Base URL: `http://host:8080/api/v1`
Interactive docs: `http://host:8080/api/v1/docs`

### Ingest

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/ingest/alerts` | operator | Submit one or more alerts for ingestion. `run_pipeline=true` triggers immediate processing. |

```bash
curl -X POST -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "alerts": [{
      "source_ref": "SIEM-001",
      "source_type": "SIEM",
      "source_id": "splunk-01",
      "event_time": "2024-01-15T10:00:00Z",
      "severity": "HIGH",
      "title": "Suspicious PowerShell execution",
      "mitre_technique_ids": ["T1059.001"]
    }],
    "run_pipeline": true
  }' \
  http://localhost:8080/api/v1/ingest/alerts
```

### Pipeline

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/pipeline/run` | analyst | Run correlation + prioritisation on stored alerts. |

### Threats

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/threats` | reader | List prioritised threats. Query: `tier`, `limit`, `offset`. |
| `GET` | `/threats/{id}` | reader | Full threat detail with score and audit trail. |
| `GET` | `/threats/{id}/bluf` | reader | BLUF report. Query: `format=json\|text`. |
| `GET` | `/threats/{id}/graph` | analyst | Attack graph (Cytoscape-compatible JSON). |
| `POST` | `/threats/{id}/feedback` | analyst | Submit analyst verdict. Query: `verdict`, `confidence`, `notes`. |

### Reports, Alerts, Audit

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/reports` | reader | Recent BLUF reports. |
| `GET` | `/reports/{id}` | reader | Single BLUF report (json or text). |
| `GET` | `/alerts/{id}` | reader | Single alert. |
| `GET` | `/alerts` | reader | Recent alerts list. |
| `GET` | `/audit` | reader | Audit trail. Query: `threat_id`, `alert_id`, `limit`. |

### System

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | none | Health check (storage + enricher states). |
| `GET` | `/metrics` | reader | JSON operational metrics. |
| `GET` | `/metrics/prometheus` | none | Prometheus text exposition. |

### Admin

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/admin/api-keys` | admin | Generate a new API key. Returns raw key once — store immediately. |

---

## Configuration Reference

All settings live in `config/config.yaml`. Every value can be overridden via environment variables. The file is loaded at startup; live reload is not supported (restart required).

### Key sections

```yaml
# Correlation engine
correlation:
  ioc_enabled: true
  temporal_enabled: true
  asset_enabled: true
  behaviour_enabled: true
  graph_enabled: true              # NetworkX attack graph (requires networkx)
  temporal_window_seconds: 3600
  min_group_confidence: 0.30
  graph_centrality_boost_max: 0.15 # Priority boost for hub alerts

# Scoring weights (must sum to 1.0)
scoring:
  weights:
    severity: 0.30
    confidence: 0.25
    source_reliability: 0.15
    asset_criticality: 0.20
    temporal_urgency: 0.10
  thresholds:
    critical: 80.0
    high: 60.0
    medium: 35.0

# MITRE ATT&CK
mitre:
  knowledge_base_path: "config/mitre_attack_kb.yaml"
  # Production: download enterprise-attack.json from MITRE CTI repo and set:
  # stix_bundle_path: "config/enterprise-attack.json"

# Storage backend
storage:
  backend: "memory"     # "memory" | "postgresql"
  pool_min_size: 2
  pool_max_size: 10

# Streaming (Redis Streams)
streaming:
  enabled: false
  stream_name: "threaticap:alerts:inbound"
  consumer_group: "threaticap-workers"
  batch_size: 100
  poll_interval_seconds: 1.0
  dead_letter_stream: "threaticap:alerts:dead"
  max_retry_count: 3

# Enrichment
enrichment:
  enabled: false
  reputation:
    enabled: false
    provider: "stub"   # stub | virustotal | abuseipdb | misp
  cmdb:
    enabled: false
    provider: "static" # static | servicenow | device42
  cve:
    enabled: false
```

### Asset Registry

The `asset_registry` section in `config.yaml` maps IP addresses and hostnames to asset context (criticality, owner, classification, tags). In production, replace with a live CMDB integration via `enrichment.cmdb`.

---

## MITRE ATT&CK Knowledge Base

The YAML knowledge base at `config/mitre_attack_kb.yaml` contains 27 pre-configured techniques covering:
- Initial Access (T1190, T1566.001, T1133)
- Execution (T1059.001, T1059.003, T1204.002)
- Persistence (T1547.001, T1543.003, T1053.005)
- Privilege Escalation (T1068, T1055)
- Defense Evasion (T1027, T1562.001)
- Credential Access (T1003.001, T1110)
- Discovery (T1082, T1016, T1057)
- Lateral Movement (T1021.001, T1021.002, T1570)
- Collection (T1005, T1056.001)
- Command and Control (T1071.001, T1095, T1573.002)
- Exfiltration (T1041)

### Loading the Official STIX Bundle

For production, download the official MITRE ATT&CK Enterprise STIX bundle:

```bash
# Download from MITRE CTI repo (or via TAXII)
curl -L https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
  -o config/enterprise-attack.json

# Enable in config.yaml:
# mitre:
#   stix_bundle_path: "config/enterprise-attack.json"
```

The STIX bundle and YAML KB are merged — YAML entries take precedence (override layer for classified/custom techniques).

---

## Streaming Ingestion (Redis Streams)

### Architecture

```
External Sources ──► Redis Stream (threaticap:alerts:inbound)
                                │
              ┌─────────────────┴─────────────────┐
              │  Worker 1 (Consumer Group)         │
              │  Worker 2 (Consumer Group)   ...   │   ← horizontal scale
              └─────────────────┬─────────────────┘
                                │
                          IngestionPipeline
                          (normalise → dedup → enrich → store)
```

### Enable Streaming

```yaml
# config.yaml
streaming:
  enabled: true
  stream_name: "threaticap:alerts:inbound"
  consumer_group: "threaticap-workers"
  batch_size: 100
```

```bash
# Start a streaming worker
REDIS_URL="redis://:password@localhost:6379/0" \
python -c "
import asyncio
from threaticap.ingestion.stream_consumer import StreamingIngestionManager
manager = StreamingIngestionManager.from_config('config/config.yaml')
asyncio.run(manager.run())
"
```

### Publishing alerts to the stream

```python
import redis
import json

r = redis.from_url("redis://:password@localhost:6379/0")
r.xadd("threaticap:alerts:inbound", {
    "alert": json.dumps({
        "source_ref": "SIEM-STREAM-001",
        "source_type": "SIEM",
        "source_id": "kafka-bridge",
        "event_time": "2024-01-15T10:00:00Z",
        "severity": "HIGH",
        "title": "Credential dumping detected"
    })
})
```

---

## Graph Correlation

### Overview

When `networkx` is installed and `correlation.graph_enabled=true`, the correlation engine builds a directed attack graph alongside the Union-Find clusters:

- **Nodes** — each alert, with attributes (severity, MITRE techniques, asset criticality, source type)
- **Edges** — correlation signals (IOC match, temporal proximity, asset overlap) with weights
- **Attack paths** — topological sort of directed subgraphs reveals kill-chain sequences
- **Centrality** — betweenness centrality identifies hub alerts that connect many correlation chains → priority boost

### Install

```bash
pip install networkx
```

### Retrieve the attack graph

```bash
curl -H "X-API-Key: $ANALYST_KEY" \
  http://localhost:8080/api/v1/threats/threat-id-here/graph
```

Response (Cytoscape-compatible):
```json
{
  "threat_id": "abc123",
  "graph": {
    "nodes": [{"id": "alert-1", "severity": "HIGH", ...}],
    "edges": [{"source": "alert-1", "target": "alert-2", "weight": 0.8}],
    "stats": {"node_count": 5, "edge_count": 7, "density": 0.35}
  },
  "attack_paths": [["alert-1", "alert-3", "alert-5"]]
}
```

---

## Enrichment

### Configuring live enrichment

```yaml
# config.yaml
enrichment:
  enabled: true
  reputation:
    enabled: true
    provider: "virustotal"    # Replace stub with real provider
    # api_key: set via REPUTATION_API_KEY env var
  cmdb:
    enabled: true
    provider: "servicenow"
    # cmdb_url: set via CMDB_URL env var
    # api_token: set via CMDB_API_TOKEN env var
```

### Implementing a custom enricher

```python
from threaticap.enrichment.broker import BaseEnricher
import httpx

class VirusTotalEnricher(BaseEnricher):
    def __init__(self, api_key: str, **kwargs):
        super().__init__("virustotal", ttl_seconds=1800, **kwargs)
        self._api_key = api_key

    def _fetch(self, key: str) -> dict:
        r = httpx.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{key}",
            headers={"x-apikey": self._api_key},
            timeout=10,
        )
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        stats = attrs["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "reputation": attrs.get("reputation", 0),
            "provider": "virustotal",
        }
```

### Circuit breaker behaviour

Each enricher has an independent circuit breaker:
- **CLOSED** — requests pass through
- **OPEN** — fast-fail after `failure_threshold` consecutive failures; no external calls
- **HALF_OPEN** — one test request after `reset_timeout_seconds`; success closes, failure re-opens

The system degrades gracefully — missing enrichment data never blocks alert processing.

---

## Analyst Feedback

```bash
# Mark a threat as a confirmed true positive
curl -X POST -H "X-API-Key: $ANALYST_KEY" \
  "http://localhost:8080/api/v1/threats/threat-id/feedback?verdict=TRUE_POSITIVE&confidence=0.95&notes=Confirmed+C2+comms"

# Mark as false positive
curl -X POST -H "X-API-Key: $ANALYST_KEY" \
  "http://localhost:8080/api/v1/threats/threat-id/feedback?verdict=FALSE_POSITIVE&confidence=1.0&notes=Scheduled+scanner"

# Retrieve all feedback for a threat
curl -H "X-API-Key: $READER_KEY" \
  http://localhost:8080/api/v1/threats/threat-id/feedback
```

Feedback verdicts: `TRUE_POSITIVE` | `FALSE_POSITIVE` | `BENIGN` | `NEEDS_REVIEW`

Every feedback submission is written to the audit trail with the analyst's actor ID, timestamp, and verdict. This creates an accountability record for all analyst decisions and provides training data for future FP filter improvements.

---

## Observability

### Prometheus metrics

```bash
# Scrape metrics
curl http://localhost:8080/api/v1/metrics/prometheus
```

Example output:
```
# HELP threaticap_alerts_ingested_total Total alerts ingested
# TYPE threaticap_alerts_ingested_total counter
threaticap_alerts_ingested_total 1423.0
# HELP threaticap_threats_created_total Total correlated threats created
# TYPE threaticap_threats_created_total counter
threaticap_threats_created_total 87.0
...
```

### Prometheus scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: threaticap
    static_configs:
      - targets: ['threaticap-api:8080']
    metrics_path: /api/v1/metrics/prometheus
```

### Health check

```bash
curl http://localhost:8080/api/v1/health
```

```json
{
  "status": "ok",
  "version": "2.0.0",
  "uptime_seconds": 3600,
  "alerts_stored": 1423,
  "threats_stored": 87
}
```

### Structured logging

Set `JSON_LOGS=true` for production log shipping (Splunk, ELK, Loki):

```json
{"timestamp": "2024-01-15T10:00:01Z", "level": "INFO", "logger": "threaticap.pipeline",
 "message": "Pipeline run complete: 47 alerts -> 12 threats", "alerts": 47, "threats": 12}
```

---

## Sample Data & Demo

```bash
# Load and process all sample data sources
python -m threaticap demo

# The demo:
# 1. Loads data from data/sample/ (SIEM, EDR, intel reports, STIX, satellite/ISR)
# 2. Runs the full ingestion → correlation → scoring → BLUF pipeline
# 3. Prints a prioritised threat list and sample BLUF reports
# 4. Shows statistics broken down by source type, severity, and priority tier
```

Sample data files:
- `data/sample/siem_alerts.json` — 10 realistic SIEM events including lateral movement and C2
- `data/sample/edr_events.json` — EDR telemetry including credential dumping and process injection
- `data/sample/intel_reports.json` — HUMINT/SIGINT reports with IOCs and threat actor attribution
- `data/sample/stix_bundle.json` — STIX 2.1 bundle with indicators, threat actors, and attack patterns
- `data/sample/satellite_isr_reports.json` — Overhead imagery and SIGINT intercept reports

The sample data exercises both **true positive paths** (correlated multi-source APT activity) and **false positive paths** (benign scanner traffic, routine maintenance).

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=threaticap --cov-report=term-missing

# Run specific test module
python -m pytest tests/test_graph_correlator.py -v
python -m pytest tests/test_enrichment.py -v
python -m pytest tests/test_auth.py -v
python -m pytest tests/test_feedback.py -v
python -m pytest tests/test_satellite_connector.py -v
```

### Test coverage

| Module | Tests | Coverage area |
|---|---|---|
| `test_models.py` | 25 | All Pydantic models, validation, serialisation |
| `test_ingestion.py` | 35 | Normaliser, deduplicator, enricher, connectors |
| `test_correlation.py` | 20 | IOC/temporal/asset/behaviour correlators, FP filter |
| `test_scoring_bluf.py` | 15 | Prioritisation engine, BLUF generator |
| `test_pipeline.py` | 10 | End-to-end pipeline runs |
| `test_api.py` | 20 | All FastAPI endpoints (auth disabled via env) |
| `test_graph_correlator.py` | 35 | AttackGraph construction, paths, centrality, community |
| `test_enrichment.py` | 40 | CircuitBreaker, TTLCache, BaseEnricher, broker |
| `test_auth.py` | 30 | Roles, TLP, key generation/verification, JWT, store |
| `test_feedback.py` | 30 | Feedback model, repository, API integration |
| `test_satellite_connector.py` | 25 | ISR loading, normalisation, observables, errors |

Graph tests are automatically skipped when `networkx` is not installed. JWT tests are automatically skipped when `python-jose` is not installed.

---

## Extension Points

### Swap storage backend

```python
# Activate PostgreSQL backend
from threaticap.storage.postgres_repositories import create_postgres_repositories

alert_repo, threat_repo, audit_repo, report_repo = create_postgres_repositories(
    dsn="postgresql://user:pass@host:5432/threaticap"
)
pipeline = ThreatPipeline(
    alert_repo=alert_repo,
    threat_repo=threat_repo,
    audit_repo=audit_repo,
    report_repo=report_repo,
)
```

### Add a custom connector

```python
from threaticap.ingestion.base_connector import BaseConnector, ConnectorConfig

class MyCustomConnector(BaseConnector):
    def connect(self) -> None: ...
    def disconnect(self) -> None: ...
    def fetch_raw(self): yield from my_api.get_alerts()
    def normalise(self, raw): return Alert(...)
```

### Add a custom enricher

```python
from threaticap.enrichment.broker import BaseEnricher

class ThreatFoxEnricher(BaseEnricher):
    def _fetch(self, key: str) -> dict:
        # Call ThreatFox API, return dict
        ...
```

### Plug in an ML model

The `FalsePositiveFilter` and `PrioritisationEngine` both accept their parameters from config. Replace the heuristic FP filter with a trained classifier:

```python
from threaticap.correlation.fp_filter import FalsePositiveFilter

class MLFPFilter(FalsePositiveFilter):
    def __init__(self, model_path: str):
        self._model = joblib.load(model_path)

    def score(self, group: AlertGroup) -> float:
        features = self._extract_features(group)
        return float(self._model.predict_proba([features])[0][1])
```

### Graph database integration

The `AttackGraph` exports to Cytoscape-compatible JSON. To persist to Neo4j or ArangoDB:

```python
from threaticap.correlation.graph_correlator import AttackGraph

graph = attack_graph  # from pipeline run
graph_data = graph.to_dict()
# Push nodes and edges to Neo4j/ArangoDB via their respective Python clients
```

---

## Security & Operational Considerations

### Secrets management

- All secrets (DB passwords, API keys, JWT secrets) must be set via environment variables or mounted files — **never in config.yaml or Docker images**
- Use Docker secrets (`docker secret create`) or Kubernetes Secrets (`kubectl create secret`) in production
- In classified environments, integrate with a hardware security module (HSM) or approved secrets manager (CyberArk, HashiCorp Vault)
- JWT secret should be a cryptographically random 256-bit value: `python -c "import secrets; print(secrets.token_hex(32))"`

### API key management

- Raw API keys are shown only once at creation — store immediately in a secure credential store
- In production, replace `_DEV_API_KEYS` with a database-backed `PostgresApiKeyStore`
- Implement key rotation policy (e.g., 90-day expiry) at the application layer
- Consider upgrading from SHA-256 to bcrypt for key hashing in high-assurance environments: `pip install bcrypt` then update `_hash_api_key()`

### JWT hardening

- For production, switch from HS256 to RS256 with a dedicated signing key pair
- Implement a token revocation list (Redis TTL-based) for immediate session invalidation
- Set token expiry appropriate to operational tempo (default: 8 hours)

### Network security

- Deploy behind mTLS-terminating ingress (Envoy, nginx, Istio) for service-to-service communications
- Bind PostgreSQL and Redis ports to loopback only (already done in docker-compose.yml: `127.0.0.1:5432`)
- Rate-limit the API at the ingress layer; do not rely on application-level rate limiting alone
- In classified environments, place the entire cluster on an isolated network segment with no internet access

### Container security

- Dockerfile uses `nobody` user (uid 65534) — no home directory, no login shell
- No secrets baked into image layers
- Add `readOnlyRootFilesystem: true` and `allowPrivilegeEscalation: false` to Kubernetes SecurityContext
- Scan images with Trivy or Grype in CI before deployment
- Consider `distroless` base images for further attack surface reduction

### Data handling

- All ISR/classified data should be TLP:RED by default — the connector enforces this
- Implement field-level encryption for `raw_payload` in the PostgreSQL schema for classified deployments
- Consider a separate database instance per classification level (physical separation)
- Audit log is append-only — implement database-level constraints (`INSERT` only) in production

### Air-gapped operation

- The CLI (`python -m threaticap`) operates entirely offline
- The in-memory backend requires no external services
- Disable enrichment (`enrichment.enabled: false`) when external lookups are not available
- Bundle the MITRE ATT&CK STIX bundle with the deployment package (do not fetch at runtime)

---

## Kubernetes Deployment

### Minimal deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threaticap
spec:
  replicas: 3
  selector:
    matchLabels:
      app: threaticap
  template:
    metadata:
      labels:
        app: threaticap
    spec:
      containers:
        - name: threaticap
          image: threaticap:2.0.0
          ports:
            - containerPort: 8080
          env:
            - name: POSTGRES_DSN
              valueFrom:
                secretKeyRef:
                  name: threaticap-secrets
                  key: postgres-dsn
            - name: THREATICAP_MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: threaticap-secrets
                  key: master-key
            - name: JWT_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: threaticap-secrets
                  key: jwt-secret
            - name: JSON_LOGS
              value: "true"
            - name: ENVIRONMENT
              value: "production"
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
          livenessProbe:
            httpGet:
              path: /api/v1/health
              port: 8080
            initialDelaySeconds: 20
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /api/v1/health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          resources:
            requests:
              memory: "256Mi"
              cpu: "200m"
            limits:
              memory: "1Gi"
              cpu: "1000m"
          volumeMounts:
            - name: config
              mountPath: /app/config
              readOnly: true
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: config
          configMap:
            name: threaticap-config
        - name: tmp
          emptyDir: {}
```

```bash
# Create secrets
kubectl create secret generic threaticap-secrets \
  --from-literal=postgres-dsn="postgresql://threaticap:$(openssl rand -hex 16)@postgres:5432/threaticap" \
  --from-literal=master-key="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  --from-literal=jwt-secret="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# Create configmap from config file
kubectl create configmap threaticap-config --from-file=config/config.yaml

# Deploy
kubectl apply -f k8s/
```

### Horizontal scaling

THREATICAP's stateless API tier scales horizontally with standard Kubernetes HPA:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: threaticap-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: threaticap
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

For the streaming worker (Redis Streams consumer), scale worker pods independently from the API pods.

---

## Roadmap for Classified Environments

The following items represent a typical hardening programme for deployment into a classified/air-gapped environment:

### Immediate (before any classified data)

- [ ] Replace `SHA-256` API key hashing with `bcrypt` (`pip install bcrypt`)
- [ ] Switch JWT from `HS256` to `RS256` with a hardware-generated key pair
- [ ] Implement token revocation list (Redis TTL)
- [ ] Replace `_DEV_API_KEYS` in-memory store with `PostgresApiKeyStore`
- [ ] Field-level encryption for `raw_payload` in alert storage
- [ ] Enable `readOnlyRootFilesystem` and drop all capabilities in Kubernetes SecurityContext
- [ ] Implement network policies (`NetworkPolicy`) to restrict pod-to-pod traffic
- [ ] Static code analysis (Bandit, Semgrep) and dependency scanning (Safety) in CI

### Short-term (operational deployment)

- [ ] LDAP/CAC/PIV integration for analyst authentication (replace JWT with federated IdP)
- [ ] Mandatory access control (MAC) label enforcement beyond TLP (e.g., ACCM/SCI compartments)
- [ ] Data-at-rest encryption for PostgreSQL volumes (LUKS, cloud KMS)
- [ ] Centralised log aggregation with tamper-evident log signing
- [ ] Automated MITRE ATT&CK STIX bundle refresh (via internal TAXII server)
- [ ] Integration with national threat intelligence sharing platforms (MISP, TAXII 2.1)
- [ ] Graph database (Neo4j Enterprise) for persistent attack path storage and analyst queries

### Medium-term (advanced analytics)

- [ ] ML-based FP classification model (scikit-learn → training pipeline from analyst feedback)
- [ ] Embedding-based behavioural clustering (sentence-transformers for alert description similarity)
- [ ] Anomaly detection on network telemetry (isolation forest, autoencoder)
- [ ] Threat hunting query interface (EQL / Sigma rule execution)
- [ ] Campaign attribution scoring (probabilistic actor profiling against known TTPs)
- [ ] Integration with vulnerability management platforms (Tenable, Qualys) for exploit-chain scoring

### Infrastructure (hardened production cluster)

- [ ] Air-gap the cluster (no outbound internet; internal mirror for packages)
- [ ] Hardware Security Module (HSM) integration for key management
- [ ] Immutable infrastructure (golden image pipeline; no `docker pull` at runtime)
- [ ] FIPS 140-2 compliant cryptographic modules
- [ ] Formal penetration test and security accreditation
- [ ] Red team exercise against the SOC workflow

---

## Development & Contributing

```bash
# Set up development environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev,production]"

# Run tests
python -m pytest tests/ -v --cov=threaticap

# Run the demo
THREATICAP_AUTH_DISABLED=true python -m threaticap demo

# Start dev server (auth disabled)
THREATICAP_AUTH_DISABLED=true python -m threaticap serve

# Lint (if configured)
python -m flake8 threaticap/
python -m mypy threaticap/
```

### Code conventions

- Python 3.11+ with full type hints throughout
- Pydantic v2 for all data models — never use raw dicts as data contracts
- Every business-logic decision must be logged at INFO level and written to the audit trail
- No hard-coded thresholds or mappings — everything in config or the MITRE KB
- Tests for all new logic — aim for >85% branch coverage on core modules
- No secrets in source code, config files, or Docker images

---

*THREATICAP v2.0 — Threat Intelligence Correlation & Alert Prioritisation System*
*Designed for national-level defence SOC environments. Handle all operational data in accordance with applicable information security policies and classification guidance.*

---

## Phase 3 — National Defence SOC Capabilities

### 1. Mission-Aware Prioritisation

Threats are scored not only by technical severity but by their operational impact on active missions. The prioritisation engine applies a **mission impact multiplier** (1.0–3.0×) to the asset criticality component when a threat targets assets involved in live operations.

**How to use:**
```python
from threaticap.models.mission import Mission, MissionContext, MissionReadiness, AssetMissionRole
from threaticap.pipeline import ThreatPipeline

ctx = MissionContext(missions=[
    Mission(
        mission_id="OP-ALPHA-01",
        name="Operation Alpha",
        readiness=MissionReadiness.ACTIVE,
        priority_rank=1,
        asset_roles=[
            AssetMissionRole(asset_id="ASSET-001", mission_id="OP-ALPHA-01",
                             role="C2", impact_weight=2.5, degradation_threshold=0.4)
        ],
    )
])

pipeline = ThreatPipeline(mission_context=ctx)
# Hot-reload without restart:
pipeline.update_mission_context(new_ctx)
```

Mission context is also configurable via `config.yaml` → `mission_context.missions`.

---

### 2. Multi-Stage Attack Campaign Reconstruction

The `KillChainReconstructor` maps observed MITRE techniques to **Unified Kill Chain phases**, orders them chronologically, and produces a narrative automatically embedded in BLUF reports.

| Field | Description |
|---|---|
| `observed_phases` | Ordered list of kill chain phases with supporting evidence |
| `kill_chain_completion` | Fraction of kill chain completed (0.0–1.0) |
| `adversary_objective` | Assessed intent (Data Theft, Destructive Attack, etc.) |
| `is_advanced_persistent` | True when ≥4 phases and ≥50% completion |
| `coverage_gaps` | Phases expected but not observed — collection gaps |
| `narrative` | Plain-English summary for commander BLUF |

Campaign reconstruction runs automatically in the pipeline for every threat. The narrative appears in `BlufReport.campaign_narrative`.

---

### 3. Closed-Loop False Positive Reduction

Analyst TP/FP/BENIGN labels are recorded against the originating rules and sources. The `FeedbackAwareFPFilter` blends heuristic FP probability with learned empirical rates using **Exponential Moving Averages**.

```python
from threaticap.correlation.fp_learning import FeedbackStore, FeedbackAwareFPFilter
from threaticap.correlation.fp_filter import FalsePositiveFilter

store = FeedbackStore(persist_path=Path("data/feedback.json"))
# record feedback:
store.record(analyst_feedback, constituent_alerts)
# The AdjustedFPFilter automatically uses this when scoring:
adjusted_filter = FeedbackAwareFPFilter(FalsePositiveFilter(), store)
```

The learning rate is capped to prevent overfit. Minimum 3 samples required before learning activates per key.

---

### 4. Classified & Coalition Intelligence Handling

**Classification levels:** `UNCLASSIFIED` → `OFFICIAL` → `OFFICIAL-SENSITIVE` → `SECRET` → `TOP SECRET` → `TOP SECRET//SCI`

**TLP 2.0:** `TLP:CLEAR` / `TLP:GREEN` / `TLP:AMBER` / `TLP:AMBER+STRICT` / `TLP:RED`

**Handling caveats:** NOFORN, REL TO, ORCON, EYES ONLY, SI, SAP, HCS

```python
from threaticap.classification.handler import (
    ClassificationLabel, ClassificationLevel, TLPLevel, HandlingCaveat,
    SharingPolicy, SharingPartner, IntelSanitiser, STIXExporter
)

label = ClassificationLabel(
    level=ClassificationLevel.SECRET,
    tlp=TLPLevel.AMBER,
    caveats=[HandlingCaveat.RELTO],
    releasable_to=["GBR", "AUS", "CAN", "NZL", "USA"],
)
allowed, reason = label.is_shareable_with(partner)
```

`IntelSanitiser` strips raw payloads, anonymises source identifiers, and blocks HUMINT/SIGINT source types before any outbound transfer. `STIXExporter` produces STIX 2.1 bundles with correct TLP marking definition IDs (FIRST.org).

---

### 5. Cross-Domain & Air-Gapped Operation

```python
from threaticap.transfer.cross_domain import (
    CrossDomainGuard, SecurityDomain,
    SecureTransferPackage, AirGappedExportWriter, AirGappedImportReader,
    DisconnectedModeManager
)

# Enforce domain boundary
guard = CrossDomainGuard(allow_high_to_low=True, require_sanitisation=True)
guard.check(SecurityDomain.HIGH, SecurityDomain.LOW, is_sanitised=True)

# Package for physical media transfer
pkg = SecureTransferPackage(records=[...], classification="SECRET")
pkg.seal(transfer_key=os.environ["TRANSFER_KEY"].encode())
AirGappedExportWriter().write(pkg, Path("outbound/"), transfer_key)

# Import and verify on the other side
loaded = AirGappedImportReader().read(pkg_path, transfer_key)
```

**Transfer packages** (`.tigpkg`) are self-describing JSON with SHA-256 checksum and optional HMAC-SHA256 signature. Any modification to any field invalidates the signature, detected immediately on import. In disconnected mode, STIX bundles are queued in memory and flushed when connectivity restores.

---

### 6. MISP & National TIP Connectors

```python
from threaticap.ingestion.connectors.misp_connector import MISPConnector
from threaticap.ingestion.connectors.national_tip_connector import NationalTIPConnector

misp = MISPConnector(
    url="https://misp.example.mil",
    api_key=os.environ["MISP_API_KEY"],
    event_filters={"tags": ["tlp:amber"], "limit": 200},
    push_sightings=True,
    cache_path="data/misp_cache.json",   # fallback for disconnected ops
)
alerts = misp.normalise(misp.fetch())

# TAXII 2.1 (national TIP / CISP)
tip = NationalTIPConnector(
    adapter_type="taxii21",
    url="https://tip.example.mil/taxii/",
    collection_id="...",
    api_key=os.environ["NATIONAL_TIP_API_KEY"],
)
alerts = tip.normalise(tip.fetch())
```

Both connectors degrade gracefully when the upstream platform is unreachable (cache fallback, empty list respectively) — critical for disconnected operations.

---

### 7. Role-Specific BLUF Formats

```python
from threaticap.reporting.commander_bluf import CommanderBlufRenderer, OutputRole

renderer = CommanderBlufRenderer()
text = renderer.render(
    bluf_report,
    role=OutputRole.COMMANDER,
    degraded_missions=score.degraded_missions,
    campaign_narrative=campaign.narrative,
    classification_banner="OFFICIAL-SENSITIVE",
)
```

| Role | Focus | Key sections |
|---|---|---|
| `COMMANDER` | Decision-centric, no jargon | SO WHAT → RECOMMENDED COMMAND DECISIONS → MISSION IMPACT |
| `WATCH_OFFICER` | SITREP brevity (≤10 lines) | DTG, SITUATION, RECOMMENDED ACTION |
| `SOC_ANALYST` | Full technical detail | All standard BlufReport sections + campaign + mission |
| `INTEL_OFFICER` | Attribution & collection gaps | KEY JUDGEMENTS, CAMPAIGN ANALYSIS, COLLECTION GAPS |
| `COALITION` | Sanitised for sharing | Indicators, techniques, TLP — no mission/classification caveats |

---

### 8. Threat Intelligence Quality Management

Sources are rated against the **NATO Admiralty Scale** (A–F reliability, 1–6 credibility).

```python
from threaticap.intel_quality.feed_quality import FeedQualityManager

qm = FeedQualityManager.from_config(config_dict)
qm.record_alert_ingested(alert.model_dump())
qm.record_verdict("source-id", is_true_positive=True)
weight = qm.get_source_weight("source-id")   # 0.0–1.0
decayed = qm.get_decayed_confidence("ipv4-addr", "1.2.3.4", base_confidence=0.9)
report = qm.get_source_quality_report()      # sorted by reliability
qm.retire_stale_indicators()                 # auto-retire after max_staleness_days
```

Confidence decay uses a **radioactive half-life model**: confidence halves every `half_life_days` (default 30). The floor `min_confidence` (default 0.05) ensures indicators never fully expire without explicit retirement. All state is optionally persisted to JSON for air-gapped deployments.

---

### New File Structure (Phase 3)

```
threaticap/
├── models/
│   ├── mission.py              # MissionContext, Mission, AssetMissionRole
│   └── priority.py             # PriorityScore (+ mission_impact_multiplier, degraded_missions)
├── analysis/
│   └── campaign_reconstructor.py  # KillChainReconstructor, CampaignReconstruction
├── classification/
│   └── handler.py              # ClassificationLabel, SharingPolicy, IntelSanitiser, STIXExporter
├── transfer/
│   └── cross_domain.py         # CrossDomainGuard, SecureTransferPackage, AirGapped{Export,Import}
├── intel_quality/
│   └── feed_quality.py         # FeedQualityManager, ConfidenceDecayEngine, SourceQualityRecord
├── correlation/
│   └── fp_learning.py          # FeedbackStore, FeedbackAwareFPFilter
├── ingestion/connectors/
│   ├── misp_connector.py       # MISPConnector
│   └── national_tip_connector.py  # NationalTIPConnector, TAXII21Adapter
├── reporting/
│   └── commander_bluf.py       # CommanderBlufRenderer, OutputRole
└── scoring/
    └── prioritisation_engine.py  # Extended with mission context
```

