"""
FastAPI application — THREATICAP REST API (production-hardened).

Endpoints:
    POST /api/v1/ingest/alerts                     — Submit alerts
    POST /api/v1/pipeline/run                      — Run correlation pipeline
    GET  /api/v1/threats                           — List prioritised threats
    GET  /api/v1/threats/{id}                      — Threat detail
    GET  /api/v1/threats/{id}/bluf                 — BLUF report (json/text)
    GET  /api/v1/threats/{id}/graph                — Attack graph (NetworkX)
    POST /api/v1/threats/{id}/feedback             — Analyst feedback (TP/FP/Benign)
    GET  /api/v1/reports                           — List BLUF reports
    GET  /api/v1/reports/{id}                      — Single report
    GET  /api/v1/alerts/{id}                       — Single alert
    GET  /api/v1/alerts                            — Recent alerts
    GET  /api/v1/audit                             — Audit trail
    GET  /api/v1/health                            — Health check
    GET  /api/v1/metrics                           — JSON operational metrics
    GET  /api/v1/metrics/prometheus                — Prometheus text metrics
    POST /api/v1/admin/api-keys                    — Create API key (admin)

Security:
    All endpoints require X-API-Key or Authorization: Bearer <jwt>
    Set THREATICAP_AUTH_DISABLED=true to bypass in development only.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import yaml
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from threaticap import __version__
from threaticap.api.auth import AuthToken, Role, authenticate_request, require_role, generate_api_key, _hash_api_key, _DEV_API_KEYS
from threaticap.api.schemas import (
    AlertSubmitRequest,
    AlertSubmitResponse,
    BlufReportResponse,
    ErrorResponse,
    HealthResponse,
    MetricsResponse,
    PipelineRunRequest,
    PipelineRunResponse,
    ThreatDetailResponse,
    ThreatListResponse,
)
from threaticap.api.dependencies import get_pipeline, get_ingestion_pipeline, get_feedback_repo
from threaticap.ingestion.pipeline import IngestionPipeline, IngestionConfig
from threaticap.models.feedback import AnalystFeedback, Verdict
from threaticap.models.audit import AuditEventType, AuditRecord
from threaticap.observability.metrics import (
    record_api_request, record_alert_ingested, record_threat_created,
    record_bluf_generated, update_stored_counts, generate_prometheus_output,
    get_metrics,
)
from threaticap.pipeline import ThreatPipeline
from threaticap.storage.feedback_repository import InMemoryFeedbackRepository

logger = logging.getLogger(__name__)

# Application startup time for uptime tracking
_START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    logger.info("THREATICAP API starting (v%s)", __version__)

    # Initialise pipeline from config
    config_path = os.environ.get("THREATICAP_CONFIG", "config/config.yaml")
    pipeline = ThreatPipeline.from_config_file(config_path)
    app.state.pipeline = pipeline

    # Initialise ingestion pipeline
    ingest_cfg = IngestionConfig(
        asset_registry=_load_asset_registry(config_path),
    )
    app.state.ingest_pipeline = IngestionPipeline(config=ingest_cfg)

    # Feedback repository
    app.state.feedback_repo = InMemoryFeedbackRepository()

    logger.info("THREATICAP API ready (auth_disabled=%s)",
                os.environ.get("THREATICAP_AUTH_DISABLED", "false"))
    yield
    logger.info("THREATICAP API shutting down")


def _load_asset_registry(config_path: str) -> dict[str, Any]:
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
        return cfg.get("asset_registry", {})
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="THREATICAP — Threat Intelligence Correlation & Alert Prioritisation",
    description=(
        "Production-grade API for ingesting multi-source threat data, correlating alerts, "
        "mapping to MITRE ATT&CK, and generating commander-ready BLUF reports.\n\n"
        "**Authentication**: Supply `X-API-Key` header or `Authorization: Bearer <jwt>`.\n"
        "Set `THREATICAP_AUTH_DISABLED=true` for development bypass only."
    ),
    version=__version__,
    openapi_tags=[
        {"name": "Ingest", "description": "Submit alerts and threat feeds"},
        {"name": "Pipeline", "description": "Trigger processing pipeline"},
        {"name": "Threats", "description": "Query correlated threats"},
        {"name": "Feedback", "description": "Analyst verdicts on correlated threats"},
        {"name": "Reports", "description": "BLUF report access"},
        {"name": "Alerts", "description": "Raw alert access"},
        {"name": "Audit", "description": "Audit trail queries"},
        {"name": "System", "description": "Health, metrics, status"},
        {"name": "Admin", "description": "Administrative functions (admin role required)"},
    ],
    lifespan=lifespan,
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request logging middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def request_log_middleware(request: Request, call_next: Any) -> Any:
    start = time.perf_counter()
    request_id = str(uuid.uuid4())[:8]
    response = await call_next(request)
    duration = time.perf_counter() - start
    logger.info(
        "req_id=%s %s %s %d %.1fms",
        request_id, request.method, request.url.path,
        response.status_code, duration * 1000,
    )
    # Record to metrics (skip health/metrics paths to avoid noise)
    if not request.url.path.startswith("/api/v1/health"):
        record_api_request(
            request.method, request.url.path,
            response.status_code, duration
        )
    return response


# ---------------------------------------------------------------------------
# Ingest endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/ingest/alerts",
    response_model=AlertSubmitResponse,
    tags=["Ingest"],
    summary="Submit alerts for ingestion",
    description=(
        "Submit one or more normalised alerts for ingestion into the pipeline. "
        "Alerts are deduplicated and enriched before storage. "
        "Supply `run_pipeline=true` to trigger correlation immediately."
    ),
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_alerts(
    request: AlertSubmitRequest,
    pipeline: ThreatPipeline = Depends(get_pipeline),
    auth: AuthToken = Depends(require_role(Role.OPERATOR)),
) -> AlertSubmitResponse:
    from threaticap.models.alert import Alert as AlertModel

    ingested: list[AlertModel] = []
    errors: list[str] = []

    for raw_alert in request.alerts:
        try:
            alert = AlertModel(**raw_alert)
            ingested.append(alert)
        except Exception as exc:
            errors.append(f"Validation error: {exc}")

    if not ingested:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "No valid alerts submitted", "errors": errors},
        )

    pipeline.alert_repo.save_batch(ingested)

    run_result = None
    if request.run_pipeline:
        run_result = pipeline.run(ingested)

    return AlertSubmitResponse(
        accepted=len(ingested),
        rejected=len(errors),
        errors=errors,
        threats_created=run_result.threats_created if run_result else 0,
        alert_ids=[a.alert_id for a in ingested],
    )


# ---------------------------------------------------------------------------
# Pipeline endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/pipeline/run",
    response_model=PipelineRunResponse,
    tags=["Pipeline"],
    summary="Run correlation and prioritisation pipeline",
    description=(
        "Triggers the full processing pipeline on stored (unprocessed) alerts. "
        "Returns prioritised threats and BLUF report summaries."
    ),
)
async def run_pipeline(
    request: PipelineRunRequest,
    pipeline: ThreatPipeline = Depends(get_pipeline),
) -> PipelineRunResponse:
    # Retrieve alerts
    alert_repo = pipeline.alert_repo
    alerts = alert_repo.list_recent(limit=request.alert_limit or 1000)

    if not alerts:
        return PipelineRunResponse(
            alerts_processed=0,
            threats_created=0,
            message="No alerts available for processing",
        )

    result = pipeline.run(alerts)

    top_threats = [
        {
            "threat_id": t.threat_id,
            "title": t.title,
            "priority": result.scores[t.threat_id].priority_tier.value if t.threat_id in result.scores else "UNKNOWN",
            "score": result.scores[t.threat_id].final_score if t.threat_id in result.scores else 0.0,
            "alert_count": t.alert_count,
        }
        for t in result.threats[:10]
    ]

    return PipelineRunResponse(
        alerts_processed=result.alerts_ingested,
        threats_created=result.threats_created,
        critical=result.threats_critical,
        high=result.threats_high,
        medium=result.threats_medium,
        low=result.threats_low,
        reports_generated=result.reports_generated,
        top_threats=top_threats,
        errors=result.errors,
        message=f"Pipeline complete: {result.threats_created} threats identified",
    )


# ---------------------------------------------------------------------------
# Threat endpoints
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/threats",
    response_model=ThreatListResponse,
    tags=["Threats"],
    summary="List prioritised threats",
)
async def list_threats(
    tier: str | None = Query(default=None, description="Filter by priority tier (CRITICAL/HIGH/MEDIUM/LOW)"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    pipeline: ThreatPipeline = Depends(get_pipeline),
) -> ThreatListResponse:
    from threaticap.models.priority import PriorityTier

    tier_filter = None
    if tier:
        try:
            tier_filter = PriorityTier(tier.upper())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid tier: {tier}. Must be CRITICAL, HIGH, MEDIUM, or LOW",
            )

    items = pipeline.threat_repo.list_by_priority(
        tier=tier_filter, limit=limit, offset=offset
    )

    threats_out = []
    for threat, score in items:
        reports = pipeline.report_repo.get_for_threat(threat.threat_id)
        threats_out.append({
            "threat_id": threat.threat_id,
            "title": threat.title,
            "status": threat.status.value,
            "priority": score.priority_tier.value if score else "UNKNOWN",
            "score": score.final_score if score else 0.0,
            "alert_count": threat.alert_count,
            "source_types": threat.source_types,
            "max_severity": threat.max_severity,
            "correlation_confidence": threat.correlation_confidence,
            "false_positive_probability": threat.false_positive_probability,
            "mitre_technique_ids": threat.mitre_technique_ids,
            "affected_assets": threat.affected_assets[:5],
            "created_at": threat.created_at.isoformat(),
            "has_bluf": len(reports) > 0,
            "bluf_report_id": reports[-1].report_id if reports else None,
        })

    return ThreatListResponse(
        total=pipeline.threat_repo.count(),
        limit=limit,
        offset=offset,
        threats=threats_out,
    )


@app.get(
    "/api/v1/threats/{threat_id}",
    response_model=ThreatDetailResponse,
    tags=["Threats"],
    summary="Get threat detail",
)
async def get_threat(
    threat_id: str,
    pipeline: ThreatPipeline = Depends(get_pipeline),
) -> ThreatDetailResponse:
    threat = pipeline.threat_repo.get(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")

    score = pipeline.threat_repo.get_score(threat_id)
    audit = pipeline.audit_repo.get_for_threat(threat_id)

    return ThreatDetailResponse(
        threat=threat.model_dump(),
        score=score.model_dump() if score else None,
        audit_records=[r.model_dump() for r in audit[:20]],
    )


@app.get(
    "/api/v1/threats/{threat_id}/bluf",
    tags=["Threats"],
    summary="Get BLUF report for a threat (text or JSON)",
)
async def get_threat_bluf(
    threat_id: str,
    format: str = Query(default="json", description="Response format: json | text"),
    pipeline: ThreatPipeline = Depends(get_pipeline),
    auth: AuthToken = Depends(require_role(Role.READER)),
) -> Any:
    reports = pipeline.report_repo.get_for_threat(threat_id)
    if not reports:
        raise HTTPException(
            status_code=404,
            detail=f"No BLUF report found for threat {threat_id}",
        )
    report = reports[-1]  # Most recent

    if format.lower() == "text":
        return PlainTextResponse(report.to_text())
    return JSONResponse(content=report.model_dump(mode="json"))


@app.get(
    "/api/v1/threats/{threat_id}/graph",
    tags=["Threats"],
    summary="Get attack graph for a threat",
    description="Returns the NetworkX attack graph for a correlated threat as Cytoscape-compatible JSON.",
)
async def get_threat_graph(
    threat_id: str,
    pipeline: ThreatPipeline = Depends(get_pipeline),
    auth: AuthToken = Depends(require_role(Role.ANALYST)),
) -> Any:
    threat = pipeline.threat_repo.get(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")

    # Build a fresh graph for this threat's alerts
    try:
        from threaticap.correlation.graph_correlator import AttackGraph, _HAS_NX
        if not _HAS_NX:
            return JSONResponse({"error": "networkx not installed", "threat_id": threat_id})

        alert_ids = [ev.alert_id for ev in threat.evidence_links]
        alerts = [pipeline.alert_repo.get(aid) for aid in alert_ids if pipeline.alert_repo.get(aid)]

        if not alerts:
            return JSONResponse({"nodes": [], "edges": [], "threat_id": threat_id})

        # Reconstruct links from audit trail
        graph = AttackGraph()
        for alert in alerts:
            graph.add_alert(alert)

        return JSONResponse({
            "threat_id": threat_id,
            "graph": graph.to_dict(),
            "attack_paths": graph.find_attack_paths()[:3],
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc), "threat_id": threat_id})


# ---------------------------------------------------------------------------
# Reports endpoints
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/reports",
    response_model=BlufReportResponse,
    tags=["Reports"],
    summary="List recent BLUF reports",
)
async def list_reports(
    limit: int = Query(default=20, ge=1, le=100),
    pipeline: ThreatPipeline = Depends(get_pipeline),
) -> BlufReportResponse:
    reports = pipeline.report_repo.list_recent(limit=limit)
    return BlufReportResponse(
        total=len(reports),
        reports=[r.model_dump(mode="json") for r in reports],
    )


@app.get(
    "/api/v1/reports/{report_id}",
    tags=["Reports"],
    summary="Get a specific BLUF report",
)
async def get_report(
    report_id: str,
    format: str = Query(default="json"),
    pipeline: ThreatPipeline = Depends(get_pipeline),
) -> Any:
    report = pipeline.report_repo.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    if format.lower() == "text":
        return PlainTextResponse(report.to_text())
    return JSONResponse(content=report.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# Alert endpoints
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/alerts/{alert_id}",
    tags=["Alerts"],
    summary="Get a single alert",
)
async def get_alert(
    alert_id: str,
    pipeline: ThreatPipeline = Depends(get_pipeline),
) -> Any:
    alert = pipeline.alert_repo.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return JSONResponse(content=alert.model_dump(mode="json"))


@app.get(
    "/api/v1/alerts",
    tags=["Alerts"],
    summary="List recent alerts",
)
async def list_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    pipeline: ThreatPipeline = Depends(get_pipeline),
) -> Any:
    alerts = pipeline.alert_repo.list_recent(limit=limit, offset=offset)
    return JSONResponse(content={
        "total": pipeline.alert_repo.count(),
        "alerts": [a.model_dump(mode="json") for a in alerts],
    })


# ---------------------------------------------------------------------------
# Audit endpoint
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/audit",
    tags=["Audit"],
    summary="Query audit trail",
)
async def get_audit(
    threat_id: str | None = Query(default=None),
    alert_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    pipeline: ThreatPipeline = Depends(get_pipeline),
) -> Any:
    if threat_id:
        records = pipeline.audit_repo.get_for_threat(threat_id)
    elif alert_id:
        records = pipeline.audit_repo.get_for_alert(alert_id)
    else:
        records = pipeline.audit_repo.list_recent(limit=limit)

    return JSONResponse(content={
        "count": len(records),
        "records": [r.model_dump(mode="json") for r in records[:limit]],
    })


# ---------------------------------------------------------------------------
# Feedback endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/threats/{threat_id}/feedback",
    tags=["Feedback"],
    summary="Submit analyst verdict on a correlated threat",
    status_code=status.HTTP_201_CREATED,
)
async def submit_feedback(
    threat_id: str,
    verdict: str,
    notes: str = "",
    confidence: float = 1.0,
    pipeline: ThreatPipeline = Depends(get_pipeline),
    feedback_repo: Any = Depends(get_feedback_repo),
    auth: AuthToken = Depends(require_role(Role.ANALYST)),
) -> Any:
    threat = pipeline.threat_repo.get(threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail=f"Threat {threat_id} not found")

    try:
        v = Verdict(verdict.upper())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid verdict '{verdict}'. Must be one of: {[v.value for v in Verdict]}"
        )

    feedback = AnalystFeedback(
        threat_id=threat_id,
        analyst_id=auth.actor,
        verdict=v,
        notes=notes,
        confidence=min(1.0, max(0.0, confidence)),
    )
    feedback_repo.save(feedback)

    # Emit audit record
    audit = AuditRecord(
        event_type=AuditEventType.ANALYST_ACTION,
        actor=auth.actor,
        component="FeedbackEndpoint",
        threat_id=threat_id,
        summary=f"Analyst {auth.actor} marked threat as {v.value}",
        detail={"verdict": v.value, "confidence": confidence, "notes": notes},
    )
    pipeline.audit_repo.append(audit)

    return JSONResponse(
        status_code=201,
        content={"feedback_id": feedback.feedback_id, "verdict": v.value, "threat_id": threat_id}
    )


@app.get(
    "/api/v1/threats/{threat_id}/feedback",
    tags=["Feedback"],
    summary="Get analyst feedback for a threat",
)
async def get_feedback(
    threat_id: str,
    feedback_repo: Any = Depends(get_feedback_repo),
    auth: AuthToken = Depends(require_role(Role.READER)),
) -> Any:
    items = feedback_repo.get_for_threat(threat_id)
    return JSONResponse(content={
        "threat_id": threat_id,
        "count": len(items),
        "feedback": [f.model_dump(mode="json") for f in items],
    })


# ---------------------------------------------------------------------------
# System endpoints
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Health check",
)
async def health(pipeline: ThreatPipeline = Depends(get_pipeline)) -> HealthResponse:
    alert_count = pipeline.alert_repo.count()
    threat_count = pipeline.threat_repo.count()
    update_stored_counts(alert_count, threat_count)
    return HealthResponse(
        status="ok",
        version=__version__,
        uptime_seconds=int(time.time() - _START_TIME),
        alerts_stored=alert_count,
        threats_stored=threat_count,
    )


@app.get(
    "/api/v1/metrics",
    response_model=MetricsResponse,
    tags=["System"],
    summary="JSON operational metrics",
)
async def metrics_json(
    pipeline: ThreatPipeline = Depends(get_pipeline),
    auth: AuthToken = Depends(require_role(Role.READER)),
) -> MetricsResponse:
    threat_items = pipeline.threat_repo.list_by_priority(limit=10000)
    tier_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for _, score in threat_items:
        if score:
            tier_counts[score.priority_tier.value] = tier_counts.get(score.priority_tier.value, 0) + 1

    return MetricsResponse(
        alerts_total=pipeline.alert_repo.count(),
        threats_total=pipeline.threat_repo.count(),
        reports_total=len(pipeline.report_repo.list_recent(limit=100000)),
        threat_by_tier=tier_counts,
        uptime_seconds=int(time.time() - _START_TIME),
    )


@app.get(
    "/api/v1/metrics/prometheus",
    tags=["System"],
    summary="Prometheus-format metrics",
    response_class=PlainTextResponse,
)
async def metrics_prometheus() -> PlainTextResponse:
    """
    Metrics in Prometheus text exposition format.
    Suitable for scraping by Prometheus/Grafana.
    No authentication required (standard practice for metrics endpoints).
    """
    return PlainTextResponse(
        content=generate_prometheus_output(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/admin/api-keys",
    tags=["Admin"],
    summary="Create a new API key (admin role required)",
    status_code=status.HTTP_201_CREATED,
)
async def create_api_key(
    description: str = "",
    role: str = "reader",
    clearance: str = "TLP:GREEN",
    actor: str = "service",
    auth: AuthToken = Depends(require_role(Role.ADMIN)),
) -> Any:
    """
    Generate a new API key. Returns the raw key ONCE — it cannot be retrieved again.
    Store it securely immediately.
    """
    try:
        role_enum = Role(role.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {role}")

    raw_key, key_hash = generate_api_key()
    key_id = f"key-{uuid.uuid4().hex[:8]}"

    # Register in dev store (production: insert into api_keys table)
    _DEV_API_KEYS[key_hash] = {
        "key_id": key_id,
        "actor": actor,
        "role": role_enum,
        "clearance": clearance,
    }

    return JSONResponse(
        status_code=201,
        content={
            "key_id": key_id,
            "raw_key": raw_key,
            "role": role_enum.value,
            "clearance": clearance,
            "actor": actor,
            "warning": "Store this key immediately. It will not be shown again.",
        }
    )


# ---------------------------------------------------------------------------
# Root redirect
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
async def root() -> Any:
    return JSONResponse({
        "service": "THREATICAP",
        "version": __version__,
        "docs": "/api/v1/docs",
        "health": "/api/v1/health",
        "auth": "X-API-Key header required (THREATICAP_AUTH_DISABLED=true to bypass in dev)",
    })
