"""
API request/response schemas — separates API contract from internal models.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AlertSubmitRequest(BaseModel):
    alerts: list[dict[str, Any]] = Field(..., min_length=1)
    run_pipeline: bool = Field(default=False, description="If true, immediately run correlation")


class AlertSubmitResponse(BaseModel):
    accepted: int
    rejected: int
    errors: list[str] = Field(default_factory=list)
    threats_created: int = 0
    alert_ids: list[str] = Field(default_factory=list)


class PipelineRunRequest(BaseModel):
    alert_limit: int | None = Field(default=1000, ge=1, le=10000)


class PipelineRunResponse(BaseModel):
    alerts_processed: int
    threats_created: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    reports_generated: int = 0
    top_threats: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    message: str = ""


class ThreatListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    threats: list[dict[str, Any]]


class ThreatDetailResponse(BaseModel):
    threat: dict[str, Any]
    score: dict[str, Any] | None
    audit_records: list[dict[str, Any]] = Field(default_factory=list)


class BlufReportResponse(BaseModel):
    total: int
    reports: list[dict[str, Any]]


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_seconds: int
    alerts_stored: int
    threats_stored: int


class MetricsResponse(BaseModel):
    alerts_total: int
    threats_total: int
    reports_total: int
    threat_by_tier: dict[str, int]
    uptime_seconds: int


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
    request_id: str | None = None
