"""
Correlated Threat model — groups one or more related Alerts into a unified
threat object after the correlation engine has processed them.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ThreatStatus(str, Enum):
    OPEN        = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED   = "CONTAINED"
    RESOLVED    = "RESOLVED"
    FALSE_POS   = "FALSE_POSITIVE"


class CorrelationMethod(str, Enum):
    """Which correlation signal(s) linked the constituent alerts."""
    IOC_MATCH       = "IOC_MATCH"
    TEMPORAL        = "TEMPORAL"
    ASSET_OVERLAP   = "ASSET_OVERLAP"
    BEHAVIOUR       = "BEHAVIOUR"
    CAMPAIGN        = "CAMPAIGN"
    MANUAL          = "MANUAL"
    COMPOSITE       = "COMPOSITE"


class EvidenceLink(BaseModel):
    """Traceable link from a CorrelatedThreat back to a source Alert."""
    alert_id: str
    source_ref: str
    source_type: str
    relevance: float = Field(ge=0.0, le=1.0, description="How strongly this alert supports the correlation.")
    contributing_observables: list[str] = Field(
        default_factory=list,
        description="Observable IDs from this alert that contributed to correlation.",
    )


class CorrelatedThreat(BaseModel):
    """
    A fully correlated threat object produced by the Correlation Engine.

    Contains references to all constituent alerts, the methods used to link
    them, aggregated observables, and the overall confidence score.
    """

    model_config = {"populate_by_name": True}

    threat_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = "1.0"

    # ---- Identification --------------------------------------------------
    title: str = Field(..., min_length=1, max_length=512)
    description: str = Field(default="")
    status: ThreatStatus = ThreatStatus.OPEN

    # ---- Constituent Alerts ---------------------------------------------
    alert_count: int = Field(default=0, ge=0)
    evidence_links: list[EvidenceLink] = Field(default_factory=list)
    source_types: list[str] = Field(
        default_factory=list,
        description="Deduplicated list of source types that contributed.",
    )

    # ---- Correlation Metadata -------------------------------------------
    correlation_methods: list[CorrelationMethod] = Field(default_factory=list)
    correlation_confidence: float = Field(
        ge=0.0, le=1.0,
        description="Aggregate confidence that these alerts represent a single threat.",
    )
    false_positive_probability: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Estimated probability that this is a false positive.",
    )

    # ---- Aggregated Observables -----------------------------------------
    shared_observables: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Observables that appear in more than one constituent alert.",
    )
    all_observable_ids: list[str] = Field(default_factory=list)

    # ---- Asset & Target -------------------------------------------------
    affected_assets: list[str] = Field(default_factory=list)
    network_segments: list[str] = Field(default_factory=list)

    # ---- MITRE ----------------------------------------------------------
    mitre_technique_ids: list[str] = Field(default_factory=list)
    suspected_actor: str | None = None
    campaign: str | None = None

    # ---- Severity Aggregation -------------------------------------------
    max_severity: str = Field(default="LOW")
    min_event_time: datetime | None = None
    max_event_time: datetime | None = None

    # ---- Lifecycle -------------------------------------------------------
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_version: str = Field(
        default="1.0",
        description="Version of the correlation engine configuration used.",
    )
    audit_trail: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Ordered list of correlation decisions — fully auditable.",
    )
