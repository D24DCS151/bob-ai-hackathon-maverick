"""
Audit record model.

Every significant system decision — correlation, scoring, BLUF generation,
status change — produces an AuditRecord. These records are append-only,
immutable after creation, and must be persisted to the audit store.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    ALERT_INGESTED          = "ALERT_INGESTED"
    ALERT_DEDUPLICATED      = "ALERT_DEDUPLICATED"
    ALERT_ENRICHED          = "ALERT_ENRICHED"
    CORRELATION_CREATED     = "CORRELATION_CREATED"
    CORRELATION_UPDATED     = "CORRELATION_UPDATED"
    CORRELATION_CLOSED      = "CORRELATION_CLOSED"
    FALSE_POSITIVE_FLAGGED  = "FALSE_POSITIVE_FLAGGED"
    PRIORITY_SCORED         = "PRIORITY_SCORED"
    PRIORITY_RESCORED       = "PRIORITY_RESCORED"
    BLUF_GENERATED          = "BLUF_GENERATED"
    BLUF_UPDATED            = "BLUF_UPDATED"
    STATUS_CHANGED          = "STATUS_CHANGED"
    CONFIG_RELOADED         = "CONFIG_RELOADED"
    ANALYST_ACTION          = "ANALYST_ACTION"
    API_REQUEST             = "API_REQUEST"
    SYSTEM_ERROR            = "SYSTEM_ERROR"


class AuditRecord(BaseModel):
    """
    Immutable audit record.

    Fields are set at creation and MUST NOT be modified. Downstream storage
    implementations should enforce append-only semantics (e.g. INSERT only,
    no UPDATE on audit tables).
    """

    model_config = {"frozen": True}

    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = "1.0"
    event_type: AuditEventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # ---- Actor ----------------------------------------------------------
    actor: str = Field(
        default="SYSTEM",
        description="Identity of the actor (system component, analyst username, API key ID).",
    )
    component: str = Field(
        default="",
        description="Software component that generated this record.",
    )

    # ---- Subjects -------------------------------------------------------
    alert_id: str | None = None
    threat_id: str | None = None
    report_id: str | None = None

    # ---- Payload --------------------------------------------------------
    summary: str = Field(default="")
    detail: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured detail — kept minimal to avoid PII leakage.",
    )
    previous_state: dict[str, Any] | None = Field(
        default=None,
        description="Previous state snapshot for change-tracking events.",
    )
    new_state: dict[str, Any] | None = Field(
        default=None,
        description="New state snapshot.",
    )

    # ---- Traceability ---------------------------------------------------
    session_id: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None
