"""
Alert model — the canonical normalised representation of a single security event
ingested from any source connector.

Design principles:
- All fields are explicitly typed; no bare `Any` except for raw_payload.
- Enums are string-based so they serialise cleanly to JSON.
- Optional fields use None (not absent keys) so schema stays stable.
- schema_version enables forward-compatible migrations.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AlertSeverity(str, Enum):
    """Standardised severity drawn from industry practice (CVSS-inspired)."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class AlertSource(str, Enum):
    """Canonical source type labels — individual connectors add their own
    sub-identifiers via the `source_id` field."""
    SIEM            = "SIEM"
    EDR             = "EDR"
    NETWORK_SENSOR  = "NETWORK_SENSOR"
    SIGINT          = "SIGINT"
    HUMINT          = "HUMINT"
    OSINT           = "OSINT"
    STIX_TAXII      = "STIX_TAXII"
    COMMERCIAL_FEED = "COMMERCIAL_FEED"
    SATELLITE_ISR   = "SATELLITE_ISR"
    MANUAL          = "MANUAL"


class AlertStatus(str, Enum):
    NEW         = "NEW"
    INGESTED    = "INGESTED"
    CORRELATED  = "CORRELATED"
    PRIORITISED = "PRIORITISED"
    CLOSED      = "CLOSED"
    FALSE_POS   = "FALSE_POSITIVE"


class ObservableType(str, Enum):
    """Observable / IOC types aligned with STIX 2.1 cyber-observable objects."""
    IP_ADDRESS   = "ipv4-addr"
    IPV6_ADDRESS = "ipv6-addr"
    DOMAIN       = "domain-name"
    URL          = "url"
    FILE_HASH    = "file:hashes"
    EMAIL        = "email-addr"
    USER_ACCOUNT = "user-account"
    PROCESS      = "process"
    REGISTRY_KEY = "windows-registry-key"
    NETWORK_CONN = "network-traffic"
    ASSET_ID     = "asset-id"
    CVE          = "vulnerability"
    TOOL         = "tool"
    CUSTOM       = "x-custom"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class Observable(BaseModel):
    """A single extracted IOC / observable linked to an alert."""

    model_config = {"frozen": True}

    observable_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Stable ID — deduplication key when type+value match.",
    )
    type: ObservableType
    value: str = Field(..., min_length=1, max_length=2048)
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Extraction confidence (1.0 = authoritative, 0.0 = speculative).",
    )
    context: str | None = Field(
        default=None,
        description="Free-text human annotation (e.g. 'seen in C2 beacon header').",
    )
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = Field(default_factory=list)


class GeoLocation(BaseModel):
    """Best-effort geolocation data — never used as sole evidence."""
    country_code: str | None = Field(default=None, max_length=3)
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    asn_org: str | None = None


class AssetContext(BaseModel):
    """Information about the affected or involved asset(s)."""
    asset_id: str | None = None
    hostname: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    owner: str | None = None
    classification: str | None = None      # e.g. SECRET, UNCLASSIFIED
    criticality: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Mission criticality weight (0=irrelevant, 1=mission-critical).",
    )
    network_segment: str | None = None
    tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Primary Alert model
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    """
    Canonical normalised alert record.

    Every connector MUST produce an Alert instance. Downstream components
    consume only this model — never raw source data.
    """

    model_config = {"populate_by_name": True}

    # ---- Identity --------------------------------------------------------
    alert_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="System-assigned unique ID (UUID4).",
    )
    schema_version: str = Field(
        default="1.0",
        description="Enables forward-compatible schema migrations.",
    )
    source_ref: str = Field(
        ...,
        description="Original event ID from the source system — enables traceability.",
    )
    source_type: AlertSource
    source_id: str = Field(
        ...,
        description="Logical name of the originating connector instance.",
    )
    source_reliability: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Pre-assessed reliability weight for this source (0–1).",
    )

    # ---- Timing ----------------------------------------------------------
    event_time: datetime = Field(
        ...,
        description="When the event occurred (UTC). Required — never None.",
    )
    ingestion_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this alert was ingested by THREATICAP.",
    )

    # ---- Classification --------------------------------------------------
    severity: AlertSeverity
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Source-reported or computed detection confidence.",
    )
    status: AlertStatus = AlertStatus.INGESTED

    # ---- Content ---------------------------------------------------------
    title: str = Field(..., min_length=1, max_length=512)
    description: str = Field(default="", max_length=8192)
    category: str = Field(
        default="",
        description="Source-specific alert category (e.g. 'Lateral Movement', 'Exfiltration').",
    )
    rule_id: str | None = Field(
        default=None,
        description="Detection rule or signature ID that fired.",
    )
    raw_payload: dict[str, Any] | None = Field(
        default=None,
        description="Preserved original payload — never modified after ingest.",
        exclude=False,
    )

    # ---- Observables & Context -------------------------------------------
    observables: list[Observable] = Field(default_factory=list)
    asset_context: AssetContext = Field(default_factory=AssetContext)
    geo: GeoLocation | None = None

    # ---- MITRE (preliminary — from source if available) ------------------
    mitre_technique_ids: list[str] = Field(
        default_factory=list,
        description="Technique IDs suggested by source (e.g. ['T1059.001']).",
    )

    # ---- Enrichment ------------------------------------------------------
    enrichment_tags: list[str] = Field(default_factory=list)
    threat_actor: str | None = None
    campaign: str | None = None
    tlp: str = Field(
        default="TLP:GREEN",
        description="Traffic Light Protocol classification.",
    )

    # ---- Deduplication ---------------------------------------------------
    dedup_hash: str | None = Field(
        default=None,
        description="Content hash used for deduplication — set by ingest pipeline.",
    )

    @field_validator("event_time", "ingestion_time", mode="before")
    @classmethod
    def ensure_utc(cls, v: Any) -> datetime:
        if isinstance(v, str):
            v = datetime.fromisoformat(v)
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @model_validator(mode="after")
    def validate_mitre_ids(self) -> "Alert":
        """Loose format check on MITRE technique IDs (T####.###)."""
        import re
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for tid in self.mitre_technique_ids:
            if not pattern.match(tid):
                raise ValueError(f"Invalid MITRE technique ID format: {tid!r}")
        return self
