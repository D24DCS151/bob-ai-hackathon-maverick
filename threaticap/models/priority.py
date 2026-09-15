"""
Priority scoring models.

The PriorityScore captures both the final score/tier and the full breakdown of
contributing factors — making every prioritisation decision fully auditable and
explainable to operators and commanders.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PriorityTier(str, Enum):
    """Operational priority tiers — directly map to SOC queue lanes."""
    CRITICAL = "CRITICAL"   # Immediate action required
    HIGH     = "HIGH"       # Action required within 1 hour
    MEDIUM   = "MEDIUM"     # Action required within 4 hours
    LOW      = "LOW"        # Monitor / routine investigation


class ScoreComponent(BaseModel):
    """
    A single contributing factor to the overall priority score.

    Recording each component separately enables:
    - Human-readable explanation ("Why is this CRITICAL?")
    - Threshold tuning without touching code
    - Audit trail of scoring decisions
    """
    name: str = Field(..., description="Human-readable factor name.")
    raw_value: float = Field(description="Input value before weighting.")
    weight: float = Field(ge=0.0, le=1.0, description="Configuration-driven weight.")
    weighted_value: float = Field(description="raw_value * weight.")
    description: str = Field(default="", description="Explanation of this component.")
    metadata: dict[str, Any] = Field(default_factory=dict)


class PriorityScore(BaseModel):
    """
    Full priority scoring record for a CorrelatedThreat.

    The final_score is a normalised 0–100 value; priority_tier maps it to an
    operational queue via configurable thresholds.
    """

    threat_id: str

    # ---- Score Components ------------------------------------------------
    components: list[ScoreComponent] = Field(default_factory=list)

    # ---- Aggregated Scores ----------------------------------------------
    severity_score: float = Field(ge=0.0, le=100.0)
    confidence_score: float = Field(ge=0.0, le=100.0)
    source_reliability_score: float = Field(ge=0.0, le=100.0)
    asset_criticality_score: float = Field(ge=0.0, le=100.0)
    temporal_urgency_score: float = Field(ge=0.0, le=100.0)

    # ---- Final Output ---------------------------------------------------
    final_score: float = Field(
        ge=0.0,
        le=100.0,
        description="Weighted composite score on 0–100 scale.",
    )
    priority_tier: PriorityTier
    rank_position: int | None = Field(
        default=None,
        description="Rank within the current threat queue (1 = highest priority).",
    )

    # ---- Explanation / Auditability ------------------------------------
    score_explanation: str = Field(
        default="",
        description="Human-readable narrative explaining the score.",
    )
    threshold_used: str = Field(
        default="",
        description="Name/version of the scoring threshold configuration used.",
    )
    false_positive_adjustment: float = Field(
        default=0.0,
        description="Score reduction applied due to FP probability estimate.",
    )

    scored_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scoring_version: str = Field(default="1.0")
