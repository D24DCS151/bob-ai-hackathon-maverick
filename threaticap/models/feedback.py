"""
Analyst feedback model.

Feedback is used to:
1. Mark correlated threats as True Positive, False Positive, or Benign
2. Feed into future FP filter improvements (ML training data)
3. Provide accountability trail for all analyst decisions
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    TRUE_POSITIVE  = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN         = "BENIGN"
    NEEDS_REVIEW   = "NEEDS_REVIEW"


class AnalystFeedback(BaseModel):
    """Analyst verdict on a CorrelatedThreat."""

    feedback_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    threat_id: str
    analyst_id: str
    verdict: Verdict
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Analyst's confidence in their verdict (1.0 = certain).",
    )
    notes: str = Field(default="")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
