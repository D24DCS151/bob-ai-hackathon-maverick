"""
Mission context models.

Defence organisations operate within active operational contexts — ongoing
missions, exercises, and readiness cycles.  Threat impact is fundamentally
different when the target is a C2 system supporting an active kinetic mission
compared with a routine administrative workstation.

This module defines the data contracts for injecting dynamic mission context
into the prioritisation engine so threats are scored by *operational impact*,
not just technical severity.

Design:
- MissionContext is configuration-driven and can be hot-reloaded.
- AssetMissionRole maps individual assets (by ID or tag) to specific missions.
- MissionPriority combines mission urgency + asset role into an impact score.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class MissionReadiness(str, Enum):
    """NATO-aligned readiness states."""
    ACTIVE      = "ACTIVE"       # Mission is live / execution phase
    PREPARING   = "PREPARING"    # Build-up / rehearsal phase
    STANDBY     = "STANDBY"      # Forces available, not yet deployed
    RECOVERY    = "RECOVERY"     # Post-operation reset
    EXERCISE    = "EXERCISE"     # Training / validation


class MissionDomain(str, Enum):
    CYBER       = "CYBER"
    LAND        = "LAND"
    MARITIME    = "MARITIME"
    AIR         = "AIR"
    SPACE       = "SPACE"
    INFORMATION = "INFORMATION"
    JOINT       = "JOINT"


class AssetMissionRole(BaseModel):
    """Links an asset to a mission and quantifies its operational importance."""

    model_config = {"frozen": True}

    asset_id: str = Field(..., description="Asset ID or tag pattern (prefix match).")
    mission_id: str
    role: str = Field(
        default="SUPPORTING",
        description="Operational role, e.g. C2, ISR, FIRES, LOGISTICS, COMMS.",
    )
    impact_weight: float = Field(
        default=1.0,
        ge=0.0,
        le=3.0,
        description=(
            "Multiplier applied to the asset criticality score when this mission "
            "is active.  Values > 1.0 amplify; values < 1.0 dampen."
        ),
    )
    degradation_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description=(
            "If asset criticality × impact_weight exceeds this, the threat is "
            "flagged as mission-degrading in the BLUF."
        ),
    )


class Mission(BaseModel):
    """A single operational mission / priority."""

    mission_id: str
    name: str
    description: str = ""
    classification: str = Field(
        default="UNCLASSIFIED",
        description="Classification handling caveat for this mission record.",
    )
    readiness: MissionReadiness = MissionReadiness.STANDBY
    domain: MissionDomain = MissionDomain.JOINT
    priority_rank: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Relative priority of this mission (1=highest). Drives score multiplier.",
    )
    start_time: datetime | None = None
    end_time: datetime | None = None
    asset_roles: list[AssetMissionRole] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        """True when the mission is in an executing or high-readiness state."""
        active_states = {MissionReadiness.ACTIVE, MissionReadiness.PREPARING}
        if self.readiness not in active_states:
            return False
        now = datetime.now(timezone.utc)
        if self.start_time and self.start_time.tzinfo is None:
            start = self.start_time.replace(tzinfo=timezone.utc)
        else:
            start = self.start_time
        if self.end_time and self.end_time.tzinfo is None:
            end = self.end_time.replace(tzinfo=timezone.utc)
        else:
            end = self.end_time
        if start and now < start:
            return False
        if end and now > end:
            return False
        return True

    @property
    def urgency_multiplier(self) -> float:
        """
        Score multiplier for a threat impacting this mission.
        Active missions with high priority rank get a larger multiplier.
        """
        if not self.is_active:
            return 1.0
        # priority_rank=1 → 2.0×, priority_rank=10 → 1.1×
        return round(1.0 + (10 - self.priority_rank) / 9.0, 3)


class MissionContext(BaseModel):
    """
    Container for all active mission contexts.

    This object is injected into the prioritisation engine and can be
    hot-reloaded without restarting the pipeline.
    """

    missions: list[Mission] = Field(default_factory=list)
    context_version: str = "1.0"
    loaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    classification: str = Field(
        default="UNCLASSIFIED",
        description="Classification of the overall context object.",
    )

    def get_active_missions(self) -> list[Mission]:
        return [m for m in self.missions if m.is_active]

    def get_mission_impact(
        self,
        asset_ids: list[str],
        asset_tags: list[str],
    ) -> float:
        """
        Return the maximum mission impact weight for the given assets.

        Returns a float [1.0, 3.0] — 1.0 means no mission amplification.
        """
        max_weight = 1.0
        for mission in self.get_active_missions():
            for role in mission.asset_roles:
                for aid in asset_ids:
                    if aid.startswith(role.asset_id) or aid == role.asset_id:
                        effective = role.impact_weight * mission.urgency_multiplier
                        max_weight = max(max_weight, effective)
                for tag in asset_tags:
                    if tag == role.asset_id:
                        effective = role.impact_weight * mission.urgency_multiplier
                        max_weight = max(max_weight, effective)
        return round(min(3.0, max_weight), 3)

    def get_degraded_mission_names(
        self,
        asset_ids: list[str],
        asset_tags: list[str],
        asset_criticality: float,
    ) -> list[str]:
        """Return names of active missions degraded by impact on these assets."""
        degraded = []
        for mission in self.get_active_missions():
            for role in mission.asset_roles:
                matched = any(
                    a.startswith(role.asset_id) or a == role.asset_id
                    for a in asset_ids + asset_tags
                )
                if matched:
                    effective = asset_criticality * role.impact_weight
                    if effective >= role.degradation_threshold:
                        degraded.append(mission.name)
        return list(set(degraded))
