"""
BLUF (Bottom Line Up Front) report models.

BLUF reports are the primary commander-facing output of the system.
They are structured for rapid consumption — the bottom line is always first,
followed by supporting evidence and recommended actions.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    """Analytic confidence levels aligned with intelligence community standards."""
    HIGH        = "HIGH"        # Strong corroborating evidence from multiple sources
    MODERATE    = "MODERATE"    # Some corroborating evidence; gaps remain
    LOW         = "LOW"         # Limited evidence; significant uncertainty
    UNDETERMINED = "UNDETERMINED"


class BlufSection(str, Enum):
    BOTTOM_LINE         = "BOTTOM_LINE"
    KEY_EVIDENCE        = "KEY_EVIDENCE"
    MITRE_MAPPING       = "MITRE_MAPPING"
    IMMEDIATE_ACTIONS   = "IMMEDIATE_ACTIONS"
    INVESTIGATION_STEPS = "INVESTIGATION_STEPS"
    PRIORITY_JUSTIFICATION = "PRIORITY_JUSTIFICATION"
    METADATA            = "METADATA"


class EvidenceSummary(BaseModel):
    """Summarised evidence item with traceability back to source alerts."""
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_ids: list[str] = Field(default_factory=list)
    source_types: list[str] = Field(default_factory=list)
    description: str
    observable_values: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class ActionItem(BaseModel):
    """A recommended action for operators or commanders."""
    priority: int = Field(ge=1, description="Execution order (1 = highest priority).")
    action: str
    rationale: str = Field(default="")
    owner: str = Field(default="SOC Analyst")
    timeframe: str = Field(default="Immediate")


class BlufReport(BaseModel):
    """
    Commander-ready BLUF report for a CorrelatedThreat.

    Structure follows the military/intelligence BLUF convention:
    the most actionable information appears first, with supporting
    detail below. Both JSON (machine-readable) and formatted text
    (human-readable) are produced from this single model.
    """

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = "1.0"
    threat_id: str
    report_version: int = Field(default=1, ge=1)

    # ---- Bottom Line (commander summary — must be ≤ 3 sentences) --------
    bottom_line: str = Field(
        ...,
        description="Clear, actionable summary a commander can act on in 60 seconds.",
    )
    bottom_line_extended: str = Field(
        default="",
        description="Optional extended summary with additional context.",
    )

    # ---- Classification & Confidence ------------------------------------
    priority_tier: str
    priority_score: float = Field(ge=0.0, le=100.0)
    confidence_level: ConfidenceLevel
    tlp: str = Field(default="TLP:GREEN")

    # ---- Key Evidence ---------------------------------------------------
    key_evidence: list[EvidenceSummary] = Field(default_factory=list)
    alert_count: int = Field(ge=0)
    source_types: list[str] = Field(default_factory=list)
    time_window: str = Field(default="", description="Human-readable time span of activity.")
    affected_assets: list[str] = Field(default_factory=list)

    # ---- MITRE ATT&CK ---------------------------------------------------
    mitre_technique_ids: list[str] = Field(default_factory=list)
    mitre_tactic_names: list[str] = Field(default_factory=list)
    kill_chain_stage: str | None = None

    # ---- Actions -------------------------------------------------------
    immediate_actions: list[ActionItem] = Field(default_factory=list)
    investigation_steps: list[ActionItem] = Field(default_factory=list)

    # ---- Priority Justification ----------------------------------------
    priority_justification: str = Field(
        default="",
        description="Prose explanation of why this threat was assigned its priority tier.",
    )
    score_breakdown: dict[str, float] = Field(
        default_factory=dict,
        description="Component-level score breakdown for transparency.",
    )

    # ---- Lifecycle ------------------------------------------------------
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    generated_by: str = Field(default="THREATICAP-BLUF-ENGINE")
    analyst_notes: str = Field(default="")

    def to_text(self) -> str:
        """
        Render a human-readable plain-text BLUF report suitable for
        terminal display, email, or secure messaging.
        """
        lines: list[str] = []
        sep = "=" * 72

        lines.append(sep)
        lines.append(f"BLUF REPORT  |  {self.priority_tier}  |  {self.tlp}")
        lines.append(f"Threat ID : {self.threat_id}")
        lines.append(f"Report ID : {self.report_id}")
        lines.append(f"Generated : {self.generated_at.strftime('%Y-%m-%dT%H:%MZ')}")
        lines.append(sep)

        lines.append("")
        lines.append("BOTTOM LINE")
        lines.append("-" * 40)
        lines.append(self.bottom_line)
        if self.bottom_line_extended:
            lines.append("")
            lines.append(self.bottom_line_extended)

        lines.append("")
        lines.append("PRIORITY & CONFIDENCE")
        lines.append("-" * 40)
        lines.append(f"  Priority    : {self.priority_tier}  (score {self.priority_score:.1f}/100)")
        lines.append(f"  Confidence  : {self.confidence_level.value}")
        lines.append(f"  Time window : {self.time_window}")
        if self.affected_assets:
            lines.append(f"  Assets      : {', '.join(self.affected_assets[:5])}")

        lines.append("")
        lines.append("KEY EVIDENCE")
        lines.append("-" * 40)
        for i, ev in enumerate(self.key_evidence, 1):
            lines.append(f"  [{i}] {ev.description}")
            if ev.observable_values:
                lines.append(f"      Observables: {', '.join(ev.observable_values[:4])}")
            lines.append(f"      Source(s): {', '.join(ev.source_types)}  |  "
                         f"Confidence: {ev.confidence:.0%}")

        lines.append("")
        lines.append("MITRE ATT&CK MAPPING")
        lines.append("-" * 40)
        if self.mitre_tactic_names:
            lines.append(f"  Tactics    : {', '.join(self.mitre_tactic_names)}")
        if self.mitre_technique_ids:
            lines.append(f"  Techniques : {', '.join(self.mitre_technique_ids)}")
        if self.kill_chain_stage:
            lines.append(f"  Kill chain : {self.kill_chain_stage}")

        if self.immediate_actions:
            lines.append("")
            lines.append("IMMEDIATE ACTIONS")
            lines.append("-" * 40)
            for act in self.immediate_actions:
                lines.append(f"  {act.priority}. [{act.timeframe}] {act.action}")
                if act.rationale:
                    lines.append(f"     Rationale : {act.rationale}")

        if self.investigation_steps:
            lines.append("")
            lines.append("INVESTIGATION STEPS")
            lines.append("-" * 40)
            for step in self.investigation_steps:
                lines.append(f"  {step.priority}. {step.action}")

        lines.append("")
        lines.append("PRIORITY JUSTIFICATION")
        lines.append("-" * 40)
        lines.append(f"  {self.priority_justification}")

        lines.append("")
        lines.append(sep)

        return "\n".join(lines)
