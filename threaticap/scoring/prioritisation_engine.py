"""
Risk-based prioritisation engine.

Produces a PriorityScore for every CorrelatedThreat by combining five weighted
factors. All weights and thresholds are configuration-driven.

Scoring model (0–100 scale):
    final_score = Σ(component_score × weight) / Σ(weights)

Components:
    1. Severity score     — based on max alert severity
    2. Confidence score   — correlation + source reliability
    3. Source reliability — weighted avg of source reliability
    4. Asset criticality  — mission criticality of affected assets
    5. Temporal urgency   — recency of latest event

Priority tiers (configurable thresholds):
    CRITICAL : final_score ≥ 80
    HIGH     : final_score ≥ 60
    MEDIUM   : final_score ≥ 35
    LOW      : final_score < 35
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from threaticap.models.alert import Alert, AlertSeverity
from threaticap.models.correlated_threat import CorrelatedThreat
from threaticap.models.priority import PriorityScore, PriorityTier, ScoreComponent
from threaticap.models.audit import AuditEventType, AuditRecord

logger = logging.getLogger(__name__)


@dataclass
class ScoringWeights:
    """Relative weights for each scoring component (must sum to 1.0)."""
    severity: float = 0.30
    confidence: float = 0.25
    source_reliability: float = 0.15
    asset_criticality: float = 0.20
    temporal_urgency: float = 0.10

    def __post_init__(self) -> None:
        total = (self.severity + self.confidence + self.source_reliability +
                 self.asset_criticality + self.temporal_urgency)
        if not (0.999 < total < 1.001):
            raise ValueError(
                f"Scoring weights must sum to 1.0, got {total:.4f}. "
                "Adjust config/scoring_config.yaml."
            )


@dataclass
class ScoringThresholds:
    """Priority tier thresholds (lower bound, inclusive)."""
    critical: float = 80.0
    high: float = 60.0
    medium: float = 35.0
    # below medium → LOW
    config_name: str = "default-v1"


@dataclass
class PrioritisationConfig:
    weights: ScoringWeights = field(default_factory=ScoringWeights)
    thresholds: ScoringThresholds = field(default_factory=ScoringThresholds)
    # Severity raw values (0–100)
    severity_values: dict[str, float] = field(default_factory=lambda: {
        "CRITICAL": 100.0,
        "HIGH":     75.0,
        "MEDIUM":   50.0,
        "LOW":      25.0,
        "INFO":     10.0,
    })
    # Temporal urgency decay: alerts older than this get urgency=0
    urgency_max_age_hours: float = 72.0


# ---------------------------------------------------------------------------
# Prioritisation engine
# ---------------------------------------------------------------------------

class PrioritisationEngine:
    """
    Computes a fully explainable priority score for each CorrelatedThreat.
    """

    def __init__(
        self,
        config: PrioritisationConfig | None = None,
        alert_store: dict[str, Alert] | None = None,
        audit_callback: Callable[[AuditRecord], None] | None = None,
    ) -> None:
        self._config = config or PrioritisationConfig()
        # alert_store: alert_id → Alert (for looking up asset context)
        self._alert_store: dict[str, Alert] = alert_store or {}
        self._audit_callback = audit_callback

    def score(
        self,
        threat: CorrelatedThreat,
        alert_lookup: dict[str, Alert] | None = None,
    ) -> PriorityScore:
        """
        Compute the priority score for a single CorrelatedThreat.

        Args:
            threat:       The CorrelatedThreat to score.
            alert_lookup: Optional dict of alert_id → Alert for this batch.
        """
        store = alert_lookup or self._alert_store
        constituent_alerts = [
            store[ev.alert_id]
            for ev in threat.evidence_links
            if ev.alert_id in store
        ]

        # ---- Component 1: Severity ----------------------------------------
        severity_raw = self._compute_severity(threat, constituent_alerts)
        severity_component = ScoreComponent(
            name="Severity",
            raw_value=severity_raw,
            weight=self._config.weights.severity,
            weighted_value=severity_raw * self._config.weights.severity,
            description=(
                f"Max severity: {threat.max_severity}; "
                f"alert count: {threat.alert_count}"
            ),
        )

        # ---- Component 2: Confidence / evidence strength ----------------
        confidence_raw = self._compute_confidence(threat)
        confidence_component = ScoreComponent(
            name="Confidence",
            raw_value=confidence_raw,
            weight=self._config.weights.confidence,
            weighted_value=confidence_raw * self._config.weights.confidence,
            description=(
                f"Correlation confidence: {threat.correlation_confidence:.2f}; "
                f"source types: {len(threat.source_types)}"
            ),
        )

        # ---- Component 3: Source reliability ----------------------------
        rel_raw = self._compute_source_reliability(constituent_alerts)
        reliability_component = ScoreComponent(
            name="Source Reliability",
            raw_value=rel_raw,
            weight=self._config.weights.source_reliability,
            weighted_value=rel_raw * self._config.weights.source_reliability,
            description=f"Weighted average reliability of contributing sources",
        )

        # ---- Component 4: Asset criticality ----------------------------
        crit_raw = self._compute_asset_criticality(constituent_alerts)
        criticality_component = ScoreComponent(
            name="Asset Criticality",
            raw_value=crit_raw,
            weight=self._config.weights.asset_criticality,
            weighted_value=crit_raw * self._config.weights.asset_criticality,
            description=(
                f"Max asset criticality across {len(constituent_alerts)} alert(s)"
            ),
        )

        # ---- Component 5: Temporal urgency ------------------------------
        urgency_raw = self._compute_temporal_urgency(threat)
        urgency_component = ScoreComponent(
            name="Temporal Urgency",
            raw_value=urgency_raw,
            weight=self._config.weights.temporal_urgency,
            weighted_value=urgency_raw * self._config.weights.temporal_urgency,
            description=(
                f"Latest event: {threat.max_event_time.isoformat() if threat.max_event_time else 'unknown'}"
            ),
        )

        components = [
            severity_component,
            confidence_component,
            reliability_component,
            criticality_component,
            urgency_component,
        ]

        # ---- Weighted composite score -----------------------------------
        raw_score = sum(c.weighted_value for c in components)
        final_score = min(100.0, max(0.0, raw_score * 100.0))

        # ---- FP adjustment ----------------------------------------------
        fp_adjustment = threat.false_positive_probability * 20.0
        adjusted_score = max(0.0, final_score - fp_adjustment)

        # ---- Priority tier ----------------------------------------------
        tier = self._assign_tier(adjusted_score)

        # ---- Explanation prose ------------------------------------------
        explanation = self._build_explanation(
            components=components,
            final_score=final_score,
            adjusted_score=adjusted_score,
            fp_adjustment=fp_adjustment,
            tier=tier,
            threat=threat,
        )

        ps = PriorityScore(
            threat_id=threat.threat_id,
            components=components,
            severity_score=round(severity_raw, 2),
            confidence_score=round(confidence_raw, 2),
            source_reliability_score=round(rel_raw, 2),
            asset_criticality_score=round(crit_raw, 2),
            temporal_urgency_score=round(urgency_raw, 2),
            final_score=round(adjusted_score, 2),
            priority_tier=tier,
            false_positive_adjustment=round(fp_adjustment, 2),
            score_explanation=explanation,
            threshold_used=self._config.thresholds.config_name,
            scoring_version="1.0",
        )

        self._emit_audit(
            AuditEventType.PRIORITY_SCORED,
            threat_id=threat.threat_id,
            summary=(
                f"Priority scored: {tier.value} "
                f"(score={adjusted_score:.1f}, fp_adj={fp_adjustment:.1f})"
            ),
            detail={
                "raw_score": round(final_score, 2),
                "adjusted_score": round(adjusted_score, 2),
                "components": {c.name: round(c.weighted_value * 100, 2) for c in components},
            },
        )

        return ps

    def score_batch(
        self,
        threats: list[CorrelatedThreat],
        alert_lookup: dict[str, Alert] | None = None,
    ) -> list[tuple[CorrelatedThreat, PriorityScore]]:
        """Score a list of threats and return them ranked highest-to-lowest."""
        scored = [
            (threat, self.score(threat, alert_lookup))
            for threat in threats
        ]
        scored.sort(key=lambda x: x[1].final_score, reverse=True)

        # Assign rank positions
        for rank, (_, ps) in enumerate(scored, 1):
            object.__setattr__(ps, "rank_position", rank) if ps.model_config.get("frozen") else setattr(ps, "rank_position", rank)

        return scored

    # ------------------------------------------------------------------
    # Component computation methods
    # ------------------------------------------------------------------

    def _compute_severity(
        self,
        threat: CorrelatedThreat,
        alerts: list[Alert],
    ) -> float:
        """
        0–1 score based on max severity and alert count.
        Multi-alert clusters get a small count bonus.
        """
        base = self._config.severity_values.get(threat.max_severity, 25.0) / 100.0

        # Count bonus: up to +0.10 for large correlated clusters
        count_bonus = min(0.10, (threat.alert_count - 1) * 0.015)

        return min(1.0, base + count_bonus)

    def _compute_confidence(self, threat: CorrelatedThreat) -> float:
        """
        0–1 score combining correlation confidence and multi-source corroboration.
        """
        conf = threat.correlation_confidence

        # Multi-source corroboration bonus
        source_count = len(threat.source_types)
        source_bonus = min(0.20, (source_count - 1) * 0.08)

        # FP penalisation
        fp_penalty = threat.false_positive_probability * 0.30

        return min(1.0, max(0.0, conf + source_bonus - fp_penalty))

    def _compute_source_reliability(self, alerts: list[Alert]) -> float:
        """Weighted average of source reliability across constituent alerts."""
        if not alerts:
            return 0.5
        return sum(a.source_reliability for a in alerts) / len(alerts)

    def _compute_asset_criticality(self, alerts: list[Alert]) -> float:
        """Max asset criticality across all constituent alerts."""
        if not alerts:
            return 0.5
        return max(a.asset_context.criticality for a in alerts)

    def _compute_temporal_urgency(self, threat: CorrelatedThreat) -> float:
        """
        0–1 urgency score — decays linearly from 1.0 (now) to 0.0 (max_age).
        Recent threats are more operationally urgent.
        """
        if threat.max_event_time is None:
            return 0.5
        now = datetime.now(timezone.utc)
        latest = threat.max_event_time
        if latest.tzinfo is None:
            latest = latest.replace(tzinfo=timezone.utc)
        age_hours = (now - latest).total_seconds() / 3600.0
        max_age = self._config.urgency_max_age_hours
        urgency = max(0.0, 1.0 - (age_hours / max_age))
        return round(urgency, 3)

    def _assign_tier(self, score: float) -> PriorityTier:
        t = self._config.thresholds
        if score >= t.critical:
            return PriorityTier.CRITICAL
        if score >= t.high:
            return PriorityTier.HIGH
        if score >= t.medium:
            return PriorityTier.MEDIUM
        return PriorityTier.LOW

    def _build_explanation(
        self,
        components: list[ScoreComponent],
        final_score: float,
        adjusted_score: float,
        fp_adjustment: float,
        tier: PriorityTier,
        threat: CorrelatedThreat,
    ) -> str:
        lines = [
            f"Priority {tier.value} (score {adjusted_score:.1f}/100).",
        ]
        dominant = max(components, key=lambda c: c.weighted_value)
        lines.append(
            f"Primary driver: {dominant.name} (contributes "
            f"{dominant.weighted_value * 100:.1f} points, "
            f"weight={dominant.weight:.0%})."
        )
        if fp_adjustment > 0:
            lines.append(
                f"Score reduced by {fp_adjustment:.1f} points due to "
                f"FP probability {threat.false_positive_probability:.0%}."
            )
        if threat.alert_count > 1:
            lines.append(
                f"Corroborated by {threat.alert_count} alerts from "
                f"{len(threat.source_types)} source type(s): "
                f"{', '.join(threat.source_types)}."
            )
        return " ".join(lines)

    def _emit_audit(self, event_type: AuditEventType, **kwargs: Any) -> None:
        if self._audit_callback is None:
            return
        record = AuditRecord(
            event_type=event_type,
            component="PrioritisationEngine",
            **kwargs,
        )
        try:
            self._audit_callback(record)
        except Exception as exc:
            logger.error("Audit callback error: %s", exc)
