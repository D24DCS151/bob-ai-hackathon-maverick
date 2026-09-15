"""
Feedback-driven false positive learning engine.

This module implements a closed-loop FP reduction system:

1.  Analyst labels (TP / FP / BENIGN) are collected via AnalystFeedback records.
2.  The FeedbackLearner maintains lightweight per-rule and per-source counters
    that are persisted to a simple JSON store (no external ML framework needed).
3.  The AdjustedFPFilter wraps the base FalsePositiveFilter and blends its
    heuristic score with the learned adjustment to produce a final FP probability.
4.  The adjustment logic is rules-based and fully auditable — every adjustment
    records its reason.

Data contract:
    FeedbackSummary   — aggregated statistics per rule_id / source_id.
    FeedbackLearner   — loads/saves feedback state and computes adjustments.
    AdjustedFPFilter  — pluggable wrapper around FalsePositiveFilter.

Deployment note:
    In production the FeedbackStore should be backed by PostgreSQL.  The in-memory
    implementation here is fully functional for small deployments and testing.
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from threaticap.models.alert import Alert
from threaticap.models.feedback import AnalystFeedback, Verdict
from threaticap.correlation.fp_filter import FalsePositiveFilter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Feedback statistics store
# ---------------------------------------------------------------------------

@dataclass
class FeedbackStats:
    """Running TP/FP/BENIGN counts for a single key (rule_id or source_id)."""
    key: str
    tp_count: int = 0
    fp_count: int = 0
    benign_count: int = 0
    total_count: int = 0
    last_updated: str = ""

    @property
    def fp_rate(self) -> float:
        """Empirical FP rate for this key (0–1)."""
        if self.total_count == 0:
            return 0.0
        return (self.fp_count + self.benign_count) / self.total_count

    @property
    def confidence_weight(self) -> float:
        """
        Beta-distribution-inspired weight [0, 1] reflecting sample size.
        Returns ≈0 for very few samples, approaches 1 for ≥50 samples.
        """
        return 1.0 - math.exp(-self.total_count / 20.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "tp_count": self.tp_count,
            "fp_count": self.fp_count,
            "benign_count": self.benign_count,
            "total_count": self.total_count,
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "FeedbackStats":
        return cls(
            key=d["key"],
            tp_count=d.get("tp_count", 0),
            fp_count=d.get("fp_count", 0),
            benign_count=d.get("benign_count", 0),
            total_count=d.get("total_count", 0),
            last_updated=d.get("last_updated", ""),
        )


class FeedbackStore:
    """
    Thread-safe in-memory feedback statistics store with optional JSON
    persistence to disk (for air-gapped / no-database deployments).
    """

    def __init__(self, persist_path: Path | None = None) -> None:
        self._lock = Lock()
        # key → FeedbackStats.  Key format: "rule:<rule_id>" or "source:<source_id>"
        self._stats: dict[str, FeedbackStats] = {}
        self._persist_path = persist_path
        if persist_path and persist_path.exists():
            self._load(persist_path)

    def record(self, feedback: AnalystFeedback, alerts: list[Alert]) -> None:
        """Update counters for all rule_ids and source_ids in the constituent alerts."""
        with self._lock:
            for alert in alerts:
                rule_keys = []
                if alert.rule_id:
                    rule_keys.append(f"rule:{alert.rule_id}")
                rule_keys.append(f"source:{alert.source_id}")
                rule_keys.append(f"source_type:{alert.source_type.value}")

                for key in rule_keys:
                    if key not in self._stats:
                        self._stats[key] = FeedbackStats(key=key)
                    s = self._stats[key]
                    s.total_count += 1
                    s.last_updated = datetime.now(timezone.utc).isoformat()
                    if feedback.verdict == Verdict.TRUE_POSITIVE:
                        s.tp_count += 1
                    elif feedback.verdict == Verdict.FALSE_POSITIVE:
                        s.fp_count += 1
                    elif feedback.verdict == Verdict.BENIGN:
                        s.benign_count += 1
        if self._persist_path:
            self._save(self._persist_path)

    def get(self, key: str) -> FeedbackStats | None:
        with self._lock:
            return self._stats.get(key)

    def all_stats(self) -> list[FeedbackStats]:
        with self._lock:
            return list(self._stats.values())

    def _save(self, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {k: v.to_dict() for k, v in self._stats.items()},
                    fh,
                    indent=2,
                )
        except Exception as exc:
            logger.error("Failed to persist feedback store: %s", exc)

    def _load(self, path: Path) -> None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            self._stats = {k: FeedbackStats.from_dict(v) for k, v in raw.items()}
            logger.info("Loaded %d feedback stats from %s", len(self._stats), path)
        except Exception as exc:
            logger.warning("Could not load feedback store from %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Feedback-aware FP filter
# ---------------------------------------------------------------------------

class FeedbackAwareFPFilter:
    """
    Wraps FalsePositiveFilter and blends heuristic FP probability with
    learned feedback statistics.

    Blending formula:
        adjusted = (1 - w) × heuristic + w × learned_fp_rate

    where w = confidence_weight of the best-matching feedback statistics.

    This ensures:
    - When feedback is scarce, the system behaves exactly as before.
    - As analyst labels accumulate, the system adapts to real-world patterns.
    - Every adjustment is reason-logged for auditability.
    """

    def __init__(
        self,
        base_filter: FalsePositiveFilter,
        store: FeedbackStore,
        learning_rate: float = 0.40,  # Max weight given to learned data
    ) -> None:
        self._base = base_filter
        self._store = store
        self._learning_rate = learning_rate

    def compute_fp_probability(
        self,
        alerts: list[Alert],
        correlation_confidence: float,
        reasons: list[str] | None = None,
    ) -> float:
        if reasons is None:
            reasons = []

        # Step 1: heuristic baseline
        heuristic = self._base.compute_fp_probability(alerts, correlation_confidence, reasons)

        # Step 2: gather learned FP rates
        learned_rates: list[tuple[float, float]] = []  # (fp_rate, weight)
        for alert in alerts:
            keys_to_check = []
            if alert.rule_id:
                keys_to_check.append(f"rule:{alert.rule_id}")
            keys_to_check.append(f"source:{alert.source_id}")
            keys_to_check.append(f"source_type:{alert.source_type.value}")
            for key in keys_to_check:
                stats = self._store.get(key)
                if stats and stats.total_count >= 3:  # min samples before learning kicks in
                    learned_rates.append((stats.fp_rate, stats.confidence_weight))
                    reasons.append(
                        f"Feedback adjustment for {key}: "
                        f"fp_rate={stats.fp_rate:.0%} "
                        f"(n={stats.total_count}, weight={stats.confidence_weight:.2f})"
                    )

        if not learned_rates:
            return heuristic

        # Step 3: weighted average of learned rates
        total_w = sum(w for _, w in learned_rates)
        avg_learned = sum(r * w for r, w in learned_rates) / total_w

        # Step 4: blend heuristic with learned, capped at learning_rate
        blend_weight = min(self._learning_rate, total_w / len(learned_rates))
        adjusted = (1.0 - blend_weight) * heuristic + blend_weight * avg_learned

        final = round(min(0.95, max(0.0, adjusted)), 3)
        logger.debug(
            "FP adjusted: heuristic=%.3f learned=%.3f blend_w=%.2f final=%.3f",
            heuristic, avg_learned, blend_weight, final,
        )
        return final
