"""
Threat intelligence quality management.

Tracks source reliability, indicator age, and confidence decay over time.
Automatically down-weights stale or low-quality feeds.

Components:
1.  IndicatorLifecycle — tracks age, last-seen, and staleness for each IOC.
2.  SourceQualityTracker — maintains historical accuracy metrics per source.
3.  ConfidenceDecayEngine — applies time-based decay to indicator confidence.
4.  FeedQualityManager — orchestrates all three; provides a pluggable hook
    into the ingestion pipeline.

The quality ratings use the NATO Admiralty Scale:
  Source reliability: A (Completely reliable) → F (Reliability not judged)
  Information credibility: 1 (Confirmed) → 6 (Truth cannot be judged)

Configuration (config.yaml → intel_quality):
    decay:
        half_life_days: 30           # Confidence halves every 30 days
        min_confidence: 0.05         # Floor — never reach 0
        max_staleness_days: 90       # Indicators older than this are retired
    source_tracking:
        enabled: true
        min_samples_for_rating: 10   # Minimum verdicts before adjusting weight
        smoothing_alpha: 0.1         # EMA smoothing factor
    persist_path: "data/intel_quality.json"
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# NATO Admiralty Scale
# ---------------------------------------------------------------------------

class SourceReliabilityGrade(str, Enum):
    """NATO Admiralty Scale — source reliability."""
    A = "A"  # Completely reliable
    B = "B"  # Usually reliable
    C = "C"  # Fairly reliable
    D = "D"  # Not usually reliable
    E = "E"  # Unreliable
    F = "F"  # Reliability not judged


class InformationCredibilityGrade(str, Enum):
    """NATO Admiralty Scale — information credibility."""
    CONFIRMED        = "1"  # Confirmed by other independent sources
    PROBABLY_TRUE    = "2"  # Probably true (not confirmed but consistent)
    POSSIBLY_TRUE    = "3"  # Possibly true (not confirmed, unusual)
    DOUBTFUL         = "4"  # Doubtful (not confirmed, inconsistent)
    IMPROBABLE       = "5"  # Improbable
    CANNOT_JUDGE     = "6"  # Truth cannot be judged


# Grade → numeric reliability (0–1)
_RELIABILITY_GRADE_VALUE: dict[SourceReliabilityGrade, float] = {
    SourceReliabilityGrade.A: 1.00,
    SourceReliabilityGrade.B: 0.85,
    SourceReliabilityGrade.C: 0.65,
    SourceReliabilityGrade.D: 0.45,
    SourceReliabilityGrade.E: 0.20,
    SourceReliabilityGrade.F: 0.50,  # Unknown — start neutral
}


# ---------------------------------------------------------------------------
# Indicator lifecycle
# ---------------------------------------------------------------------------

@dataclass
class IndicatorRecord:
    """Per-indicator quality tracking."""
    value: str
    obs_type: str
    source_id: str
    first_seen: str       # ISO 8601
    last_seen: str        # ISO 8601
    initial_confidence: float
    current_confidence: float
    hit_count: int = 0    # Times seen in new alerts
    tp_count: int = 0     # Analyst-confirmed TPs
    fp_count: int = 0     # Analyst-confirmed FPs
    retired: bool = False

    @property
    def age_days(self) -> float:
        try:
            ls = datetime.fromisoformat(self.last_seen)
            if ls.tzinfo is None:
                ls = ls.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - ls).days
        except (ValueError, TypeError):
            return 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "obs_type": self.obs_type,
            "source_id": self.source_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "initial_confidence": self.initial_confidence,
            "current_confidence": self.current_confidence,
            "hit_count": self.hit_count,
            "tp_count": self.tp_count,
            "fp_count": self.fp_count,
            "retired": self.retired,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "IndicatorRecord":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Source quality tracker
# ---------------------------------------------------------------------------

@dataclass
class SourceQualityRecord:
    """Running quality statistics per source."""
    source_id: str
    source_type: str = ""
    tp_count: int = 0
    fp_count: int = 0
    total_count: int = 0
    ema_fp_rate: float = 0.0          # Exponential moving average of FP rate
    current_reliability: float = 0.8  # Current reliability weight (0–1)
    admiralty_grade: str = "F"        # SourceReliabilityGrade value
    last_updated: str = ""
    notes: str = ""

    @property
    def empirical_fp_rate(self) -> float:
        if self.total_count == 0:
            return 0.0
        return (self.fp_count) / self.total_count

    @property
    def empirical_tp_rate(self) -> float:
        if self.total_count == 0:
            return 1.0
        return self.tp_count / self.total_count

    def to_admiralty_grade(self) -> SourceReliabilityGrade:
        r = self.current_reliability
        if r >= 0.95:
            return SourceReliabilityGrade.A
        if r >= 0.80:
            return SourceReliabilityGrade.B
        if r >= 0.60:
            return SourceReliabilityGrade.C
        if r >= 0.40:
            return SourceReliabilityGrade.D
        if r >= 0.20:
            return SourceReliabilityGrade.E
        return SourceReliabilityGrade.F

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_type": self.source_type,
            "tp_count": self.tp_count,
            "fp_count": self.fp_count,
            "total_count": self.total_count,
            "ema_fp_rate": round(self.ema_fp_rate, 4),
            "current_reliability": round(self.current_reliability, 4),
            "admiralty_grade": self.admiralty_grade,
            "last_updated": self.last_updated,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SourceQualityRecord":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Confidence decay
# ---------------------------------------------------------------------------

class ConfidenceDecayEngine:
    """
    Applies radioactive decay model to indicator confidence over time.

    Decay formula (half-life model):
        current_confidence = initial × exp(-λ × age_days)
        where λ = ln(2) / half_life_days

    This means confidence halves every `half_life_days` days.
    """

    def __init__(
        self,
        half_life_days: float = 30.0,
        min_confidence: float = 0.05,
        max_staleness_days: float = 90.0,
    ) -> None:
        self._half_life = max(1.0, half_life_days)
        self._min_conf = min_confidence
        self._max_staleness = max_staleness_days
        self._lambda = math.log(2) / self._half_life

    def decay(self, initial_confidence: float, age_days: float) -> float:
        """Apply exponential decay.  Returns decayed confidence in [min_conf, 1.0]."""
        if age_days <= 0:
            return initial_confidence
        decayed = initial_confidence * math.exp(-self._lambda * age_days)
        return round(max(self._min_conf, decayed), 4)

    def is_stale(self, age_days: float) -> bool:
        """True when the indicator has exceeded max staleness."""
        return age_days > self._max_staleness

    def effective_weight(self, initial_confidence: float, last_seen: datetime) -> float:
        """
        Combined quality weight for scoring: decayed_confidence × freshness.
        """
        age = (datetime.now(timezone.utc) - last_seen).days
        if self.is_stale(age):
            return self._min_conf
        return self.decay(initial_confidence, float(age))


# ---------------------------------------------------------------------------
# Feed quality manager
# ---------------------------------------------------------------------------

class FeedQualityManager:
    """
    Orchestrates indicator lifecycle tracking and source quality management.

    Usage:
        qm = FeedQualityManager.from_config(cfg)
        qm.record_alert_ingested(alert)
        qm.record_feedback(feedback, constituent_alerts)
        weight = qm.get_source_weight("source_id")
        adj_confidence = qm.apply_decay(observable_value, confidence)
    """

    def __init__(
        self,
        decay_engine: ConfidenceDecayEngine | None = None,
        smoothing_alpha: float = 0.1,
        min_samples_for_rating: int = 10,
        persist_path: Path | None = None,
    ) -> None:
        self._decay = decay_engine or ConfidenceDecayEngine()
        self._alpha = smoothing_alpha
        self._min_samples = min_samples_for_rating
        self._persist_path = persist_path
        self._lock = Lock()

        # source_id → SourceQualityRecord
        self._sources: dict[str, SourceQualityRecord] = {}
        # "{obs_type}:{value}" → IndicatorRecord
        self._indicators: dict[str, IndicatorRecord] = {}

        if persist_path and persist_path.exists():
            self._load(persist_path)

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> "FeedQualityManager":
        qual_cfg = cfg.get("intel_quality", {})
        decay_cfg = qual_cfg.get("decay", {})
        source_cfg = qual_cfg.get("source_tracking", {})
        persist = qual_cfg.get("persist_path")
        return cls(
            decay_engine=ConfidenceDecayEngine(
                half_life_days=decay_cfg.get("half_life_days", 30.0),
                min_confidence=decay_cfg.get("min_confidence", 0.05),
                max_staleness_days=decay_cfg.get("max_staleness_days", 90.0),
            ),
            smoothing_alpha=source_cfg.get("smoothing_alpha", 0.1),
            min_samples_for_rating=source_cfg.get("min_samples_for_rating", 10),
            persist_path=Path(persist) if persist else None,
        )

    def record_alert_ingested(self, alert_data: dict[str, Any]) -> None:
        """Update indicator records when a new alert is ingested."""
        source_id = alert_data.get("source_id", "unknown")
        now_str = datetime.now(timezone.utc).isoformat()

        with self._lock:
            if source_id not in self._sources:
                self._sources[source_id] = SourceQualityRecord(
                    source_id=source_id,
                    source_type=alert_data.get("source_type", ""),
                    last_updated=now_str,
                )

            for obs in alert_data.get("observables", []):
                key = f"{obs.get('type', '')}:{obs.get('value', '')}"
                if key not in self._indicators:
                    self._indicators[key] = IndicatorRecord(
                        value=obs.get("value", ""),
                        obs_type=obs.get("type", ""),
                        source_id=source_id,
                        first_seen=now_str,
                        last_seen=now_str,
                        initial_confidence=obs.get("confidence", 0.5),
                        current_confidence=obs.get("confidence", 0.5),
                    )
                else:
                    self._indicators[key].last_seen = now_str
                    self._indicators[key].hit_count += 1

    def record_verdict(
        self,
        source_id: str,
        is_true_positive: bool,
        observable_keys: list[str] | None = None,
    ) -> None:
        """Record an analyst TP/FP verdict and update source quality."""
        now_str = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if source_id not in self._sources:
                self._sources[source_id] = SourceQualityRecord(
                    source_id=source_id, last_updated=now_str
                )
            src = self._sources[source_id]
            src.total_count += 1
            src.last_updated = now_str

            if is_true_positive:
                src.tp_count += 1
                verdict_fp = 0.0
            else:
                src.fp_count += 1
                verdict_fp = 1.0

            # Update EMA of FP rate
            src.ema_fp_rate = (
                self._alpha * verdict_fp + (1 - self._alpha) * src.ema_fp_rate
            )

            # Adjust reliability weight (only when enough samples)
            if src.total_count >= self._min_samples:
                src.current_reliability = max(0.1, 1.0 - src.ema_fp_rate)
                src.admiralty_grade = src.to_admiralty_grade().value

            # Update indicator records
            for key in (observable_keys or []):
                if key in self._indicators:
                    if is_true_positive:
                        self._indicators[key].tp_count += 1
                    else:
                        self._indicators[key].fp_count += 1

        if self._persist_path:
            self._save(self._persist_path)

    def get_source_weight(self, source_id: str) -> float:
        """
        Return the current reliability weight for a source (0–1).
        Returns 0.8 (neutral default) if the source has not yet been assessed.
        """
        with self._lock:
            src = self._sources.get(source_id)
        if src is None:
            return 0.8
        if src.total_count < self._min_samples:
            return src.current_reliability  # Prior (not yet adjusted)
        return src.current_reliability

    def get_decayed_confidence(
        self,
        obs_type: str,
        obs_value: str,
        base_confidence: float,
    ) -> float:
        """
        Return the current confidence for an indicator after time-based decay.
        """
        key = f"{obs_type}:{obs_value}"
        with self._lock:
            rec = self._indicators.get(key)

        if rec is None:
            return base_confidence  # No history — use base
        try:
            last_seen = datetime.fromisoformat(rec.last_seen)
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return base_confidence

        return self._decay.effective_weight(base_confidence, last_seen)

    def is_indicator_stale(self, obs_type: str, obs_value: str) -> bool:
        key = f"{obs_type}:{obs_value}"
        with self._lock:
            rec = self._indicators.get(key)
        return rec is not None and self._decay.is_stale(rec.age_days)

    def get_source_quality_report(self) -> list[dict[str, Any]]:
        """Return summary of all tracked source quality records, sorted by reliability."""
        with self._lock:
            records = [s.to_dict() for s in sorted(
                self._sources.values(),
                key=lambda r: r.current_reliability,
                reverse=True,
            )]
        return records

    def retire_stale_indicators(self) -> int:
        """Mark all stale indicators as retired. Returns count retired."""
        count = 0
        with self._lock:
            for rec in self._indicators.values():
                if not rec.retired and self._decay.is_stale(rec.age_days):
                    rec.retired = True
                    count += 1
        if count:
            logger.info("Retired %d stale indicators", count)
        return count

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "sources": {k: v.to_dict() for k, v in self._sources.items()},
                        "indicators": {k: v.to_dict() for k, v in self._indicators.items()},
                    },
                    fh,
                    indent=2,
                )
        except Exception as exc:
            logger.error("FeedQualityManager save failed: %s", exc)

    def _load(self, path: Path) -> None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            self._sources = {
                k: SourceQualityRecord.from_dict(v)
                for k, v in data.get("sources", {}).items()
            }
            self._indicators = {
                k: IndicatorRecord.from_dict(v)
                for k, v in data.get("indicators", {}).items()
            }
            logger.info(
                "FeedQualityManager loaded: %d sources, %d indicators",
                len(self._sources), len(self._indicators),
            )
        except Exception as exc:
            logger.warning("FeedQualityManager load failed: %s", exc)
