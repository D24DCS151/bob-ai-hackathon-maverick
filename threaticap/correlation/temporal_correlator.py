"""
Temporal correlator — groups alerts that occur within a configurable time window.

Temporal proximity is a necessary but not sufficient condition for correlation.
A temporal link alone produces low confidence; combined with IOC or asset
overlap it significantly strengthens the correlation signal.
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from threaticap.models.alert import Alert

logger = logging.getLogger(__name__)


class TemporalCorrelator:
    """
    Identifies alerts that fall within a temporal proximity window.

    Produces lower-confidence links than IOC matching; intended to be combined
    with other correlators in the CorrelationEngine.
    """

    def __init__(
        self,
        window_seconds: int = 3600,
        base_confidence: float = 0.35,
        same_source_confidence: float = 0.15,
    ) -> None:
        """
        Args:
            window_seconds: Time window in seconds (default: 1 hour).
            base_confidence: Base confidence for temporal links.
            same_source_confidence: Reduced confidence when alerts come from
                the same source (less informative — could be repeated alerts).
        """
        self._window = timedelta(seconds=window_seconds)
        self._base_confidence = base_confidence
        self._same_source_confidence = same_source_confidence

    def correlate(self, alerts: list[Alert]) -> list[dict[str, Any]]:
        """
        Find all pairs of alerts within the temporal window.

        To avoid O(N²) cost on large alert sets, alerts are sorted by
        event_time and only compared against a sliding window.
        """
        if len(alerts) < 2:
            return []

        sorted_alerts = sorted(alerts, key=lambda a: a.event_time)
        results: list[dict[str, Any]] = []
        seen_pairs: set[tuple[str, str]] = set()

        for i, a in enumerate(sorted_alerts):
            for j in range(i + 1, len(sorted_alerts)):
                b = sorted_alerts[j]

                delta = b.event_time - a.event_time
                if delta > self._window:
                    break  # sorted — no need to check further

                pair = (
                    min(a.alert_id, b.alert_id),
                    max(a.alert_id, b.alert_id),
                )
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                # Adjust confidence based on source diversity
                if a.source_type == b.source_type and a.source_id == b.source_id:
                    confidence = self._same_source_confidence
                else:
                    confidence = self._base_confidence

                # Tighter time proximity → slightly higher confidence
                closeness = 1.0 - (delta.total_seconds() / self._window.total_seconds())
                confidence = confidence + closeness * 0.1

                delta_seconds = int(delta.total_seconds())
                results.append({
                    "alert_id_a": pair[0],
                    "alert_id_b": pair[1],
                    "confidence": round(min(1.0, confidence), 3),
                    "method": "TEMPORAL",
                    "shared_observables": [],
                    "audit": (
                        f"Temporal correlation: delta={delta_seconds}s "
                        f"(window={int(self._window.total_seconds())}s); "
                        f"confidence={confidence:.2f}"
                    ),
                    "delta_seconds": delta_seconds,
                })

        logger.debug(
            "Temporal correlator found %d pairs within %ds window from %d alerts",
            len(results), int(self._window.total_seconds()), len(alerts)
        )
        return results
