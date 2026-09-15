"""
IOC correlator — identifies alerts sharing common observables.

Two alerts are linked if they share one or more observable values of the same
type. Confidence is weighted by the specificity of the shared observable type
(file hashes are more specific than IP addresses).
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from threaticap.models.alert import Alert, ObservableType

logger = logging.getLogger(__name__)

# Observable type specificity weights — higher = stronger correlation signal
IOC_SPECIFICITY: dict[ObservableType, float] = {
    ObservableType.FILE_HASH:   1.0,   # Most specific — near-certain link
    ObservableType.CVE:         0.9,
    ObservableType.URL:         0.85,
    ObservableType.EMAIL:       0.8,
    ObservableType.USER_ACCOUNT: 0.75,
    ObservableType.REGISTRY_KEY: 0.7,
    ObservableType.PROCESS:     0.65,
    ObservableType.DOMAIN:      0.6,
    ObservableType.NETWORK_CONN: 0.55,
    ObservableType.IP_ADDRESS:  0.4,   # Least specific — IPs may be shared infra
    ObservableType.ASSET_ID:    0.8,
    ObservableType.TOOL:        0.7,
    ObservableType.CUSTOM:      0.5,
}

# Observable types that are too common to use as sole correlation signals
WEAK_IOC_TYPES = {ObservableType.IP_ADDRESS, ObservableType.DOMAIN}


class IOCCorrelator:
    """
    Correlates alerts that share one or more observables.

    Returns a list of (alert_id_a, alert_id_b, confidence, shared_observables)
    tuples that the CorrelationEngine uses to build correlation groups.
    """

    def __init__(
        self,
        min_specificity: float = 0.4,
        require_strong_for_weak_iocs: bool = True,
    ) -> None:
        """
        Args:
            min_specificity: Minimum observable specificity to consider (0–1).
            require_strong_for_weak_iocs: If True, weak IOC types (IP/domain)
                must be corroborated by at least one strong observable to
                count as a correlation link.
        """
        self._min_specificity = min_specificity
        self._require_strong = require_strong_for_weak_iocs

    def correlate(
        self, alerts: list[Alert]
    ) -> list[dict[str, Any]]:
        """
        Find all pairs of alerts sharing observables.

        Returns list of dicts:
        {
            "alert_id_a": str,
            "alert_id_b": str,
            "confidence": float,
            "method": "IOC_MATCH",
            "shared_observables": list[dict],
            "audit": str,
        }
        """
        # Build inverted index: observable_key → list[alert_id]
        index: dict[str, list[str]] = defaultdict(list)
        obs_meta: dict[str, dict[str, Any]] = {}  # obs_key → {type, value, specificity}

        for alert in alerts:
            for obs in alert.observables:
                specificity = IOC_SPECIFICITY.get(obs.type, 0.5)
                if specificity < self._min_specificity:
                    continue
                key = f"{obs.type.value}:{obs.value.lower()}"
                if alert.alert_id not in index[key]:
                    index[key].append(alert.alert_id)
                obs_meta[key] = {
                    "type": obs.type.value,
                    "value": obs.value,
                    "specificity": specificity,
                }

        # Find pairs sharing at least one observable
        pairs: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

        for key, alert_ids in index.items():
            if len(alert_ids) < 2:
                continue
            meta = obs_meta[key]
            for i in range(len(alert_ids)):
                for j in range(i + 1, len(alert_ids)):
                    pair = (
                        min(alert_ids[i], alert_ids[j]),
                        max(alert_ids[i], alert_ids[j]),
                    )
                    pairs[pair].append(meta)

        results: list[dict[str, Any]] = []

        for (id_a, id_b), shared in pairs.items():
            # Check if any strong observable is present
            max_specificity = max(s["specificity"] for s in shared)
            has_strong = any(
                s["specificity"] >= 0.6 for s in shared
            )
            only_weak = all(
                ObservableType(s["type"]) in WEAK_IOC_TYPES for s in shared
            )

            if self._require_strong and only_weak:
                logger.debug(
                    "Skipping weak-IOC-only correlation between %s and %s",
                    id_a[:8], id_b[:8]
                )
                continue

            # Confidence: highest single-observable specificity, boosted by count
            count_boost = min(0.15, (len(shared) - 1) * 0.05)
            confidence = min(1.0, max_specificity + count_boost)

            results.append({
                "alert_id_a": id_a,
                "alert_id_b": id_b,
                "confidence": confidence,
                "method": "IOC_MATCH",
                "shared_observables": shared,
                "audit": (
                    f"IOC correlation: {len(shared)} shared observable(s); "
                    f"max specificity={max_specificity:.2f}; "
                    f"confidence={confidence:.2f}"
                ),
            })

        logger.debug("IOC correlator found %d pairs from %d alerts", len(results), len(alerts))
        return results
