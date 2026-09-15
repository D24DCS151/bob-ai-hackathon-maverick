"""
False positive filter — reduces FP probability and adjusts correlation confidence.

This module implements heuristic and rule-based FP reduction. In production,
replace or augment with a trained ML classifier (e.g. RandomForest on historical
FP labels, or a graph-based anomaly detector).

FP signals considered:
- Single-source alerts with no corroboration
- Low-severity alerts with no malicious observables
- Benign asset ownership (whitelisted subnets / hostnames)
- High-frequency repetitive alerts (scanning noise)
- Source reliability below threshold
"""
from __future__ import annotations

import logging
from typing import Any

from threaticap.models.alert import Alert, AlertSeverity

logger = logging.getLogger(__name__)


class FalsePositiveFilter:
    """
    Assigns a false-positive probability to a candidate CorrelatedThreat.

    Returns a float in [0, 1.0] where:
        0.0 = almost certainly a true positive
        1.0 = almost certainly a false positive
    """

    def __init__(
        self,
        whitelist_ips: set[str] | None = None,
        whitelist_hostnames: set[str] | None = None,
        whitelist_domains: set[str] | None = None,
        low_reliability_threshold: float = 0.3,
        min_sources_for_high_confidence: int = 2,
        max_fp_probability: float = 0.95,
    ) -> None:
        self._whitelist_ips = {ip.lower() for ip in (whitelist_ips or set())}
        self._whitelist_hostnames = {h.lower() for h in (whitelist_hostnames or set())}
        self._whitelist_domains = {d.lower() for d in (whitelist_domains or set())}
        self._low_reliability = low_reliability_threshold
        self._min_sources = min_sources_for_high_confidence
        self._max_fp = max_fp_probability

    def compute_fp_probability(
        self,
        alerts: list[Alert],
        correlation_confidence: float,
        reasons: list[str] | None = None,
    ) -> float:
        """
        Compute the false-positive probability for a group of correlated alerts.

        Args:
            alerts:                 All constituent alerts.
            correlation_confidence: Confidence from the correlation engine.
            reasons:                Mutable list to append FP reason strings to.

        Returns:
            Float in [0.0, 1.0] — estimated FP probability.
        """
        if reasons is None:
            reasons = []

        fp_score: float = 0.0

        # ---- Single source (lower trust) --------------------------------
        unique_sources = {a.source_id for a in alerts}
        unique_source_types = {a.source_type for a in alerts}
        if len(unique_source_types) == 1:
            fp_score += 0.20
            reasons.append(
                f"All {len(alerts)} alert(s) from single source type {list(unique_source_types)[0].value}"
            )

        # ---- Source reliability ----------------------------------------
        avg_reliability = sum(a.source_reliability for a in alerts) / len(alerts)
        if avg_reliability < self._low_reliability:
            fp_score += 0.25
            reasons.append(f"Low average source reliability: {avg_reliability:.2f}")

        # ---- Severity profile ------------------------------------------
        severities = [a.severity for a in alerts]
        max_sev = self._max_severity(severities)
        if max_sev in (AlertSeverity.INFO, AlertSeverity.LOW):
            fp_score += 0.25
            reasons.append(f"Maximum severity is {max_sev.value}")

        # ---- Whitelist check -------------------------------------------
        for alert in alerts:
            for ip in alert.asset_context.ip_addresses:
                if ip.lower() in self._whitelist_ips:
                    fp_score += 0.30
                    reasons.append(f"Whitelisted IP: {ip}")
                    break
            if alert.asset_context.hostname:
                if alert.asset_context.hostname.lower() in self._whitelist_hostnames:
                    fp_score += 0.30
                    reasons.append(f"Whitelisted hostname: {alert.asset_context.hostname}")

        # ---- Confidence discount ----------------------------------------
        # Low correlation confidence → higher FP probability
        if correlation_confidence < 0.4:
            fp_score += 0.15
            reasons.append(f"Low correlation confidence: {correlation_confidence:.2f}")

        # ---- Multi-source corroboration bonus ---------------------------
        if len(unique_source_types) >= self._min_sources:
            fp_score = max(0.0, fp_score - 0.20)
            reasons.append(
                f"Multi-source corroboration ({len(unique_source_types)} source types)"
            )

        # ---- High-severity / high-confidence reduction -----------------
        if max_sev in (AlertSeverity.CRITICAL, AlertSeverity.HIGH):
            fp_score = max(0.0, fp_score - 0.10)

        final = min(self._max_fp, max(0.0, fp_score))
        logger.debug("FP probability computed: %.2f | reasons: %s", final, reasons)
        return round(final, 3)

    @staticmethod
    def _max_severity(severities: list[AlertSeverity]) -> AlertSeverity:
        order = [
            AlertSeverity.CRITICAL,
            AlertSeverity.HIGH,
            AlertSeverity.MEDIUM,
            AlertSeverity.LOW,
            AlertSeverity.INFO,
        ]
        for sev in order:
            if sev in severities:
                return sev
        return AlertSeverity.INFO
