"""
Asset correlator — groups alerts targeting the same assets or network segments.

An asset overlap is a strong correlation signal when the asset is mission-
critical. It identifies lateral movement, multi-stage attacks targeting
specific infrastructure, and sustained campaigns against key assets.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from threaticap.models.alert import Alert

logger = logging.getLogger(__name__)


class AssetCorrelator:
    """
    Correlates alerts that share asset identifiers, hostnames, IP addresses,
    or network segments.

    Priority is given to exact asset_id matches; fuzzy matching (network
    segment, subnet) produces lower confidence.
    """

    def __init__(
        self,
        asset_id_confidence: float = 0.75,
        hostname_confidence: float = 0.70,
        ip_confidence: float = 0.55,
        segment_confidence: float = 0.35,
        criticality_boost_max: float = 0.15,
    ) -> None:
        self._asset_id_conf = asset_id_confidence
        self._hostname_conf = hostname_confidence
        self._ip_conf = ip_confidence
        self._segment_conf = segment_confidence
        self._criticality_boost = criticality_boost_max

    def correlate(self, alerts: list[Alert]) -> list[dict[str, Any]]:
        """
        Find all alert pairs sharing an asset dimension.
        """
        # Build index for each asset dimension
        asset_id_index: dict[str, list[str]] = defaultdict(list)
        hostname_index: dict[str, list[str]] = defaultdict(list)
        ip_index: dict[str, list[str]] = defaultdict(list)
        segment_index: dict[str, list[str]] = defaultdict(list)

        alert_map: dict[str, Alert] = {a.alert_id: a for a in alerts}

        for alert in alerts:
            ctx = alert.asset_context
            aid = alert.alert_id

            if ctx.asset_id:
                asset_id_index[ctx.asset_id.lower()].append(aid)
            if ctx.hostname:
                hostname_index[ctx.hostname.lower()].append(aid)
            for ip in ctx.ip_addresses:
                if ip:
                    ip_index[ip.lower()].append(aid)
            if ctx.network_segment:
                segment_index[ctx.network_segment.lower()].append(aid)

        # Collect pairs with their best matching dimension
        pair_matches: dict[tuple[str, str], dict[str, Any]] = {}

        def _add_pairs(index: dict[str, list[str]], base_conf: float, dimension: str) -> None:
            for dim_value, alert_ids in index.items():
                if len(alert_ids) < 2:
                    continue
                for i in range(len(alert_ids)):
                    for j in range(i + 1, len(alert_ids)):
                        pair = (
                            min(alert_ids[i], alert_ids[j]),
                            max(alert_ids[i], alert_ids[j]),
                        )
                        existing = pair_matches.get(pair, {})
                        existing_conf = existing.get("confidence", 0.0)
                        if base_conf > existing_conf:
                            pair_matches[pair] = {
                                "confidence": base_conf,
                                "dimension": dimension,
                                "value": dim_value,
                            }

        _add_pairs(asset_id_index, self._asset_id_conf, "asset_id")
        _add_pairs(hostname_index, self._hostname_conf, "hostname")
        _add_pairs(ip_index, self._ip_conf, "ip_address")
        _add_pairs(segment_index, self._segment_conf, "network_segment")

        results: list[dict[str, Any]] = []

        for (id_a, id_b), match in pair_matches.items():
            # Apply criticality boost: higher criticality → higher confidence
            max_criticality = max(
                alert_map[id_a].asset_context.criticality,
                alert_map[id_b].asset_context.criticality,
            )
            boost = max_criticality * self._criticality_boost
            final_conf = min(1.0, match["confidence"] + boost)

            results.append({
                "alert_id_a": id_a,
                "alert_id_b": id_b,
                "confidence": round(final_conf, 3),
                "method": "ASSET_OVERLAP",
                "shared_observables": [],
                "audit": (
                    f"Asset correlation: {match['dimension']}={match['value']!r}; "
                    f"criticality_boost={boost:.2f}; confidence={final_conf:.2f}"
                ),
                "asset_dimension": match["dimension"],
                "asset_value": match["value"],
            })

        logger.debug(
            "Asset correlator found %d pairs from %d alerts", len(results), len(alerts)
        )
        return results
