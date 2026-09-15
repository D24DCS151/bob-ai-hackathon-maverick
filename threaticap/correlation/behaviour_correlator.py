"""
Behaviour correlator — identifies alerts sharing MITRE ATT&CK technique patterns.

Two or more alerts showing a sequence of related techniques (e.g. Initial
Access → Execution → Lateral Movement) are more likely to represent a single
coordinated attack than random noise.

Strategy:
    1. For each pair of alerts, compare their MITRE technique sets.
    2. Technique overlap = direct match.
    3. Tactic chain = different techniques in the same tactic, or adjacent
       kill-chain stages → attack progression signal.
    4. Threat actor / campaign match → strongest behavioural link.
"""
from __future__ import annotations

import logging
from typing import Any

from threaticap.models.alert import Alert

logger = logging.getLogger(__name__)

# Kill chain progression order (MITRE ATT&CK tactics by phase)
KILL_CHAIN_ORDER: list[str] = [
    "TA0043",  # Reconnaissance
    "TA0042",  # Resource Development
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0011",  # Command and Control
    "TA0010",  # Exfiltration
    "TA0040",  # Impact
]

KILL_CHAIN_POSITION: dict[str, int] = {tac: i for i, tac in enumerate(KILL_CHAIN_ORDER)}


class BehaviourCorrelator:
    """
    Correlates alerts that share behavioural patterns via MITRE ATT&CK.
    """

    def __init__(
        self,
        technique_match_confidence: float = 0.7,
        tactic_match_confidence: float = 0.45,
        chain_match_confidence: float = 0.5,
        actor_match_confidence: float = 0.85,
        campaign_match_confidence: float = 0.90,
    ) -> None:
        self._tech_conf = technique_match_confidence
        self._tac_conf = tactic_match_confidence
        self._chain_conf = chain_match_confidence
        self._actor_conf = actor_match_confidence
        self._campaign_conf = campaign_match_confidence

    def correlate(self, alerts: list[Alert]) -> list[dict[str, Any]]:
        """Find behavioural links between alert pairs."""
        results: list[dict[str, Any]] = []

        for i in range(len(alerts)):
            for j in range(i + 1, len(alerts)):
                a, b = alerts[i], alerts[j]
                links = self._compare(a, b)
                if links:
                    best = max(links, key=lambda l: l["confidence"])
                    pair = (
                        min(a.alert_id, b.alert_id),
                        max(a.alert_id, b.alert_id),
                    )
                    results.append({
                        "alert_id_a": pair[0],
                        "alert_id_b": pair[1],
                        "confidence": best["confidence"],
                        "method": "BEHAVIOUR",
                        "shared_observables": [],
                        "audit": best["audit"],
                        "behaviour_links": links,
                    })

        logger.debug(
            "Behaviour correlator found %d pairs from %d alerts",
            len(results), len(alerts)
        )
        return results

    def _compare(self, a: Alert, b: Alert) -> list[dict[str, Any]]:
        """Compare two alerts for behavioural links. Returns list of link dicts."""
        links: list[dict[str, Any]] = []

        # ---- Campaign / actor match (strongest signal) --------------------
        if a.campaign and b.campaign and a.campaign.lower() == b.campaign.lower():
            links.append({
                "confidence": self._campaign_conf,
                "audit": f"Campaign match: {a.campaign!r}",
            })
        elif a.threat_actor and b.threat_actor and a.threat_actor.lower() == b.threat_actor.lower():
            links.append({
                "confidence": self._actor_conf,
                "audit": f"Threat actor match: {a.threat_actor!r}",
            })

        # ---- MITRE technique overlap -------------------------------------
        techs_a = set(a.mitre_technique_ids)
        techs_b = set(b.mitre_technique_ids)
        shared_techs = techs_a & techs_b

        if shared_techs:
            # Boost for multiple shared techniques
            boost = min(0.15, (len(shared_techs) - 1) * 0.07)
            conf = min(1.0, self._tech_conf + boost)
            links.append({
                "confidence": conf,
                "audit": (
                    f"MITRE technique overlap: {sorted(shared_techs)}; "
                    f"confidence={conf:.2f}"
                ),
            })

        # ---- Kill chain progression link --------------------------------
        # Check if one alert's techniques are adjacent in the kill chain
        # to the other's (attack progression pattern)
        if techs_a and techs_b and not shared_techs:
            progression = self._check_kill_chain_progression(
                list(techs_a), list(techs_b)
            )
            if progression:
                links.append({
                    "confidence": self._chain_conf,
                    "audit": f"Kill chain progression: {progression}",
                })

        return links

    def _check_kill_chain_progression(
        self,
        techs_a: list[str],
        techs_b: list[str],
    ) -> str | None:
        """
        Detect if the techniques represent adjacent kill-chain stages.
        Uses a simplified tactic-level check.
        """
        # Map technique IDs to known tactic IDs via prefix conventions
        # Real implementation uses the loaded MITRE knowledge base
        # Here we use a lightweight heuristic based on technique numbering
        def estimate_phase(tech_id: str) -> int:
            """Rough phase estimate based on technique ID range."""
            base = tech_id.split(".")[0]  # T#### part
            try:
                num = int(base[1:])
            except ValueError:
                return -1
            # These ranges are approximate; real mapping uses ATT&CK data
            ranges = [
                (1580, 1600, 0),   # Recon
                (1583, 1588, 1),   # Resource Dev
                (1189, 1200, 2),   # Initial Access
                (1059, 1106, 3),   # Execution
                (1053, 1078, 4),   # Persistence
                (1134, 1574, 5),   # Privilege Escalation
                (1006, 1140, 6),   # Defense Evasion
                (1003, 1558, 7),   # Credential Access
                (1007, 1120, 8),   # Discovery
                (1021, 1080, 9),   # Lateral Movement
                (1005, 1602, 10),  # Collection
                (1071, 1572, 11),  # C2
                (1020, 1567, 12),  # Exfiltration
                (1485, 1570, 13),  # Impact
            ]
            for lo, hi, phase in ranges:
                if lo <= num <= hi:
                    return phase
            return -1

        phases_a = {estimate_phase(t) for t in techs_a if estimate_phase(t) >= 0}
        phases_b = {estimate_phase(t) for t in techs_b if estimate_phase(t) >= 0}

        if not phases_a or not phases_b:
            return None

        for pa in phases_a:
            for pb in phases_b:
                if abs(pa - pb) == 1:
                    return (
                        f"phases {pa}→{pb} "
                        f"({KILL_CHAIN_ORDER[pa] if pa < len(KILL_CHAIN_ORDER) else 'unknown'}"
                        f"→{KILL_CHAIN_ORDER[pb] if pb < len(KILL_CHAIN_ORDER) else 'unknown'})"
                    )
        return None
