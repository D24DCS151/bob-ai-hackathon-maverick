"""
Kill chain and attack campaign reconstruction.

Reconstructs likely multi-stage attack campaigns from correlated alert clusters
by mapping observed MITRE ATT&CK techniques to ordered kill chain phases and
identifying progression patterns.

Design:
- KillChainReconstructor consumes a CorrelatedThreat + its constituent Alerts.
- It maps MITRE technique IDs to kill chain phases using the KB.
- It produces a CampaignReconstruction with an ordered phase timeline and
  confidence annotations.
- The reconstruction is attached to the CorrelatedThreat and surfaced in BLUF.

References:
- Lockheed Martin Cyber Kill Chain (7 phases)
- MITRE ATT&CK Enterprise tactics (14 tactics)
- Unified Kill Chain (18 phases) — abbreviated here
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Kill chain phase taxonomy
# ---------------------------------------------------------------------------

class KillChainPhase(str, Enum):
    """
    Unified kill chain phases covering both pre- and post-compromise.
    Mapped from MITRE ATT&CK tactic names.
    """
    RECONNAISSANCE      = "Reconnaissance"
    WEAPONISATION       = "Weaponisation"
    DELIVERY            = "Resource Development / Delivery"
    EXPLOITATION        = "Initial Access / Exploitation"
    INSTALLATION        = "Execution / Persistence / Installation"
    PRIVILEGE_ESC       = "Privilege Escalation"
    DEFENSE_EVASION     = "Defense Evasion"
    CREDENTIAL_ACCESS   = "Credential Access"
    DISCOVERY           = "Discovery"
    LATERAL_MOVEMENT    = "Lateral Movement"
    COLLECTION          = "Collection"
    C2                  = "Command and Control"
    EXFILTRATION        = "Exfiltration"
    IMPACT              = "Impact"
    UNKNOWN             = "Unknown"


# MITRE tactic name → kill chain phase mapping
_TACTIC_TO_PHASE: dict[str, KillChainPhase] = {
    "Reconnaissance":        KillChainPhase.RECONNAISSANCE,
    "Resource Development":  KillChainPhase.WEAPONISATION,
    "Initial Access":        KillChainPhase.EXPLOITATION,
    "Execution":             KillChainPhase.INSTALLATION,
    "Persistence":           KillChainPhase.INSTALLATION,
    "Privilege Escalation":  KillChainPhase.PRIVILEGE_ESC,
    "Defense Evasion":       KillChainPhase.DEFENSE_EVASION,
    "Credential Access":     KillChainPhase.CREDENTIAL_ACCESS,
    "Discovery":             KillChainPhase.DISCOVERY,
    "Lateral Movement":      KillChainPhase.LATERAL_MOVEMENT,
    "Collection":            KillChainPhase.COLLECTION,
    "Command and Control":   KillChainPhase.C2,
    "Exfiltration":          KillChainPhase.EXFILTRATION,
    "Impact":                KillChainPhase.IMPACT,
}

# Ordered kill chain progression (phase index for advancement scoring)
_PHASE_ORDER: list[KillChainPhase] = [
    KillChainPhase.RECONNAISSANCE,
    KillChainPhase.WEAPONISATION,
    KillChainPhase.DELIVERY,
    KillChainPhase.EXPLOITATION,
    KillChainPhase.INSTALLATION,
    KillChainPhase.PRIVILEGE_ESC,
    KillChainPhase.DEFENSE_EVASION,
    KillChainPhase.CREDENTIAL_ACCESS,
    KillChainPhase.DISCOVERY,
    KillChainPhase.LATERAL_MOVEMENT,
    KillChainPhase.COLLECTION,
    KillChainPhase.C2,
    KillChainPhase.EXFILTRATION,
    KillChainPhase.IMPACT,
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class PhaseEvidence(BaseModel):
    """Evidence supporting a specific kill chain phase."""
    phase: KillChainPhase
    techniques: list[str] = Field(default_factory=list, description="MITRE technique IDs observed.")
    alert_ids: list[str] = Field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    notes: str = ""


class CampaignReconstruction(BaseModel):
    """
    Reconstructed attack campaign / kill chain.

    Contains an ordered sequence of observed kill chain phases with evidence,
    an adversary objective assessment, and campaign confidence metrics.
    """

    campaign_id: str
    threat_id: str

    # ---- Observed phases in chronological order --------------------------
    observed_phases: list[PhaseEvidence] = Field(default_factory=list)
    phase_sequence: list[str] = Field(
        default_factory=list,
        description="Ordered list of phase names as a narrative string.",
    )

    # ---- Campaign assessment -------------------------------------------
    earliest_activity: datetime | None = None
    latest_activity: datetime | None = None
    campaign_duration_hours: float | None = None
    phases_observed: int = 0
    kill_chain_completion: float = Field(
        ge=0.0,
        le=1.0,
        default=0.0,
        description="Fraction of the kill chain that has been completed (0=start, 1=impact).",
    )
    adversary_objective: str = Field(
        default="Unknown",
        description="Assessed adversary objective based on progression.",
    )
    is_advanced_persistent: bool = Field(
        default=False,
        description="True if multi-phase progression spans >4 kill chain stages.",
    )

    # ---- Confidence ------------------------------------------------------
    reconstruction_confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    coverage_gaps: list[str] = Field(
        default_factory=list,
        description="Kill chain phases expected but not observed — intelligence gaps.",
    )

    # ---- Narrative for BLUF -----------------------------------------------
    narrative: str = Field(
        default="",
        description="Plain-English description for commander BLUF.",
    )

    # ---- Attribution hints ------------------------------------------------
    suspected_actor: str | None = None
    actor_confidence: float = Field(ge=0.0, le=1.0, default=0.0)


# ---------------------------------------------------------------------------
# Reconstructor
# ---------------------------------------------------------------------------

class KillChainReconstructor:
    """
    Reconstructs an attack campaign timeline from a CorrelatedThreat.

    The reconstructor:
    1. Maps observed MITRE techniques to kill chain phases.
    2. Orders phases by first-seen timestamp.
    3. Assesses kill chain completion and adversary objective.
    4. Identifies intelligence gaps (expected but unseen phases).
    5. Generates a narrative for the BLUF.
    """

    # Technique prefix → phase mapping for fast lookup when tactic names
    # are not available (e.g. when the MITRE KB is not fully populated)
    _TECHNIQUE_PHASE_HINTS: dict[str, KillChainPhase] = {
        "T1595": KillChainPhase.RECONNAISSANCE,
        "T1592": KillChainPhase.RECONNAISSANCE,
        "T1589": KillChainPhase.RECONNAISSANCE,
        "T1566": KillChainPhase.EXPLOITATION,   # Phishing / Initial Access
        "T1190": KillChainPhase.EXPLOITATION,   # Exploit Public-Facing
        "T1059": KillChainPhase.INSTALLATION,   # Command & Scripting Interpreter
        "T1053": KillChainPhase.INSTALLATION,   # Scheduled Task
        "T1547": KillChainPhase.INSTALLATION,   # Boot/Logon Autostart
        "T1548": KillChainPhase.PRIVILEGE_ESC,
        "T1078": KillChainPhase.CREDENTIAL_ACCESS,  # Valid Accounts
        "T1003": KillChainPhase.CREDENTIAL_ACCESS,
        "T1110": KillChainPhase.CREDENTIAL_ACCESS,
        "T1083": KillChainPhase.DISCOVERY,
        "T1087": KillChainPhase.DISCOVERY,
        "T1018": KillChainPhase.DISCOVERY,
        "T1021": KillChainPhase.LATERAL_MOVEMENT,
        "T1570": KillChainPhase.LATERAL_MOVEMENT,
        "T1039": KillChainPhase.COLLECTION,
        "T1005": KillChainPhase.COLLECTION,
        "T1071": KillChainPhase.C2,
        "T1095": KillChainPhase.C2,
        "T1041": KillChainPhase.EXFILTRATION,
        "T1048": KillChainPhase.EXFILTRATION,
        "T1485": KillChainPhase.IMPACT,
        "T1486": KillChainPhase.IMPACT,   # Ransomware
        "T1489": KillChainPhase.IMPACT,
        "T1491": KillChainPhase.IMPACT,
    }

    def reconstruct(
        self,
        threat_id: str,
        mitre_technique_ids: list[str],
        tactic_names: list[str],
        alert_timeline: list[dict[str, Any]],  # [{alert_id, event_time, techniques}]
        suspected_actor: str | None = None,
    ) -> CampaignReconstruction:
        """
        Reconstruct a campaign from observed techniques and alert timeline.

        Args:
            threat_id:            The CorrelatedThreat ID.
            mitre_technique_ids:  All technique IDs observed in the threat.
            tactic_names:         Tactic names from MITRE mapper.
            alert_timeline:       Ordered list of alert metadata dicts.
            suspected_actor:      Optional actor name from threat attribution.
        """
        import uuid

        # ---- Map techniques to phases ------------------------------------
        phase_data: dict[KillChainPhase, dict[str, Any]] = {}

        # Priority: tactic name mapping (more accurate)
        for tactic in tactic_names:
            phase = _TACTIC_TO_PHASE.get(tactic, KillChainPhase.UNKNOWN)
            if phase not in phase_data:
                phase_data[phase] = {"techniques": [], "alert_ids": [], "times": []}

        # Map individual techniques
        for tid in mitre_technique_ids:
            prefix = tid[:5]  # T#### prefix
            phase = self._TECHNIQUE_PHASE_HINTS.get(prefix, KillChainPhase.UNKNOWN)
            if phase not in phase_data:
                phase_data[phase] = {"techniques": [], "alert_ids": [], "times": []}
            phase_data[phase]["techniques"].append(tid)

        # Cross-reference with alert timeline for temporal anchoring
        for entry in alert_timeline:
            entry_techs = set(entry.get("techniques", []))
            for phase, data in phase_data.items():
                if entry_techs.intersection(set(data["techniques"])):
                    data["alert_ids"].append(entry.get("alert_id", ""))
                    t = entry.get("event_time")
                    if t:
                        data["times"].append(t)

        # ---- Build PhaseEvidence list ------------------------------------
        observed: list[PhaseEvidence] = []
        for phase, data in phase_data.items():
            if phase == KillChainPhase.UNKNOWN:
                continue
            times = sorted(data["times"])
            conf = min(1.0, 0.4 + len(data["techniques"]) * 0.15 + len(data["alert_ids"]) * 0.05)
            observed.append(PhaseEvidence(
                phase=phase,
                techniques=list(set(data["techniques"])),
                alert_ids=list(set(data["alert_ids"])),
                first_seen=times[0] if times else None,
                last_seen=times[-1] if times else None,
                confidence=round(conf, 2),
            ))

        # Sort phases by kill chain order
        def _phase_idx(pe: PhaseEvidence) -> int:
            try:
                return _PHASE_ORDER.index(pe.phase)
            except ValueError:
                return 99

        observed.sort(key=_phase_idx)

        # ---- Kill chain completion ---------------------------------------
        if observed:
            max_idx = max(_phase_idx(p) for p in observed)
            completion = round((max_idx + 1) / len(_PHASE_ORDER), 2)
        else:
            completion = 0.0

        # ---- Coverage gaps -----------------------------------------------
        observed_set = {p.phase for p in observed}
        gaps = []
        if observed:
            min_idx = min(_phase_idx(p) for p in observed)
            max_idx = max(_phase_idx(p) for p in observed)
            for i in range(min_idx, max_idx + 1):
                if i < len(_PHASE_ORDER) and _PHASE_ORDER[i] not in observed_set:
                    gaps.append(_PHASE_ORDER[i].value)

        # ---- Adversary objective assessment --------------------------------
        objective = self._assess_objective(observed)

        # ---- Campaign timing -----------------------------------------------
        all_times = [
            t for pe in observed
            for t in [pe.first_seen, pe.last_seen]
            if t is not None
        ]
        earliest = min(all_times) if all_times else None
        latest = max(all_times) if all_times else None
        duration_hours = None
        if earliest and latest:
            duration_hours = round((latest - earliest).total_seconds() / 3600.0, 2)

        # ---- Is this likely an APT? ----------------------------------------
        is_apt = len(observed) >= 4 and completion >= 0.5

        # ---- Narrative for BLUF -------------------------------------------
        narrative = self._build_narrative(
            observed=observed,
            completion=completion,
            objective=objective,
            is_apt=is_apt,
            duration_hours=duration_hours,
            gaps=gaps,
        )

        # ---- Reconstruction confidence -------------------------------------
        recon_conf = min(1.0, len(observed) * 0.15 + (1.0 - len(gaps) / max(1, len(observed) + len(gaps))))

        return CampaignReconstruction(
            campaign_id=str(uuid.uuid4()),
            threat_id=threat_id,
            observed_phases=observed,
            phase_sequence=[p.phase.value for p in observed],
            earliest_activity=earliest,
            latest_activity=latest,
            campaign_duration_hours=duration_hours,
            phases_observed=len(observed),
            kill_chain_completion=completion,
            adversary_objective=objective,
            is_advanced_persistent=is_apt,
            reconstruction_confidence=round(recon_conf, 2),
            coverage_gaps=gaps,
            narrative=narrative,
            suspected_actor=suspected_actor,
        )

    def _assess_objective(self, phases: list[PhaseEvidence]) -> str:
        """Infer adversary objective from observed kill chain phases."""
        phase_set = {p.phase for p in phases}
        if KillChainPhase.IMPACT in phase_set:
            return "Destructive Attack / Disruption"
        if KillChainPhase.EXFILTRATION in phase_set:
            return "Data Theft / Intelligence Collection"
        if KillChainPhase.C2 in phase_set and KillChainPhase.LATERAL_MOVEMENT in phase_set:
            return "Persistent Access / Espionage"
        if KillChainPhase.CREDENTIAL_ACCESS in phase_set:
            return "Credential Harvesting / Privilege Acquisition"
        if KillChainPhase.DISCOVERY in phase_set:
            return "Network Reconnaissance / Mapping"
        if KillChainPhase.EXPLOITATION in phase_set or KillChainPhase.INSTALLATION in phase_set:
            return "Initial Compromise / Foothold Establishment"
        if KillChainPhase.RECONNAISSANCE in phase_set:
            return "Pre-Attack Reconnaissance"
        return "Unknown"

    def _build_narrative(
        self,
        observed: list[PhaseEvidence],
        completion: float,
        objective: str,
        is_apt: bool,
        duration_hours: float | None,
        gaps: list[str],
    ) -> str:
        if not observed:
            return "Insufficient evidence to reconstruct attack campaign."

        parts = []
        phase_names = " → ".join(p.phase.value for p in observed)
        parts.append(f"Observed kill chain: {phase_names}.")

        completion_pct = int(completion * 100)
        parts.append(f"Kill chain {completion_pct}% complete.")

        if duration_hours is not None:
            if duration_hours < 1:
                time_str = f"{int(duration_hours * 60)} minute(s)"
            elif duration_hours < 24:
                time_str = f"{duration_hours:.1f} hour(s)"
            else:
                time_str = f"{duration_hours / 24:.1f} day(s)"
            parts.append(f"Campaign duration: {time_str}.")

        if is_apt:
            parts.append("Multi-phase progression consistent with Advanced Persistent Threat activity.")

        parts.append(f"Assessed adversary objective: {objective}.")

        if gaps:
            parts.append(f"Intelligence gaps (phases not observed): {', '.join(gaps)}.")

        return " ".join(parts)
