"""
BLUF generator — produces commander-ready Bottom Line Up Front reports.

The generator takes a CorrelatedThreat with its PriorityScore and MitreMapping
and produces a fully structured BlufReport.

Design:
- Template-driven action generation (no hard-coded strings in logic code).
- Confidence levels aligned with intelligence community standards.
- Both JSON (machine-readable) and plain-text (human-readable) output.
- Every report is versioned and linked to the source threat and audit trail.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable

from threaticap.models.alert import Alert
from threaticap.models.bluf import (
    ActionItem,
    BlufReport,
    ConfidenceLevel,
    EvidenceSummary,
)
from threaticap.models.correlated_threat import CorrelatedThreat
from threaticap.models.mitre import MitreMapping
from threaticap.models.priority import PriorityScore, PriorityTier
from threaticap.models.audit import AuditEventType, AuditRecord

logger = logging.getLogger(__name__)


def _confidence_from_score(
    correlation_confidence: float,
    fp_probability: float,
    source_count: int,
) -> ConfidenceLevel:
    """
    Map numeric confidence to analytic confidence level.

    HIGH     : strong evidence, low FP probability, multi-source
    MODERATE : reasonable evidence, some uncertainty
    LOW      : limited evidence or high FP probability
    """
    if correlation_confidence >= 0.75 and fp_probability <= 0.15 and source_count >= 2:
        return ConfidenceLevel.HIGH
    if correlation_confidence >= 0.45 and fp_probability <= 0.40:
        return ConfidenceLevel.MODERATE
    return ConfidenceLevel.LOW


def _format_time_window(
    min_time: datetime | None,
    max_time: datetime | None,
) -> str:
    if min_time is None:
        return "Unknown time window"
    if max_time is None or min_time == max_time:
        return f"Single event at {min_time.strftime('%Y-%m-%dT%H:%MZ')}"

    delta = max_time - min_time
    hours = int(delta.total_seconds() / 3600)
    minutes = int((delta.total_seconds() % 3600) / 60)

    if hours == 0:
        span = f"{minutes} minute(s)"
    elif hours < 24:
        span = f"{hours}h {minutes}m"
    else:
        days = hours // 24
        span = f"{days} day(s)"

    return (
        f"{min_time.strftime('%Y-%m-%dT%H:%MZ')} to "
        f"{max_time.strftime('%Y-%m-%dT%H:%MZ')} ({span})"
    )


class BlufGenerator:
    """
    Generates structured BLUF reports from correlated threat data.

    The generator is stateless — each generate() call is independent.
    """

    def __init__(
        self,
        audit_callback: Callable[[AuditRecord], None] | None = None,
    ) -> None:
        self._audit_callback = audit_callback

    def generate(
        self,
        threat: CorrelatedThreat,
        priority_score: PriorityScore,
        mitre_mapping: MitreMapping,
        alert_lookup: dict[str, Alert] | None = None,
    ) -> BlufReport:
        """
        Generate a BlufReport for a CorrelatedThreat.

        Args:
            threat:         The correlated threat object.
            priority_score: Priority score with component breakdown.
            mitre_mapping:  Enriched MITRE ATT&CK mapping.
            alert_lookup:   Dict of alert_id → Alert for evidence detail.
        """
        alert_lookup = alert_lookup or {}
        tier = priority_score.priority_tier
        conf_level = _confidence_from_score(
            threat.correlation_confidence,
            threat.false_positive_probability,
            len(threat.source_types),
        )
        time_window = _format_time_window(threat.min_event_time, threat.max_event_time)

        bottom_line = self._build_bottom_line(threat, priority_score, mitre_mapping, conf_level)
        key_evidence = self._build_key_evidence(threat, alert_lookup)
        immediate_actions = self._build_immediate_actions(tier, mitre_mapping, threat)
        investigation_steps = self._build_investigation_steps(threat, mitre_mapping)
        priority_justification = priority_score.score_explanation

        score_breakdown = {
            c.name: round(c.weighted_value * 100, 1)
            for c in priority_score.components
        }

        report = BlufReport(
            threat_id=threat.threat_id,
            bottom_line=bottom_line,
            bottom_line_extended=self._build_extended_summary(threat, mitre_mapping),
            priority_tier=tier.value,
            priority_score=priority_score.final_score,
            confidence_level=conf_level,
            tlp=self._determine_tlp(threat, alert_lookup),
            key_evidence=key_evidence,
            alert_count=threat.alert_count,
            source_types=threat.source_types,
            time_window=time_window,
            affected_assets=threat.affected_assets[:10],
            mitre_technique_ids=mitre_mapping.technique_ids,
            mitre_tactic_names=mitre_mapping.tactic_names,
            kill_chain_stage=mitre_mapping.kill_chain_stage,
            immediate_actions=immediate_actions,
            investigation_steps=investigation_steps,
            priority_justification=priority_justification,
            score_breakdown=score_breakdown,
            generated_at=datetime.now(timezone.utc),
        )

        self._emit_audit(
            AuditEventType.BLUF_GENERATED,
            threat_id=threat.threat_id,
            report_id=report.report_id,
            summary=f"BLUF report generated: {tier.value} priority, confidence={conf_level.value}",
        )

        logger.info(
            "BLUF generated for threat %s: %s / %s (score=%.1f)",
            threat.threat_id[:8], tier.value, conf_level.value, priority_score.final_score
        )
        return report

    # ------------------------------------------------------------------
    # Builder methods
    # ------------------------------------------------------------------

    def _build_bottom_line(
        self,
        threat: CorrelatedThreat,
        priority_score: PriorityScore,
        mitre_mapping: MitreMapping,
        conf_level: ConfidenceLevel,
    ) -> str:
        """
        Construct a 1–3 sentence BLUF bottom line.
        Follows the military BLUF convention: WHO/WHAT, evidence, action.
        """
        # Sentence 1: What is happening
        actor_str = f" attributed to {threat.suspected_actor}" if threat.suspected_actor else ""
        source_str = f"{len(threat.source_types)} independent source(s)" if len(threat.source_types) > 1 else threat.source_types[0] if threat.source_types else "multiple sensors"
        tactic_str = (
            f" consistent with {' and '.join(mitre_mapping.tactic_names[:3])}"
            if mitre_mapping.tactic_names else ""
        )
        sentence1 = (
            f"{priority_score.priority_tier.value}-priority threat{actor_str} detected "
            f"across {source_str}{tactic_str}."
        )

        # Sentence 2: Evidence summary
        asset_str = ""
        if threat.affected_assets:
            n = min(3, len(threat.affected_assets))
            asset_str = f" Affected asset(s): {', '.join(threat.affected_assets[:n])}{'...' if len(threat.affected_assets) > 3 else ''}."

        sentence2 = (
            f"{threat.alert_count} correlated alert(s) with "
            f"{conf_level.value.lower()} confidence.{asset_str}"
        )

        # Sentence 3: Action required
        action_map = {
            PriorityTier.CRITICAL: "Immediate containment action required.",
            PriorityTier.HIGH:     "Urgent investigation and containment required within 1 hour.",
            PriorityTier.MEDIUM:   "Investigation required within 4 hours.",
            PriorityTier.LOW:      "Routine investigation warranted; monitor for escalation.",
        }
        sentence3 = action_map.get(
            PriorityTier(priority_score.priority_tier), "Investigate and assess impact."
        )

        return f"{sentence1} {sentence2} {sentence3}"

    def _build_extended_summary(
        self, threat: CorrelatedThreat, mitre_mapping: MitreMapping
    ) -> str:
        """Extended context paragraph for analysts."""
        parts = []
        if threat.campaign:
            parts.append(f"Campaign: {threat.campaign}.")
        if mitre_mapping.techniques:
            tech_str = ", ".join(
                f"{t.technique_id} ({t.technique_name})"
                for t in mitre_mapping.techniques[:4]
            )
            parts.append(f"Observed techniques: {tech_str}.")
        if threat.false_positive_probability > 0.3:
            parts.append(
                f"Note: elevated false-positive probability "
                f"({threat.false_positive_probability:.0%}) — "
                "corroborate with additional sources before escalating."
            )
        if threat.network_segments:
            parts.append(
                f"Activity spans network segment(s): {', '.join(threat.network_segments[:3])}."
            )
        return " ".join(parts)

    def _build_key_evidence(
        self,
        threat: CorrelatedThreat,
        alert_lookup: dict[str, Alert],
    ) -> list[EvidenceSummary]:
        """Build summarised evidence items linked to source alerts."""
        evidence_items: list[EvidenceSummary] = []

        # Group evidence links by source type for concise display
        source_groups: dict[str, list[str]] = {}
        for ev in threat.evidence_links[:10]:
            alert = alert_lookup.get(ev.alert_id)
            group_key = ev.source_type
            source_groups.setdefault(group_key, [])
            source_groups[group_key].append(ev.alert_id)

            if alert:
                obs_vals = [
                    o.value for o in alert.observables[:4]
                    if o.value
                ]
                evidence_items.append(EvidenceSummary(
                    alert_ids=[ev.alert_id],
                    source_types=[ev.source_type],
                    description=alert.title,
                    observable_values=obs_vals,
                    confidence=alert.confidence,
                ))
            else:
                evidence_items.append(EvidenceSummary(
                    alert_ids=[ev.alert_id],
                    source_types=[ev.source_type],
                    description=f"Alert from {ev.source_type} (details not available)",
                    confidence=0.5,
                ))

        # Add shared observable evidence item
        if threat.shared_observables:
            obs_vals = [o["value"] for o in threat.shared_observables[:6]]
            evidence_items.insert(0, EvidenceSummary(
                alert_ids=[ev.alert_id for ev in threat.evidence_links],
                source_types=threat.source_types,
                description=(
                    f"{len(threat.shared_observables)} observable(s) appear in "
                    f"multiple alerts: {', '.join(obs_vals[:4])}"
                ),
                observable_values=obs_vals,
                confidence=min(1.0, threat.correlation_confidence + 0.1),
            ))

        return evidence_items[:8]

    def _build_immediate_actions(
        self,
        tier: PriorityTier,
        mitre_mapping: MitreMapping,
        threat: CorrelatedThreat,
    ) -> list[ActionItem]:
        """
        Generate priority-tiered immediate actions.
        Actions are driven by tier and MITRE tactic context.
        """
        actions: list[ActionItem] = []
        tactics = set(mitre_mapping.tactic_names)

        if tier == PriorityTier.CRITICAL:
            actions.append(ActionItem(
                priority=1,
                action="Activate Incident Response Team (IRT) immediately",
                rationale="CRITICAL priority threat requires immediate escalation",
                owner="SOC Manager / Incident Commander",
                timeframe="Immediate",
            ))

        if "Command and Control" in tactics or "Exfiltration" in tactics:
            actions.append(ActionItem(
                priority=2 if tier != PriorityTier.CRITICAL else 3,
                action="Block identified C2 domains/IPs at perimeter firewall and proxy",
                rationale="Prevent active C2 communication or ongoing data exfiltration",
                owner="Network Operations",
                timeframe="Within 15 minutes",
            ))

        if "Lateral Movement" in tactics:
            actions.append(ActionItem(
                priority=2,
                action="Isolate affected hosts from the network to contain lateral movement",
                rationale="Lateral movement indicates attacker is spreading through the environment",
                owner="SOC Analyst / System Owner",
                timeframe="Within 30 minutes",
            ))

        if "Credential Access" in tactics:
            actions.append(ActionItem(
                priority=3,
                action="Force password reset and revoke tokens for affected accounts",
                rationale="Credential theft may enable persistent access or privilege escalation",
                owner="Identity & Access Management",
                timeframe="Within 1 hour",
            ))

        if "Exfiltration" in tactics:
            actions.append(ActionItem(
                priority=2,
                action="Engage legal/compliance team and notify data protection officer",
                rationale="Potential data exfiltration triggers regulatory notification obligations",
                owner="Legal / Compliance",
                timeframe="Within 2 hours",
            ))

        # Generic actions based on tier
        if not actions or tier in (PriorityTier.HIGH, PriorityTier.CRITICAL):
            actions.append(ActionItem(
                priority=len(actions) + 1,
                action="Preserve forensic artefacts — memory dumps, logs, network captures",
                rationale="Forensic preservation enables post-incident analysis and legal proceedings",
                owner="SOC Analyst",
                timeframe="Within 1 hour",
            ))

        actions.append(ActionItem(
            priority=len(actions) + 1,
            action="Update threat ticket and brief CISO / command authority",
            rationale="Leadership situational awareness required for operational decisions",
            owner="SOC Manager",
            timeframe=(
                "Immediate" if tier == PriorityTier.CRITICAL
                else "Within 2 hours"
            ),
        ))

        return sorted(actions, key=lambda a: a.priority)

    def _build_investigation_steps(
        self,
        threat: CorrelatedThreat,
        mitre_mapping: MitreMapping,
    ) -> list[ActionItem]:
        """Generate investigation steps tailored to the threat context."""
        steps: list[ActionItem] = []

        steps.append(ActionItem(
            priority=1,
            action=(
                f"Review all {threat.alert_count} constituent alert(s) in full; "
                "correlate timestamps and source system logs"
            ),
            owner="Tier-2 Analyst",
            timeframe="Within 4 hours",
        ))

        if threat.shared_observables:
            steps.append(ActionItem(
                priority=2,
                action=(
                    f"Search all log sources for {len(threat.shared_observables)} "
                    "shared IOC(s) across 72-hour window"
                ),
                owner="Tier-2 Analyst",
                timeframe="Within 4 hours",
            ))

        for tech in mitre_mapping.techniques[:3]:
            if tech.detection_notes:
                steps.append(ActionItem(
                    priority=3,
                    action=f"Execute detection for {tech.technique_id} ({tech.technique_name}): {tech.detection_notes[:200]}",
                    owner="Threat Hunter",
                    timeframe="Within 8 hours",
                ))

        if threat.suspected_actor:
            steps.append(ActionItem(
                priority=4,
                action=(
                    f"Cross-reference threat actor {threat.suspected_actor!r} "
                    "against national / classified threat intelligence databases"
                ),
                owner="Threat Intelligence Analyst",
                timeframe="Within 24 hours",
            ))

        steps.append(ActionItem(
            priority=len(steps) + 1,
            action="Submit IOCs to threat intelligence sharing platform (ISACs / national platforms)",
            owner="Threat Intelligence Analyst",
            timeframe="Within 24 hours",
        ))

        return steps

    @staticmethod
    def _determine_tlp(
        threat: CorrelatedThreat,
        alert_lookup: dict[str, Alert],
    ) -> str:
        """Propagate the most restrictive TLP from constituent alerts."""
        tlp_order = ["TLP:RED", "TLP:AMBER", "TLP:GREEN", "TLP:WHITE"]
        tlp_set = set()
        for ev in threat.evidence_links:
            alert = alert_lookup.get(ev.alert_id)
            if alert and alert.tlp:
                tlp_set.add(alert.tlp)
        for tlp in tlp_order:
            if tlp in tlp_set:
                return tlp
        return "TLP:GREEN"

    def _emit_audit(
        self,
        event_type: AuditEventType,
        threat_id: str | None = None,
        report_id: str | None = None,
        summary: str = "",
    ) -> None:
        if self._audit_callback is None:
            return
        record = AuditRecord(
            event_type=event_type,
            component="BlufGenerator",
            threat_id=threat_id,
            report_id=report_id,
            summary=summary,
        )
        try:
            self._audit_callback(record)
        except Exception as exc:
            logger.error("Audit callback error: %s", exc)
