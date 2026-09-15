"""
Commander-optimised BLUF renderer.

Produces role-specific output formats from a standard BlufReport:

1.  COMMANDER format  — 1-page, decision-focused, no technical jargon.
    Includes: SO WHAT, RECOMMENDED DECISIONS, MISSION IMPACT.
2.  SOC_ANALYST format — full technical detail including kill chain.
3.  INTEL_OFFICER format — attribution-focused, campaign context, gaps.
4.  WATCH_OFFICER format — brief situation report (SITREP) for the watch desk.
5.  COALITION format  — sanitised for sharing with coalition partners.

Design:
- CommanderBlufRenderer is stateless.
- Each format method returns a plain string suitable for:
  - Secure messaging (Signal / equivalent)
  - PDF generation (via reportlab / weasyprint)
  - Classified display terminal
  - Voice read-out (VOIP briefing)
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from threaticap.models.bluf import BlufReport, ActionItem, ConfidenceLevel
from threaticap.models.priority import PriorityTier


class OutputRole(str, Enum):
    COMMANDER       = "COMMANDER"
    SOC_ANALYST     = "SOC_ANALYST"
    INTEL_OFFICER   = "INTEL_OFFICER"
    WATCH_OFFICER   = "WATCH_OFFICER"
    COALITION       = "COALITION"


class CommanderBlufRenderer:
    """
    Renders BlufReport objects into role-specific textual formats.

    The key insight is that commanders and watch officers need different
    cognitive loads.  A commander needs: SO WHAT → DECISION → MISSION IMPACT.
    An analyst needs: evidence → techniques → investigation steps.
    """

    def render(
        self,
        report: BlufReport,
        role: OutputRole = OutputRole.COMMANDER,
        mission_impact: str | None = None,
        degraded_missions: list[str] | None = None,
        campaign_narrative: str | None = None,
        classification_banner: str = "OFFICIAL",
    ) -> str:
        """
        Render a BlufReport for the given role.

        Args:
            report:               The BlufReport to render.
            role:                 Target audience role.
            mission_impact:       Optional mission impact description.
            degraded_missions:    List of mission names being degraded.
            campaign_narrative:   Kill chain narrative from CampaignReconstruction.
            classification_banner: Header/footer classification marking.
        """
        dispatch = {
            OutputRole.COMMANDER:     self._render_commander,
            OutputRole.SOC_ANALYST:   self._render_analyst,
            OutputRole.INTEL_OFFICER: self._render_intel,
            OutputRole.WATCH_OFFICER: self._render_watch,
            OutputRole.COALITION:     self._render_coalition,
        }
        renderer = dispatch.get(role, self._render_commander)
        return renderer(
            report=report,
            mission_impact=mission_impact,
            degraded_missions=degraded_missions or [],
            campaign_narrative=campaign_narrative,
            classification_banner=classification_banner,
        )

    # ------------------------------------------------------------------
    # Commander format — decision-focused, minimal technical noise
    # ------------------------------------------------------------------

    def _render_commander(
        self,
        report: BlufReport,
        mission_impact: str | None,
        degraded_missions: list[str],
        campaign_narrative: str | None,
        classification_banner: str,
    ) -> str:
        sep = "═" * 72
        thin = "─" * 72
        lines: list[str] = []

        lines.append(f"\n{'■ ' + classification_banner + ' ■':^72}")
        lines.append(sep)
        lines.append(f"COMMANDER'S CYBER THREAT BRIEF  |  {report.tlp}")
        lines.append(f"Generated: {report.generated_at.strftime('%d %b %Y %H:%MZ')}")
        lines.append(sep)

        # ---- SO WHAT (priority marker) -----------------------------------
        tier_marker = {
            "CRITICAL": "⚠ CRITICAL THREAT — COMMAND DECISION REQUIRED NOW",
            "HIGH":     "▲ HIGH THREAT — ACTION REQUIRED WITHIN 1 HOUR",
            "MEDIUM":   "◆ MEDIUM THREAT — INVESTIGATION REQUIRED TODAY",
            "LOW":      "● LOW THREAT — ROUTINE MONITORING",
        }.get(report.priority_tier, report.priority_tier)

        lines.append(f"\n  {tier_marker}")
        lines.append(thin)

        # ---- BOTTOM LINE -------------------------------------------------
        lines.append("\nBOTTOM LINE:")
        for sentence in report.bottom_line.split(". "):
            if sentence.strip():
                lines.append(f"  {sentence.strip()}.")
        lines.append("")

        # ---- MISSION IMPACT (new for defence SOC) -----------------------
        if degraded_missions:
            lines.append(thin)
            lines.append("MISSION IMPACT:")
            for mission in degraded_missions:
                lines.append(f"  ⚠ ACTIVE MISSION DEGRADED: {mission}")
            if mission_impact:
                lines.append(f"  {mission_impact}")
            lines.append("")

        # ---- RECOMMENDED COMMAND DECISIONS -------------------------------
        lines.append(thin)
        lines.append("RECOMMENDED COMMAND DECISIONS:")
        decisions = self._build_command_decisions(report, degraded_missions)
        for i, dec in enumerate(decisions, 1):
            lines.append(f"  {i}. {dec['decision']}")
            lines.append(f"     ACTION:  {dec['action']}")
            lines.append(f"     OWNER:   {dec['owner']}")
            lines.append(f"     BY:      {dec['timeframe']}")

        # ---- TIME & SCOPE -----------------------------------------------
        lines.append("")
        lines.append(thin)
        lines.append(f"  Time window  : {report.time_window}")
        lines.append(f"  Alert count  : {report.alert_count}")
        if report.affected_assets:
            lines.append(f"  Affected     : {', '.join(report.affected_assets[:5])}")
        lines.append(f"  Confidence   : {report.confidence_level.value}")
        lines.append(f"  Score        : {report.priority_score:.0f}/100")

        # ---- CAMPAIGN NARRATIVE (condensed) ------------------------------
        if campaign_narrative:
            lines.append("")
            lines.append(thin)
            lines.append("ATTACK CAMPAIGN:")
            lines.append(f"  {campaign_narrative}")

        lines.append("")
        lines.append(sep)
        lines.append(f"{'■ ' + classification_banner + ' ■':^72}")
        lines.append(f"  Report ID: {report.report_id}")
        lines.append(f"  Threat ID: {report.threat_id}")
        lines.append(sep + "\n")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Watch officer format — concise SITREP
    # ------------------------------------------------------------------

    def _render_watch(
        self,
        report: BlufReport,
        mission_impact: str | None,
        degraded_missions: list[str],
        campaign_narrative: str | None,
        classification_banner: str,
    ) -> str:
        ts = report.generated_at.strftime("%d%H%MZ %b %y").upper()
        lines = [
            f"[{classification_banner} // {report.tlp}]",
            f"CYBER SITREP DTG: {ts}",
            f"PRIORITY: {report.priority_tier}",
            f"",
            f"SITUATION: {report.bottom_line}",
        ]
        if degraded_missions:
            lines.append(f"MISSION IMPACT: {', '.join(degraded_missions)}")
        if report.immediate_actions:
            act = report.immediate_actions[0]
            lines.append(f"RECOMMENDED ACTION: {act.action} [{act.timeframe}] — {act.owner}")
        lines.append(f"CONFIDENCE: {report.confidence_level.value}")
        lines.append(f"REF: {report.report_id[:8].upper()}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # SOC Analyst format — full technical detail
    # ------------------------------------------------------------------

    def _render_analyst(
        self,
        report: BlufReport,
        mission_impact: str | None,
        degraded_missions: list[str],
        campaign_narrative: str | None,
        classification_banner: str,
    ) -> str:
        # Use the existing BlufReport.to_text() as the base and extend it
        base = report.to_text()

        extras: list[str] = []
        if campaign_narrative:
            extras.append("")
            extras.append("ATTACK CAMPAIGN RECONSTRUCTION")
            extras.append("-" * 40)
            extras.append(f"  {campaign_narrative}")

        if degraded_missions:
            extras.append("")
            extras.append("MISSION IMPACT ASSESSMENT")
            extras.append("-" * 40)
            for m in degraded_missions:
                extras.append(f"  ⚠ DEGRADED: {m}")
            if mission_impact:
                extras.append(f"  {mission_impact}")

        if extras:
            # Insert before the final separator
            lines = base.split("\n")
            insert_idx = next(
                (i for i, l in enumerate(lines) if l.startswith("=" * 40)), len(lines) - 1
            )
            lines[insert_idx:insert_idx] = extras
            return "\n".join(lines)
        return base

    # ------------------------------------------------------------------
    # Intelligence officer format
    # ------------------------------------------------------------------

    def _render_intel(
        self,
        report: BlufReport,
        mission_impact: str | None,
        degraded_missions: list[str],
        campaign_narrative: str | None,
        classification_banner: str,
    ) -> str:
        sep = "=" * 72
        lines = [
            sep,
            f"INTELLIGENCE ASSESSMENT  |  {report.tlp}  |  {classification_banner}",
            f"Report : {report.report_id}  |  Threat: {report.threat_id}",
            f"DTG    : {report.generated_at.strftime('%d%H%MZ %b %y').upper()}",
            sep,
            "",
            "1. KEY JUDGEMENTS",
            "-" * 40,
        ]

        lines.append(f"  a. {report.bottom_line}")
        if report.bottom_line_extended:
            lines.append(f"  b. {report.bottom_line_extended}")

        lines.extend([
            "",
            "2. CAMPAIGN ANALYSIS",
            "-" * 40,
        ])
        if campaign_narrative:
            lines.append(f"  {campaign_narrative}")
        else:
            lines.append("  Insufficient data for campaign reconstruction.")

        lines.extend([
            "",
            "3. MITRE ATT&CK MAPPING",
            "-" * 40,
        ])
        if report.mitre_tactic_names:
            lines.append(f"  Tactics    : {', '.join(report.mitre_tactic_names)}")
        if report.mitre_technique_ids:
            lines.append(f"  Techniques : {', '.join(report.mitre_technique_ids)}")

        lines.extend([
            "",
            "4. CONFIDENCE & RELIABILITY",
            "-" * 40,
            f"  Analytic confidence : {report.confidence_level.value}",
            f"  Priority score      : {report.priority_score:.1f}/100",
            f"  Sources             : {', '.join(report.source_types)}",
        ])

        if degraded_missions:
            lines.extend([
                "",
                "5. OPERATIONAL IMPACT",
                "-" * 40,
            ])
            for m in degraded_missions:
                lines.append(f"  ⚠ MISSION DEGRADED: {m}")

        lines.extend([
            "",
            "6. COLLECTION GAPS",
            "-" * 40,
            "  (See campaign reconstruction coverage_gaps for intelligence gaps.)",
            "",
            sep,
        ])
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Coalition format — sanitised, no classification caveats
    # ------------------------------------------------------------------

    def _render_coalition(
        self,
        report: BlufReport,
        mission_impact: str | None,
        degraded_missions: list[str],
        campaign_narrative: str | None,
        classification_banner: str,
    ) -> str:
        lines = [
            f"[{report.tlp}]",
            f"THREAT ADVISORY",
            f"Priority: {report.priority_tier}  |  Confidence: {report.confidence_level.value}",
            f"Generated: {report.generated_at.strftime('%Y-%m-%dT%H:%MZ')}",
            "",
            "SUMMARY:",
            f"  {report.bottom_line}",
        ]

        if report.mitre_technique_ids:
            lines.extend([
                "",
                f"MITRE TECHNIQUES: {', '.join(report.mitre_technique_ids[:6])}",
            ])

        if report.key_evidence:
            lines.append("")
            lines.append("INDICATORS:")
            for ev in report.key_evidence[:4]:
                for obs in ev.observable_values[:3]:
                    lines.append(f"  - {obs}")

        lines.extend([
            "",
            f"REF: {report.report_id[:8].upper()}",
        ])
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Command decision generator
    # ------------------------------------------------------------------

    @staticmethod
    def _build_command_decisions(
        report: BlufReport,
        degraded_missions: list[str],
    ) -> list[dict[str, str]]:
        """
        Produce 2–4 concise command decisions (not tactical actions).

        Command decisions are strategic choices: AUTHORISE, NOTIFY, ESCALATE,
        SUSPEND, DEGRADE — not "block this IP".
        """
        decisions: list[dict[str, str]] = []
        tier = report.priority_tier

        if degraded_missions:
            decisions.append({
                "decision": f"ASSESS: Evaluate operational impact on {', '.join(degraded_missions[:2])}",
                "action": "Convene operational security (OPSEC) review immediately",
                "owner": "Mission Commander / J3",
                "timeframe": "Immediate",
            })

        if tier == "CRITICAL":
            decisions.append({
                "decision": "ESCALATE: Invoke National Incident Response Protocol",
                "action": "Notify CISO, Deputy Commander, and legal authority immediately",
                "owner": "Incident Commander",
                "timeframe": "Immediate",
            })
            decisions.append({
                "decision": "AUTHORISE: Emergency containment measures",
                "action": "Authorise network isolation of affected segment(s)",
                "owner": "Commander / CISO",
                "timeframe": "Within 15 minutes",
            })
        elif tier == "HIGH":
            decisions.append({
                "decision": "ESCALATE: Elevate to senior CISO and J6",
                "action": "Brief on threat status and authorise Tier-2 response",
                "owner": "SOC Manager",
                "timeframe": "Within 30 minutes",
            })
        else:
            decisions.append({
                "decision": "ASSIGN: Designate investigation owner",
                "action": "Assign Tier-2 analyst and set SLA for response",
                "owner": "SOC Manager",
                "timeframe": "Within 2 hours",
            })

        tactics = set(report.mitre_tactic_names)
        if "Exfiltration" in tactics or "Collection" in tactics:
            decisions.append({
                "decision": "NOTIFY: Consider mandatory breach disclosure",
                "action": "Brief legal / data protection officer on potential data loss",
                "owner": "Legal / Compliance",
                "timeframe": "Within 2 hours",
            })

        return decisions[:4]  # Cap at 4 for readability
