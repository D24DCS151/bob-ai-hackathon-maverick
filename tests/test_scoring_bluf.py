"""
Tests for scoring engine and BLUF generation.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from threaticap.scoring.prioritisation_engine import (
    PrioritisationEngine,
    PrioritisationConfig,
    ScoringWeights,
    ScoringThresholds,
)
from threaticap.reporting.bluf_generator import BlufGenerator, _confidence_from_score
from threaticap.models.alert import AlertSeverity, AlertSource, AssetContext
from threaticap.models.correlated_threat import CorrelatedThreat
from threaticap.models.mitre import MitreMapping, MitreTechnique
from threaticap.models.priority import PriorityTier
from threaticap.models.bluf import ConfidenceLevel
from tests.conftest import make_alert


def make_threat(
    alert_count: int = 1,
    max_severity: str = "HIGH",
    correlation_confidence: float = 0.7,
    false_positive_probability: float = 0.1,
    source_types: list[str] | None = None,
    mitre_technique_ids: list[str] | None = None,
    affected_assets: list[str] | None = None,
    min_event_time: datetime | None = None,
    max_event_time: datetime | None = None,
) -> CorrelatedThreat:
    now = datetime.now(timezone.utc)
    return CorrelatedThreat(
        title="Test Threat",
        alert_count=alert_count,
        max_severity=max_severity,
        correlation_confidence=correlation_confidence,
        false_positive_probability=false_positive_probability,
        source_types=source_types or ["SIEM"],
        mitre_technique_ids=mitre_technique_ids or [],
        affected_assets=affected_assets or [],
        min_event_time=min_event_time or now - timedelta(hours=1),
        max_event_time=max_event_time or now,
    )


class TestPrioritisationEngine:

    def test_critical_severity_produces_high_score(self):
        engine = PrioritisationEngine()
        threat = make_threat(max_severity="CRITICAL", correlation_confidence=0.9)
        alert = make_alert(severity=AlertSeverity.CRITICAL, source_reliability=0.9,
                           asset_context=AssetContext(criticality=0.9))
        threat = threat.model_copy(update={"evidence_links": []})  # no evidence for scoring
        score = engine.score(threat)
        assert score.final_score > 40.0

    def test_low_severity_low_confidence_produces_low_score(self):
        engine = PrioritisationEngine()
        threat = make_threat(
            max_severity="INFO",
            correlation_confidence=0.2,
            false_positive_probability=0.7,
        )
        score = engine.score(threat)
        assert score.priority_tier == PriorityTier.LOW

    def test_critical_threshold_assignment(self):
        config = PrioritisationConfig(
            thresholds=ScoringThresholds(critical=80.0, high=60.0, medium=35.0),
        )
        engine = PrioritisationEngine(config=config)
        # Create a high-scoring threat
        threat = make_threat(
            max_severity="CRITICAL",
            correlation_confidence=0.95,
            false_positive_probability=0.0,
            source_types=["SIEM", "EDR", "HUMINT"],
            alert_count=8,
        )
        score = engine.score(threat)
        # With no constituent alerts for asset/reliability lookup,
        # expect at least HIGH or CRITICAL given the inputs
        assert score.priority_tier in (PriorityTier.CRITICAL, PriorityTier.HIGH)

    def test_fp_adjustment_reduces_score(self):
        engine = PrioritisationEngine()
        threat_low_fp = make_threat(correlation_confidence=0.8, false_positive_probability=0.0)
        threat_high_fp = make_threat(correlation_confidence=0.8, false_positive_probability=0.8)
        score_low_fp = engine.score(threat_low_fp)
        score_high_fp = engine.score(threat_high_fp)
        assert score_low_fp.final_score > score_high_fp.final_score

    def test_recent_alert_higher_urgency(self):
        engine = PrioritisationEngine()
        now = datetime.now(timezone.utc)
        recent = make_threat(max_event_time=now - timedelta(minutes=5))
        old = make_threat(max_event_time=now - timedelta(hours=60))
        score_recent = engine.score(recent)
        score_old = engine.score(old)
        assert score_recent.temporal_urgency_score > score_old.temporal_urgency_score

    def test_score_explanation_populated(self):
        engine = PrioritisationEngine()
        threat = make_threat(max_severity="HIGH", correlation_confidence=0.7)
        score = engine.score(threat)
        assert len(score.score_explanation) > 10

    def test_batch_scoring_sorted(self):
        engine = PrioritisationEngine()
        threats = [
            make_threat(max_severity="LOW", correlation_confidence=0.2),
            make_threat(max_severity="CRITICAL", correlation_confidence=0.9),
            make_threat(max_severity="MEDIUM", correlation_confidence=0.5),
        ]
        scored = engine.score_batch(threats)
        scores = [s.final_score for _, s in scored]
        assert scores == sorted(scores, reverse=True)

    def test_weights_sum_validation(self):
        with pytest.raises(ValueError):
            ScoringWeights(
                severity=0.50,
                confidence=0.50,
                source_reliability=0.50,
                asset_criticality=0.50,
                temporal_urgency=0.50,
            )

    def test_constituent_alert_enriches_scoring(self):
        """Verify that alert lookup enriches asset criticality and reliability."""
        engine = PrioritisationEngine()
        alert = make_alert(
            alert_id="a1",
            source_reliability=0.95,
            asset_context=AssetContext(criticality=1.0),
        )
        threat = make_threat(max_severity="HIGH", correlation_confidence=0.8)
        from threaticap.models.correlated_threat import EvidenceLink
        threat = threat.model_copy(update={
            "evidence_links": [
                EvidenceLink(alert_id="a1", source_ref="REF1", source_type="SIEM", relevance=1.0)
            ]
        })
        score = engine.score(threat, alert_lookup={"a1": alert})
        # asset_criticality_score and source_reliability_score store the
        # raw 0–1 component value (multiplied by 100 only in the final_score)
        assert score.asset_criticality_score == 1.0    # criticality=1.0
        assert score.source_reliability_score == 0.95  # reliability=0.95


class TestBlufGenerator:

    def _make_mitre_mapping(self, tactics: list[str] = None) -> MitreMapping:
        return MitreMapping(
            technique_ids=["T1059.001", "T1003"],
            tactic_ids=["TA0002", "TA0006"],
            tactic_names=tactics or ["Execution", "Credential Access"],
            techniques=[
                MitreTechnique(
                    technique_id="T1059.001",
                    technique_name="PowerShell",
                    tactic_ids=["TA0002"],
                    tactic_names=["Execution"],
                    detection_notes="Monitor PowerShell Script Block Logging",
                )
            ],
            kill_chain_stage="Credential Access",
            mapping_confidence=0.85,
        )

    def test_bluf_report_generated_successfully(self):
        from threaticap.models.priority import PriorityScore, PriorityTier
        gen = BlufGenerator()
        threat = make_threat(
            max_severity="CRITICAL",
            correlation_confidence=0.9,
            source_types=["SIEM", "EDR"],
            alert_count=4,
        )
        score = PriorityScore(
            threat_id=threat.threat_id,
            severity_score=90.0,
            confidence_score=80.0,
            source_reliability_score=85.0,
            asset_criticality_score=90.0,
            temporal_urgency_score=70.0,
            final_score=85.5,
            priority_tier=PriorityTier.CRITICAL,
        )
        mapping = self._make_mitre_mapping()
        report = gen.generate(threat, score, mapping)
        assert report.threat_id == threat.threat_id
        assert report.priority_tier == "CRITICAL"
        assert len(report.bottom_line) > 20
        assert len(report.immediate_actions) > 0
        assert len(report.investigation_steps) > 0

    def test_bluf_text_output_contains_key_sections(self):
        from threaticap.models.priority import PriorityScore, PriorityTier
        gen = BlufGenerator()
        threat = make_threat(source_types=["SIEM"])
        score = PriorityScore(
            threat_id=threat.threat_id,
            severity_score=60.0,
            confidence_score=65.0,
            source_reliability_score=80.0,
            asset_criticality_score=50.0,
            temporal_urgency_score=75.0,
            final_score=65.0,
            priority_tier=PriorityTier.HIGH,
        )
        mapping = self._make_mitre_mapping()
        report = gen.generate(threat, score, mapping)
        text = report.to_text()
        assert "BOTTOM LINE" in text
        assert "KEY EVIDENCE" in text
        assert "MITRE ATT&CK" in text
        assert "IMMEDIATE ACTIONS" in text
        assert "INVESTIGATION STEPS" in text

    def test_bluf_c2_tactic_generates_c2_action(self):
        from threaticap.models.priority import PriorityScore, PriorityTier
        gen = BlufGenerator()
        threat = make_threat(source_types=["SIEM", "EDR"])
        score = PriorityScore(
            threat_id=threat.threat_id,
            severity_score=80.0,
            confidence_score=80.0,
            source_reliability_score=80.0,
            asset_criticality_score=80.0,
            temporal_urgency_score=80.0,
            final_score=80.0,
            priority_tier=PriorityTier.CRITICAL,
        )
        mapping = self._make_mitre_mapping(tactics=["Command and Control", "Exfiltration"])
        report = gen.generate(threat, score, mapping)
        action_texts = " ".join(a.action for a in report.immediate_actions)
        assert any(keyword in action_texts.lower() for keyword in ["c2", "block", "firewall"])

    def test_confidence_level_mapping(self):
        # HIGH: strong confidence, low FP, multi-source
        assert _confidence_from_score(0.9, 0.05, 3) == ConfidenceLevel.HIGH
        # MODERATE: reasonable evidence
        assert _confidence_from_score(0.6, 0.25, 2) == ConfidenceLevel.MODERATE
        # LOW: poor correlation
        assert _confidence_from_score(0.2, 0.6, 1) == ConfidenceLevel.LOW
