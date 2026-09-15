"""
Tests for Phase 3 defence SOC capabilities:
1. Mission-aware prioritisation
2. Campaign reconstruction
3. Feedback-driven FP learning
4. Classification & coalition intelligence handling
5. Cross-domain / air-gapped transfer
6. MISP connector normalisation
7. Commander BLUF renderer
8. Feed quality management
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.conftest import make_alert, make_observable
from threaticap.models.alert import AlertSeverity, AlertSource, AssetContext, ObservableType
from threaticap.models.feedback import AnalystFeedback, Verdict


# ===========================================================================
# 1. Mission-Aware Prioritisation
# ===========================================================================

class TestMissionContext:

    def _make_mission_context(self):
        from threaticap.models.mission import (
            Mission, MissionContext, MissionReadiness, AssetMissionRole, MissionDomain
        )
        role = AssetMissionRole(
            asset_id="ASSET-001",
            mission_id="TEST-01",
            role="C2",
            impact_weight=2.5,
            degradation_threshold=0.4,
        )
        mission = Mission(
            mission_id="TEST-01",
            name="Op Overlord",
            readiness=MissionReadiness.ACTIVE,
            domain=MissionDomain.CYBER,
            priority_rank=1,
            asset_roles=[role],
        )
        return MissionContext(missions=[mission])

    def test_active_mission_detected(self):
        ctx = self._make_mission_context()
        active = ctx.get_active_missions()
        assert len(active) == 1
        assert active[0].name == "Op Overlord"

    def test_mission_urgency_multiplier_active(self):
        ctx = self._make_mission_context()
        m = ctx.get_active_missions()[0]
        assert m.urgency_multiplier > 1.0

    def test_mission_impact_weight_amplified(self):
        ctx = self._make_mission_context()
        weight = ctx.get_mission_impact(["ASSET-001"], [])
        assert weight > 1.0

    def test_mission_impact_no_match(self):
        ctx = self._make_mission_context()
        weight = ctx.get_mission_impact(["UNRELATED-ASSET"], [])
        assert weight == 1.0

    def test_degraded_mission_names(self):
        ctx = self._make_mission_context()
        degraded = ctx.get_degraded_mission_names(["ASSET-001"], [], asset_criticality=0.9)
        assert "Op Overlord" in degraded

    def test_tag_based_matching(self):
        from threaticap.models.mission import Mission, MissionContext, MissionReadiness, AssetMissionRole
        role = AssetMissionRole(
            asset_id="c2-server",
            mission_id="M2",
            role="C2",
            impact_weight=2.0,
            degradation_threshold=0.3,
        )
        mission = Mission(
            mission_id="M2",
            name="Mission Alpha",
            readiness=MissionReadiness.ACTIVE,
            priority_rank=2,
            asset_roles=[role],
        )
        ctx = MissionContext(missions=[mission])
        weight = ctx.get_mission_impact([], ["c2-server"])
        assert weight > 1.0

    def test_scorer_applies_mission_multiplier(self):
        from threaticap.scoring.prioritisation_engine import PrioritisationEngine, PrioritisationConfig
        from threaticap.models.correlated_threat import CorrelatedThreat, EvidenceLink
        from datetime import timedelta

        ctx = self._make_mission_context()
        engine = PrioritisationEngine(mission_context=ctx)

        alert = make_alert(
            alert_id="a1",
            source_ref="s1",
            severity=AlertSeverity.HIGH,
            asset_context=AssetContext(asset_id="ASSET-001", criticality=0.8),
        )
        ev = EvidenceLink(
            alert_id="a1", source_ref="s1", source_type="SIEM", relevance=1.0
        )
        threat = CorrelatedThreat(
            title="Test",
            correlation_confidence=0.8,
            false_positive_probability=0.0,
            alert_count=1,
            evidence_links=[ev],
            max_severity="HIGH",
            max_event_time=datetime.now(timezone.utc),
        )
        score = engine.score(threat, {"a1": alert})
        assert score.mission_impact_multiplier > 1.0
        assert "Op Overlord" in score.degraded_missions


# ===========================================================================
# 2. Campaign Reconstruction
# ===========================================================================

class TestCampaignReconstructor:

    def test_basic_reconstruction(self):
        from threaticap.analysis.campaign_reconstructor import KillChainReconstructor
        r = KillChainReconstructor()
        campaign = r.reconstruct(
            threat_id="t-001",
            mitre_technique_ids=["T1566", "T1059", "T1071", "T1041"],
            tactic_names=["Initial Access", "Execution", "Command and Control", "Exfiltration"],
            alert_timeline=[],
        )
        assert campaign.phases_observed >= 3
        assert campaign.kill_chain_completion > 0.0
        assert campaign.adversary_objective != "Unknown"

    def test_apt_detection(self):
        from threaticap.analysis.campaign_reconstructor import KillChainReconstructor
        r = KillChainReconstructor()
        campaign = r.reconstruct(
            threat_id="t-002",
            mitre_technique_ids=["T1566", "T1059", "T1003", "T1021", "T1041", "T1486"],
            tactic_names=[
                "Initial Access", "Execution", "Credential Access",
                "Lateral Movement", "Exfiltration", "Impact"
            ],
            alert_timeline=[],
        )
        assert campaign.is_advanced_persistent

    def test_empty_input_returns_valid_object(self):
        from threaticap.analysis.campaign_reconstructor import KillChainReconstructor
        r = KillChainReconstructor()
        campaign = r.reconstruct(
            threat_id="t-003",
            mitre_technique_ids=[],
            tactic_names=[],
            alert_timeline=[],
        )
        assert campaign.phases_observed == 0
        assert campaign.kill_chain_completion == 0.0

    def test_narrative_contains_phase_info(self):
        from threaticap.analysis.campaign_reconstructor import KillChainReconstructor
        r = KillChainReconstructor()
        campaign = r.reconstruct(
            threat_id="t-004",
            mitre_technique_ids=["T1566", "T1041"],
            tactic_names=["Initial Access", "Exfiltration"],
            alert_timeline=[],
        )
        assert "kill chain" in campaign.narrative.lower() or "phase" in campaign.narrative.lower() or "observed" in campaign.narrative.lower()

    def test_objective_exfil(self):
        from threaticap.analysis.campaign_reconstructor import KillChainReconstructor, KillChainPhase
        r = KillChainReconstructor()
        campaign = r.reconstruct(
            threat_id="t-005",
            mitre_technique_ids=["T1041"],
            tactic_names=["Exfiltration"],
            alert_timeline=[],
        )
        assert "exfil" in campaign.adversary_objective.lower() or "theft" in campaign.adversary_objective.lower()


# ===========================================================================
# 3. Feedback-driven FP Learning
# ===========================================================================

class TestFeedbackFPLearning:

    def _make_store(self):
        from threaticap.correlation.fp_learning import FeedbackStore, FeedbackAwareFPFilter
        from threaticap.correlation.fp_filter import FalsePositiveFilter
        store = FeedbackStore()
        base = FalsePositiveFilter()
        fp_filter = FeedbackAwareFPFilter(base, store)
        return store, fp_filter

    def test_no_feedback_returns_heuristic(self):
        store, fp_filter = self._make_store()
        alert = make_alert(source_id="siem-01", source_reliability=0.9)
        reasons = []
        fp = fp_filter.compute_fp_probability([alert], 0.8, reasons)
        # No feedback yet — should be same as heuristic baseline
        assert 0.0 <= fp <= 1.0

    def test_fp_feedback_increases_fp_score(self):
        from threaticap.correlation.fp_learning import FeedbackStore, FeedbackAwareFPFilter
        from threaticap.correlation.fp_filter import FalsePositiveFilter
        from threaticap.models.feedback import AnalystFeedback, Verdict

        store = FeedbackStore()
        base = FalsePositiveFilter()
        fp_filter = FeedbackAwareFPFilter(base, store, learning_rate=0.4)

        alert = make_alert(source_id="noisy-siem", rule_id="RULE-999")

        # Inject 15 FP labels for this rule
        feedback_fp = AnalystFeedback(
            threat_id="threat-x", analyst_id="analyst-1", verdict=Verdict.FALSE_POSITIVE
        )
        for _ in range(15):
            store.record(feedback_fp, [alert])

        reasons = []
        fp = fp_filter.compute_fp_probability([alert], 0.8, reasons)
        # Should be elevated due to FP feedback
        assert fp > 0.15

    def test_tp_feedback_decreases_fp_score(self):
        from threaticap.correlation.fp_learning import FeedbackStore, FeedbackAwareFPFilter
        from threaticap.correlation.fp_filter import FalsePositiveFilter

        store = FeedbackStore()
        base = FalsePositiveFilter()
        fp_filter = FeedbackAwareFPFilter(base, store, learning_rate=0.4)

        alert = make_alert(source_id="reliable-source", rule_id="RULE-100")
        feedback_tp = AnalystFeedback(
            threat_id="threat-y", analyst_id="analyst-2", verdict=Verdict.TRUE_POSITIVE
        )
        for _ in range(15):
            store.record(feedback_tp, [alert])

        reasons_no_feedback: list[str] = []
        from threaticap.correlation.fp_filter import FalsePositiveFilter as BaseFPF
        base_score = BaseFPF().compute_fp_probability([alert], 0.6, reasons_no_feedback)

        reasons: list[str] = []
        adjusted = fp_filter.compute_fp_probability([alert], 0.6, reasons)
        # Adjusted score should be <= base (TP feedback reduces FP estimate)
        assert adjusted <= base_score + 0.05  # small tolerance

    def test_feedback_store_persistence(self):
        from threaticap.correlation.fp_learning import FeedbackStore
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "feedback.json"
            store = FeedbackStore(persist_path=path)
            alert = make_alert(source_id="siem-persist", rule_id="R-PERSIST")
            feedback = AnalystFeedback(
                threat_id="t1", analyst_id="a1", verdict=Verdict.FALSE_POSITIVE
            )
            store.record(feedback, [alert])
            assert path.exists()

            # Load from disk
            store2 = FeedbackStore(persist_path=path)
            stats = store2.get("rule:R-PERSIST")
            assert stats is not None
            assert stats.fp_count == 1


# ===========================================================================
# 4. Classification & Coalition Intelligence Handling
# ===========================================================================

class TestClassificationHandler:

    def _make_policy(self):
        from threaticap.classification.handler import (
            SharingPolicy, SharingPartner, TLPLevel, ClassificationLevel
        )
        partner = SharingPartner(
            partner_id="FVEY-AUS",
            name="Australia",
            nations=["AUS"],
            max_classification=ClassificationLevel.SECRET,
            allowed_tlp=[TLPLevel.CLEAR, TLPLevel.GREEN, TLPLevel.AMBER],
            stix_feed_enabled=True,
            requires_sanitisation=True,
        )
        return SharingPolicy(
            organisation_id="GBR-NCSC",
            home_nation="GBR",
            partners=[partner],
            sources_methods_protection=True,
            blocked_source_types=["HUMINT", "SIGINT"],
        ), partner

    def test_classification_label_shareable(self):
        from threaticap.classification.handler import (
            ClassificationLabel, ClassificationLevel, TLPLevel
        )
        _, partner = self._make_policy()
        label = ClassificationLabel(
            level=ClassificationLevel.OFFICIAL,
            tlp=TLPLevel.GREEN,
        )
        allowed, reason = label.is_shareable_with(partner)
        assert allowed, reason

    def test_classification_label_blocked_by_level(self):
        from threaticap.classification.handler import (
            ClassificationLabel, ClassificationLevel, TLPLevel, SharingPartner
        )
        partner = SharingPartner(
            partner_id="RESTRICTED-PARTNER",
            name="Restricted",
            nations=["XYZ"],
            max_classification=ClassificationLevel.OFFICIAL,
            allowed_tlp=[TLPLevel.GREEN],
        )
        label = ClassificationLabel(
            level=ClassificationLevel.TOP_SECRET,
            tlp=TLPLevel.GREEN,
        )
        allowed, reason = label.is_shareable_with(partner)
        assert not allowed
        assert "exceeds" in reason.lower()

    def test_noforn_blocks_sharing(self):
        from threaticap.classification.handler import (
            ClassificationLabel, ClassificationLevel, TLPLevel, HandlingCaveat, SharingPartner
        )
        partner = SharingPartner(
            partner_id="FOREIGN",
            name="Foreign Partner",
            nations=["FRA"],
            max_classification=ClassificationLevel.SECRET,
            allowed_tlp=[TLPLevel.AMBER],
        )
        label = ClassificationLabel(
            level=ClassificationLevel.SECRET,
            tlp=TLPLevel.AMBER,
            caveats=[HandlingCaveat.NOFORN],
        )
        allowed, reason = label.is_shareable_with(partner)
        assert not allowed
        assert "noforn" in reason.lower()

    def test_sanitiser_strips_raw_payload(self):
        from threaticap.classification.handler import IntelSanitiser, SharingPartner, TLPLevel

        policy, partner = self._make_policy()
        sanitiser = IntelSanitiser(policy)
        alert_data = {
            "alert_id": "a1",
            "source_type": "SIEM",
            "source_ref": "SRC-001",
            "source_id": "siem-01",
            "raw_payload": {"secret": "data"},
            "asset_context": {"ip_addresses": ["10.0.1.1"], "hostname": "host.internal"},
            "enrichment_tags": ["tag1"],
            "tlp": "TLP:GREEN",
        }
        sanitised = sanitiser.sanitise_alert(alert_data, partner)
        assert sanitised is not None
        assert "raw_payload" not in sanitised

    def test_sanitiser_blocks_humint(self):
        from threaticap.classification.handler import IntelSanitiser

        policy, partner = self._make_policy()
        sanitiser = IntelSanitiser(policy)
        alert_data = {
            "source_type": "HUMINT",
            "tlp": "TLP:GREEN",
        }
        result = sanitiser.sanitise_alert(alert_data, partner)
        assert result is None

    def test_stix_export_produces_bundle(self):
        from threaticap.classification.handler import (
            STIXExporter, IntelSanitiser, TLPLevel, ClassificationLabel, ClassificationLevel
        )
        policy, partner = self._make_policy()
        sanitiser = IntelSanitiser(policy)
        exporter = STIXExporter(policy, sanitiser)

        threat_data = {
            "threat_id": "t1",
            "title": "Test Threat",
            "description": "Test",
            "mitre_technique_ids": ["T1566"],
            "suspected_actor": None,
            "evidence_links": [],
            "audit_trail": [{"secret": "redact me"}],
        }
        obs = [{"type": "ipv4-addr", "value": "1.2.3.4"}]
        label = ClassificationLabel(
            level=ClassificationLevel.OFFICIAL,
            tlp=TLPLevel.GREEN,
        )
        bundle = exporter.export_threat(threat_data, obs, partner, label)
        assert bundle is not None
        assert bundle["type"] == "bundle"
        assert any(o["type"] == "indicator" for o in bundle["objects"])


# ===========================================================================
# 5. Cross-Domain / Air-Gapped Operation
# ===========================================================================

class TestCrossDomainTransfer:

    def test_same_domain_transfer_allowed(self):
        from threaticap.transfer.cross_domain import CrossDomainGuard, SecurityDomain
        guard = CrossDomainGuard()
        # Should not raise
        guard.check(SecurityDomain.HIGH, SecurityDomain.HIGH)

    def test_high_to_low_blocked_by_default(self):
        from threaticap.transfer.cross_domain import CrossDomainGuard, SecurityDomain, CrossDomainViolation
        guard = CrossDomainGuard(allow_high_to_low=False)
        with pytest.raises(CrossDomainViolation):
            guard.check(SecurityDomain.HIGH, SecurityDomain.LOW)

    def test_high_to_low_allowed_with_sanitisation(self):
        from threaticap.transfer.cross_domain import CrossDomainGuard, SecurityDomain
        guard = CrossDomainGuard(allow_high_to_low=True, require_sanitisation=True)
        # Should not raise when sanitised
        guard.check(SecurityDomain.HIGH, SecurityDomain.LOW, is_sanitised=True)

    def test_package_seal_and_verify(self):
        from threaticap.transfer.cross_domain import SecureTransferPackage, SecurityDomain
        pkg = SecureTransferPackage(
            source_domain=SecurityDomain.HIGH.value,
            target_domain=SecurityDomain.LOW.value,
            classification="SECRET",
            records=[{"alert_id": "a1", "title": "test"}],
        )
        key = b"test-hmac-key-32-bytes-long-here"
        pkg.seal(key)
        assert pkg.checksum != ""
        assert pkg.signature != ""
        assert pkg.verify(key)

    def test_tamper_detection(self):
        from threaticap.transfer.cross_domain import SecureTransferPackage, SecurityDomain
        pkg = SecureTransferPackage(
            source_domain=SecurityDomain.HIGH.value,
            target_domain=SecurityDomain.LOW.value,
            records=[{"data": "original"}],
        )
        pkg.seal()
        # Tamper with records after sealing
        pkg.records.append({"injected": "malicious"})
        assert not pkg.verify()

    def test_air_gapped_write_and_read(self):
        from threaticap.transfer.cross_domain import (
            SecureTransferPackage, AirGappedExportWriter, AirGappedImportReader, SecurityDomain
        )
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            pkg = SecureTransferPackage(
                source_domain=SecurityDomain.MEDIUM.value,
                target_domain=SecurityDomain.LOW.value,
                records=[{"threat_id": "t1", "score": 85.0}],
            )
            key = b"air-gap-hmac-key-32bytes-long!"
            written = AirGappedExportWriter().write(pkg, out_dir, key)
            assert written.exists()
            assert written.suffix == ".tigpkg"

            # Read back
            reader = AirGappedImportReader()
            loaded = reader.read(written, key)
            assert loaded.package_id == pkg.package_id
            assert len(loaded.records) == 1

    def test_disconnected_mode_manager(self):
        from threaticap.transfer.cross_domain import DisconnectedModeManager, ConnectivityState
        mgr = DisconnectedModeManager()
        assert mgr.state == ConnectivityState.CONNECTED
        mgr.set_disconnected()
        assert not mgr.is_online
        bundle = {"type": "bundle", "id": "bundle--x"}
        mgr.queue_stix_bundle(bundle)
        assert mgr.pending_count == 1
        flushed = mgr.flush_pending()
        assert len(flushed) == 1
        assert mgr.pending_count == 0


# ===========================================================================
# 6. MISP Connector
# ===========================================================================

class TestMISPConnector:

    def _make_misp_event(self):
        return {
            "Event": {
                "id": "123",
                "uuid": "abc-123",
                "info": "APT29 phishing campaign",
                "threat_level_id": "1",
                "timestamp": "1700000000",
                "analysis": "2",
                "Attribute": [
                    {
                        "type": "ip-dst",
                        "value": "192.168.1.100",
                        "to_ids": True,
                        "comment": "C2 IP",
                    },
                    {
                        "type": "sha256",
                        "value": "a" * 64,
                        "to_ids": True,
                        "comment": "malware hash",
                    },
                ],
                "Galaxy": [],
                "Tag": [{"name": "tlp:amber"}],
            }
        }

    def test_misp_normalisation(self):
        from threaticap.ingestion.connectors.misp_connector import MISPConnector
        connector = MISPConnector(url="https://misp.example.mil", api_key="test")
        events = [self._make_misp_event()]
        alerts = connector.normalise(events)
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.severity.value == "CRITICAL"
        assert len(alert.observables) == 2
        assert alert.tlp == "TLP:AMBER"

    def test_misp_observable_types(self):
        from threaticap.ingestion.connectors.misp_connector import MISPConnector
        connector = MISPConnector(url="https://misp.example.mil")
        event = {"Event": {
            "id": "1", "uuid": "x", "info": "test", "threat_level_id": "2",
            "timestamp": "1700000000", "analysis": "1",
            "Attribute": [
                {"type": "domain", "value": "evil.com", "to_ids": True, "comment": ""},
                {"type": "url", "value": "http://evil.com/payload", "to_ids": False, "comment": ""},
                {"type": "email-src", "value": "attacker@evil.com", "to_ids": True, "comment": ""},
            ],
            "Galaxy": [], "Tag": [],
        }}
        alerts = connector.normalise([event])
        assert len(alerts) == 1
        obs_types = {o.type.value for o in alerts[0].observables}
        assert "domain-name" in obs_types
        assert "url" in obs_types
        assert "email-addr" in obs_types


# ===========================================================================
# 7. Commander BLUF Renderer
# ===========================================================================

class TestCommanderBluf:

    def _make_report(self):
        from threaticap.models.bluf import BlufReport, ConfidenceLevel, EvidenceSummary, ActionItem
        return BlufReport(
            threat_id="t1",
            bottom_line="HIGH-priority threat detected from SIEM.",
            priority_tier="HIGH",
            priority_score=72.5,
            confidence_level=ConfidenceLevel.MODERATE,
            tlp="TLP:AMBER",
            alert_count=3,
            source_types=["SIEM", "EDR"],
            time_window="2024-01-01T10:00Z to 2024-01-01T11:30Z (1h 30m)",
            affected_assets=["dc01.corp.internal"],
            mitre_technique_ids=["T1059", "T1021"],
            mitre_tactic_names=["Execution", "Lateral Movement"],
            immediate_actions=[
                ActionItem(priority=1, action="Block C2 IP", owner="NOC", timeframe="15 mins"),
            ],
            investigation_steps=[],
            degraded_missions=["Op Overlord"],
            mission_impact_multiplier=2.5,
            campaign_narrative="Observed kill chain: Execution → Lateral Movement. 50% complete.",
        )

    def test_commander_format(self):
        from threaticap.reporting.commander_bluf import CommanderBlufRenderer, OutputRole
        renderer = CommanderBlufRenderer()
        report = self._make_report()
        text = renderer.render(
            report, role=OutputRole.COMMANDER,
            degraded_missions=["Op Overlord"],
            classification_banner="OFFICIAL-SENSITIVE",
        )
        assert "BOTTOM LINE" in text
        assert "RECOMMENDED COMMAND DECISIONS" in text
        assert "Op Overlord" in text
        assert "OFFICIAL-SENSITIVE" in text

    def test_watch_officer_format(self):
        from threaticap.reporting.commander_bluf import CommanderBlufRenderer, OutputRole
        renderer = CommanderBlufRenderer()
        report = self._make_report()
        text = renderer.render(report, role=OutputRole.WATCH_OFFICER)
        assert "SITREP" in text
        assert "PRIORITY: HIGH" in text

    def test_intel_officer_format(self):
        from threaticap.reporting.commander_bluf import CommanderBlufRenderer, OutputRole
        renderer = CommanderBlufRenderer()
        report = self._make_report()
        text = renderer.render(report, role=OutputRole.INTEL_OFFICER)
        assert "KEY JUDGEMENTS" in text
        assert "CAMPAIGN ANALYSIS" in text
        assert "MITRE ATT&CK" in text

    def test_coalition_format_sanitised(self):
        from threaticap.reporting.commander_bluf import CommanderBlufRenderer, OutputRole
        renderer = CommanderBlufRenderer()
        report = self._make_report()
        text = renderer.render(report, role=OutputRole.COALITION)
        assert "TLP:AMBER" in text
        # Should not contain detailed mission context
        assert "Op Overlord" not in text

    def test_critical_tier_produces_escalate_decision(self):
        from threaticap.reporting.commander_bluf import CommanderBlufRenderer, OutputRole
        from threaticap.models.bluf import BlufReport, ConfidenceLevel
        renderer = CommanderBlufRenderer()
        report = BlufReport(
            threat_id="t2",
            bottom_line="CRITICAL threat.",
            priority_tier="CRITICAL",
            priority_score=91.0,
            confidence_level=ConfidenceLevel.HIGH,
            tlp="TLP:RED",
            alert_count=5,
        )
        text = renderer.render(report, role=OutputRole.COMMANDER)
        assert "ESCALATE" in text or "CRITICAL" in text


# ===========================================================================
# 8. Feed Quality Management
# ===========================================================================

class TestFeedQualityManager:

    def test_decay_halves_at_half_life(self):
        from threaticap.intel_quality.feed_quality import ConfidenceDecayEngine
        engine = ConfidenceDecayEngine(half_life_days=30.0)
        decayed = engine.decay(1.0, 30.0)
        assert abs(decayed - 0.5) < 0.01  # Should be ≈ 0.5

    def test_decay_floor(self):
        from threaticap.intel_quality.feed_quality import ConfidenceDecayEngine
        engine = ConfidenceDecayEngine(half_life_days=30.0, min_confidence=0.05)
        very_old = engine.decay(1.0, 10000.0)
        assert very_old == 0.05

    def test_staleness_detection(self):
        from threaticap.intel_quality.feed_quality import ConfidenceDecayEngine
        engine = ConfidenceDecayEngine(max_staleness_days=90.0)
        assert engine.is_stale(91.0)
        assert not engine.is_stale(89.0)

    def test_source_quality_tracking(self):
        from threaticap.intel_quality.feed_quality import FeedQualityManager
        qm = FeedQualityManager(min_samples_for_rating=3)
        # Record 5 FP verdicts for source
        for _ in range(5):
            qm.record_verdict("bad-source", is_true_positive=False)
        weight = qm.get_source_weight("bad-source")
        # Weight should be reduced
        assert weight < 0.8

    def test_good_source_maintains_weight(self):
        from threaticap.intel_quality.feed_quality import FeedQualityManager
        qm = FeedQualityManager(min_samples_for_rating=3)
        for _ in range(10):
            qm.record_verdict("good-source", is_true_positive=True)
        weight = qm.get_source_weight("good-source")
        assert weight >= 0.8

    def test_indicator_record_created_on_ingest(self):
        from threaticap.intel_quality.feed_quality import FeedQualityManager
        qm = FeedQualityManager()
        alert_data = {
            "source_id": "siem-test",
            "source_type": "SIEM",
            "observables": [
                {"type": "ipv4-addr", "value": "1.2.3.4", "confidence": 0.9}
            ],
        }
        qm.record_alert_ingested(alert_data)
        assert not qm.is_indicator_stale("ipv4-addr", "1.2.3.4")

    def test_quality_report_sorted(self):
        from threaticap.intel_quality.feed_quality import FeedQualityManager
        qm = FeedQualityManager(min_samples_for_rating=1)
        qm.record_verdict("high-quality", is_true_positive=True)
        qm.record_verdict("low-quality", is_true_positive=False)
        report = qm.get_source_quality_report()
        # Should be sorted by reliability descending
        assert len(report) >= 2
        reliabilities = [r["current_reliability"] for r in report]
        assert reliabilities == sorted(reliabilities, reverse=True)

    def test_persist_and_reload(self):
        from threaticap.intel_quality.feed_quality import FeedQualityManager
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "quality.json"
            qm = FeedQualityManager(persist_path=path, min_samples_for_rating=1)
            qm.record_verdict("src-persisted", is_true_positive=True)
            assert path.exists()
            # Reload
            qm2 = FeedQualityManager(persist_path=path)
            w = qm2.get_source_weight("src-persisted")
            assert w > 0.5

    def test_admiralty_grade_assignment(self):
        from threaticap.intel_quality.feed_quality import SourceQualityRecord, SourceReliabilityGrade
        record = SourceQualityRecord(source_id="test", current_reliability=0.95)
        assert record.to_admiralty_grade() == SourceReliabilityGrade.A
        # reliability 0.20 exactly → E (border of the E ≥ 0.20 threshold)
        record2 = SourceQualityRecord(source_id="test2", current_reliability=0.20)
        assert record2.to_admiralty_grade() == SourceReliabilityGrade.E
        # reliability below 0.20 → F
        record3 = SourceQualityRecord(source_id="test3", current_reliability=0.10)
        assert record3.to_admiralty_grade() == SourceReliabilityGrade.F


# ===========================================================================
# Integration: Full pipeline with capabilities 1 + 2 + 8
# ===========================================================================

class TestPipelineIntegration:

    def test_pipeline_produces_campaign_data(self):
        from threaticap.pipeline import ThreatPipeline
        pipeline = ThreatPipeline()

        alerts = [
            make_alert(
                alert_id=f"a{i}",
                source_ref=f"s{i}",
                source_type=AlertSource.SIEM,
                severity=AlertSeverity.HIGH,
                observables=[make_observable(ObservableType.IP_ADDRESS, "10.1.2.3")],
                mitre_technique_ids=["T1566", "T1021"],
            )
            for i in range(3)
        ]
        result = pipeline.run(alerts)
        assert result.alerts_ingested == 3
        assert result.threats_created > 0
        # All reports should have adversary_objective field
        for report in result.reports:
            assert hasattr(report, "adversary_objective")
            assert hasattr(report, "campaign_narrative")

    def test_pipeline_with_mission_context(self):
        from threaticap.pipeline import ThreatPipeline
        from threaticap.models.mission import Mission, MissionContext, MissionReadiness, AssetMissionRole

        role = AssetMissionRole(
            asset_id="ASSET-001",
            mission_id="M1",
            role="C2",
            impact_weight=2.0,
            degradation_threshold=0.3,
        )
        mission = Mission(
            mission_id="M1",
            name="Active Op",
            readiness=MissionReadiness.ACTIVE,
            priority_rank=1,
            asset_roles=[role],
        )
        ctx = MissionContext(missions=[mission])
        pipeline = ThreatPipeline(mission_context=ctx)

        alert = make_alert(
            source_ref="s1",
            severity=AlertSeverity.CRITICAL,
            asset_context=AssetContext(asset_id="ASSET-001", criticality=0.9),
            mitre_technique_ids=["T1059"],
        )
        result = pipeline.run([alert])
        assert result.alerts_ingested == 1
        if result.scores:
            score = next(iter(result.scores.values()))
            assert score.mission_impact_multiplier >= 1.0

    def test_pipeline_feed_quality_accessible(self):
        from threaticap.pipeline import ThreatPipeline
        pipeline = ThreatPipeline()
        # Feed quality manager should be accessible
        qm = pipeline.feed_quality
        assert qm is not None
        report = qm.get_source_quality_report()
        assert isinstance(report, list)
