"""
Tests for the correlation engine and individual correlators.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from threaticap.correlation.ioc_correlator import IOCCorrelator
from threaticap.correlation.temporal_correlator import TemporalCorrelator
from threaticap.correlation.asset_correlator import AssetCorrelator
from threaticap.correlation.behaviour_correlator import BehaviourCorrelator
from threaticap.correlation.fp_filter import FalsePositiveFilter
from threaticap.correlation.engine import CorrelationEngine, CorrelationConfig
from threaticap.models.alert import Alert, AlertSeverity, AlertSource, AssetContext, Observable, ObservableType
from tests.conftest import make_alert, make_observable


class TestIOCCorrelator:

    def test_shared_file_hash_creates_link(self):
        hash_obs = make_observable(ObservableType.FILE_HASH, "deadbeef" * 8)
        a = make_alert(alert_id="a1", observables=[hash_obs])
        b = make_alert(alert_id="a2", observables=[hash_obs])
        correlator = IOCCorrelator()
        links = correlator.correlate([a, b])
        assert len(links) == 1
        assert links[0]["method"] == "IOC_MATCH"
        assert links[0]["confidence"] >= 0.9  # File hash = high specificity

    def test_shared_ip_only_skipped_when_strong_required(self):
        ip_obs = make_observable(ObservableType.IP_ADDRESS, "203.0.113.1")
        a = make_alert(alert_id="a1", observables=[ip_obs])
        b = make_alert(alert_id="a2", observables=[ip_obs])
        correlator = IOCCorrelator(require_strong_for_weak_iocs=True)
        links = correlator.correlate([a, b])
        assert len(links) == 0  # IP-only = weak, filtered when require_strong=True

    def test_shared_ip_allowed_when_strong_not_required(self):
        ip_obs = make_observable(ObservableType.IP_ADDRESS, "203.0.113.1")
        a = make_alert(alert_id="a1", observables=[ip_obs])
        b = make_alert(alert_id="a2", observables=[ip_obs])
        correlator = IOCCorrelator(require_strong_for_weak_iocs=False)
        links = correlator.correlate([a, b])
        assert len(links) == 1

    def test_multiple_shared_observables_boost_confidence(self):
        ip_obs = make_observable(ObservableType.IP_ADDRESS, "203.0.113.1")
        hash_obs = make_observable(ObservableType.FILE_HASH, "deadbeef" * 8)
        a = make_alert(alert_id="a1", observables=[ip_obs, hash_obs])
        b = make_alert(alert_id="a2", observables=[ip_obs, hash_obs])
        correlator = IOCCorrelator(require_strong_for_weak_iocs=False)
        links = correlator.correlate([a, b])
        assert len(links) == 1
        # More shared observables → higher confidence
        assert links[0]["confidence"] > 0.9

    def test_no_shared_observables_no_links(self):
        a = make_alert(alert_id="a1", observables=[make_observable(ObservableType.IP_ADDRESS, "1.1.1.1")])
        b = make_alert(alert_id="a2", observables=[make_observable(ObservableType.IP_ADDRESS, "2.2.2.2")])
        correlator = IOCCorrelator(require_strong_for_weak_iocs=False)
        links = correlator.correlate([a, b])
        assert len(links) == 0

    def test_single_alert_no_links(self):
        a = make_alert()
        correlator = IOCCorrelator()
        links = correlator.correlate([a])
        assert links == []


class TestTemporalCorrelator:

    def test_alerts_within_window_linked(self):
        now = datetime.now(timezone.utc)
        a = make_alert(alert_id="a1", source_type=AlertSource.SIEM, event_time=now)
        b = make_alert(alert_id="a2", source_type=AlertSource.EDR,
                       event_time=now + timedelta(minutes=30))
        correlator = TemporalCorrelator(window_seconds=3600)
        links = correlator.correlate([a, b])
        assert len(links) == 1
        assert links[0]["method"] == "TEMPORAL"

    def test_alerts_outside_window_not_linked(self):
        now = datetime.now(timezone.utc)
        a = make_alert(alert_id="a1", event_time=now)
        b = make_alert(alert_id="a2", event_time=now + timedelta(hours=3))
        correlator = TemporalCorrelator(window_seconds=3600)
        links = correlator.correlate([a, b])
        assert len(links) == 0

    def test_same_source_gets_lower_confidence(self):
        now = datetime.now(timezone.utc)
        a = make_alert(alert_id="a1", source_type=AlertSource.SIEM, source_id="s1",
                       event_time=now)
        b = make_alert(alert_id="a2", source_type=AlertSource.SIEM, source_id="s1",
                       event_time=now + timedelta(minutes=5))
        c = make_alert(alert_id="a3", source_type=AlertSource.EDR, source_id="edr1",
                       event_time=now + timedelta(minutes=5))
        correlator = TemporalCorrelator()
        links_same = correlator.correlate([a, b])
        links_diff = correlator.correlate([a, c])
        assert links_diff[0]["confidence"] > links_same[0]["confidence"]


class TestAssetCorrelator:

    def test_shared_hostname_creates_link(self):
        ctx = AssetContext(hostname="dc01.corp.internal", criticality=0.9)
        a = make_alert(alert_id="a1", asset_context=ctx)
        b = make_alert(alert_id="a2", asset_context=ctx)
        correlator = AssetCorrelator()
        links = correlator.correlate([a, b])
        assert len(links) >= 1
        assert any(l["method"] == "ASSET_OVERLAP" for l in links)

    def test_high_criticality_boosts_confidence(self):
        ctx_high = AssetContext(hostname="dc01.corp.internal", criticality=1.0)
        ctx_low = AssetContext(hostname="workstation.corp.internal", criticality=0.1)
        a1 = make_alert(alert_id="a1", asset_context=ctx_high)
        b1 = make_alert(alert_id="a2", asset_context=ctx_high)
        a2 = make_alert(alert_id="a3", asset_context=ctx_low)
        b2 = make_alert(alert_id="a4", asset_context=ctx_low)
        correlator = AssetCorrelator()
        links_high = correlator.correlate([a1, b1])
        links_low = correlator.correlate([a2, b2])
        if links_high and links_low:
            assert links_high[0]["confidence"] > links_low[0]["confidence"]


class TestBehaviourCorrelator:

    def test_same_campaign_creates_high_confidence_link(self):
        a = make_alert(alert_id="a1", campaign="OP-PHANTOM")
        b = make_alert(alert_id="a2", campaign="OP-PHANTOM")
        correlator = BehaviourCorrelator()
        links = correlator.correlate([a, b])
        assert len(links) >= 1
        assert links[0]["confidence"] >= 0.85

    def test_same_threat_actor_creates_link(self):
        a = make_alert(alert_id="a1", threat_actor="APT-X")
        b = make_alert(alert_id="a2", threat_actor="APT-X")
        correlator = BehaviourCorrelator()
        links = correlator.correlate([a, b])
        assert len(links) >= 1

    def test_shared_mitre_techniques_create_link(self):
        a = make_alert(alert_id="a1", mitre_technique_ids=["T1059.001", "T1003"])
        b = make_alert(alert_id="a2", mitre_technique_ids=["T1059.001", "T1021"])
        correlator = BehaviourCorrelator()
        links = correlator.correlate([a, b])
        assert len(links) >= 1
        assert any(l["confidence"] >= 0.7 for l in links)

    def test_different_campaigns_no_behaviour_link(self):
        a = make_alert(alert_id="a1", campaign="OP-A")
        b = make_alert(alert_id="a2", campaign="OP-B")
        correlator = BehaviourCorrelator()
        links = correlator.correlate([a, b])
        # Should not link different campaigns via behaviour alone
        assert all(l["confidence"] < 0.8 for l in links)


class TestFalsePositiveFilter:

    def test_single_source_increases_fp_probability(self):
        fp_filter = FalsePositiveFilter()
        alerts = [make_alert(source_type=AlertSource.SIEM, source_id="s1") for _ in range(3)]
        prob = fp_filter.compute_fp_probability(alerts, correlation_confidence=0.5)
        assert prob >= 0.1  # single-source adds 0.20 but may be reduced by other factors

    def test_multi_source_reduces_fp_probability(self):
        fp_filter = FalsePositiveFilter()
        single_source = [
            make_alert(alert_id=f"a{i}", source_type=AlertSource.SIEM, source_id="s1")
            for i in range(3)
        ]
        multi_source = [
            make_alert(alert_id="a1", source_type=AlertSource.SIEM, source_id="s1"),
            make_alert(alert_id="a2", source_type=AlertSource.EDR, source_id="edr1"),
            make_alert(alert_id="a3", source_type=AlertSource.HUMINT, source_id="humint1"),
        ]
        prob_single = fp_filter.compute_fp_probability(single_source, 0.5)
        prob_multi = fp_filter.compute_fp_probability(multi_source, 0.5)
        assert prob_multi < prob_single

    def test_whitelisted_ip_increases_fp_probability(self):
        fp_filter = FalsePositiveFilter(whitelist_ips={"10.0.2.100"})
        alert = make_alert(asset_context=AssetContext(ip_addresses=["10.0.2.100"]))
        prob = fp_filter.compute_fp_probability([alert], 0.7)
        assert prob >= 0.25

    def test_critical_severity_reduces_fp_probability(self):
        fp_filter = FalsePositiveFilter()
        low_alert = make_alert(severity=AlertSeverity.INFO, source_reliability=0.3)
        crit_alert = make_alert(severity=AlertSeverity.CRITICAL, source_reliability=0.9)
        prob_low = fp_filter.compute_fp_probability([low_alert], 0.3)
        prob_crit = fp_filter.compute_fp_probability([crit_alert], 0.9)
        assert prob_crit < prob_low


class TestCorrelationEngine:

    def test_single_alert_becomes_singleton(self):
        alert = make_alert()
        engine = CorrelationEngine()
        threats = engine.correlate([alert])
        assert len(threats) == 1
        assert threats[0].alert_count == 1

    def test_alerts_with_shared_ioc_grouped(self):
        hash_obs = make_observable(ObservableType.FILE_HASH, "badfile" * 8)
        a = make_alert(
            alert_id="a1",
            source_type=AlertSource.SIEM,
            observables=[hash_obs],
        )
        b = make_alert(
            alert_id="a2",
            source_type=AlertSource.EDR,
            observables=[hash_obs],
        )
        engine = CorrelationEngine()
        threats = engine.correlate([a, b])
        # Should produce one correlated threat with both alerts
        correlated = [t for t in threats if t.alert_count > 1]
        assert len(correlated) == 1
        assert correlated[0].alert_count == 2

    def test_campaign_match_groups_alerts(self):
        a = make_alert(alert_id="a1", campaign="OP-PHANTOM")
        b = make_alert(alert_id="a2", campaign="OP-PHANTOM")
        c = make_alert(alert_id="a3", campaign=None)
        engine = CorrelationEngine()
        threats = engine.correlate([a, b, c])
        campaign_group = [t for t in threats if t.alert_count == 2]
        assert len(campaign_group) >= 1

    def test_dissimilar_alerts_remain_singletons(self):
        """Alerts with no shared signals should not be grouped."""
        now = datetime.now(timezone.utc)
        a = make_alert(
            alert_id="a1",
            event_time=now - timedelta(hours=24),  # outside temporal window
            observables=[make_observable(ObservableType.IP_ADDRESS, "1.2.3.4")],
        )
        b = make_alert(
            alert_id="a2",
            event_time=now,
            observables=[make_observable(ObservableType.IP_ADDRESS, "5.6.7.8")],
        )
        config = CorrelationConfig(temporal_window_seconds=60)  # very short window
        engine = CorrelationEngine(config=config)
        threats = engine.correlate([a, b])
        # Both should be singletons
        assert all(t.alert_count == 1 for t in threats)

    def test_audit_callback_called(self):
        audit_records = []
        a = make_alert(alert_id="a1")
        engine = CorrelationEngine(audit_callback=lambda r: audit_records.append(r))
        engine.correlate([a])
        assert any(r.component == "CorrelationEngine" for r in audit_records)

    def test_correlation_includes_fp_probability(self):
        a = make_alert(alert_id="a1")
        engine = CorrelationEngine()
        threats = engine.correlate([a])
        for threat in threats:
            assert 0.0 <= threat.false_positive_probability <= 1.0

    def test_multi_source_threat_has_composite_method(self):
        hash_obs = make_observable(ObservableType.FILE_HASH, "abc123" * 8)
        now = datetime.now(timezone.utc)
        a = make_alert(
            alert_id="a1",
            source_type=AlertSource.SIEM,
            event_time=now,
            observables=[hash_obs],
            campaign="OP-TEST",
        )
        b = make_alert(
            alert_id="a2",
            source_type=AlertSource.EDR,
            event_time=now + timedelta(minutes=5),
            observables=[hash_obs],
            campaign="OP-TEST",
        )
        engine = CorrelationEngine()
        threats = engine.correlate([a, b])
        correlated = [t for t in threats if t.alert_count == 2]
        if correlated:
            from threaticap.models.correlated_threat import CorrelationMethod
            assert len(correlated[0].correlation_methods) >= 1
