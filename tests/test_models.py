"""
Tests for core Pydantic models.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from threaticap.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus, Observable, ObservableType
from threaticap.models.correlated_threat import CorrelatedThreat, ThreatStatus, CorrelationMethod
from threaticap.models.priority import PriorityScore, PriorityTier, ScoreComponent
from threaticap.models.bluf import BlufReport, ConfidenceLevel
from threaticap.models.audit import AuditRecord, AuditEventType


class TestAlertModel:

    def test_valid_alert_creation(self):
        alert = Alert(
            source_ref="SRC-001",
            source_type=AlertSource.SIEM,
            source_id="siem-01",
            event_time=datetime.now(timezone.utc),
            severity=AlertSeverity.HIGH,
            title="Test Alert",
        )
        assert alert.alert_id  # UUID generated
        assert alert.schema_version == "1.0"
        assert alert.status == AlertStatus.INGESTED

    def test_alert_requires_title(self):
        with pytest.raises(ValidationError):
            Alert(
                source_ref="SRC-001",
                source_type=AlertSource.SIEM,
                source_id="siem-01",
                event_time=datetime.now(timezone.utc),
                severity=AlertSeverity.HIGH,
                title="",  # empty string → min_length=1 violation
            )

    def test_alert_confidence_bounds(self):
        with pytest.raises(ValidationError):
            Alert(
                source_ref="SRC-001",
                source_type=AlertSource.SIEM,
                source_id="siem-01",
                event_time=datetime.now(timezone.utc),
                severity=AlertSeverity.HIGH,
                title="Test",
                confidence=1.5,  # exceeds max=1.0
            )

    def test_alert_invalid_mitre_id(self):
        with pytest.raises(ValidationError):
            Alert(
                source_ref="SRC-001",
                source_type=AlertSource.SIEM,
                source_id="siem-01",
                event_time=datetime.now(timezone.utc),
                severity=AlertSeverity.HIGH,
                title="Test",
                mitre_technique_ids=["INVALID-ID"],
            )

    def test_alert_valid_sub_technique(self):
        alert = Alert(
            source_ref="SRC-001",
            source_type=AlertSource.SIEM,
            source_id="siem-01",
            event_time=datetime.now(timezone.utc),
            severity=AlertSeverity.HIGH,
            title="Test",
            mitre_technique_ids=["T1059.001"],
        )
        assert "T1059.001" in alert.mitre_technique_ids

    def test_naive_datetime_gets_utc(self):
        """Naive datetimes should be coerced to UTC."""
        naive_dt = datetime(2024, 1, 15, 2, 0, 0)  # no tzinfo
        alert = Alert(
            source_ref="SRC-001",
            source_type=AlertSource.SIEM,
            source_id="siem-01",
            event_time=naive_dt,
            severity=AlertSeverity.HIGH,
            title="Test",
        )
        assert alert.event_time.tzinfo is not None

    def test_alert_model_copy(self):
        """model_copy preserves all fields and applies updates."""
        alert = Alert(
            source_ref="SRC-001",
            source_type=AlertSource.SIEM,
            source_id="siem-01",
            event_time=datetime.now(timezone.utc),
            severity=AlertSeverity.HIGH,
            title="Original",
        )
        updated = alert.model_copy(update={"title": "Updated", "status": AlertStatus.CORRELATED})
        assert updated.title == "Updated"
        assert updated.status == AlertStatus.CORRELATED
        assert updated.alert_id == alert.alert_id  # ID preserved


class TestObservableModel:

    def test_observable_frozen(self):
        obs = Observable(type=ObservableType.IP_ADDRESS, value="10.0.0.1")
        with pytest.raises(Exception):
            obs.value = "changed"  # frozen model

    def test_observable_confidence_bounds(self):
        with pytest.raises(ValidationError):
            Observable(type=ObservableType.IP_ADDRESS, value="10.0.0.1", confidence=1.5)

    def test_observable_empty_value(self):
        with pytest.raises(ValidationError):
            Observable(type=ObservableType.IP_ADDRESS, value="")


class TestCorrelatedThreatModel:

    def test_basic_creation(self):
        threat = CorrelatedThreat(
            title="Test Threat",
            correlation_confidence=0.75,
        )
        assert threat.threat_id
        assert threat.status == ThreatStatus.OPEN

    def test_audit_trail_appended(self):
        threat = CorrelatedThreat(
            title="Test Threat",
            correlation_confidence=0.75,
            audit_trail=[{"event": "created", "ts": "2024-01-01"}]
        )
        assert len(threat.audit_trail) == 1


class TestPriorityScoreModel:

    def test_score_bounds(self):
        with pytest.raises(ValidationError):
            PriorityScore(
                threat_id="t1",
                severity_score=110.0,  # > 100
                confidence_score=50.0,
                source_reliability_score=50.0,
                asset_criticality_score=50.0,
                temporal_urgency_score=50.0,
                final_score=50.0,
                priority_tier=PriorityTier.MEDIUM,
            )

    def test_valid_score(self):
        ps = PriorityScore(
            threat_id="t1",
            severity_score=75.0,
            confidence_score=60.0,
            source_reliability_score=80.0,
            asset_criticality_score=90.0,
            temporal_urgency_score=70.0,
            final_score=74.5,
            priority_tier=PriorityTier.HIGH,
        )
        assert ps.priority_tier == PriorityTier.HIGH


class TestBlufReportModel:

    def test_to_text_contains_bottom_line(self):
        report = BlufReport(
            threat_id="t1",
            bottom_line="Critical threat detected. Immediate action required.",
            priority_tier="CRITICAL",
            priority_score=87.5,
            confidence_level=ConfidenceLevel.HIGH,
            alert_count=4,
        )
        text = report.to_text()
        assert "BOTTOM LINE" in text
        assert "Critical threat detected" in text
        assert "CRITICAL" in text
        assert "87.5" in text


class TestAuditRecordModel:

    def test_audit_record_frozen(self):
        record = AuditRecord(
            event_type=AuditEventType.ALERT_INGESTED,
            summary="Test event",
        )
        with pytest.raises(Exception):
            record.summary = "modified"  # frozen model

    def test_audit_record_fields(self):
        record = AuditRecord(
            event_type=AuditEventType.CORRELATION_CREATED,
            component="CorrelationEngine",
            threat_id="t-001",
            summary="Threat correlated",
        )
        assert record.audit_id
        assert record.timestamp is not None
        assert record.component == "CorrelationEngine"
