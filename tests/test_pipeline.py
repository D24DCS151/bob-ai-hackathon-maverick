"""
End-to-end pipeline integration test using realistic sample data.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from threaticap.pipeline import ThreatPipeline
from threaticap.ingestion.pipeline import IngestionPipeline, IngestionConfig
from threaticap.ingestion.base_connector import ConnectorConfig
from threaticap.ingestion.connectors.siem_connector import SiemConnector
from threaticap.ingestion.connectors.edr_connector import EdrConnector
from threaticap.ingestion.connectors.intel_report_connector import IntelReportConnector


SAMPLE_DATA_DIR = Path(__file__).parent.parent / "data" / "sample"
CONFIG_FILE = Path(__file__).parent.parent / "config" / "config.yaml"


@pytest.mark.skipif(
    not SAMPLE_DATA_DIR.exists(),
    reason="Sample data directory not found"
)
class TestEndToEndPipeline:

    def _build_pipeline_with_sample_data(self) -> tuple[ThreatPipeline, list]:
        ingest = IngestionPipeline(config=IngestionConfig())

        siem_file = SAMPLE_DATA_DIR / "siem_alerts.json"
        edr_file = SAMPLE_DATA_DIR / "edr_events.json"
        intel_file = SAMPLE_DATA_DIR / "intel_reports.json"

        if siem_file.exists():
            ingest.register_connector(SiemConnector(ConnectorConfig(
                connector_id="siem-sample",
                source_type="SIEM",
                source_reliability=0.85,
                extra={"mode": "file", "file_path": str(siem_file)},
            )))
        if edr_file.exists():
            ingest.register_connector(EdrConnector(ConnectorConfig(
                connector_id="edr-sample",
                source_type="EDR",
                source_reliability=0.9,
                extra={"mode": "file", "file_path": str(edr_file)},
            )))
        if intel_file.exists():
            ingest.register_connector(IntelReportConnector(ConnectorConfig(
                connector_id="intel-sample",
                source_type="HUMINT",
                source_reliability=0.75,
                extra={
                    "mode": "file",
                    "file_path": str(intel_file),
                    "source_subtype": "humint",
                },
            )))

        alerts = ingest.run_batch()
        config_path = CONFIG_FILE if CONFIG_FILE.exists() else None
        pipeline = (
            ThreatPipeline.from_config_file(config_path)
            if config_path else ThreatPipeline()
        )
        return pipeline, alerts

    def test_pipeline_processes_sample_data(self):
        pipeline, alerts = self._build_pipeline_with_sample_data()
        assert len(alerts) > 0, "Sample data should produce at least 1 alert"
        result = pipeline.run(alerts)
        assert result.alerts_ingested == len(alerts)
        assert result.threats_created > 0

    def test_campaign_alerts_correlated(self):
        """APT-X OP-PHANTOM-2024 alerts should be grouped into a single threat."""
        pipeline, alerts = self._build_pipeline_with_sample_data()
        result = pipeline.run(alerts)
        campaign_threat = [
            t for t in result.threats
            if t.campaign == "OP-PHANTOM-2024"
        ]
        # All OP-PHANTOM alerts share IOCs + campaign → should correlate
        assert len(campaign_threat) > 0
        if campaign_threat:
            biggest = max(campaign_threat, key=lambda t: t.alert_count)
            assert biggest.alert_count >= 2

    def test_bluf_reports_generated(self):
        pipeline, alerts = self._build_pipeline_with_sample_data()
        result = pipeline.run(alerts)
        assert result.reports_generated > 0
        for report in result.reports:
            assert len(report.bottom_line) > 20
            assert report.priority_tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_critical_threats_rank_highest(self):
        pipeline, alerts = self._build_pipeline_with_sample_data()
        result = pipeline.run(alerts)
        if result.threats and result.scores:
            scores = [
                result.scores[t.threat_id].final_score
                for t in result.threats
                if t.threat_id in result.scores
            ]
            # Scores should be in descending order (result.threats is sorted)
            assert scores == sorted(scores, reverse=True)

    def test_false_positive_alerts_have_low_score(self):
        """The low-severity 'antivirus update' alert should score LOW."""
        pipeline, alerts = self._build_pipeline_with_sample_data()
        result = pipeline.run(alerts)
        # Find the FP singleton threat
        fp_threats = [
            (t, result.scores.get(t.threat_id))
            for t in result.threats
            if t.alert_count == 1 and t.max_severity in ("INFO", "LOW")
            and result.scores.get(t.threat_id) is not None
        ]
        for threat, score in fp_threats:
            assert score.priority_tier in ("LOW", "MEDIUM"), (
                f"Expected FP threat to score LOW/MEDIUM, got {score.priority_tier}"
            )

    def test_audit_trail_populated(self):
        pipeline, alerts = self._build_pipeline_with_sample_data()
        result = pipeline.run(alerts)
        audit_records = pipeline.audit_repo.list_recent(limit=1000)
        assert len(audit_records) > 0
        event_types = {r.event_type.value for r in audit_records}
        assert "CORRELATION_CREATED" in event_types
        assert "PRIORITY_SCORED" in event_types
        assert "BLUF_GENERATED" in event_types


class TestPipelineWithSyntheticData:
    """Synthetic-data tests — no file system dependency."""

    def test_multi_source_campaign_creates_high_priority_threat(self):
        from datetime import datetime, timezone, timedelta
        from threaticap.models.alert import AlertSeverity, AlertSource, AssetContext, Observable, ObservableType
        from tests.conftest import make_alert, make_observable

        now = datetime.now(timezone.utc)
        shared_ip = make_observable(ObservableType.IP_ADDRESS, "203.0.113.99")
        shared_hash = make_observable(ObservableType.FILE_HASH, "feed1234" * 8)

        alerts = [
            make_alert(
                alert_id="synth-a1",
                source_type=AlertSource.SIEM,
                source_id="siem-01",
                source_reliability=0.85,
                severity=AlertSeverity.CRITICAL,
                event_time=now - timedelta(minutes=15),
                observables=[shared_ip, shared_hash],
                mitre_technique_ids=["T1059.001"],
                asset_context=AssetContext(criticality=0.95, hostname="dc01.test"),
                campaign="OP-SYNTH",
                confidence=0.92,
            ),
            make_alert(
                alert_id="synth-a2",
                source_type=AlertSource.EDR,
                source_id="edr-01",
                source_reliability=0.9,
                severity=AlertSeverity.HIGH,
                event_time=now - timedelta(minutes=10),
                observables=[shared_hash],
                mitre_technique_ids=["T1003"],
                asset_context=AssetContext(criticality=0.95, hostname="dc01.test"),
                campaign="OP-SYNTH",
                confidence=0.95,
            ),
            make_alert(
                alert_id="synth-a3",
                source_type=AlertSource.HUMINT,
                source_id="humint-01",
                source_reliability=0.75,
                severity=AlertSeverity.HIGH,
                event_time=now - timedelta(hours=2),
                observables=[shared_ip],
                mitre_technique_ids=["T1071.001"],
                campaign="OP-SYNTH",
                confidence=0.7,
            ),
        ]

        pipeline = ThreatPipeline()
        result = pipeline.run(alerts)

        assert result.threats_created > 0
        top_threat = result.threats[0]
        top_score = result.scores.get(top_threat.threat_id)
        assert top_score is not None
        assert top_score.priority_tier in (
            "CRITICAL", "HIGH"
        ), f"Expected CRITICAL or HIGH, got {top_score.priority_tier} (score={top_score.final_score:.1f})"

    def test_unrelated_alerts_do_not_group(self):
        from datetime import datetime, timezone, timedelta
        from tests.conftest import make_alert

        now = datetime.now(timezone.utc)
        a = make_alert(alert_id="u1", event_time=now - timedelta(hours=25))
        b = make_alert(alert_id="u2", event_time=now)

        from threaticap.correlation.engine import CorrelationConfig
        config = CorrelationConfig(temporal_window_seconds=60)
        pipeline = ThreatPipeline(correlation_config=config)
        result = pipeline.run([a, b])
        assert all(t.alert_count == 1 for t in result.threats)
