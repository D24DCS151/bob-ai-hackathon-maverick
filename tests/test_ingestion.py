"""
Tests for ingestion pipeline components.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from threaticap.ingestion.normaliser import AlertNormaliser
from threaticap.ingestion.deduplicator import AlertDeduplicator
from threaticap.ingestion.enricher import AlertEnricher
from threaticap.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus, AssetContext, Observable, ObservableType
from tests.conftest import make_alert, make_observable


class TestAlertNormaliser:

    def test_extracts_ip_from_description(self):
        alert = make_alert(description="Suspicious connection to 203.0.113.42 detected")
        normaliser = AlertNormaliser(extract_iocs_from_text=True)
        result = normaliser.normalise(alert)
        ip_obs = [o for o in result.observables if o.type == ObservableType.IP_ADDRESS and o.value == "203.0.113.42"]
        assert len(ip_obs) == 1
        assert ip_obs[0].confidence == 0.6  # auto-extracted = lower confidence

    def test_skips_private_ips_in_extraction(self):
        alert = make_alert(description="Connection from 192.168.1.1 to 10.0.0.5")
        normaliser = AlertNormaliser(extract_iocs_from_text=True)
        result = normaliser.normalise(alert)
        # Private IPs should be filtered out
        ip_obs = [o for o in result.observables if o.type == ObservableType.IP_ADDRESS]
        assert all(
            not o.value.startswith(("192.168.", "10."))
            for o in ip_obs
        )

    def test_extracts_domain_from_description(self):
        alert = make_alert(description="DNS query to malicious.evil.com observed")
        normaliser = AlertNormaliser()
        result = normaliser.normalise(alert)
        domain_obs = [o for o in result.observables if o.type == ObservableType.DOMAIN and "malicious.evil.com" in o.value]
        assert len(domain_obs) >= 1

    def test_deduplicates_existing_observables(self):
        existing_obs = make_observable(ObservableType.IP_ADDRESS, "203.0.113.1")
        alert = make_alert(
            description="Connection to 203.0.113.1",
            observables=[existing_obs],
        )
        normaliser = AlertNormaliser()
        result = normaliser.normalise(alert)
        ip_obs = [o for o in result.observables if o.value == "203.0.113.1"]
        assert len(ip_obs) == 1  # Not duplicated

    def test_normalise_severity_mapping(self):
        assert AlertNormaliser.normalise_severity("critical") == AlertSeverity.CRITICAL
        assert AlertNormaliser.normalise_severity("CRITICAL") == AlertSeverity.CRITICAL
        assert AlertNormaliser.normalise_severity("5") == AlertSeverity.CRITICAL
        assert AlertNormaliser.normalise_severity("high") == AlertSeverity.HIGH
        assert AlertNormaliser.normalise_severity("info") == AlertSeverity.INFO
        assert AlertNormaliser.normalise_severity("unknown_value") == AlertSeverity.LOW

    def test_no_extraction_when_disabled(self):
        alert = make_alert(description="Connection to 203.0.113.42 detected")
        normaliser = AlertNormaliser(extract_iocs_from_text=False)
        result = normaliser.normalise(alert)
        assert len(result.observables) == 0  # No extraction

    def test_truncates_oversized_description(self):
        """Normaliser truncates descriptions that exceed the model's 8192-char limit."""
        # Build alert with max-length description, then manually create one that
        # bypasses Pydantic validation to simulate a pre-validated too-long payload
        # arriving via model_construct (internal path).
        from threaticap.models.alert import Alert, AlertSource, AlertSeverity
        from datetime import datetime, timezone
        # Use model_construct to skip validation (simulates data arriving from
        # a connector that hasn't yet been normalised)
        long_desc = "X" * 9000
        alert = Alert.model_construct(
            alert_id="test-long",
            schema_version="1.0",
            source_ref="SRC-LONG",
            source_type=AlertSource.SIEM,
            source_id="siem-01",
            source_reliability=0.8,
            event_time=datetime.now(timezone.utc),
            ingestion_time=datetime.now(timezone.utc),
            severity=AlertSeverity.HIGH,
            confidence=0.75,
            status="INGESTED",
            title="Long description alert",
            description=long_desc,
            category="",
            observables=[],
            asset_context={},
            mitre_technique_ids=[],
            enrichment_tags=[],
            tlp="TLP:GREEN",
        )
        normaliser = AlertNormaliser(extract_iocs_from_text=False)
        result = normaliser.normalise(alert)
        assert len(result.description) <= 8192


class TestAlertDeduplicator:

    def test_same_alert_detected_as_duplicate(self):
        dedup = AlertDeduplicator()
        alert = make_alert()
        _, is_dup1 = dedup.process(alert)
        _, is_dup2 = dedup.process(alert)
        assert not is_dup1
        assert is_dup2

    def test_different_alerts_not_duplicates(self):
        dedup = AlertDeduplicator()
        a = make_alert(alert_id="a1", source_ref="REF-001")
        b = make_alert(alert_id="a2", source_ref="REF-002")
        _, is_dup_a = dedup.process(a)
        _, is_dup_b = dedup.process(b)
        assert not is_dup_a
        assert not is_dup_b

    def test_dedup_hash_set_on_alert(self):
        dedup = AlertDeduplicator()
        alert = make_alert()
        result, _ = dedup.process(alert)
        assert result.dedup_hash is not None
        assert len(result.dedup_hash) == 64  # SHA-256 hex

    def test_stats_tracking(self):
        dedup = AlertDeduplicator()
        alert = make_alert()
        dedup.process(alert)
        dedup.process(alert)  # duplicate
        stats = dedup.stats
        assert stats["total_seen"] == 2
        assert stats["total_duplicates"] == 1

    def test_ttl_expiry(self):
        """After TTL expires, the same alert should not be detected as duplicate."""
        dedup = AlertDeduplicator(ttl_seconds=0)  # Immediate expiry
        import time
        alert = make_alert()
        dedup.process(alert)
        time.sleep(0.01)  # Allow TTL to lapse
        _, is_dup = dedup.process(alert)
        assert not is_dup  # Expired — not a duplicate


class TestAlertEnricher:

    def test_asset_registry_enrichment(self):
        registry = {
            "10.0.1.50": {
                "asset_id": "DC-001",
                "hostname": "dc01.corp.internal",
                "criticality": 0.95,
                "classification": "SECRET",
            }
        }
        enricher = AlertEnricher(asset_registry=registry)
        alert = make_alert(
            asset_context=AssetContext(ip_addresses=["10.0.1.50"])
        )
        result = enricher.enrich(alert)
        assert result.asset_context.asset_id == "DC-001"
        assert result.asset_context.criticality == 0.95
        assert result.asset_context.classification == "SECRET"

    def test_sensitive_source_gets_red_tlp(self):
        enricher = AlertEnricher()
        alert = make_alert()
        humint_alert = alert.model_copy(update={"source_type": AlertSource.HUMINT, "tlp": "TLP:GREEN"})
        result = enricher.enrich(humint_alert)
        assert result.tlp == "TLP:RED"

    def test_commercial_feed_gets_amber_tlp(self):
        enricher = AlertEnricher()
        alert = make_alert()
        commercial_alert = alert.model_copy(update={
            "source_type": AlertSource.COMMERCIAL_FEED,
            "tlp": "TLP:GREEN"
        })
        result = enricher.enrich(commercial_alert)
        assert result.tlp == "TLP:AMBER"

    def test_no_registry_match_returns_unchanged_context(self):
        enricher = AlertEnricher(asset_registry={})
        alert = make_alert(asset_context=AssetContext(ip_addresses=["10.99.99.99"]))
        result = enricher.enrich(alert)
        assert result.asset_context.ip_addresses == ["10.99.99.99"]


class TestSiemConnector:

    def test_normalise_json_alert(self, tmp_path: Path):
        import json
        from threaticap.ingestion.connectors.siem_connector import SiemConnector
        from threaticap.ingestion.base_connector import ConnectorConfig

        sample = [{
            "event_id": "TEST-001",
            "timestamp": "2024-01-15T02:14:33Z",
            "title": "Test SIEM Alert",
            "description": "Test description",
            "severity": "high",
            "src_ip": "10.0.2.100",
            "dst_ip": "203.0.113.45",
            "hostname": "test-host",
            "confidence": 0.85,
        }]
        f = tmp_path / "siem_test.json"
        f.write_text(json.dumps(sample))

        conn = SiemConnector(ConnectorConfig(
            connector_id="test-siem",
            source_type="SIEM",
            extra={"mode": "file", "file_path": str(f)},
        ))
        conn.connect()
        raws = list(conn.fetch_raw())
        conn.disconnect()

        assert len(raws) == 1
        alert = conn.normalise(raws[0])
        assert alert is not None
        assert alert.source_ref == "TEST-001"
        assert alert.severity == AlertSeverity.HIGH
        ip_obs = [o for o in alert.observables if o.type == ObservableType.IP_ADDRESS]
        assert any(o.value == "10.0.2.100" for o in ip_obs)
        assert any(o.value == "203.0.113.45" for o in ip_obs)

    def test_heartbeat_event_skipped(self):
        from threaticap.ingestion.connectors.siem_connector import SiemConnector
        from threaticap.ingestion.base_connector import ConnectorConfig

        conn = SiemConnector(ConnectorConfig(
            connector_id="test-siem",
            source_type="SIEM",
            extra={},
        ))
        result = conn.normalise({"event_type": "heartbeat"})
        assert result is None
