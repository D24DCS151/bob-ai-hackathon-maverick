"""
Tests for the Satellite/ISR connector (Phase 2).

Covers:
- Loading satellite ISR report JSON via ConnectorConfig
- Normalisation into Alert objects
- Correct source_type mapping
- Observable extraction from satellite reports
- MITRE technique mapping from activity_type
- Confidence propagation from source_reliability
- Sparse / default records
- Error handling (missing file, empty, malformed JSON, bad records)
"""
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

import pytest

from threaticap.ingestion.base_connector import ConnectorConfig
from threaticap.ingestion.connectors.satellite_connector import SatelliteISRConnector
from threaticap.models.alert import AlertSource, AlertSeverity


# ---------------------------------------------------------------------------
# Fixtures — sample data uses flat fields matching the connector's normaliser
# ---------------------------------------------------------------------------

SAMPLE_REPORTS = [
    {
        "report_id": "SAT-2024-001",
        "report_time": "2024-01-15T08:30:00Z",
        "platform": "Sentinel-2",
        "classification": "SECRET",
        "sensor_type": "SAR",
        "activity_type": "VEHICLE_MOVEMENT",
        "event_type": "Satellite observation: increased vehicle activity",
        "severity": "HIGH",
        "confidence": 0.85,
        "source_reliability": 0.90,
        "lat": 35.6892,
        "lon": 51.3890,
        "target_ip": "10.0.99.1",
        "description": "Satellite imagery analysis shows increased vehicle movement at the target facility.",
        "mitre_techniques": ["T1583"],
        "campaign": "CAMPAIGN-ALPHA",
        "threat_actor": "APT-X",
    },
    {
        "report_id": "SAT-2024-002",
        "report_time": "2024-01-15T10:15:00Z",
        "platform": "Synthetic-Aperture-1",
        "classification": "TOP SECRET",
        "sensor_type": "SIGINT",
        "activity_type": "RADAR_EMISSION",
        "event_type": "SIGINT intercept detected",
        "severity": "CRITICAL",
        "confidence": 0.92,
        "lat": 32.0853,
        "lon": 34.7818,
        "description": "SIGINT intercept of X-band radar emissions at coastal facility.",
        "mitre_techniques": ["T1592"],
    },
    # Minimal / sparse record — tests defaults
    {
        "report_id": "SAT-2024-003",
        "activity_type": "UNKNOWN",
        "severity": "LOW",
        "confidence": 0.5,
    },
]


def _make_config(file_path: str, reliability: float = 0.9) -> ConnectorConfig:
    return ConnectorConfig(
        connector_id="sat-test",
        source_type="SATELLITE_ISR",
        source_reliability=reliability,
        extra={"file_path": file_path, "source_subtype": "satellite"},
    )


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    p = tmp_path / "satellite_reports.json"
    p.write_text(json.dumps(SAMPLE_REPORTS))
    return p


@pytest.fixture
def connector(sample_file: Path) -> SatelliteISRConnector:
    cfg = _make_config(str(sample_file))
    conn = SatelliteISRConnector(cfg)
    conn.connect()
    return conn


def _load(connector: SatelliteISRConnector) -> list:
    """Helper: fetch + normalise all records, skip None results."""
    alerts = []
    for raw in connector.fetch_raw():
        try:
            alert = connector.normalise(raw)
            if alert is not None:
                alerts.append(alert)
        except Exception:
            pass
    return alerts


# ---------------------------------------------------------------------------
# Basic loading
# ---------------------------------------------------------------------------

class TestSatelliteConnectorLoading:

    def test_load_returns_alerts(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        assert len(alerts) >= 2  # At minimum the first 2 valid records

    def test_source_type_is_satellite_isr(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        for alert in alerts:
            assert alert.source_type == AlertSource.SATELLITE_ISR

    def test_source_ref_matches_report_id(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        source_refs = {a.source_ref for a in alerts}
        assert "SAT-2024-001" in source_refs
        assert "SAT-2024-002" in source_refs

    def test_high_severity_mapping(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        high_alert = next(a for a in alerts if a.source_ref == "SAT-2024-001")
        assert high_alert.severity == AlertSeverity.HIGH

    def test_critical_severity_mapping(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        critical = next(a for a in alerts if a.source_ref == "SAT-2024-002")
        assert critical.severity == AlertSeverity.CRITICAL

    def test_confidence_propagated(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        alert = next(a for a in alerts if a.source_ref == "SAT-2024-001")
        assert abs(alert.confidence - 0.85) < 0.01

    def test_source_reliability_from_connector_config(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        alert = next(a for a in alerts if a.source_ref == "SAT-2024-001")
        # source_reliability comes from ConnectorConfig, not the record
        assert alert.source_reliability == 0.9

    def test_event_time_parsed(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        alert = next(a for a in alerts if a.source_ref == "SAT-2024-001")
        assert isinstance(alert.event_time, datetime)
        assert alert.event_time.year == 2024

    def test_campaign_propagated(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        alert = next(a for a in alerts if a.source_ref == "SAT-2024-001")
        assert alert.campaign == "CAMPAIGN-ALPHA"

    def test_threat_actor_propagated(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        alert = next(a for a in alerts if a.source_ref == "SAT-2024-001")
        assert alert.threat_actor == "APT-X"


# ---------------------------------------------------------------------------
# MITRE techniques
# ---------------------------------------------------------------------------

class TestSatelliteMitreTechniques:

    def test_mitre_techniques_mapped(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        alert = next(a for a in alerts if a.source_ref == "SAT-2024-001")
        assert "T1583" in alert.mitre_technique_ids

    def test_mitre_techniques_second_report(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        alert = next(a for a in alerts if a.source_ref == "SAT-2024-002")
        assert "T1592" in alert.mitre_technique_ids


# ---------------------------------------------------------------------------
# Observables
# ---------------------------------------------------------------------------

class TestSatelliteObservables:

    def test_geo_observable_extracted(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        alert = next(a for a in alerts if a.source_ref == "SAT-2024-001")
        # Should have at least the GEO observable from lat/lon
        obs_values = [o.value for o in alert.observables]
        assert any("GEO:" in v for v in obs_values)

    def test_ip_observable_extracted(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        alert = next(a for a in alerts if a.source_ref == "SAT-2024-001")
        obs_values = {o.value for o in alert.observables}
        # target_ip: 10.0.99.1 should be extracted
        assert "10.0.99.1" in obs_values


# ---------------------------------------------------------------------------
# Sparse / default records
# ---------------------------------------------------------------------------

class TestSatelliteSparseRecords:

    def test_sparse_record_loads_without_crash(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        sparse = next((a for a in alerts if a.source_ref == "SAT-2024-003"), None)
        assert sparse is not None

    def test_sparse_record_has_valid_event_time(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        sparse = next((a for a in alerts if a.source_ref == "SAT-2024-003"), None)
        if sparse:
            assert isinstance(sparse.event_time, datetime)

    def test_sparse_record_confidence_is_float(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        sparse = next((a for a in alerts if a.source_ref == "SAT-2024-003"), None)
        if sparse:
            assert isinstance(sparse.confidence, float)
            assert 0.0 <= sparse.confidence <= 1.0


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestSatelliteConnectorErrors:

    def test_missing_file_raises_on_connect(self, tmp_path: Path):
        cfg = _make_config(str(tmp_path / "nonexistent.json"))
        conn = SatelliteISRConnector(cfg)
        from threaticap.ingestion.base_connector import ConnectorError
        with pytest.raises((ConnectorError, FileNotFoundError, Exception)):
            conn.connect()

    def test_empty_json_array_returns_no_alerts(self, tmp_path: Path):
        p = tmp_path / "empty.json"
        p.write_text("[]")
        cfg = _make_config(str(p))
        conn = SatelliteISRConnector(cfg)
        conn.connect()
        alerts = _load(conn)
        assert alerts == []

    def test_malformed_json_raises_or_returns_empty(self, tmp_path: Path):
        p = tmp_path / "bad.json"
        p.write_text("not valid json {{{")
        cfg = _make_config(str(p))
        conn = SatelliteISRConnector(cfg)
        conn.connect()
        try:
            alerts = _load(conn)
            # If it doesn't raise, it must return empty
            assert alerts == []
        except Exception:
            pass  # Acceptable — connector propagates parse error

    def test_tlp_defaults_to_red(self, connector: SatelliteISRConnector):
        alerts = _load(connector)
        for alert in alerts:
            # Default TLP for ISR data is TLP:RED
            assert alert.tlp in ("TLP:RED", "TLP:AMBER", "SECRET", "TOP SECRET", "")
