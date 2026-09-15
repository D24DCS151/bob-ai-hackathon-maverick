"""
FastAPI endpoint tests.

Auth is bypassed via THREATICAP_AUTH_DISABLED=true (set in pytest fixtures).
This mirrors real dev/CI usage and exercises the full API surface without
requiring live API key management in tests.
"""
from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

# Bypass authentication for all API tests — never do this outside tests/dev
os.environ["THREATICAP_AUTH_DISABLED"] = "true"

from threaticap.api.app import app
from threaticap.pipeline import ThreatPipeline


@pytest.fixture
def client():
    """TestClient with a fresh in-memory pipeline and auth disabled."""
    pipeline = ThreatPipeline()
    app.state.pipeline = pipeline

    from threaticap.ingestion.pipeline import IngestionPipeline, IngestionConfig
    from threaticap.storage.feedback_repository import InMemoryFeedbackRepository
    app.state.ingest_pipeline = IngestionPipeline(config=IngestionConfig())
    app.state.feedback_repo = InMemoryFeedbackRepository()

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


class TestHealthEndpoint:

    def test_health_returns_ok(self, client: TestClient):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert "version" in body

    def test_root_redirect(self, client: TestClient):
        r = client.get("/")
        assert r.status_code == 200
        assert "docs" in r.json()


class TestMetricsEndpoint:

    def test_metrics_returns_counts(self, client: TestClient):
        r = client.get("/api/v1/metrics")
        assert r.status_code == 200
        body = r.json()
        assert "alerts_total" in body
        assert "threats_total" in body
        assert "threat_by_tier" in body


class TestIngestEndpoint:

    def test_submit_valid_alert(self, client: TestClient):
        from datetime import datetime, timezone
        payload = {
            "alerts": [{
                "source_ref": "TEST-API-001",
                "source_type": "SIEM",
                "source_id": "test-siem",
                "event_time": datetime.now(timezone.utc).isoformat(),
                "severity": "HIGH",
                "title": "API Test Alert",
                "description": "Test description",
            }],
            "run_pipeline": False,
        }
        r = client.post("/api/v1/ingest/alerts", json=payload)
        assert r.status_code == 202
        body = r.json()
        assert body["accepted"] == 1
        assert body["rejected"] == 0
        assert len(body["alert_ids"]) == 1

    def test_submit_empty_alerts_rejected(self, client: TestClient):
        r = client.post("/api/v1/ingest/alerts", json={"alerts": []})
        assert r.status_code == 422

    def test_submit_invalid_alert_reports_error(self, client: TestClient):
        # Missing required fields
        payload = {"alerts": [{"bad_field": "value"}]}
        r = client.post("/api/v1/ingest/alerts", json=payload)
        # Should either accept (with errors) or return 422
        assert r.status_code in (202, 422)

    def test_submit_with_run_pipeline(self, client: TestClient):
        from datetime import datetime, timezone
        payload = {
            "alerts": [{
                "source_ref": "TEST-API-002",
                "source_type": "SIEM",
                "source_id": "test-siem",
                "event_time": datetime.now(timezone.utc).isoformat(),
                "severity": "HIGH",
                "title": "Pipeline Test Alert",
            }],
            "run_pipeline": True,
        }
        r = client.post("/api/v1/ingest/alerts", json=payload)
        assert r.status_code == 202
        body = r.json()
        assert body["accepted"] == 1


class TestPipelineEndpoint:

    def _seed_alerts(self, client: TestClient, count: int = 3) -> list[str]:
        from datetime import datetime, timezone
        alerts = []
        for i in range(count):
            alerts.append({
                "source_ref": f"SEED-{i:03d}",
                "source_type": "SIEM",
                "source_id": "seed-siem",
                "event_time": datetime.now(timezone.utc).isoformat(),
                "severity": "MEDIUM",
                "title": f"Seeded Alert {i}",
            })
        r = client.post("/api/v1/ingest/alerts", json={"alerts": alerts})
        return r.json()["alert_ids"]

    def test_run_pipeline_returns_summary(self, client: TestClient):
        self._seed_alerts(client)
        r = client.post("/api/v1/pipeline/run", json={"alert_limit": 100})
        assert r.status_code == 200
        body = r.json()
        assert "threats_created" in body
        assert body["alerts_processed"] > 0

    def test_run_pipeline_no_alerts_handled(self, client: TestClient):
        # Fresh client — no alerts
        r = client.post("/api/v1/pipeline/run", json={})
        assert r.status_code == 200
        assert r.json()["alerts_processed"] == 0


class TestThreatEndpoints:

    def _setup_with_threat(self, client: TestClient):
        from datetime import datetime, timezone
        payload = {
            "alerts": [{
                "source_ref": "THREAT-TEST-001",
                "source_type": "SIEM",
                "source_id": "test-siem",
                "event_time": datetime.now(timezone.utc).isoformat(),
                "severity": "HIGH",
                "title": "Threat Test Alert",
            }],
            "run_pipeline": True,
        }
        client.post("/api/v1/ingest/alerts", json=payload)

    def test_list_threats_empty(self, client: TestClient):
        r = client.get("/api/v1/threats")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0

    def test_list_threats_after_pipeline(self, client: TestClient):
        self._setup_with_threat(client)
        r = client.get("/api/v1/threats")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] >= 1

    def test_get_threat_not_found(self, client: TestClient):
        r = client.get("/api/v1/threats/nonexistent-id")
        assert r.status_code == 404

    def test_get_threat_detail(self, client: TestClient):
        self._setup_with_threat(client)
        threats = client.get("/api/v1/threats").json()["threats"]
        if threats:
            threat_id = threats[0]["threat_id"]
            r = client.get(f"/api/v1/threats/{threat_id}")
            assert r.status_code == 200
            body = r.json()
            assert "threat" in body
            assert "score" in body

    def test_invalid_tier_filter(self, client: TestClient):
        r = client.get("/api/v1/threats?tier=INVALID")
        assert r.status_code == 400


class TestReportEndpoints:

    def test_list_reports_empty(self, client: TestClient):
        r = client.get("/api/v1/reports")
        assert r.status_code == 200

    def test_get_report_not_found(self, client: TestClient):
        r = client.get("/api/v1/reports/nonexistent-id")
        assert r.status_code == 404


class TestAuditEndpoint:

    def test_audit_returns_records(self, client: TestClient):
        from datetime import datetime, timezone
        payload = {
            "alerts": [{
                "source_ref": "AUDIT-TEST",
                "source_type": "SIEM",
                "source_id": "test-siem",
                "event_time": datetime.now(timezone.utc).isoformat(),
                "severity": "MEDIUM",
                "title": "Audit Test",
            }],
            "run_pipeline": True,
        }
        client.post("/api/v1/ingest/alerts", json=payload)
        r = client.get("/api/v1/audit")
        assert r.status_code == 200
        body = r.json()
        assert "records" in body
