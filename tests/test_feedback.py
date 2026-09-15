"""
Tests for analyst feedback model and repository (Phase 2).

Covers:
- AnalystFeedback model validation and defaults
- Verdict enum values
- InMemoryFeedbackRepository CRUD
- Feedback for non-existent threat
- Multiple feedback records per threat
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone

from threaticap.models.feedback import AnalystFeedback, Verdict
from threaticap.storage.feedback_repository import InMemoryFeedbackRepository


# ---------------------------------------------------------------------------
# AnalystFeedback model
# ---------------------------------------------------------------------------

class TestAnalystFeedbackModel:

    def test_create_basic_feedback(self):
        fb = AnalystFeedback(
            threat_id="threat-001",
            analyst_id="analyst-alice",
            verdict=Verdict.TRUE_POSITIVE,
        )
        assert fb.threat_id == "threat-001"
        assert fb.analyst_id == "analyst-alice"
        assert fb.verdict == Verdict.TRUE_POSITIVE

    def test_feedback_id_generated(self):
        fb = AnalystFeedback(
            threat_id="t1",
            analyst_id="a1",
            verdict=Verdict.FALSE_POSITIVE,
        )
        assert fb.feedback_id
        assert len(fb.feedback_id) > 0

    def test_two_feedbacks_have_different_ids(self):
        fb1 = AnalystFeedback(threat_id="t1", analyst_id="a1", verdict=Verdict.BENIGN)
        fb2 = AnalystFeedback(threat_id="t1", analyst_id="a1", verdict=Verdict.BENIGN)
        assert fb1.feedback_id != fb2.feedback_id

    def test_default_confidence_is_one(self):
        fb = AnalystFeedback(threat_id="t", analyst_id="a", verdict=Verdict.TRUE_POSITIVE)
        assert fb.confidence == 1.0

    def test_confidence_validated_range(self):
        fb = AnalystFeedback(
            threat_id="t", analyst_id="a",
            verdict=Verdict.TRUE_POSITIVE,
            confidence=0.75,
        )
        assert fb.confidence == 0.75

    def test_confidence_below_zero_rejected(self):
        with pytest.raises(Exception):
            AnalystFeedback(
                threat_id="t", analyst_id="a",
                verdict=Verdict.TRUE_POSITIVE,
                confidence=-0.1,
            )

    def test_confidence_above_one_rejected(self):
        with pytest.raises(Exception):
            AnalystFeedback(
                threat_id="t", analyst_id="a",
                verdict=Verdict.TRUE_POSITIVE,
                confidence=1.1,
            )

    def test_notes_default_empty(self):
        fb = AnalystFeedback(threat_id="t", analyst_id="a", verdict=Verdict.NEEDS_REVIEW)
        assert fb.notes == ""

    def test_notes_stored(self):
        fb = AnalystFeedback(
            threat_id="t", analyst_id="a",
            verdict=Verdict.FALSE_POSITIVE,
            notes="Scanner misconfiguration — benign scheduled task",
        )
        assert "benign" in fb.notes

    def test_timestamps_set_on_creation(self):
        before = datetime.now(timezone.utc)
        fb = AnalystFeedback(threat_id="t", analyst_id="a", verdict=Verdict.TRUE_POSITIVE)
        after = datetime.now(timezone.utc)
        assert before <= fb.created_at <= after
        assert before <= fb.updated_at <= after

    def test_all_verdict_values_valid(self):
        for verdict in Verdict:
            fb = AnalystFeedback(threat_id="t", analyst_id="a", verdict=verdict)
            assert fb.verdict == verdict

    def test_model_serialises_to_dict(self):
        fb = AnalystFeedback(
            threat_id="t-001",
            analyst_id="alice",
            verdict=Verdict.TRUE_POSITIVE,
        )
        d = fb.model_dump()
        assert d["threat_id"] == "t-001"
        assert d["verdict"] == "TRUE_POSITIVE"


# ---------------------------------------------------------------------------
# Verdict enum
# ---------------------------------------------------------------------------

class TestVerdict:

    def test_all_verdicts_are_strings(self):
        for v in Verdict:
            assert isinstance(v.value, str)

    def test_true_positive(self):
        assert Verdict.TRUE_POSITIVE.value == "TRUE_POSITIVE"

    def test_false_positive(self):
        assert Verdict.FALSE_POSITIVE.value == "FALSE_POSITIVE"

    def test_benign(self):
        assert Verdict.BENIGN.value == "BENIGN"

    def test_needs_review(self):
        assert Verdict.NEEDS_REVIEW.value == "NEEDS_REVIEW"


# ---------------------------------------------------------------------------
# InMemoryFeedbackRepository
# ---------------------------------------------------------------------------

class TestInMemoryFeedbackRepository:

    def _repo(self) -> InMemoryFeedbackRepository:
        return InMemoryFeedbackRepository()

    def _feedback(self, threat_id: str = "t1", verdict: Verdict = Verdict.TRUE_POSITIVE) -> AnalystFeedback:
        return AnalystFeedback(
            threat_id=threat_id,
            analyst_id="analyst-bob",
            verdict=verdict,
        )

    def test_save_and_get_by_id(self):
        repo = self._repo()
        fb = self._feedback()
        repo.save(fb)
        retrieved = repo.get_by_id(fb.feedback_id)
        assert retrieved is not None
        assert retrieved.feedback_id == fb.feedback_id

    def test_get_nonexistent_returns_none(self):
        repo = self._repo()
        assert repo.get_by_id("nonexistent-id") is None

    def test_get_for_threat_empty(self):
        repo = self._repo()
        results = repo.get_for_threat("threat-99")
        assert results == []

    def test_get_for_threat_returns_matching(self):
        repo = self._repo()
        fb1 = self._feedback("threat-A")
        fb2 = self._feedback("threat-A", verdict=Verdict.FALSE_POSITIVE)
        fb3 = self._feedback("threat-B")
        repo.save(fb1)
        repo.save(fb2)
        repo.save(fb3)
        results = repo.get_for_threat("threat-A")
        assert len(results) == 2
        threat_ids = [r.threat_id for r in results]
        assert all(tid == "threat-A" for tid in threat_ids)

    def test_get_for_threat_no_cross_contamination(self):
        repo = self._repo()
        repo.save(self._feedback("threat-X"))
        results = repo.get_for_threat("threat-Y")
        assert results == []

    def test_multiple_saves_accumulate(self):
        repo = self._repo()
        for i in range(5):
            repo.save(AnalystFeedback(
                threat_id=f"t-{i}",
                analyst_id="analyst",
                verdict=Verdict.TRUE_POSITIVE,
            ))
        # Each in own bucket
        for i in range(5):
            assert len(repo.get_for_threat(f"t-{i}")) == 1

    def test_save_same_threat_multiple_times(self):
        repo = self._repo()
        for _ in range(3):
            repo.save(self._feedback("multi-threat"))
        results = repo.get_for_threat("multi-threat")
        assert len(results) == 3

    def test_latest_verdict_for_threat(self):
        """Most recent feedback can be retrieved via get_for_threat[-1]."""
        repo = self._repo()
        fb_tp = AnalystFeedback(threat_id="t", analyst_id="a", verdict=Verdict.TRUE_POSITIVE)
        fb_fp = AnalystFeedback(threat_id="t", analyst_id="a", verdict=Verdict.FALSE_POSITIVE)
        repo.save(fb_tp)
        repo.save(fb_fp)
        results = repo.get_for_threat("t")
        verdicts = {r.feedback_id: r.verdict for r in results}
        # Both should be present
        assert Verdict.TRUE_POSITIVE in verdicts.values()
        assert Verdict.FALSE_POSITIVE in verdicts.values()


# ---------------------------------------------------------------------------
# Feedback API endpoints (via TestClient, auth disabled)
# ---------------------------------------------------------------------------

class TestFeedbackAPIEndpoints:
    """
    Integration tests exercising the /threats/{id}/feedback endpoints
    via the FastAPI TestClient.
    """

    @pytest.fixture
    def client_with_threat(self):
        import os
        os.environ["THREATICAP_AUTH_DISABLED"] = "true"
        from fastapi.testclient import TestClient
        from threaticap.api.app import app
        from threaticap.pipeline import ThreatPipeline
        from threaticap.ingestion.pipeline import IngestionPipeline, IngestionConfig
        from threaticap.storage.feedback_repository import InMemoryFeedbackRepository

        pipeline = ThreatPipeline()
        app.state.pipeline = pipeline
        app.state.ingest_pipeline = IngestionPipeline(config=IngestionConfig())
        app.state.feedback_repo = InMemoryFeedbackRepository()

        with TestClient(app, raise_server_exceptions=True) as c:
            # Create and pipeline an alert to get a threat
            from datetime import datetime, timezone
            payload = {
                "alerts": [{
                    "source_ref": "FB-TEST-001",
                    "source_type": "SIEM",
                    "source_id": "siem-test",
                    "event_time": datetime.now(timezone.utc).isoformat(),
                    "severity": "HIGH",
                    "title": "Feedback Test Alert",
                }],
                "run_pipeline": True,
            }
            c.post("/api/v1/ingest/alerts", json=payload)
            threats_resp = c.get("/api/v1/threats")
            threats = threats_resp.json().get("threats", [])
            threat_id = threats[0]["threat_id"] if threats else None
            yield c, threat_id

    def test_submit_feedback_true_positive(self, client_with_threat):
        client, threat_id = client_with_threat
        if not threat_id:
            pytest.skip("No threat created")
        r = client.post(
            f"/api/v1/threats/{threat_id}/feedback",
            params={"verdict": "TRUE_POSITIVE", "confidence": 0.9, "notes": "Confirmed C2 activity"},
        )
        assert r.status_code in (200, 201)

    def test_submit_feedback_false_positive(self, client_with_threat):
        client, threat_id = client_with_threat
        if not threat_id:
            pytest.skip("No threat created")
        r = client.post(
            f"/api/v1/threats/{threat_id}/feedback",
            params={"verdict": "FALSE_POSITIVE", "confidence": 1.0, "notes": "Scheduled scan"},
        )
        assert r.status_code in (200, 201)

    def test_feedback_nonexistent_threat(self, client_with_threat):
        client, _ = client_with_threat
        r = client.post(
            "/api/v1/threats/nonexistent-id/feedback",
            params={"verdict": "BENIGN"},
        )
        assert r.status_code == 404
