"""
In-memory feedback repository.

Production: replace with PostgresFeedbackRepository using the analyst_feedback
table from migration 002. The interface is identical.
"""
from __future__ import annotations

import threading
from typing import Any

from threaticap.models.feedback import AnalystFeedback, Verdict


class BaseFeedbackRepository:
    def save(self, feedback: AnalystFeedback) -> None: ...
    def get_by_id(self, feedback_id: str) -> AnalystFeedback | None: ...
    def get_for_threat(self, threat_id: str) -> list[AnalystFeedback]: ...
    def list_recent(self, limit: int = 100) -> list[AnalystFeedback]: ...
    def get_stats(self) -> dict[str, Any]: ...


class InMemoryFeedbackRepository(BaseFeedbackRepository):

    def __init__(self) -> None:
        self._store: dict[str, AnalystFeedback] = {}
        self._by_threat: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    def save(self, feedback: AnalystFeedback) -> None:
        with self._lock:
            self._store[feedback.feedback_id] = feedback
            self._by_threat.setdefault(feedback.threat_id, []).append(
                feedback.feedback_id
            )

    def get_by_id(self, feedback_id: str) -> AnalystFeedback | None:
        return self._store.get(feedback_id)

    def get_for_threat(self, threat_id: str) -> list[AnalystFeedback]:
        ids = self._by_threat.get(threat_id, [])
        return [self._store[fid] for fid in ids if fid in self._store]

    def list_recent(self, limit: int = 100) -> list[AnalystFeedback]:
        items = sorted(
            self._store.values(),
            key=lambda f: f.created_at,
            reverse=True,
        )
        return items[:limit]

    def get_stats(self) -> dict[str, Any]:
        from collections import Counter
        verdicts = Counter(f.verdict.value for f in self._store.values())
        return {
            "total": len(self._store),
            "by_verdict": dict(verdicts),
        }
