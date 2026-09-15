"""
Repository interfaces and in-memory implementations.

The abstract base classes define the contract; every downstream consumer
MUST use only these interfaces — never concrete implementations directly.
This enables clean database backend swaps without touching business logic.
"""
from __future__ import annotations

import abc
import threading
from collections import OrderedDict
from datetime import datetime
from typing import Any

from threaticap.models.alert import Alert, AlertSeverity, AlertStatus
from threaticap.models.audit import AuditRecord
from threaticap.models.bluf import BlufReport
from threaticap.models.correlated_threat import CorrelatedThreat, ThreatStatus
from threaticap.models.priority import PriorityScore, PriorityTier


# ---------------------------------------------------------------------------
# Alert repository
# ---------------------------------------------------------------------------

class BaseAlertRepository(abc.ABC):
    @abc.abstractmethod
    def save(self, alert: Alert) -> None: ...

    @abc.abstractmethod
    def save_batch(self, alerts: list[Alert]) -> int: ...

    @abc.abstractmethod
    def get(self, alert_id: str) -> Alert | None: ...

    @abc.abstractmethod
    def list_recent(self, limit: int = 100, offset: int = 0) -> list[Alert]: ...

    @abc.abstractmethod
    def find_by_observable(self, value: str) -> list[Alert]: ...

    @abc.abstractmethod
    def count(self) -> int: ...


class InMemoryAlertRepository(BaseAlertRepository):
    """Thread-safe in-memory alert store using an OrderedDict (insertion order)."""

    def __init__(self, max_size: int = 100_000) -> None:
        self._store: OrderedDict[str, Alert] = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = max_size

    def save(self, alert: Alert) -> None:
        with self._lock:
            self._store[alert.alert_id] = alert
            if len(self._store) > self._max_size:
                self._store.popitem(last=False)

    def save_batch(self, alerts: list[Alert]) -> int:
        for alert in alerts:
            self.save(alert)
        return len(alerts)

    def get(self, alert_id: str) -> Alert | None:
        return self._store.get(alert_id)

    def list_recent(self, limit: int = 100, offset: int = 0) -> list[Alert]:
        items = list(reversed(list(self._store.values())))
        return items[offset : offset + limit]

    def find_by_observable(self, value: str) -> list[Alert]:
        value_lower = value.lower()
        return [
            a for a in self._store.values()
            if any(o.value.lower() == value_lower for o in a.observables)
        ]

    def count(self) -> int:
        return len(self._store)

    def get_lookup(self) -> dict[str, Alert]:
        return dict(self._store)


# ---------------------------------------------------------------------------
# Threat repository
# ---------------------------------------------------------------------------

class BaseThreatRepository(abc.ABC):
    @abc.abstractmethod
    def save(self, threat: CorrelatedThreat, score: PriorityScore | None = None) -> None: ...

    @abc.abstractmethod
    def get(self, threat_id: str) -> CorrelatedThreat | None: ...

    @abc.abstractmethod
    def get_score(self, threat_id: str) -> PriorityScore | None: ...

    @abc.abstractmethod
    def list_by_priority(
        self,
        tier: PriorityTier | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[tuple[CorrelatedThreat, PriorityScore | None]]: ...

    @abc.abstractmethod
    def count(self) -> int: ...


class InMemoryThreatRepository(BaseThreatRepository):
    def __init__(self) -> None:
        self._threats: dict[str, CorrelatedThreat] = {}
        self._scores: dict[str, PriorityScore] = {}
        self._lock = threading.Lock()

    def save(self, threat: CorrelatedThreat, score: PriorityScore | None = None) -> None:
        with self._lock:
            self._threats[threat.threat_id] = threat
            if score:
                self._scores[threat.threat_id] = score

    def get(self, threat_id: str) -> CorrelatedThreat | None:
        return self._threats.get(threat_id)

    def get_score(self, threat_id: str) -> PriorityScore | None:
        return self._scores.get(threat_id)

    def list_by_priority(
        self,
        tier: PriorityTier | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[tuple[CorrelatedThreat, PriorityScore | None]]:
        items = [
            (t, self._scores.get(t.threat_id))
            for t in self._threats.values()
        ]
        if tier:
            items = [
                (t, s) for t, s in items
                if s and s.priority_tier == tier
            ]
        items.sort(
            key=lambda x: x[1].final_score if x[1] else 0.0,
            reverse=True
        )
        return items[offset : offset + limit]

    def count(self) -> int:
        return len(self._threats)


# ---------------------------------------------------------------------------
# Audit repository
# ---------------------------------------------------------------------------

class BaseAuditRepository(abc.ABC):
    @abc.abstractmethod
    def append(self, record: AuditRecord) -> None: ...

    @abc.abstractmethod
    def get_for_threat(self, threat_id: str) -> list[AuditRecord]: ...

    @abc.abstractmethod
    def get_for_alert(self, alert_id: str) -> list[AuditRecord]: ...

    @abc.abstractmethod
    def list_recent(self, limit: int = 200) -> list[AuditRecord]: ...


class InMemoryAuditRepository(BaseAuditRepository):
    """Append-only in-memory audit log."""

    def __init__(self, max_size: int = 500_000) -> None:
        self._records: list[AuditRecord] = []
        self._lock = threading.Lock()
        self._max_size = max_size

    def append(self, record: AuditRecord) -> None:
        with self._lock:
            self._records.append(record)
            if len(self._records) > self._max_size:
                self._records = self._records[-self._max_size:]

    def get_for_threat(self, threat_id: str) -> list[AuditRecord]:
        return [r for r in self._records if r.threat_id == threat_id]

    def get_for_alert(self, alert_id: str) -> list[AuditRecord]:
        return [r for r in self._records if r.alert_id == alert_id]

    def list_recent(self, limit: int = 200) -> list[AuditRecord]:
        return list(reversed(self._records[-limit:]))

    def count(self) -> int:
        return len(self._records)


# ---------------------------------------------------------------------------
# Report repository
# ---------------------------------------------------------------------------

class BaseReportRepository(abc.ABC):
    @abc.abstractmethod
    def save(self, report: BlufReport) -> None: ...

    @abc.abstractmethod
    def get(self, report_id: str) -> BlufReport | None: ...

    @abc.abstractmethod
    def get_for_threat(self, threat_id: str) -> list[BlufReport]: ...

    @abc.abstractmethod
    def list_recent(self, limit: int = 50) -> list[BlufReport]: ...


class InMemoryReportRepository(BaseReportRepository):
    def __init__(self) -> None:
        self._reports: dict[str, BlufReport] = {}
        self._by_threat: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    def save(self, report: BlufReport) -> None:
        with self._lock:
            self._reports[report.report_id] = report
            self._by_threat.setdefault(report.threat_id, []).append(report.report_id)

    def get(self, report_id: str) -> BlufReport | None:
        return self._reports.get(report_id)

    def get_for_threat(self, threat_id: str) -> list[BlufReport]:
        ids = self._by_threat.get(threat_id, [])
        return [self._reports[rid] for rid in ids if rid in self._reports]

    def list_recent(self, limit: int = 50) -> list[BlufReport]:
        items = sorted(
            self._reports.values(),
            key=lambda r: r.generated_at,
            reverse=True,
        )
        return items[:limit]
