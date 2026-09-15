"""
Alert deduplicator.

Prevents the same event from entering the correlation engine multiple times
due to duplicate delivery from overlapping sources (e.g. SIEM + EDR both
report the same endpoint event).

Strategy:
    1. Compute a deterministic content hash from stable alert fields.
    2. Check the hash against an in-memory LRU cache (production: Redis / DB).
    3. If the hash is known within the deduplication window, mark as duplicate.

The dedup hash is stored on the Alert model so downstream components can
reference it for their own deduplication logic.
"""
from __future__ import annotations

import hashlib
import json
import logging
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any

from threaticap.models.alert import Alert

logger = logging.getLogger(__name__)


class _LRUCache:
    """
    Fixed-size LRU cache with TTL eviction.

    Not thread-safe on its own — callers must acquire a lock in multi-threaded
    contexts. In production, replace with a Redis-backed implementation.
    """

    def __init__(self, max_size: int = 50_000, ttl_seconds: int = 3600) -> None:
        self._store: OrderedDict[str, datetime] = OrderedDict()
        self._max_size = max_size
        self._ttl = timedelta(seconds=ttl_seconds)

    def contains(self, key: str) -> bool:
        """Returns True if key is present AND not expired."""
        if key not in self._store:
            return False
        inserted_at = self._store[key]
        if datetime.now(timezone.utc) - inserted_at > self._ttl:
            del self._store[key]
            return False
        self._store.move_to_end(key)
        return True

    def add(self, key: str) -> None:
        if key in self._store:
            self._store.move_to_end(key)
            return
        self._store[key] = datetime.now(timezone.utc)
        if len(self._store) > self._max_size:
            self._store.popitem(last=False)

    def size(self) -> int:
        return len(self._store)


class AlertDeduplicator:
    """
    Detects and marks duplicate alerts before they enter the correlation engine.

    The dedup hash is computed from:
    - source_type + source_id + source_ref  (identity)
    - event_time (rounded to minute for near-duplicate detection)
    - title
    - first observable value (if present)

    Rounding event_time to the minute catches the common case where the same
    event is delivered twice with slightly different timestamps.
    """

    def __init__(
        self,
        cache_size: int = 50_000,
        ttl_seconds: int = 3600,
    ) -> None:
        self._cache = _LRUCache(max_size=cache_size, ttl_seconds=ttl_seconds)
        self._total_seen = 0
        self._total_dupes = 0

    def compute_hash(self, alert: Alert) -> str:
        """Compute a deterministic deduplication hash for an alert."""
        # Round to minute to handle near-duplicate timestamps
        rounded_time = alert.event_time.replace(second=0, microsecond=0)
        first_obs = alert.observables[0].value if alert.observables else ""

        key_data: dict[str, Any] = {
            "source_type": alert.source_type.value,
            "source_id": alert.source_id,
            "source_ref": alert.source_ref,
            "event_time": rounded_time.isoformat(),
            "title": alert.title.lower().strip(),
            "first_observable": first_obs.lower(),
        }
        serialised = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(serialised.encode()).hexdigest()

    def is_duplicate(self, alert: Alert) -> bool:
        """
        Returns True if this alert has already been seen within the TTL window.
        Does NOT modify the cache — call record() to register the alert.
        """
        h = alert.dedup_hash or self.compute_hash(alert)
        return self._cache.contains(h)

    def record(self, alert: Alert) -> Alert:
        """
        Record the alert in the dedup cache and return it with dedup_hash set.
        """
        h = self.compute_hash(alert)
        self._cache.add(h)
        return alert.model_copy(update={"dedup_hash": h})

    def process(self, alert: Alert) -> tuple[Alert, bool]:
        """
        Combined check-and-record operation.

        Returns (alert_with_hash, is_duplicate).
        Callers should discard duplicates or route them to a dedup audit trail.
        """
        self._total_seen += 1
        h = self.compute_hash(alert)
        alert = alert.model_copy(update={"dedup_hash": h})

        if self._cache.contains(h):
            self._total_dupes += 1
            logger.debug(
                "Duplicate alert detected: source_ref=%s source_id=%s hash=%s",
                alert.source_ref, alert.source_id, h[:12]
            )
            return alert, True

        self._cache.add(h)
        return alert, False

    @property
    def stats(self) -> dict[str, int]:
        return {
            "total_seen": self._total_seen,
            "total_duplicates": self._total_dupes,
            "cache_size": self._cache.size(),
        }
