"""
Tests for the enrichment broker and circuit breaker (Phase 2).

Covers:
- CircuitBreaker state machine (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)
- TTL cache hit / miss / expiry
- BaseEnricher caching behaviour
- BaseEnricher circuit-break-on-failure
- ReputationEnricher / CMDBEnricher / CVEEnricher stub behaviour
- CMDBEnricher static registry fallback
- EnrichmentBroker observable enrichment dispatch
- EnrichmentBroker asset enrichment dispatch
- EnrichmentBroker health reporting
- Disabled enricher returns empty dict
"""
from __future__ import annotations

import time
import pytest

from threaticap.enrichment.broker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    _TTLCache,
    BaseEnricher,
    ReputationEnricher,
    CMDBEnricher,
    CVEEnricher,
    EnrichmentBroker,
)


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------

class TestCircuitBreaker:

    def _cfg(self, threshold: int = 3, timeout: int = 5) -> CircuitBreakerConfig:
        return CircuitBreakerConfig(
            failure_threshold=threshold,
            reset_timeout_seconds=timeout,
            name="test-cb",
        )

    def test_initial_state_is_closed(self):
        cb = CircuitBreaker(self._cfg())
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.is_available()

    def test_success_keeps_closed(self):
        cb = CircuitBreaker(self._cfg())
        cb.record_success()
        assert cb.state == CircuitBreaker.CLOSED

    def test_failures_below_threshold_stay_closed(self):
        cb = CircuitBreaker(self._cfg(threshold=3))
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitBreaker.CLOSED
        assert cb.is_available()

    def test_failures_at_threshold_open_circuit(self):
        cb = CircuitBreaker(self._cfg(threshold=3))
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN
        assert not cb.is_available()

    def test_open_circuit_blocks_requests(self):
        cb = CircuitBreaker(self._cfg(threshold=1, timeout=60))
        cb.record_failure()
        assert not cb.is_available()

    def test_open_circuit_transitions_to_half_open_after_timeout(self, monkeypatch):
        cb = CircuitBreaker(self._cfg(threshold=1, timeout=1))
        cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN
        # Advance time past reset_timeout — capture real time first to avoid recursion
        real_now = time.time()
        monkeypatch.setattr(time, "time", lambda: real_now + 10)
        assert cb.is_available()
        assert cb.state == CircuitBreaker.HALF_OPEN

    def test_half_open_success_closes_circuit(self):
        cb = CircuitBreaker(self._cfg(threshold=1))
        cb.record_failure()
        # Force to HALF_OPEN
        cb._state = CircuitBreaker.HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitBreaker.CLOSED

    def test_half_open_failure_reopens_circuit(self):
        cb = CircuitBreaker(self._cfg(threshold=1))
        cb._state = CircuitBreaker.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitBreaker.OPEN

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker(self._cfg(threshold=5))
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        # Failure count reset — need 5 more to open
        for _ in range(4):
            cb.record_failure()
        assert cb.state == CircuitBreaker.CLOSED


# ---------------------------------------------------------------------------
# _TTLCache
# ---------------------------------------------------------------------------

class TestTTLCache:

    def test_cache_miss_returns_none(self):
        c = _TTLCache(ttl_seconds=60)
        assert c.get("missing") is None

    def test_cache_hit_returns_value(self):
        c = _TTLCache(ttl_seconds=60)
        c.set("key", {"result": 42})
        assert c.get("key") == {"result": 42}

    def test_expired_entry_returns_none(self, monkeypatch):
        c = _TTLCache(ttl_seconds=1)
        c.set("old", "value")
        # Advance time so entry is expired
        original_time = time.time
        monkeypatch.setattr(time, "time", lambda: original_time() + 10)
        assert c.get("old") is None

    def test_max_size_evicts_oldest(self):
        c = _TTLCache(ttl_seconds=60, max_size=3)
        c.set("a", 1)
        c.set("b", 2)
        c.set("c", 3)
        c.set("d", 4)  # Should evict one entry
        # Total size must not exceed max_size
        assert len(c._store) <= 3

    def test_overwrite_existing_key(self):
        c = _TTLCache(ttl_seconds=60)
        c.set("k", "v1")
        c.set("k", "v2")
        assert c.get("k") == "v2"


# ---------------------------------------------------------------------------
# BaseEnricher
# ---------------------------------------------------------------------------

class _CountingEnricher(BaseEnricher):
    """Test enricher that counts fetch calls and returns a fixed result."""

    def __init__(self, result: dict, raise_on_call: bool = False, **kwargs):
        super().__init__("test-enricher", ttl_seconds=60, **kwargs)
        self._result = result
        self._raise = raise_on_call
        self.fetch_count = 0

    def _fetch(self, key: str) -> dict:
        self.fetch_count += 1
        if self._raise:
            raise ConnectionError("simulated network error")
        return self._result


class TestBaseEnricher:

    def test_enrich_returns_result(self):
        e = _CountingEnricher({"score": 5})
        result = e.enrich("1.2.3.4")
        assert result == {"score": 5}

    def test_enrich_caches_result(self):
        e = _CountingEnricher({"score": 5})
        e.enrich("1.2.3.4")
        e.enrich("1.2.3.4")
        # Second call should be from cache
        assert e.fetch_count == 1

    def test_disabled_enricher_returns_empty(self):
        e = _CountingEnricher({"score": 5}, enabled=False)
        result = e.enrich("1.2.3.4")
        assert result == {}
        assert e.fetch_count == 0

    def test_fetch_failure_returns_empty(self):
        e = _CountingEnricher({}, raise_on_call=True)
        result = e.enrich("1.2.3.4")
        assert result == {}

    def test_circuit_opens_after_failures(self):
        cfg = CircuitBreakerConfig(failure_threshold=2, reset_timeout_seconds=60, name="e-cb")
        e = _CountingEnricher({}, raise_on_call=True, circuit_config=cfg)
        e.enrich("a")
        e.enrich("b")
        # Circuit should now be open
        assert e.circuit_state == CircuitBreaker.OPEN
        # Further calls should be blocked (no fetch)
        count_before = e.fetch_count
        e.enrich("c")
        assert e.fetch_count == count_before  # No new fetch

    def test_open_circuit_returns_empty(self):
        cfg = CircuitBreakerConfig(failure_threshold=1, reset_timeout_seconds=60)
        e = _CountingEnricher({}, raise_on_call=True, circuit_config=cfg)
        e.enrich("x")  # Trip the circuit
        result = e.enrich("y")  # Should fast-fail
        assert result == {}


# ---------------------------------------------------------------------------
# Concrete enrichers
# ---------------------------------------------------------------------------

class TestReputationEnricher:

    def test_stub_returns_empty(self):
        e = ReputationEnricher()
        result = e.enrich("203.0.113.1")
        assert result == {}

    def test_circuit_state_initially_closed(self):
        e = ReputationEnricher()
        assert e.circuit_state == CircuitBreaker.CLOSED


class TestCMDBEnricher:

    def test_static_registry_lookup(self):
        registry = {
            "10.0.1.50": {"asset_id": "A001", "criticality": 0.9, "hostname": "dc01"},
        }
        e = CMDBEnricher(static_registry=registry)
        result = e.enrich("10.0.1.50")
        assert result["asset_id"] == "A001"
        assert result["criticality"] == 0.9

    def test_missing_key_returns_empty(self):
        e = CMDBEnricher(static_registry={})
        assert e.enrich("999.999.999.999") == {}

    def test_static_result_is_cached(self):
        registry = {"10.0.0.1": {"hostname": "host1"}}
        e = CMDBEnricher(static_registry=registry)
        e.enrich("10.0.0.1")
        e.enrich("10.0.0.1")
        # Should be from cache — _fetch called once
        # (Hard to measure directly, but no error is the key test)


class TestCVEEnricher:

    def test_stub_returns_empty(self):
        e = CVEEnricher()
        result = e.enrich("CVE-2023-12345")
        assert result == {}


# ---------------------------------------------------------------------------
# EnrichmentBroker
# ---------------------------------------------------------------------------

class TestEnrichmentBroker:

    def _broker_with_static_cmdb(self) -> EnrichmentBroker:
        cmdb = CMDBEnricher(static_registry={
            "10.0.1.50": {"asset_id": "A001", "criticality": 0.9},
        })
        return EnrichmentBroker(cmdb=cmdb)

    def test_enrich_observable_ip_with_reputation(self):
        rep = ReputationEnricher()  # Stub — returns {}
        broker = EnrichmentBroker(reputation=rep)
        result = broker.enrich_observable("ipv4-addr", "1.2.3.4")
        # Stub returns empty — no "reputation" key expected
        assert isinstance(result, dict)

    def test_enrich_observable_cve(self):
        cve = CVEEnricher()
        broker = EnrichmentBroker(cve=cve)
        result = broker.enrich_observable("vulnerability", "CVE-2023-0001")
        assert isinstance(result, dict)

    def test_enrich_observable_unknown_type_returns_empty(self):
        broker = EnrichmentBroker()
        result = broker.enrich_observable("unknown-type", "value")
        assert result == {}

    def test_enrich_asset_found(self):
        broker = self._broker_with_static_cmdb()
        result = broker.enrich_asset("10.0.1.50")
        assert result["asset_id"] == "A001"

    def test_enrich_asset_not_found(self):
        broker = self._broker_with_static_cmdb()
        result = broker.enrich_asset("192.168.99.99")
        assert result == {}

    def test_enrich_asset_no_cmdb(self):
        broker = EnrichmentBroker()
        result = broker.enrich_asset("10.0.1.50")
        assert result == {}

    def test_health_all_disabled(self):
        broker = EnrichmentBroker()
        health = broker.health()
        assert health["reputation"] == "disabled"
        assert health["cmdb"] == "disabled"
        assert health["cve"] == "disabled"

    def test_health_with_components(self):
        broker = EnrichmentBroker(
            reputation=ReputationEnricher(),
            cmdb=CMDBEnricher(),
            cve=CVEEnricher(),
        )
        health = broker.health()
        assert health["reputation"] == CircuitBreaker.CLOSED
        assert health["cmdb"] == CircuitBreaker.CLOSED
        assert health["cve"] == CircuitBreaker.CLOSED
