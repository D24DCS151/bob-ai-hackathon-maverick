"""
Pluggable live enrichment interfaces.

Architecture:
    EnrichmentBroker
    ├── ReputationEnricher      — IP/domain/hash reputation
    ├── CMDBEnricher            — Asset criticality from CMDB API
    └── CVEEnricher             — Vulnerability context

Each enricher is independently pluggable — swap the stub with a real
implementation (VirusTotal, ServiceNow CMDB, NVD API, etc.) without
touching the broker or the pipeline.

Circuit breaker pattern:
    Each enricher has a circuit breaker that opens after consecutive
    failures, preventing cascading failures from external service outages.
    The system degrades gracefully (no enrichment) when circuits are open.

Caching:
    Results are cached in-process (TTL-based) and optionally in Redis/DB.
    Cache TTL is configurable per enricher type.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 5       # Consecutive failures to open circuit
    reset_timeout_seconds: int = 60  # Seconds before trying again (half-open)
    name: str = "circuit"


class CircuitBreaker:
    """
    Simple circuit breaker: CLOSED -> OPEN -> HALF_OPEN -> CLOSED

    CLOSED: requests pass through
    OPEN: requests fail fast (no external call)
    HALF_OPEN: one test request allowed — success closes, failure re-opens
    """

    CLOSED    = "CLOSED"
    OPEN      = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(self, config: CircuitBreakerConfig) -> None:
        self._config = config
        self._state = self.CLOSED
        self._failure_count = 0
        self._last_failure_time: float | None = None

    def is_available(self) -> bool:
        if self._state == self.CLOSED:
            return True
        if self._state == self.OPEN:
            if self._last_failure_time and (
                time.time() - self._last_failure_time > self._config.reset_timeout_seconds
            ):
                self._state = self.HALF_OPEN
                logger.info("Circuit %s entering HALF_OPEN state", self._config.name)
                return True
            return False
        return True  # HALF_OPEN

    def record_success(self) -> None:
        self._failure_count = 0
        if self._state == self.HALF_OPEN:
            self._state = self.CLOSED
            logger.info("Circuit %s closed (recovered)", self._config.name)

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.time()
        if self._failure_count >= self._config.failure_threshold:
            if self._state != self.OPEN:
                logger.warning(
                    "Circuit %s OPENED after %d failures",
                    self._config.name, self._failure_count
                )
            self._state = self.OPEN

    @property
    def state(self) -> str:
        return self._state


# ---------------------------------------------------------------------------
# TTL Cache
# ---------------------------------------------------------------------------

class _TTLCache:
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 10_000) -> None:
        self._store: dict[str, tuple[Any, float]] = {}
        self._ttl = ttl_seconds
        self._max = max_size

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, ts = entry
        if time.time() - ts > self._ttl:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        if len(self._store) >= self._max:
            # Evict oldest
            oldest = min(self._store, key=lambda k: self._store[k][1])
            del self._store[oldest]
        self._store[key] = (value, time.time())


# ---------------------------------------------------------------------------
# Base enricher interface
# ---------------------------------------------------------------------------

class BaseEnricher:
    """
    Abstract base for all live enrichment sources.

    Subclasses must implement _fetch(key: str) -> dict[str, Any].
    The circuit breaker and cache are handled by this base class.
    """

    def __init__(
        self,
        name: str,
        ttl_seconds: int = 3600,
        circuit_config: CircuitBreakerConfig | None = None,
        enabled: bool = True,
    ) -> None:
        self._name = name
        self._cache = _TTLCache(ttl_seconds=ttl_seconds)
        self._circuit = CircuitBreaker(
            circuit_config or CircuitBreakerConfig(name=name)
        )
        self._enabled = enabled

    def enrich(self, key: str) -> dict[str, Any]:
        """
        Look up enrichment for the given key.
        Returns {} on cache miss, circuit open, or fetch failure.
        """
        if not self._enabled:
            return {}

        # Check cache first
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        if not self._circuit.is_available():
            logger.debug(
                "Enricher %s circuit open — skipping lookup for %s", self._name, key[:30]
            )
            return {}

        try:
            result = self._fetch(key)
            self._cache.set(key, result)
            self._circuit.record_success()
            return result
        except Exception as exc:
            self._circuit.record_failure()
            logger.warning(
                "Enricher %s lookup failed for %s: %s",
                self._name, key[:30], exc
            )
            return {}

    def _fetch(self, key: str) -> dict[str, Any]:
        """Override in subclasses. Should raise on failure (triggers circuit breaker)."""
        return {}

    @property
    def circuit_state(self) -> str:
        return self._circuit.state


# ---------------------------------------------------------------------------
# Reputation enricher
# ---------------------------------------------------------------------------

class ReputationEnricher(BaseEnricher):
    """
    IP/domain/hash reputation lookup.

    Production implementation options:
    - VirusTotal API v3 (VTAPI key required)
    - MISP attribute lookup (MISP URL + auth key required)
    - AbuseIPDB (API key required)
    - Internal threat intelligence platform

    Stub returns empty dict — replace _fetch with real API call.
    """

    def __init__(
        self,
        api_key: str = "",
        provider: str = "stub",
        **kwargs: Any,
    ) -> None:
        super().__init__("reputation", ttl_seconds=1800, **kwargs)
        self._api_key = api_key
        self._provider = provider

    def _fetch(self, key: str) -> dict[str, Any]:
        """
        Fetch reputation data.

        Production example (VirusTotal):
            import httpx
            r = httpx.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{key}",
                headers={"x-apikey": self._api_key},
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": data["data"]["attributes"].get("reputation", 0),
                "provider": "virustotal",
            }
        """
        logger.debug("Reputation lookup stub for: %s", key[:30])
        return {}


# ---------------------------------------------------------------------------
# CMDB / Asset enricher
# ---------------------------------------------------------------------------

class CMDBEnricher(BaseEnricher):
    """
    Asset criticality and ownership lookup from CMDB.

    Production implementation options:
    - ServiceNow CMDB REST API
    - Device42
    - Internal asset management API

    Falls back to static asset_registry in config if CMDB is unavailable.
    """

    def __init__(
        self,
        cmdb_url: str = "",
        api_token: str = "",
        static_registry: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__("cmdb", ttl_seconds=3600, **kwargs)
        self._cmdb_url = cmdb_url
        self._api_token = api_token
        self._static = static_registry or {}

    def _fetch(self, key: str) -> dict[str, Any]:
        """
        Fetch asset context by IP, hostname, or asset ID.

        Production example (ServiceNow):
            import httpx
            r = httpx.get(
                f"{self._cmdb_url}/api/now/table/cmdb_ci_computer",
                params={"sysparm_query": f"ip_address={key}", "sysparm_limit": 1},
                headers={"Authorization": f"Bearer {self._api_token}"},
                timeout=10,
            )
            r.raise_for_status()
            records = r.json().get("result", [])
            if records:
                rec = records[0]
                return {
                    "asset_id": rec.get("sys_id"),
                    "hostname": rec.get("name"),
                    "criticality": float(rec.get("business_criticality", 0.5)),
                    "owner": rec.get("owned_by", {}).get("display_value"),
                    "classification": rec.get("classification"),
                    "network_segment": rec.get("u_network_segment"),
                }
            return {}
        """
        # Fall back to static registry
        if key in self._static:
            return self._static[key]
        logger.debug("CMDB lookup stub for: %s", key[:30])
        return {}


# ---------------------------------------------------------------------------
# CVE enricher
# ---------------------------------------------------------------------------

class CVEEnricher(BaseEnricher):
    """
    CVE/vulnerability context lookup.

    Production implementation options:
    - NIST NVD API v2 (free, rate-limited)
    - MITRE CVE database
    - Tenable.io / Qualys vulnerability management APIs
    """

    def __init__(self, nvd_api_key: str = "", **kwargs: Any) -> None:
        super().__init__("cve", ttl_seconds=86400, **kwargs)  # CVE data changes slowly
        self._api_key = nvd_api_key

    def _fetch(self, key: str) -> dict[str, Any]:
        """
        Fetch CVE details.

        Production example (NVD API v2):
            import httpx
            headers = {}
            if self._api_key:
                headers["apiKey"] = self._api_key
            r = httpx.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": key},
                headers=headers,
                timeout=15,
            )
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
            if vulns:
                cve = vulns[0]["cve"]
                metrics = cve.get("metrics", {})
                cvss_v3 = next(iter(metrics.get("cvssMetricV31", [])), {})
                return {
                    "cve_id": key,
                    "description": cve["descriptions"][0]["value"],
                    "cvss_score": cvss_v3.get("cvssData", {}).get("baseScore"),
                    "severity": cvss_v3.get("cvssData", {}).get("baseSeverity"),
                    "published": cve.get("published"),
                }
            return {}
        """
        logger.debug("CVE lookup stub for: %s", key)
        return {}


# ---------------------------------------------------------------------------
# Enrichment broker
# ---------------------------------------------------------------------------

class EnrichmentBroker:
    """
    Orchestrates all enrichment sources for a single alert.

    Runs enrichers in parallel (optional) and aggregates results.
    Designed for use in AlertEnricher._check_reputation() and pipeline.
    """

    def __init__(
        self,
        reputation: ReputationEnricher | None = None,
        cmdb: CMDBEnricher | None = None,
        cve: CVEEnricher | None = None,
    ) -> None:
        self._reputation = reputation
        self._cmdb = cmdb
        self._cve = cve

    def enrich_observable(self, obs_type: str, value: str) -> dict[str, Any]:
        """Look up enrichment for a single observable."""
        results: dict[str, Any] = {}

        if self._reputation and obs_type in ("ipv4-addr", "domain-name", "url", "file:hashes"):
            rep = self._reputation.enrich(value)
            if rep:
                results["reputation"] = rep

        if self._cve and obs_type == "vulnerability":
            cve_data = self._cve.enrich(value)
            if cve_data:
                results["cve"] = cve_data

        return results

    def enrich_asset(self, identifier: str) -> dict[str, Any]:
        """Look up asset context by IP or hostname."""
        if self._cmdb:
            return self._cmdb.enrich(identifier)
        return {}

    def health(self) -> dict[str, str]:
        """Return circuit breaker states for all enrichers."""
        return {
            "reputation": self._reputation.circuit_state if self._reputation else "disabled",
            "cmdb": self._cmdb.circuit_state if self._cmdb else "disabled",
            "cve": self._cve.circuit_state if self._cve else "disabled",
        }
