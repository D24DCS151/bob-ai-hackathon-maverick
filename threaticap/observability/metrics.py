"""
Prometheus-style metrics for THREATICAP operational observability.

Exposes metrics at /api/v1/metrics/prometheus in text format
compatible with Prometheus scraping.

Metrics tracked:
- threaticap_alerts_ingested_total{source_type}
- threaticap_alerts_deduplicated_total
- threaticap_threats_created_total{priority_tier}
- threaticap_correlation_duration_seconds (histogram)
- threaticap_bluf_generated_total
- threaticap_enrichment_calls_total{enricher, status}
- threaticap_api_requests_total{method, path, status_code}
- threaticap_api_request_duration_seconds{method, path}
- threaticap_stream_messages_processed_total
- threaticap_circuit_breaker_state{enricher}

For production: use the prometheus-client library:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest
    This implementation provides a compatible lightweight version.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

try:
    from prometheus_client import (
        Counter, Histogram, Gauge,
        generate_latest, CONTENT_TYPE_LATEST,
        CollectorRegistry,
    )
    _HAS_PROMETHEUS = True
    _REGISTRY = CollectorRegistry()

    # ---- Counters --------------------------------------------------------
    ALERTS_INGESTED = Counter(
        "threaticap_alerts_ingested_total",
        "Total alerts ingested",
        ["source_type"],
        registry=_REGISTRY,
    )
    ALERTS_DEDUPLICATED = Counter(
        "threaticap_alerts_deduplicated_total",
        "Total duplicate alerts suppressed",
        registry=_REGISTRY,
    )
    THREATS_CREATED = Counter(
        "threaticap_threats_created_total",
        "Total correlated threats created",
        ["priority_tier"],
        registry=_REGISTRY,
    )
    BLUF_GENERATED = Counter(
        "threaticap_bluf_generated_total",
        "Total BLUF reports generated",
        registry=_REGISTRY,
    )
    API_REQUESTS = Counter(
        "threaticap_api_requests_total",
        "Total API requests",
        ["method", "path", "status_code"],
        registry=_REGISTRY,
    )
    ENRICHMENT_CALLS = Counter(
        "threaticap_enrichment_calls_total",
        "Total enrichment API calls",
        ["enricher", "status"],
        registry=_REGISTRY,
    )
    STREAM_PROCESSED = Counter(
        "threaticap_stream_messages_processed_total",
        "Total stream messages processed",
        registry=_REGISTRY,
    )

    # ---- Histograms ------------------------------------------------------
    CORRELATION_DURATION = Histogram(
        "threaticap_correlation_duration_seconds",
        "Time spent in correlation engine",
        buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0],
        registry=_REGISTRY,
    )
    API_REQUEST_DURATION = Histogram(
        "threaticap_api_request_duration_seconds",
        "API request duration",
        ["method", "path"],
        buckets=[0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
        registry=_REGISTRY,
    )

    # ---- Gauges ----------------------------------------------------------
    ALERTS_STORED = Gauge(
        "threaticap_alerts_stored",
        "Current number of alerts in store",
        registry=_REGISTRY,
    )
    THREATS_STORED = Gauge(
        "threaticap_threats_stored",
        "Current number of threats in store",
        registry=_REGISTRY,
    )

except ImportError:
    _HAS_PROMETHEUS = False


# ---------------------------------------------------------------------------
# Lightweight fallback metrics (no external dependency)
# ---------------------------------------------------------------------------

class _SimpleMetrics:
    """
    Thread-safe in-process metrics store.
    Used when prometheus-client is not installed.
    Compatible with /api/v1/metrics JSON endpoint.
    """

    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._start_time = time.time()

    def inc(self, name: str, labels: dict[str, str] | None = None, value: int = 1) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] += value

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._key(name, labels)
        with self._lock:
            self._histograms[key].append(value)
            # Keep only last 1000 observations
            if len(self._histograms[key]) > 1000:
                self._histograms[key] = self._histograms[key][-1000:]

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            histogram_summary = {}
            for k, vals in self._histograms.items():
                if vals:
                    histogram_summary[k] = {
                        "count": len(vals),
                        "sum": sum(vals),
                        "p50": self._percentile(vals, 50),
                        "p95": self._percentile(vals, 95),
                        "p99": self._percentile(vals, 99),
                    }
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": histogram_summary,
                "uptime_seconds": int(time.time() - self._start_time),
            }

    def to_prometheus_text(self) -> str:
        """Generate Prometheus-compatible text exposition format."""
        lines = []
        with self._lock:
            for key, val in sorted(self._counters.items()):
                metric_name, label_str = self._split_key(key)
                lines.append(f"# TYPE {metric_name} counter")
                lines.append(f"{metric_name}{{{label_str}}} {val}")
            for key, val in sorted(self._gauges.items()):
                metric_name, label_str = self._split_key(key)
                lines.append(f"# TYPE {metric_name} gauge")
                lines.append(f"{metric_name}{{{label_str}}} {val}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _key(name: str, labels: dict[str, str] | None) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}[{label_str}]"

    @staticmethod
    def _split_key(key: str) -> tuple[str, str]:
        if "[" not in key:
            return key, ""
        name, rest = key.split("[", 1)
        return name, rest.rstrip("]")

    @staticmethod
    def _percentile(vals: list[float], p: int) -> float:
        if not vals:
            return 0.0
        sorted_vals = sorted(vals)
        idx = int(len(sorted_vals) * p / 100)
        return sorted_vals[min(idx, len(sorted_vals) - 1)]


# Module-level metrics instance
_metrics = _SimpleMetrics()


def get_metrics() -> _SimpleMetrics:
    return _metrics


# ---------------------------------------------------------------------------
# Helper functions for use throughout the codebase
# ---------------------------------------------------------------------------

def record_alert_ingested(source_type: str) -> None:
    _metrics.inc("threaticap_alerts_ingested_total", {"source_type": source_type})
    if _HAS_PROMETHEUS:
        ALERTS_INGESTED.labels(source_type=source_type).inc()


def record_alert_deduplicated() -> None:
    _metrics.inc("threaticap_alerts_deduplicated_total")
    if _HAS_PROMETHEUS:
        ALERTS_DEDUPLICATED.inc()


def record_threat_created(priority_tier: str) -> None:
    _metrics.inc("threaticap_threats_created_total", {"priority_tier": priority_tier})
    if _HAS_PROMETHEUS:
        THREATS_CREATED.labels(priority_tier=priority_tier).inc()


def record_bluf_generated() -> None:
    _metrics.inc("threaticap_bluf_generated_total")
    if _HAS_PROMETHEUS:
        BLUF_GENERATED.inc()


def record_api_request(method: str, path: str, status_code: int, duration: float) -> None:
    # Normalise path parameters to avoid high cardinality
    normalised_path = _normalise_path(path)
    _metrics.inc(
        "threaticap_api_requests_total",
        {"method": method, "path": normalised_path, "status_code": str(status_code)}
    )
    _metrics.observe(
        "threaticap_api_request_duration_seconds",
        duration,
        {"method": method, "path": normalised_path}
    )
    if _HAS_PROMETHEUS:
        API_REQUESTS.labels(method=method, path=normalised_path, status_code=str(status_code)).inc()
        API_REQUEST_DURATION.labels(method=method, path=normalised_path).observe(duration)


def record_correlation_duration(duration_seconds: float) -> None:
    _metrics.observe("threaticap_correlation_duration_seconds", duration_seconds)
    if _HAS_PROMETHEUS:
        CORRELATION_DURATION.observe(duration_seconds)


def update_stored_counts(alerts: int, threats: int) -> None:
    _metrics.set_gauge("threaticap_alerts_stored", alerts)
    _metrics.set_gauge("threaticap_threats_stored", threats)
    if _HAS_PROMETHEUS:
        ALERTS_STORED.set(alerts)
        THREATS_STORED.set(threats)


def _normalise_path(path: str) -> str:
    """Replace UUIDs in paths to reduce metric cardinality."""
    import re
    uuid_pattern = re.compile(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
    )
    return uuid_pattern.sub("{id}", path)


def generate_prometheus_output() -> str:
    """Generate Prometheus text format output."""
    if _HAS_PROMETHEUS:
        return generate_latest(_REGISTRY).decode("utf-8")
    return _metrics.to_prometheus_text()
