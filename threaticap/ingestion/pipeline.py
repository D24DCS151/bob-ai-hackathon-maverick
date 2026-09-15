"""
Ingestion pipeline orchestrator.

Connects connectors → normaliser → deduplicator → enricher and
produces a clean stream of Alert objects ready for the correlation engine.

Design:
- Supports both batch (list of pre-fetched raw payloads) and streaming modes.
- Emits an AuditRecord for every significant event.
- Configurable via IngestionConfig (no hard-coded parameters).
- Thread-safe for concurrent connector ingestion (one thread per connector).
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable

from threaticap.models.alert import Alert, AlertStatus
from threaticap.models.audit import AuditEventType, AuditRecord
from threaticap.ingestion.base_connector import BaseConnector, IngestResult
from threaticap.ingestion.normaliser import AlertNormaliser
from threaticap.ingestion.deduplicator import AlertDeduplicator
from threaticap.ingestion.enricher import AlertEnricher

logger = logging.getLogger(__name__)


@dataclass
class IngestionConfig:
    extract_iocs_from_text: bool = True
    dedup_cache_size: int = 50_000
    dedup_ttl_seconds: int = 3600
    max_concurrent_connectors: int = 4
    asset_registry: dict[str, Any] = field(default_factory=dict)
    geoip_enabled: bool = False
    reputation_enabled: bool = False


class IngestionPipeline:
    """
    Orchestrates the ingest of alerts from multiple connectors.

    Usage:
        pipeline = IngestionPipeline(config)
        pipeline.register_connector(siem_connector)
        pipeline.register_connector(edr_connector)
        alerts = pipeline.run_batch()
    """

    def __init__(
        self,
        config: IngestionConfig | None = None,
        audit_callback: Callable[[AuditRecord], None] | None = None,
    ) -> None:
        self._config = config or IngestionConfig()
        self._connectors: list[BaseConnector] = []
        self._normaliser = AlertNormaliser(
            extract_iocs_from_text=self._config.extract_iocs_from_text
        )
        self._deduplicator = AlertDeduplicator(
            cache_size=self._config.dedup_cache_size,
            ttl_seconds=self._config.dedup_ttl_seconds,
        )
        self._enricher = AlertEnricher(
            asset_registry=self._config.asset_registry,
            geoip_enabled=self._config.geoip_enabled,
            reputation_enabled=self._config.reputation_enabled,
        )
        self._audit_callback = audit_callback
        self._lock = threading.Lock()

    def register_connector(self, connector: BaseConnector) -> None:
        with self._lock:
            self._connectors.append(connector)
        logger.info("Registered connector: %s", connector.connector_id)

    def ingest_alerts(self, raw_alerts: list[dict[str, Any]], connector: BaseConnector) -> IngestResult:
        """
        Ingest a pre-fetched batch of raw payloads from a single connector.

        This is the primary entry point for both batch and streaming modes.
        Streaming callers should pass small batches (e.g. 1–100 items).
        """
        result = IngestResult(connector_id=connector.connector_id)

        for raw in raw_alerts:
            result.total_received += 1
            try:
                alert = connector.normalise(raw)
                if alert is None:
                    continue

                # Normalise
                alert = self._normaliser.normalise(alert)
                result.normalised += 1

                # Dedup
                alert, is_dup = self._deduplicator.process(alert)
                if is_dup:
                    result.deduplicated += 1
                    self._emit_audit(AuditEventType.ALERT_DEDUPLICATED, alert_id=alert.alert_id,
                                     summary=f"Duplicate alert suppressed: {alert.source_ref}")
                    continue

                # Enrich
                alert = self._enricher.enrich(alert)
                result.enriched += 1

                # Mark as ingested
                alert = alert.model_copy(update={"status": AlertStatus.INGESTED})
                result.alerts.append(alert)

                self._emit_audit(
                    AuditEventType.ALERT_INGESTED,
                    alert_id=alert.alert_id,
                    summary=f"Alert ingested from {alert.source_id}: {alert.title}",
                    detail={"severity": alert.severity, "source_ref": alert.source_ref},
                )

            except Exception as exc:
                result.errors += 1
                result.error_details.append(str(exc))
                logger.error(
                    "Ingestion error from connector %s: %s",
                    connector.connector_id, exc, exc_info=True
                )

        logger.info(
            "Ingestion complete [%s]: received=%d normalised=%d deduped=%d "
            "enriched=%d errors=%d",
            connector.connector_id,
            result.total_received, result.normalised,
            result.deduplicated, result.enriched, result.errors,
        )
        return result

    def run_batch(self) -> list[Alert]:
        """
        Run all registered connectors concurrently and collect all alerts.
        Returns deduplicated, enriched Alert objects sorted by event_time (newest first).
        """
        all_alerts: list[Alert] = []

        with ThreadPoolExecutor(
            max_workers=self._config.max_concurrent_connectors,
            thread_name_prefix="ingest-connector",
        ) as executor:
            future_map = {}
            for connector in self._connectors:
                fut = executor.submit(self._run_single_connector, connector)
                future_map[fut] = connector.connector_id

            for future in as_completed(future_map):
                connector_id = future_map[future]
                try:
                    result: IngestResult = future.result()
                    all_alerts.extend(result.alerts)
                    if result.errors > 0:
                        logger.warning(
                            "Connector %s completed with %d error(s)",
                            connector_id, result.errors
                        )
                except Exception as exc:
                    logger.error("Connector %s failed: %s", connector_id, exc, exc_info=True)

        all_alerts.sort(key=lambda a: a.event_time, reverse=True)
        logger.info("run_batch complete: %d total alerts collected", len(all_alerts))
        return all_alerts

    def _run_single_connector(self, connector: BaseConnector) -> IngestResult:
        """Run a single connector end-to-end."""
        raw_batch: list[dict[str, Any]] = []
        with connector:
            for raw in connector.fetch_raw():
                raw_batch.append(raw)
        return self.ingest_alerts(raw_batch, connector)

    def _emit_audit(
        self,
        event_type: AuditEventType,
        alert_id: str | None = None,
        threat_id: str | None = None,
        summary: str = "",
        detail: dict[str, Any] | None = None,
    ) -> None:
        if self._audit_callback is None:
            return
        record = AuditRecord(
            event_type=event_type,
            component="IngestionPipeline",
            alert_id=alert_id,
            threat_id=threat_id,
            summary=summary,
            detail=detail or {},
        )
        try:
            self._audit_callback(record)
        except Exception as exc:
            logger.error("Audit callback failed: %s", exc)

    @property
    def dedup_stats(self) -> dict[str, int]:
        return self._deduplicator.stats
