"""
Ingestion layer — base connector interface and pipeline orchestrator.
"""
from .base_connector import BaseConnector, ConnectorConfig, IngestResult
from .normaliser import AlertNormaliser
from .deduplicator import AlertDeduplicator
from .enricher import AlertEnricher
from .pipeline import IngestionPipeline
from .connectors.siem_connector import SiemConnector
from .connectors.edr_connector import EdrConnector
from .connectors.intel_report_connector import IntelReportConnector
from .connectors.stix_connector import StixConnector

__all__ = [
    "BaseConnector",
    "ConnectorConfig",
    "IngestResult",
    "AlertNormaliser",
    "AlertDeduplicator",
    "AlertEnricher",
    "IngestionPipeline",
    "SiemConnector",
    "EdrConnector",
    "IntelReportConnector",
    "StixConnector",
]
