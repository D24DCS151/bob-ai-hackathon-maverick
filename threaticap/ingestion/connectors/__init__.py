# threaticap/ingestion/connectors/__init__.py
"""
Source connector implementations.

Connectors:
    SIEMConnector          — SIEM alerts (JSON, CEF, LEEF)
    EDRConnector           — EDR/sensor events (JSON, CSV)
    IntelReportConnector   — Intelligence reports (JSON + free-text)
    STIXConnector          — STIX 2.x bundles (file or TAXII feed)
    SatelliteISRConnector  — Satellite/ISR/SIGINT/ELINT feeds (Phase 2)
"""
from .siem_connector import SiemConnector as SIEMConnector
from .edr_connector import EdrConnector as EDRConnector
from .intel_report_connector import IntelReportConnector
from .stix_connector import StixConnector as STIXConnector
from .satellite_connector import SatelliteISRConnector

__all__ = [
    "SIEMConnector",
    "EDRConnector",
    "IntelReportConnector",
    "STIXConnector",
    "SatelliteISRConnector",
]
