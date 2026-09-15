# threaticap/models/__init__.py
"""
Core data models for the Threat Intelligence Correlation & Alert Prioritisation
(THREATICAP) system.

All models use Pydantic v2 for strict validation, serialisation, and schema
generation. These models form the canonical data contract between every layer
of the pipeline.
"""
from .alert import Alert, AlertSeverity, AlertSource, AlertStatus, Observable, ObservableType
from .correlated_threat import CorrelatedThreat, CorrelationMethod, ThreatStatus
from .mitre import MitreMapping, MitreTactic, MitreTechnique
from .priority import PriorityScore, PriorityTier, ScoreComponent
from .bluf import BlufReport, BlufSection, ConfidenceLevel
from .audit import AuditRecord, AuditEventType
from .feedback import AnalystFeedback, Verdict

__all__ = [
    "Alert",
    "AlertSeverity",
    "AlertSource",
    "AlertStatus",
    "Observable",
    "ObservableType",
    "CorrelatedThreat",
    "CorrelationMethod",
    "ThreatStatus",
    "MitreMapping",
    "MitreTactic",
    "MitreTechnique",
    "PriorityScore",
    "PriorityTier",
    "ScoreComponent",
    "BlufReport",
    "BlufSection",
    "ConfidenceLevel",
    "AuditRecord",
    "AuditEventType",
    "AnalystFeedback",
    "Verdict",
]
