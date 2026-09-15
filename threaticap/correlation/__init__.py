"""
Correlation engine — groups related alerts into CorrelatedThreat objects.

Architecture:
    CorrelationEngine
    ├── IOCCorrelator       — matches shared observables across alerts
    ├── TemporalCorrelator  — groups alerts within a time window
    ├── AssetCorrelator     — groups alerts targeting the same assets
    ├── BehaviourCorrelator — matches MITRE technique sequences
    └── FalsePositiveFilter — reduces false positive probability score

Each correlator is an independent strategy; the engine runs them in order
and merges results. All decisions are logged to the audit trail.
"""
from .engine import CorrelationEngine, CorrelationConfig
from .ioc_correlator import IOCCorrelator
from .temporal_correlator import TemporalCorrelator
from .asset_correlator import AssetCorrelator
from .behaviour_correlator import BehaviourCorrelator
from .fp_filter import FalsePositiveFilter
from .graph_correlator import AttackGraph, _HAS_NX

__all__ = [
    "CorrelationEngine",
    "CorrelationConfig",
    "IOCCorrelator",
    "TemporalCorrelator",
    "AssetCorrelator",
    "BehaviourCorrelator",
    "FalsePositiveFilter",
    "AttackGraph",
    "_HAS_NX",
]
