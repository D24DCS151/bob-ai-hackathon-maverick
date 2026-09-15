"""
Pipeline orchestrator — wires all components together and provides a clean
single entry point for running the full processing pipeline.

Usage:
    from threaticap.pipeline import ThreatPipeline, PipelineConfig
    pipeline = ThreatPipeline.from_config_file("config/config.yaml")
    results = pipeline.run(raw_alerts_by_connector)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from threaticap.models.alert import Alert
from threaticap.models.audit import AuditRecord
from threaticap.models.bluf import BlufReport
from threaticap.models.correlated_threat import CorrelatedThreat
from threaticap.models.priority import PriorityScore
from threaticap.correlation.engine import CorrelationEngine, CorrelationConfig
from threaticap.mapping.mitre_mapper import MitreMapper
from threaticap.scoring.prioritisation_engine import PrioritisationEngine, PrioritisationConfig
from threaticap.reporting.bluf_generator import BlufGenerator
from threaticap.storage.repositories import (
    BaseAlertRepository,
    BaseThreatRepository,
    BaseAuditRepository,
    BaseReportRepository,
    InMemoryAlertRepository,
    InMemoryThreatRepository,
    InMemoryAuditRepository,
    InMemoryReportRepository,
)

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Summary of a single pipeline run."""
    alerts_ingested: int = 0
    threats_created: int = 0
    threats_critical: int = 0
    threats_high: int = 0
    threats_medium: int = 0
    threats_low: int = 0
    reports_generated: int = 0
    errors: list[str] = field(default_factory=list)

    threats: list[CorrelatedThreat] = field(default_factory=list)
    scores: dict[str, PriorityScore] = field(default_factory=dict)
    reports: list[BlufReport] = field(default_factory=list)


class ThreatPipeline:
    """
    Full processing pipeline:
        Alerts → Correlation → MITRE Mapping → Prioritisation → BLUF Generation
    """

    def __init__(
        self,
        correlation_config: CorrelationConfig | None = None,
        prioritisation_config: PrioritisationConfig | None = None,
        mitre_kb_path: str | Path | None = None,
        alert_repo: BaseAlertRepository | None = None,
        threat_repo: BaseThreatRepository | None = None,
        audit_repo: BaseAuditRepository | None = None,
        report_repo: BaseReportRepository | None = None,
    ) -> None:
        # Repositories
        self._alert_repo = alert_repo or InMemoryAlertRepository()
        self._threat_repo = threat_repo or InMemoryThreatRepository()
        self._audit_repo = audit_repo or InMemoryAuditRepository()
        self._report_repo = report_repo or InMemoryReportRepository()

        # Audit callback — wires all components to the same audit store
        def _audit(record: AuditRecord) -> None:
            self._audit_repo.append(record)

        # Components
        self._correlator = CorrelationEngine(
            config=correlation_config,
            audit_callback=_audit,
        )
        self._mapper = MitreMapper(knowledge_base_path=mitre_kb_path)
        self._scorer = PrioritisationEngine(
            config=prioritisation_config,
            audit_callback=_audit,
        )
        self._bluf_gen = BlufGenerator(audit_callback=_audit)

    @classmethod
    def from_config_file(cls, config_path: str | Path) -> "ThreatPipeline":
        """
        Instantiate a ThreatPipeline from a YAML configuration file.

        Expected structure (config.yaml):
            correlation:
                temporal_window_seconds: 3600
                whitelist_ips: []
                ...
            scoring:
                weights:
                    severity: 0.30
                    ...
                thresholds:
                    critical: 80
                    ...
            mitre:
                knowledge_base_path: config/mitre_attack_kb.yaml
        """
        import yaml
        path = Path(config_path)
        if not path.exists():
            logger.warning("Config file not found: %s — using defaults", path)
            return cls()

        with open(path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}

        # ---- Correlation config ----------------------------------------
        corr_raw = cfg.get("correlation", {})
        corr_config = CorrelationConfig(
            ioc_enabled=corr_raw.get("ioc_enabled", True),
            temporal_enabled=corr_raw.get("temporal_enabled", True),
            asset_enabled=corr_raw.get("asset_enabled", True),
            behaviour_enabled=corr_raw.get("behaviour_enabled", True),
            temporal_window_seconds=corr_raw.get("temporal_window_seconds", 3600),
            min_group_confidence=corr_raw.get("min_group_confidence", 0.30),
            whitelist_ips=corr_raw.get("whitelist_ips", []),
            whitelist_hostnames=corr_raw.get("whitelist_hostnames", []),
            whitelist_domains=corr_raw.get("whitelist_domains", []),
            config_version=corr_raw.get("config_version", "1.0"),
        )

        # ---- Scoring config --------------------------------------------
        from threaticap.scoring.prioritisation_engine import ScoringWeights, ScoringThresholds
        scoring_raw = cfg.get("scoring", {})
        weights_raw = scoring_raw.get("weights", {})
        thresholds_raw = scoring_raw.get("thresholds", {})

        weights = ScoringWeights(
            severity=weights_raw.get("severity", 0.30),
            confidence=weights_raw.get("confidence", 0.25),
            source_reliability=weights_raw.get("source_reliability", 0.15),
            asset_criticality=weights_raw.get("asset_criticality", 0.20),
            temporal_urgency=weights_raw.get("temporal_urgency", 0.10),
        )
        thresholds = ScoringThresholds(
            critical=thresholds_raw.get("critical", 80.0),
            high=thresholds_raw.get("high", 60.0),
            medium=thresholds_raw.get("medium", 35.0),
            config_name=thresholds_raw.get("config_name", "default-v1"),
        )
        prio_config = PrioritisationConfig(
            weights=weights,
            thresholds=thresholds,
            urgency_max_age_hours=scoring_raw.get("urgency_max_age_hours", 72.0),
        )

        # ---- MITRE knowledge base path ---------------------------------
        mitre_raw = cfg.get("mitre", {})
        kb_path = mitre_raw.get("knowledge_base_path", "config/mitre_attack_kb.yaml")
        stix_bundle_path = mitre_raw.get("stix_bundle_path")  # Optional full ATT&CK bundle

        # ---- Storage backend -------------------------------------------
        storage_raw = cfg.get("storage", {})
        backend = storage_raw.get("backend", "memory")
        alert_repo = threat_repo = audit_repo = report_repo = None

        if backend == "postgresql":
            import os
            from threaticap.storage.postgres_repositories import create_postgres_repositories
            dsn = os.environ.get(
                "POSTGRES_DSN",
                storage_raw.get("postgresql_dsn", "")
            )
            if dsn:
                (alert_repo, threat_repo, audit_repo, report_repo, _) = \
                    create_postgres_repositories(
                        dsn=dsn,
                        pool_min=storage_raw.get("pool_min", 2),
                        pool_max=storage_raw.get("pool_max", 10),
                    )
                logger.info("Using PostgreSQL storage backend")
            else:
                logger.warning("PostgreSQL backend configured but POSTGRES_DSN not set — falling back to memory")

        pipeline = cls(
            correlation_config=corr_config,
            prioritisation_config=prio_config,
            mitre_kb_path=kb_path,
            alert_repo=alert_repo,
            threat_repo=threat_repo,
            audit_repo=audit_repo,
            report_repo=report_repo,
        )

        # Load STIX bundle if specified
        if stix_bundle_path:
            pipeline._mapper.load_stix_bundle(Path(stix_bundle_path))

        return pipeline

    def run(self, alerts: list[Alert]) -> PipelineResult:
        """
        Execute the full pipeline on a batch of ingested alerts.

        Returns a PipelineResult with all created threats, scores, and reports.
        """
        result = PipelineResult(alerts_ingested=len(alerts))

        if not alerts:
            return result

        # ---- Persist alerts -------------------------------------------
        self._alert_repo.save_batch(alerts)
        alert_lookup: dict[str, Alert] = {a.alert_id: a for a in alerts}

        # ---- Correlation -----------------------------------------------
        logger.info("Running correlation on %d alerts...", len(alerts))
        threats = self._correlator.correlate(alerts)
        result.threats_created = len(threats)

        for threat in threats:
            # ---- MITRE mapping ----------------------------------------
            mitre_mapping = self._mapper.map_techniques(threat.mitre_technique_ids)

            # ---- Prioritisation ---------------------------------------
            score = self._scorer.score(threat, alert_lookup)

            # ---- Tier counters ----------------------------------------
            tier = score.priority_tier.value
            if tier == "CRITICAL":
                result.threats_critical += 1
            elif tier == "HIGH":
                result.threats_high += 1
            elif tier == "MEDIUM":
                result.threats_medium += 1
            else:
                result.threats_low += 1

            result.threats.append(threat)
            result.scores[threat.threat_id] = score

            # ---- BLUF generation -------------------------------------
            try:
                bluf = self._bluf_gen.generate(
                    threat=threat,
                    priority_score=score,
                    mitre_mapping=mitre_mapping,
                    alert_lookup=alert_lookup,
                )
                result.reports.append(bluf)
                result.reports_generated += 1
                self._report_repo.save(bluf)
            except Exception as exc:
                logger.error(
                    "BLUF generation failed for threat %s: %s",
                    threat.threat_id[:8], exc, exc_info=True
                )
                result.errors.append(f"BLUF error for {threat.threat_id}: {exc}")

            # ---- Persist threat + score --------------------------------
            self._threat_repo.save(threat, score)

        # Sort results by score descending
        if result.threats and result.scores:
            result.threats.sort(
                key=lambda t: result.scores[t.threat_id].final_score
                if t.threat_id in result.scores else 0.0,
                reverse=True,
            )
        result.reports.sort(key=lambda r: r.priority_score, reverse=True)

        logger.info(
            "Pipeline run complete: %d alerts -> %d threats "
            "(CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d) %d reports",
            len(alerts), result.threats_created,
            result.threats_critical, result.threats_high,
            result.threats_medium, result.threats_low,
            result.reports_generated,
        )
        return result

    # ---- Accessor properties for FastAPI service ----------------------

    @property
    def alert_repo(self) -> BaseAlertRepository:
        return self._alert_repo

    @property
    def threat_repo(self) -> BaseThreatRepository:
        return self._threat_repo

    @property
    def audit_repo(self) -> BaseAuditRepository:
        return self._audit_repo

    @property
    def report_repo(self) -> BaseReportRepository:
        return self._report_repo

    @property
    def mitre_mapper(self) -> MitreMapper:
        return self._mapper
