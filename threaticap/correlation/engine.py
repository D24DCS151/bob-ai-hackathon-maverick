"""
Correlation engine — orchestrates all correlators and produces CorrelatedThreat objects.

The engine uses Union-Find (disjoint set) to group alerts into clusters based
on pairwise correlation links. Each cluster becomes a CorrelatedThreat.

Algorithm:
    1. Run all correlators to get pairwise (alert_a, alert_b, confidence, method) links.
    2. Use Union-Find to build clusters of alerts connected by any link.
    3. For each cluster, aggregate evidence and compute overall confidence.
    4. Apply FP filter to each cluster.
    5. Emit CorrelatedThreat objects for clusters above the minimum confidence threshold.
    6. Single uncorrelated alerts become singleton CorrelatedThreat objects (low confidence).
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from threaticap.models.alert import Alert, AlertSeverity, AlertStatus, ObservableType
from threaticap.models.correlated_threat import (
    CorrelatedThreat,
    CorrelationMethod,
    EvidenceLink,
    ThreatStatus,
)
from threaticap.models.audit import AuditEventType, AuditRecord
from threaticap.correlation.ioc_correlator import IOCCorrelator
from threaticap.correlation.temporal_correlator import TemporalCorrelator
from threaticap.correlation.asset_correlator import AssetCorrelator
from threaticap.correlation.behaviour_correlator import BehaviourCorrelator
from threaticap.correlation.fp_filter import FalsePositiveFilter
from threaticap.correlation.graph_correlator import AttackGraph, _HAS_NX

logger = logging.getLogger(__name__)

SEVERITY_ORDER = [
    AlertSeverity.CRITICAL,
    AlertSeverity.HIGH,
    AlertSeverity.MEDIUM,
    AlertSeverity.LOW,
    AlertSeverity.INFO,
]


@dataclass
class CorrelationConfig:
    """Configuration-driven parameters for the correlation engine."""

    # Correlator enablement
    ioc_enabled: bool = True
    temporal_enabled: bool = True
    asset_enabled: bool = True
    behaviour_enabled: bool = True
    graph_enabled: bool = True      # NetworkX graph analysis (requires networkx)

    # Temporal window
    temporal_window_seconds: int = 3600

    # Minimum confidence to form a correlated group (vs. singleton)
    min_group_confidence: float = 0.30

    # FP filter configuration
    whitelist_ips: list[str] = field(default_factory=list)
    whitelist_hostnames: list[str] = field(default_factory=list)
    whitelist_domains: list[str] = field(default_factory=list)

    # Singleton alerts (no correlated peers) get a base confidence
    singleton_confidence: float = 0.20

    # Confidence boost for multi-signal corroboration
    multi_signal_boost: float = 0.08   # Per additional method beyond the first
    max_multi_signal_boost: float = 0.25

    # Graph centrality boost cap
    centrality_boost_cap: float = 0.10

    # Configuration version for audit trail
    config_version: str = "1.0"


class _UnionFind:
    """
    Weighted union-find with path compression.
    Used to group alerts into correlation clusters.
    """

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._rank: dict[str, int] = {}
        self._confidence: dict[str, float] = {}  # max confidence seen per root

    def add(self, x: str) -> None:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0
            self._confidence[x] = 0.0

    def find(self, x: str) -> str:
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])
        return self._parent[x]

    def union(self, x: str, y: str, confidence: float) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            self._confidence[rx] = max(self._confidence[rx], confidence)
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        self._confidence[rx] = max(self._confidence[rx], confidence)
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

    def get_max_confidence(self, x: str) -> float:
        return self._confidence.get(self.find(x), 0.0)

    def groups(self) -> dict[str, list[str]]:
        """Return dict mapping root → list of members."""
        clusters: dict[str, list[str]] = defaultdict(list)
        for x in self._parent:
            clusters[self.find(x)].append(x)
        return dict(clusters)


class CorrelationEngine:
    """
    Main correlation engine.

    Usage:
        engine = CorrelationEngine(config)
        threats = engine.correlate(alerts)
    """

    def __init__(
        self,
        config: CorrelationConfig | None = None,
        audit_callback: Callable[[AuditRecord], None] | None = None,
    ) -> None:
        self._config = config or CorrelationConfig()
        self._audit_callback = audit_callback

        self._ioc = IOCCorrelator() if self._config.ioc_enabled else None
        self._temporal = TemporalCorrelator(
            window_seconds=self._config.temporal_window_seconds
        ) if self._config.temporal_enabled else None
        self._asset = AssetCorrelator() if self._config.asset_enabled else None
        self._behaviour = BehaviourCorrelator() if self._config.behaviour_enabled else None
        self._fp_filter = FalsePositiveFilter(
            whitelist_ips=set(self._config.whitelist_ips),
            whitelist_hostnames=set(self._config.whitelist_hostnames),
            whitelist_domains=set(self._config.whitelist_domains),
        )

    def correlate(self, alerts: list[Alert]) -> list[CorrelatedThreat]:
        """
        Correlate a batch of alerts into CorrelatedThreat objects.

        Returns all threats including singletons. Singletons have
        correlation_confidence == config.singleton_confidence.
        """
        if not alerts:
            return []

        logger.info("Starting correlation of %d alerts", len(alerts))

        # ---- Step 1: Gather all pairwise links --------------------------
        all_links: list[dict[str, Any]] = []

        if self._ioc:
            links = self._ioc.correlate(alerts)
            logger.debug("IOC correlator produced %d links", len(links))
            all_links.extend(links)

        if self._temporal:
            links = self._temporal.correlate(alerts)
            logger.debug("Temporal correlator produced %d links", len(links))
            all_links.extend(links)

        if self._asset:
            links = self._asset.correlate(alerts)
            logger.debug("Asset correlator produced %d links", len(links))
            all_links.extend(links)

        if self._behaviour:
            links = self._behaviour.correlate(alerts)
            logger.debug("Behaviour correlator produced %d links", len(links))
            all_links.extend(links)

        # ---- Step 2: Filter to links above minimum confidence -----------
        significant_links = [
            lnk for lnk in all_links
            if lnk["confidence"] >= self._config.min_group_confidence
        ]

        # ---- Step 2b: Graph analysis (NetworkX) -------------------------
        attack_graph: AttackGraph | None = None
        graph_centrality: dict[str, float] = {}
        if self._config.graph_enabled and _HAS_NX and len(alerts) >= 2:
            try:
                attack_graph = AttackGraph()
                attack_graph.build_from_links(alerts, significant_links)
                graph_centrality = attack_graph.compute_node_centrality()
                logger.debug(
                    "Attack graph: %d nodes, %d edges",
                    attack_graph.node_count, attack_graph.edge_count
                )
            except Exception as exc:
                logger.warning("Graph analysis failed (non-fatal): %s", exc)
                attack_graph = None

        # ---- Step 3: Build clusters via Union-Find ----------------------
        uf = _UnionFind()
        alert_map: dict[str, Alert] = {a.alert_id: a for a in alerts}

        for a in alerts:
            uf.add(a.alert_id)

        # Aggregate links by pair; apply multi-signal boost for pairs
        # connected by multiple correlation methods (stronger evidence)
        pair_methods: dict[tuple[str, str], set[str]] = defaultdict(set)
        pair_best: dict[tuple[str, str], dict[str, Any]] = {}

        for link in significant_links:
            pair = (link["alert_id_a"], link["alert_id_b"])
            pair_methods[pair].add(link.get("method", "UNKNOWN"))
            if pair not in pair_best or link["confidence"] > pair_best[pair]["confidence"]:
                pair_best[pair] = link

        for pair, link in pair_best.items():
            base_conf = link["confidence"]
            # Multi-signal boost: each additional method beyond the first adds boost
            method_count = len(pair_methods[pair])
            multi_boost = min(
                self._config.max_multi_signal_boost,
                (method_count - 1) * self._config.multi_signal_boost,
            )
            # Graph centrality boost: central nodes are more important
            centrality_a = graph_centrality.get(pair[0], 0.0)
            centrality_b = graph_centrality.get(pair[1], 0.0)
            centrality_boost = min(
                self._config.centrality_boost_cap,
                (centrality_a + centrality_b) / 2.0 * self._config.centrality_boost_cap * 2,
            )
            final_conf = min(1.0, base_conf + multi_boost + centrality_boost)
            if final_conf != base_conf:
                logger.debug(
                    "Pair %s-%s: base=%.2f multi_boost=%.2f centrality_boost=%.2f final=%.2f",
                    pair[0][:8], pair[1][:8], base_conf, multi_boost, centrality_boost, final_conf
                )
            uf.union(pair[0], pair[1], final_conf)

        # ---- Step 4: Build CorrelatedThreat per cluster -----------------
        clusters = uf.groups()
        threats: list[CorrelatedThreat] = []

        for root, member_ids in clusters.items():
            cluster_alerts = [alert_map[aid] for aid in member_ids if aid in alert_map]
            if not cluster_alerts:
                continue

            is_singleton = len(cluster_alerts) == 1
            cluster_confidence = (
                self._config.singleton_confidence
                if is_singleton
                else uf.get_max_confidence(root)
            )

            # Build subgraph for this cluster
            cluster_graph = None
            if attack_graph and not is_singleton:
                try:
                    cluster_graph = attack_graph.get_subgraph_for_threat(list(member_ids))
                except Exception:
                    pass

            threat = self._build_correlated_threat(
                cluster_alerts=cluster_alerts,
                cluster_links=[
                    lnk for lnk in significant_links
                    if lnk["alert_id_a"] in member_ids or lnk["alert_id_b"] in member_ids
                ],
                correlation_confidence=cluster_confidence,
                is_singleton=is_singleton,
                attack_graph=cluster_graph,
            )
            threats.append(threat)

        # Sort by confidence descending
        threats.sort(key=lambda t: t.correlation_confidence, reverse=True)

        logger.info(
            "Correlation complete: %d alerts -> %d threats (%d singletons)",
            len(alerts),
            len(threats),
            sum(1 for t in threats if t.alert_count == 1),
        )

        return threats

    def _build_correlated_threat(
        self,
        cluster_alerts: list[Alert],
        cluster_links: list[dict[str, Any]],
        correlation_confidence: float,
        is_singleton: bool,
        attack_graph: "AttackGraph | None" = None,
    ) -> CorrelatedThreat:
        """Build a CorrelatedThreat from a cluster of correlated alerts."""

        now = datetime.now(timezone.utc)
        audit_trail: list[dict[str, Any]] = []

        # ---- FP probability ---------------------------------------------
        fp_reasons: list[str] = []
        fp_probability = self._fp_filter.compute_fp_probability(
            alerts=cluster_alerts,
            correlation_confidence=correlation_confidence,
            reasons=fp_reasons,
        )

        # ---- Aggregated observables -------------------------------------
        obs_seen: dict[str, dict[str, Any]] = {}
        obs_frequency: dict[str, int] = defaultdict(int)

        for alert in cluster_alerts:
            for obs in alert.observables:
                key = f"{obs.type.value}:{obs.value}"
                obs_frequency[key] += 1
                if key not in obs_seen:
                    obs_seen[key] = {
                        "type": obs.type.value,
                        "value": obs.value,
                        "confidence": obs.confidence,
                        "context": obs.context,
                        "frequency": 0,
                    }
                obs_seen[key]["frequency"] = obs_frequency[key]

        shared_observables = [v for v in obs_seen.values() if v["frequency"] > 1]
        all_observable_ids = [o.observable_id for a in cluster_alerts for o in a.observables]

        # ---- Methods used -----------------------------------------------
        methods: list[CorrelationMethod] = []
        if not is_singleton:
            method_names = {l["method"] for l in cluster_links}
            method_map = {m.value: m for m in CorrelationMethod}
            methods = [method_map[m] for m in method_names if m in method_map]
            if len(methods) > 1:
                methods.append(CorrelationMethod.COMPOSITE)

        # ---- Evidence links ---------------------------------------------
        evidence_links: list[EvidenceLink] = []
        for alert in cluster_alerts:
            # Relevance = ratio of observables shared with cluster
            obs_in_cluster = len([
                k for k in obs_seen if obs_seen[k]["frequency"] > 1
                and any(
                    f"{o.type.value}:{o.value}" == k
                    for o in alert.observables
                )
            ])
            total_obs = max(1, len(alert.observables))
            relevance = min(1.0, (obs_in_cluster / total_obs) * 2) if not is_singleton else 1.0

            evidence_links.append(EvidenceLink(
                alert_id=alert.alert_id,
                source_ref=alert.source_ref,
                source_type=alert.source_type.value,
                relevance=round(relevance, 3),
                contributing_observables=[
                    o.observable_id for o in alert.observables
                    if f"{o.type.value}:{o.value}" in obs_seen
                    and obs_seen[f"{o.type.value}:{o.value}"]["frequency"] > 1
                ],
            ))

        # ---- Source types -----------------------------------------------
        source_types = sorted({a.source_type.value for a in cluster_alerts})

        # ---- MITRE aggregation -----------------------------------------
        mitre_ids: set[str] = set()
        for alert in cluster_alerts:
            mitre_ids.update(alert.mitre_technique_ids)

        # ---- Timing ----------------------------------------------------
        event_times = [a.event_time for a in cluster_alerts]
        min_time = min(event_times)
        max_time = max(event_times)

        # ---- Max severity -----------------------------------------------
        severities = [a.severity for a in cluster_alerts]
        max_sev = next((s for s in SEVERITY_ORDER if s in severities), AlertSeverity.LOW)

        # ---- Assets -------------------------------------------------------
        affected_assets = list({
            aid for a in cluster_alerts
            for aid in ([a.asset_context.asset_id] if a.asset_context.asset_id else []) +
                       a.asset_context.ip_addresses +
                       ([a.asset_context.hostname] if a.asset_context.hostname else [])
            if aid
        })

        network_segments = list({
            a.asset_context.network_segment
            for a in cluster_alerts
            if a.asset_context.network_segment
        })

        # ---- Title generation -------------------------------------------
        # Use the highest-severity alert's title, or build a composite
        primary_alert = max(cluster_alerts, key=lambda a: SEVERITY_ORDER.index(a.severity))
        if is_singleton:
            title = primary_alert.title
        elif len(source_types) > 1:
            title = f"Multi-source threat: {primary_alert.title}"
        else:
            title = f"Correlated threat: {primary_alert.title}"

        # ---- Actor / campaign aggregation --------------------------------
        actors = list({a.threat_actor for a in cluster_alerts if a.threat_actor})
        campaigns = list({a.campaign for a in cluster_alerts if a.campaign})

        # ---- Graph analysis metadata ------------------------------------
        graph_metadata: dict[str, Any] = {}
        if attack_graph and attack_graph.node_count > 0:
            graph_metadata = {
                "node_count": attack_graph.node_count,
                "edge_count": attack_graph.edge_count,
            }
            try:
                attack_paths = attack_graph.find_attack_paths()
                if attack_paths:
                    graph_metadata["attack_path_length"] = len(attack_paths[0])
                    graph_metadata["attack_path"] = attack_paths[0][:10]
            except Exception:
                pass

        # ---- Audit trail ------------------------------------------------
        audit_entry: dict[str, Any] = {
            "timestamp": now.isoformat(),
            "event": "CORRELATION_CREATED",
            "alert_count": len(cluster_alerts),
            "methods": [m.value for m in methods],
            "correlation_confidence": round(correlation_confidence, 3),
            "fp_probability": fp_probability,
            "fp_reasons": fp_reasons,
            "config_version": self._config.config_version,
        }
        if graph_metadata:
            audit_entry["graph"] = graph_metadata
        audit_trail.append(audit_entry)

        if cluster_links:
            for link in cluster_links[:10]:  # cap audit trail size
                audit_trail.append({
                    "timestamp": now.isoformat(),
                    "event": "LINK_EVIDENCE",
                    "pair": [link.get("alert_id_a", "")[:8], link.get("alert_id_b", "")[:8]],
                    "method": link.get("method"),
                    "confidence": round(link.get("confidence", 0.0), 3),
                    "detail": link.get("audit", ""),
                })

        threat = CorrelatedThreat(
            title=title,
            description=(
                f"Cluster of {len(cluster_alerts)} correlated alert(s) from "
                f"{len(source_types)} source type(s). "
                f"Correlation confidence: {correlation_confidence:.2f}."
            ),
            status=ThreatStatus.OPEN,
            alert_count=len(cluster_alerts),
            evidence_links=evidence_links,
            source_types=source_types,
            correlation_methods=methods,
            correlation_confidence=round(correlation_confidence, 3),
            false_positive_probability=fp_probability,
            shared_observables=shared_observables,
            all_observable_ids=all_observable_ids,
            affected_assets=affected_assets[:20],
            network_segments=network_segments,
            mitre_technique_ids=sorted(mitre_ids),
            suspected_actor=actors[0] if actors else None,
            campaign=campaigns[0] if campaigns else None,
            max_severity=max_sev.value,
            min_event_time=min_time,
            max_event_time=max_time,
            created_at=now,
            updated_at=now,
            correlation_version=self._config.config_version,
            audit_trail=audit_trail,
        )

        # Emit audit record
        self._emit_audit(
            AuditEventType.CORRELATION_CREATED,
            threat_id=threat.threat_id,
            summary=(
                f"Correlated threat created: {len(cluster_alerts)} alerts, "
                f"confidence={correlation_confidence:.2f}, "
                f"fp_prob={fp_probability:.2f}"
            ),
            detail={"alert_ids": [a.alert_id for a in cluster_alerts]},
        )

        # Update alert statuses (mark as correlated)
        for alert in cluster_alerts:
            alert.model_copy(update={"status": AlertStatus.CORRELATED})

        return threat

    def _emit_audit(
        self,
        event_type: AuditEventType,
        threat_id: str | None = None,
        alert_id: str | None = None,
        summary: str = "",
        detail: dict[str, Any] | None = None,
    ) -> None:
        if self._audit_callback is None:
            return
        record = AuditRecord(
            event_type=event_type,
            component="CorrelationEngine",
            threat_id=threat_id,
            alert_id=alert_id,
            summary=summary,
            detail=detail or {},
        )
        try:
            self._audit_callback(record)
        except Exception as exc:
            logger.error("Audit callback error: %s", exc)
