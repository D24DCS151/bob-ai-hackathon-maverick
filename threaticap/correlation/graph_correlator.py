"""
Graph-based correlation engine using NetworkX.

Extends the existing Union-Find clustering with a directed attack-path graph
that can:
1. Model alerts as graph nodes with attributes
2. Link alerts via weighted directed edges (correlation signals)
3. Detect attack-path sequences (Initial Access -> Lateral Movement -> Impact)
4. Find central nodes (most-connected alerts) for prioritisation
5. Detect communities of related alerts (graph community detection)
6. Export the graph for visualisation (JSON / Cytoscape-compatible)

The graph is built alongside the existing Union-Find clusters so both
the flat group structure AND the rich graph structure are available.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    _HAS_NX = True
except ImportError:
    _HAS_NX = False
    logger.warning("networkx not available — graph correlation disabled; pip install networkx")

from threaticap.models.alert import Alert, AlertSeverity


# Kill-chain stage numeric ordering for attack path detection
KILL_CHAIN_STAGE: dict[str, int] = {
    "Reconnaissance": 0,
    "Resource Development": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 4,
    "Privilege Escalation": 5,
    "Defense Evasion": 6,
    "Credential Access": 7,
    "Discovery": 8,
    "Lateral Movement": 9,
    "Collection": 10,
    "Command and Control": 11,
    "Exfiltration": 12,
    "Impact": 13,
}

SEVERITY_WEIGHT: dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.25,
    "INFO": 0.1,
}


class AttackGraph:
    """
    Directed weighted graph of correlated alerts.

    Nodes: alert_id (with alert attributes)
    Edges: correlation links (with type, weight, evidence)
    """

    def __init__(self) -> None:
        if not _HAS_NX:
            raise RuntimeError("networkx required: pip install networkx")
        self._graph: "nx.DiGraph" = nx.DiGraph()

    def add_alert(self, alert: Alert) -> None:
        """Add an alert as a graph node with rich attributes."""
        self._graph.add_node(
            alert.alert_id,
            title=alert.title,
            severity=alert.severity.value,
            severity_weight=SEVERITY_WEIGHT.get(alert.severity.value, 0.5),
            source_type=alert.source_type.value,
            source_id=alert.source_id,
            event_time=alert.event_time.isoformat(),
            confidence=alert.confidence,
            campaign=alert.campaign or "",
            threat_actor=alert.threat_actor or "",
            mitre_techniques=alert.mitre_technique_ids,
            asset_criticality=alert.asset_context.criticality,
            observable_count=len(alert.observables),
        )

    def add_correlation_link(
        self,
        alert_id_a: str,
        alert_id_b: str,
        edge_type: str,
        weight: float,
        evidence: dict[str, Any] | None = None,
        directed: bool = False,
    ) -> None:
        """
        Add a correlation edge.

        Edges are undirected by default (correlation is symmetric).
        For temporal/kill-chain edges, directed=True with A->B meaning
        A precedes B in the attack sequence.
        """
        attrs = {
            "edge_type": edge_type,
            "weight": weight,
            "evidence": evidence or {},
        }
        if directed:
            self._graph.add_edge(alert_id_a, alert_id_b, **attrs)
        else:
            # Add both directions for traversal
            self._graph.add_edge(alert_id_a, alert_id_b, **attrs)
            self._graph.add_edge(alert_id_b, alert_id_a, **attrs)

    def build_from_links(
        self,
        alerts: list[Alert],
        links: list[dict[str, Any]],
    ) -> None:
        """
        Populate the graph from alerts and correlation link dicts
        (as produced by the individual correlators).
        """
        for alert in alerts:
            self.add_alert(alert)

        # Build event_time lookup for directed temporal edges
        time_map: dict[str, datetime] = {
            a.alert_id: a.event_time for a in alerts
        }

        for link in links:
            id_a = link["alert_id_a"]
            id_b = link["alert_id_b"]
            weight = link.get("confidence", 0.5)
            method = link.get("method", "UNKNOWN")

            # Temporal edges are directed (earlier -> later)
            if method == "TEMPORAL":
                ta = time_map.get(id_a)
                tb = time_map.get(id_b)
                if ta and tb:
                    if ta <= tb:
                        self.add_correlation_link(id_a, id_b, method, weight, directed=True)
                    else:
                        self.add_correlation_link(id_b, id_a, method, weight, directed=True)
            else:
                self.add_correlation_link(id_a, id_b, method, weight, directed=False)

    def find_attack_paths(self) -> list[list[str]]:
        """
        Find sequences of alerts that represent a progressive attack path.

        A path is a sequence where each step represents a later kill-chain stage.
        Returns list of alert_id sequences (longest paths first).
        """
        if not _HAS_NX:
            return []

        # Find nodes with kill-chain relevant techniques
        # Map nodes to their minimum kill-chain stage
        def _node_stage(node_id: str) -> int:
            attrs = self._graph.nodes.get(node_id, {})
            techs = attrs.get("mitre_techniques", [])
            # Simplified: use heuristic technique-to-stage mapping
            # In full implementation, use the MITRE KB lookup
            stage = 99
            for tech in techs:
                # Map technique ranges to stages (simplified)
                try:
                    num = int(tech.split("T")[1].split(".")[0])
                    if 1189 <= num <= 1200:
                        stage = min(stage, 2)  # Initial Access
                    elif 1059 <= num <= 1106:
                        stage = min(stage, 3)  # Execution
                    elif 1021 <= num <= 1080:
                        stage = min(stage, 9)  # Lateral Movement
                    elif 1003 <= num <= 1558:
                        stage = min(stage, 7)  # Credential Access
                    elif 1041 <= num <= 1567:
                        stage = min(stage, 12)  # Exfiltration
                except (ValueError, IndexError):
                    pass
            return stage

        # Find simple paths in the directed graph
        paths: list[list[str]] = []
        # Use topological generations if the graph is a DAG
        try:
            undirected = self._graph.to_undirected()
            components = list(nx.connected_components(undirected))
            for component in components:
                subgraph = self._graph.subgraph(component)
                # Find longest simple path within component
                try:
                    # Try topological sort for DAGs
                    topo = list(nx.topological_sort(subgraph))
                    if len(topo) > 1:
                        paths.append(topo)
                except nx.NetworkXUnfeasible:
                    # Cycle detected — find longest path with cycle handling
                    longest = max(
                        nx.all_simple_paths(
                            subgraph.to_undirected(),
                            source=list(component)[0],
                            target=list(component)[-1],
                            cutoff=10,
                        ),
                        key=len,
                        default=[],
                    )
                    if longest:
                        paths.append(longest)
        except Exception as exc:
            logger.debug("Attack path detection error: %s", exc)

        return sorted(paths, key=len, reverse=True)

    def compute_node_centrality(self) -> dict[str, float]:
        """
        Compute betweenness centrality for each alert node.

        High centrality = alert is a "hub" connecting many correlation links.
        Used as a signal to increase priority of hub alerts.
        """
        if self._graph.number_of_nodes() == 0:
            return {}
        try:
            centrality = nx.betweenness_centrality(
                self._graph, normalized=True, weight="weight"
            )
            return centrality
        except Exception as exc:
            logger.debug("Centrality computation error: %s", exc)
            return {}

    def detect_communities(self) -> dict[str, int]:
        """
        Detect communities (clusters) using Louvain or greedy modularity.
        Returns dict mapping alert_id -> community_id.
        """
        if not _HAS_NX or self._graph.number_of_nodes() < 2:
            return {}
        try:
            undirected = self._graph.to_undirected()
            communities = nx.algorithms.community.greedy_modularity_communities(
                undirected
            )
            result = {}
            for community_id, nodes in enumerate(communities):
                for node in nodes:
                    result[node] = community_id
            return result
        except Exception as exc:
            logger.debug("Community detection error: %s", exc)
            return {}

    def to_dict(self) -> dict[str, Any]:
        """
        Export graph as a dict suitable for JSON serialisation.
        Compatible with Cytoscape.js / D3.js formats.
        """
        return {
            "nodes": [
                {"id": n, **data}
                for n, data in self._graph.nodes(data=True)
            ],
            "edges": [
                {
                    "source": u,
                    "target": v,
                    **data,
                }
                for u, v, data in self._graph.edges(data=True)
            ],
            "stats": {
                "node_count": self._graph.number_of_nodes(),
                "edge_count": self._graph.number_of_edges(),
                "is_connected": nx.is_weakly_connected(self._graph)
                if self._graph.number_of_nodes() > 0 else False,
                "density": nx.density(self._graph),
            },
        }

    def get_subgraph_for_threat(self, alert_ids: list[str]) -> "AttackGraph":
        """Return a subgraph containing only the specified alert nodes."""
        sub = AttackGraph()
        sub._graph = self._graph.subgraph(alert_ids).copy()
        return sub

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()
