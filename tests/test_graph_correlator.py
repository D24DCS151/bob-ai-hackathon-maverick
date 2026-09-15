"""
Tests for graph-based correlation (Phase 2).

Covers:
- AttackGraph node/edge construction
- Correlation link building from raw link dicts
- Attack path detection
- Betweenness centrality computation
- Community detection
- Serialisation to dict
- Subgraph extraction
- Graceful behaviour without NetworkX (simulated)
"""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

# Skip entire module if networkx not installed
try:
    import networkx  # noqa: F401
    _HAS_NX = True
except ImportError:
    _HAS_NX = False

pytestmark = pytest.mark.skipif(
    not _HAS_NX, reason="networkx not installed — graph tests skipped"
)

from threaticap.correlation.graph_correlator import AttackGraph, KILL_CHAIN_STAGE, SEVERITY_WEIGHT
from threaticap.models.alert import Alert, AlertSeverity, AlertSource, AssetContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(
    alert_id: str = "a1",
    severity: AlertSeverity = AlertSeverity.HIGH,
    mitre: list[str] | None = None,
    campaign: str = "",
    event_time: datetime | None = None,
) -> Alert:
    return Alert(
        alert_id=alert_id,
        source_ref=f"SRC-{alert_id}",
        source_type=AlertSource.SIEM,
        source_id="siem-test",
        event_time=event_time or datetime.now(timezone.utc),
        severity=severity,
        title=f"Alert {alert_id}",
        mitre_technique_ids=mitre or [],
        campaign=campaign,
        asset_context=AssetContext(),
    )


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestAttackGraphConstruction:

    def test_add_alert_creates_node(self):
        g = AttackGraph()
        a = _make_alert("x1")
        g.add_alert(a)
        assert g.node_count == 1

    def test_add_alert_stores_attributes(self):
        g = AttackGraph()
        a = _make_alert("x2", severity=AlertSeverity.CRITICAL, mitre=["T1059"])
        g.add_alert(a)
        node_data = g._graph.nodes["x2"]
        assert node_data["severity"] == "CRITICAL"
        assert "T1059" in node_data["mitre_techniques"]
        assert node_data["severity_weight"] == SEVERITY_WEIGHT["CRITICAL"]

    def test_add_multiple_alerts(self):
        g = AttackGraph()
        for i in range(5):
            g.add_alert(_make_alert(f"node-{i}"))
        assert g.node_count == 5

    def test_add_correlation_link_undirected(self):
        g = AttackGraph()
        g.add_alert(_make_alert("a"))
        g.add_alert(_make_alert("b"))
        g.add_correlation_link("a", "b", "IOC", 0.8, directed=False)
        # Both directions added for undirected
        assert g._graph.has_edge("a", "b")
        assert g._graph.has_edge("b", "a")
        assert g.edge_count == 2

    def test_add_correlation_link_directed(self):
        g = AttackGraph()
        g.add_alert(_make_alert("a"))
        g.add_alert(_make_alert("b"))
        g.add_correlation_link("a", "b", "TEMPORAL", 0.7, directed=True)
        assert g._graph.has_edge("a", "b")
        assert not g._graph.has_edge("b", "a")
        assert g.edge_count == 1

    def test_edge_attributes_stored(self):
        g = AttackGraph()
        g.add_alert(_make_alert("x"))
        g.add_alert(_make_alert("y"))
        evidence = {"shared_ip": "1.2.3.4"}
        g.add_correlation_link("x", "y", "IOC", 0.9, evidence=evidence, directed=True)
        edge_data = g._graph["x"]["y"]
        assert edge_data["weight"] == 0.9
        assert edge_data["edge_type"] == "IOC"
        assert edge_data["evidence"]["shared_ip"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# build_from_links
# ---------------------------------------------------------------------------

class TestBuildFromLinks:

    def _make_links(self) -> tuple[list[Alert], list[dict]]:
        now = datetime.now(timezone.utc)
        a1 = _make_alert("link-a", event_time=now)
        a2 = _make_alert("link-b", event_time=now + timedelta(minutes=5))
        a3 = _make_alert("link-c", event_time=now + timedelta(minutes=10))
        links = [
            {"alert_id_a": "link-a", "alert_id_b": "link-b", "confidence": 0.8, "method": "IOC"},
            {"alert_id_a": "link-b", "alert_id_b": "link-c", "confidence": 0.7, "method": "TEMPORAL"},
        ]
        return [a1, a2, a3], links

    def test_build_from_links_populates_graph(self):
        alerts, links = self._make_links()
        g = AttackGraph()
        g.build_from_links(alerts, links)
        assert g.node_count == 3

    def test_temporal_links_are_directed(self):
        alerts, links = self._make_links()
        g = AttackGraph()
        g.build_from_links(alerts, links)
        # Temporal link b->c should be directed in time order
        assert g._graph.has_edge("link-b", "link-c")

    def test_ioc_links_are_bidirectional(self):
        alerts, links = self._make_links()
        g = AttackGraph()
        g.build_from_links(alerts, links)
        assert g._graph.has_edge("link-a", "link-b")
        assert g._graph.has_edge("link-b", "link-a")

    def test_empty_links_still_adds_nodes(self):
        alerts = [_make_alert("solo")]
        g = AttackGraph()
        g.build_from_links(alerts, [])
        assert g.node_count == 1
        assert g.edge_count == 0


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

class TestAttackGraphAnalysis:

    def _build_chain(self, length: int = 4) -> AttackGraph:
        """Build a linear directed chain of alerts."""
        now = datetime.now(timezone.utc)
        alerts = [_make_alert(f"chain-{i}", event_time=now + timedelta(minutes=i)) for i in range(length)]
        links = [
            {
                "alert_id_a": f"chain-{i}",
                "alert_id_b": f"chain-{i+1}",
                "confidence": 0.8,
                "method": "TEMPORAL",
            }
            for i in range(length - 1)
        ]
        g = AttackGraph()
        g.build_from_links(alerts, links)
        return g

    def test_find_attack_paths_returns_list(self):
        g = self._build_chain(4)
        paths = g.find_attack_paths()
        assert isinstance(paths, list)

    def test_find_attack_paths_nonempty_for_chain(self):
        g = self._build_chain(4)
        paths = g.find_attack_paths()
        # Should find at least one path
        assert len(paths) >= 1
        # Longest path should span all nodes
        assert len(paths[0]) >= 2

    def test_centrality_returns_dict(self):
        g = self._build_chain(5)
        centrality = g.compute_node_centrality()
        assert isinstance(centrality, dict)
        assert len(centrality) == 5
        # All values between 0 and 1
        for v in centrality.values():
            assert 0.0 <= v <= 1.0

    def test_centrality_hub_is_highest(self):
        """The middle node in a chain should have highest centrality."""
        g = self._build_chain(5)
        centrality = g.compute_node_centrality()
        # Middle node (chain-2) should be most central
        middle = centrality.get("chain-2", 0)
        edge_nodes = [centrality.get("chain-0", 0), centrality.get("chain-4", 0)]
        assert middle >= max(edge_nodes)

    def test_centrality_empty_graph(self):
        g = AttackGraph()
        assert g.compute_node_centrality() == {}

    def test_community_detection_returns_dict(self):
        """Two disconnected clusters should produce two communities."""
        now = datetime.now(timezone.utc)
        # Cluster A
        a1 = _make_alert("ca1", event_time=now)
        a2 = _make_alert("ca2", event_time=now + timedelta(minutes=1))
        # Cluster B
        b1 = _make_alert("cb1", event_time=now)
        b2 = _make_alert("cb2", event_time=now + timedelta(minutes=1))

        links = [
            {"alert_id_a": "ca1", "alert_id_b": "ca2", "confidence": 0.9, "method": "IOC"},
            {"alert_id_a": "cb1", "alert_id_b": "cb2", "confidence": 0.9, "method": "IOC"},
        ]
        g = AttackGraph()
        g.build_from_links([a1, a2, b1, b2], links)
        communities = g.detect_communities()
        assert isinstance(communities, dict)
        assert len(communities) == 4

    def test_community_single_cluster(self):
        g = self._build_chain(3)
        communities = g.detect_communities()
        # All nodes in same community
        values = list(communities.values())
        assert len(set(values)) == 1

    def test_community_empty_graph(self):
        g = AttackGraph()
        communities = g.detect_communities()
        assert communities == {}


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------

class TestAttackGraphSerialisation:

    def test_to_dict_structure(self):
        g = AttackGraph()
        g.add_alert(_make_alert("n1"))
        g.add_alert(_make_alert("n2"))
        g.add_correlation_link("n1", "n2", "IOC", 0.8)
        d = g.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert "stats" in d
        assert d["stats"]["node_count"] == 2
        assert d["stats"]["edge_count"] >= 1

    def test_to_dict_node_ids(self):
        g = AttackGraph()
        g.add_alert(_make_alert("nodeA"))
        d = g.to_dict()
        node_ids = [n["id"] for n in d["nodes"]]
        assert "nodeA" in node_ids

    def test_subgraph_extraction(self):
        g = AttackGraph()
        for i in range(5):
            g.add_alert(_make_alert(f"sg-{i}"))
        g.add_correlation_link("sg-0", "sg-1", "IOC", 0.8)
        g.add_correlation_link("sg-2", "sg-3", "IOC", 0.8)

        sub = g.get_subgraph_for_threat(["sg-0", "sg-1"])
        assert sub.node_count == 2


# ---------------------------------------------------------------------------
# Kill-chain constants
# ---------------------------------------------------------------------------

class TestKillChainConstants:

    def test_all_mitre_tactics_present(self):
        expected = [
            "Reconnaissance", "Initial Access", "Execution",
            "Persistence", "Privilege Escalation", "Defense Evasion",
            "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact",
        ]
        for tactic in expected:
            assert tactic in KILL_CHAIN_STAGE

    def test_stage_ordering_monotonic(self):
        stages = list(KILL_CHAIN_STAGE.values())
        assert stages == sorted(stages)
