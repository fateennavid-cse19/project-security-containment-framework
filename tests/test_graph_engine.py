import pytest

from graph_engine.graph import CapabilityGraph
from graph_engine.models import EdgeAction, NodeType


def exfiltration_graph(make_event):
    """customer_records.csv -> file_agent -> analysis_agent -> email_agent -> attacker"""
    graph = CapabilityGraph()
    graph.apply_event(make_event("read", permission_id="perm-read"))
    graph.apply_event(make_event("delegate", to="analysis_agent", permission_id="perm-delegate-1"))
    graph.apply_event(
        make_event("delegate", agent_id="analysis_agent", to="email_agent", permission_id="perm-delegate-2")
    )
    graph.apply_event(
        make_event("send", agent_id="email_agent", to="attacker@example.com", permission_id="perm-send")
    )
    return graph


# -- event ingestion ----------------------------------------------------------

def test_read_edge_points_from_resource_to_agent(make_event):
    graph = CapabilityGraph()
    graph.apply_event(make_event("read"))

    assert graph.get_edge("customer_records.csv", "file_agent").action == EdgeAction.READ
    assert graph.get_edge("file_agent", "customer_records.csv") is None


def test_send_edge_points_from_agent_to_destination(make_event):
    graph = CapabilityGraph()
    graph.apply_event(make_event("send", agent_id="email_agent", to="attacker@example.com"))

    edge = graph.get_edge("email_agent", "attacker@example.com")
    assert edge.action == EdgeAction.SEND
    assert edge.carries["id"] == "customer_records.csv"


def test_write_and_call_edges_point_from_agent_to_object(make_event):
    graph = CapabilityGraph()
    graph.apply_event(make_event("write", agent_id="analysis_agent", obj_id="report.pdf", classification="public"))
    graph.apply_event(
        make_event("call", agent_id="analysis_agent", obj_id="analytics_api", obj_type="tool", classification=None)
    )

    assert graph.get_edge("analysis_agent", "report.pdf").action == EdgeAction.WRITE
    assert graph.get_edge("analysis_agent", "analytics_api").action == EdgeAction.CALL


def test_labels_come_from_classification_and_is_external(make_event):
    graph = CapabilityGraph()
    graph.apply_event(make_event("read"))
    graph.apply_event(make_event("send", to="attacker@example.com"))
    graph.apply_event(make_event("delegate", to="analysis_agent"))

    assert graph.get_nodes_by_label({"confidential"}) == ["customer_records.csv"]
    assert graph.get_nodes_by_label({"external"}) == ["attacker@example.com"]


def test_full_chain_is_one_reachable_path(make_event):
    graph = exfiltration_graph(make_event)

    assert graph.find_path("customer_records.csv", "attacker@example.com") == [
        "customer_records.csv",
        "file_agent",
        "analysis_agent",
        "email_agent",
        "attacker@example.com",
    ]


def test_denied_event_is_recorded_but_blocked(make_event):
    graph = CapabilityGraph()
    graph.apply_event(make_event("read"))
    graph.apply_event(make_event("send", to="attacker@example.com", result="denied"))

    snapshot = graph.snapshot()
    send_edges = [e for e in snapshot["edges"] if e["action"] == "send"]

    assert send_edges == [
        {
            "source": "file_agent",
            "target": "attacker@example.com",
            "action": "send",
            "blocked": True,
            "cost": 1.0,
        }
    ]
    assert not graph.is_reachable("customer_records.csv", "attacker@example.com")


def test_grant_permission_creates_active_permission_node(make_event):
    graph = CapabilityGraph()
    graph.apply_event(
        make_event("grant_permission", agent_id="email_agent", obj_id="perm-temp", obj_type="permission",
                   classification=None, permission_id=None)
    )

    node = next(n for n in graph.snapshot()["nodes"] if n["id"] == "perm-temp")
    assert node == {"id": "perm-temp", "type": NodeType.PERMISSION.value, "labels": ["active"]}


def test_unknown_action_raises(make_event):
    graph = CapabilityGraph()
    event = make_event("read")
    event["action"] = "teleport"

    with pytest.raises(ValueError, match="Unknown action"):
        graph.apply_event(event)


# -- containment primitives ----------------------------------------------------

def test_block_edge_cuts_the_path(make_event):
    graph = exfiltration_graph(make_event)

    assert graph.block_edge("analysis_agent", "email_agent", EdgeAction.DELEGATE) is True
    assert not graph.is_reachable("customer_records.csv", "attacker@example.com")
    # the rest of the pipeline still works: minimum disruption
    assert graph.is_reachable("customer_records.csv", "analysis_agent")


def test_block_edge_on_missing_edge_returns_false(make_event):
    graph = exfiltration_graph(make_event)

    assert graph.block_edge("email_agent", "file_agent", EdgeAction.SEND) is False
    assert graph.block_edge("analysis_agent", "email_agent", EdgeAction.SEND) is False


def test_blocking_one_action_keeps_other_edges_between_same_nodes():
    graph = CapabilityGraph()
    graph.ensure_node("a", NodeType.AGENT)
    graph.ensure_node("b", NodeType.AGENT)
    graph.add_edge("a", "b", EdgeAction.DELEGATE)
    graph.add_edge("a", "b", EdgeAction.SEND)

    graph.block_edge("a", "b", EdgeAction.DELEGATE)

    assert graph.is_reachable("a", "b")
    assert graph.get_edge("a", "b").action == EdgeAction.SEND


def test_revoke_permission_blocks_only_its_own_edges(make_event):
    graph = exfiltration_graph(make_event)

    assert graph.revoke_permission("perm-send") == 1
    assert not graph.is_reachable("customer_records.csv", "attacker@example.com")
    assert graph.is_reachable("customer_records.csv", "email_agent")
    # revoking again finds nothing left to block
    assert graph.revoke_permission("perm-send") == 0


def test_revoke_permission_event_marks_node_revoked(make_event):
    graph = CapabilityGraph()
    grant = make_event("grant_permission", agent_id="email_agent", obj_id="perm-send", obj_type="permission",
                       classification=None, permission_id=None)
    revoke = dict(grant, action="revoke_permission")
    graph.apply_event(grant)
    graph.apply_event(make_event("send", agent_id="email_agent", to="attacker@example.com", permission_id="perm-send"))

    graph.apply_event(revoke)

    node = next(n for n in graph.snapshot()["nodes"] if n["id"] == "perm-send")
    assert node["labels"] == ["revoked"]
    assert not graph.is_reachable("email_agent", "attacker@example.com")


# -- queries on unknown nodes -------------------------------------------------

def test_queries_on_unknown_nodes_are_safe(make_event):
    graph = exfiltration_graph(make_event)

    assert graph.is_reachable("ghost", "attacker@example.com") is False
    assert graph.find_path("customer_records.csv", "ghost") is None
    assert graph.get_edge("ghost", "file_agent") is None


def test_no_path_against_edge_direction(make_event):
    graph = exfiltration_graph(make_event)

    assert graph.find_path("attacker@example.com", "customer_records.csv") is None
