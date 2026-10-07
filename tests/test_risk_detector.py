import json

from graph_engine.graph import CapabilityGraph
from graph_engine.models import EdgeAction
from event_collector.collector import EventCollector
from policy_engine.engine import PolicyEngine
from risk_detector.detector import RiskDetector


EVENTS_FILE = "schema/examples/cross_agent_exfiltration.json"


def setup_detector(classification="confidential"):
    events = json.load(open(EVENTS_FILE))

    for event in events:
        event["object"]["classification"] = classification

    graph = CapabilityGraph()
    collector = EventCollector(graph)

    for event in events[:3]:
        collector.collect(event)

    policy_engine = PolicyEngine()
    detector = RiskDetector(graph, policy_engine)

    return events, graph, detector

def test_no_current_violation():
    events, graph, detector = setup_detector()

    violations = detector.detect()

    assert violations == []

def test_proposed_external_send_detected():
    events, graph, detector = setup_detector()

    violations = detector.evaluate_event(events[3])

    assert len(violations) == 1

    violation = violations[0]

    assert violation["policy_id"] == "POL-001"
    assert violation["source"] == "customer_records.csv"
    assert violation["destination"] == "attacker@example.com"
    assert violation["path"] == [
        "customer_records.csv",
        "file_agent",
        "analysis_agent",
        "email_agent",
        "attacker@example.com",
    ]
    assert len(violation["edges"]) == 4
    assert violation["edges"][0] == {
    "source": "customer_records.csv",
    "target": "file_agent",
    "action": "read",
    "permission_id": "perm-file-agent-read-internal",
    "cost": 1.0,
    }

    assert violation["edges"][1] == {
        "source": "file_agent",
        "target": "analysis_agent",
        "action": "delegate",
        "permission_id": "perm-file-agent-delegate-analysis",
        "cost": 1.0,
    }

    assert violation["edges"][2] == {
        "source": "analysis_agent",
        "target": "email_agent",
        "action": "delegate",
        "permission_id": "perm-analysis-agent-delegate-email",
        "cost": 1.0,
    }

    assert violation["edges"][3] == {
        "source": "email_agent",
        "target": "attacker@example.com",
        "action": "send",
        "permission_id": "perm-email-agent-send-external",
        "cost": 1.0,
    }

def test_containment_removes_proposed_violation():
    events, graph, detector = setup_detector()

    graph.block_edge(
        "analysis_agent",
        "email_agent",
        EdgeAction.DELEGATE,
    )

    violations = detector.evaluate_event(events[3])

    assert violations == []

def setup_public_detector():
    events = json.load(open(EVENTS_FILE))

    for event in events:
        event["object"]["classification"] = "public"

    graph = CapabilityGraph()
    collector = EventCollector(graph)

    for event in events[:3]:
        collector.collect(event)

    policy_engine = PolicyEngine()
    detector = RiskDetector(graph, policy_engine)

    return events, graph, detector

def test_public_data_external_send_not_detected():
    events, graph, detector = setup_detector("public")

    violations = detector.evaluate_event(events[3])

    assert violations == []

def setup_pii_detector():
    events = json.load(open(EVENTS_FILE))

    for event in events:
        event["object"]["classification"] = "pii"

    graph = CapabilityGraph()
    collector = EventCollector(graph)

    for event in events[:3]:
        collector.collect(event)

    policy_engine = PolicyEngine()
    detector = RiskDetector(graph, policy_engine)

    return events, graph, detector

def test_pii_external_send_detected():
    events, graph, detector = setup_detector("pii")

    violations = detector.evaluate_event(events[3])

    assert len(violations) == 1

    violation = violations[0]

    assert violation["policy_id"] == "POL-001"
    assert violation["source"] == "customer_records.csv"
    assert violation["destination"] == "attacker@example.com"

def test_confidential_internal_send_not_detected():
    events, graph, detector = setup_detector()

    proposed_event = events[3].copy()
    proposed_event["destination"] = events[3]["destination"].copy()

    proposed_event["destination"]["id"] = "internal_agent"
    proposed_event["destination"]["type"] = "agent"
    proposed_event["destination"]["is_external"] = False

    violations = detector.evaluate_event(proposed_event)

    assert violations == []

def test_external_send_without_sensitive_path_not_detected():
    events, graph, detector = setup_detector()

    proposed_event = events[3].copy()
    proposed_event["agent_id"] = "unconnected_agent"

    violations = detector.evaluate_event(proposed_event)

    assert violations == []