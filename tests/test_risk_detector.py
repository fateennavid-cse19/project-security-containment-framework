import json

from graph_engine.graph import CapabilityGraph
from graph_engine.models import EdgeAction
from event_collector.collector import EventCollector
from policy_engine.engine import PolicyEngine
from risk_detector.detector import RiskDetector


EVENTS_FILE = "schema/examples/cross_agent_exfiltration.json"


def setup_detector():
    events = json.load(open(EVENTS_FILE))

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

def test_containment_removes_proposed_violation():
    events, graph, detector = setup_detector()

    graph.block_edge(
        "analysis_agent",
        "email_agent",
        EdgeAction.DELEGATE,
    )

    violations = detector.evaluate_event(events[3])

    assert violations == []
