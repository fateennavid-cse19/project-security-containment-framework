"""Sanity check: replay the worked exfiltration example from Project-full-doc.docx
through the graph, show the dangerous path exists, contain it with a single
edge block, and show the safe work upstream still stands. Run:

    .venv/bin/python -m graph_engine.demo
"""
import json

from graph_engine.graph import CapabilityGraph
from graph_engine.models import EdgeAction
from event_collector.collector import EventCollector
from policy_engine.engine import PolicyEngine
from risk_detector.detector import RiskDetector

EVENTS_FILE = "schema/examples/cross_agent_exfiltration.json"


def main() -> None:
    events = json.load(open(EVENTS_FILE))
    graph = CapabilityGraph()
    collector = EventCollector(graph)

    # Apply the read + both delegate events (evt-0001..0003), but not the
    # already-denied send (evt-0004) yet -- we want to show the dangerous path
    # existing BEFORE any containment decision is made.
    for event in events[:3]:
        collector.collect(event)

    policy_engine = PolicyEngine()
    detector = RiskDetector(graph, policy_engine)

    print("\nCurrent policy violations:")
    print(detector.detect())

    print("\nEvaluating proposed evt-0004:")
    proposed_violations = detector.evaluate_event(events[3])
    print(proposed_violations)

    print("\nCollected event contexts:")

    for collected_event in collector.get_events():
        event = collected_event["event"]
        context = collected_event["context"]

        print(event["event_id"])
        print(context)

    print("Before containment:")
    print(
        "  customer_records.csv reachable at email_agent? ",
        graph.is_reachable("customer_records.csv", "email_agent"),
    )

    print("\nApplying minimum-disruption containment: "
          "block analysis_agent -> email_agent (delegate)")
    graph.block_edge("analysis_agent", "email_agent", EdgeAction.DELEGATE)

    print("\nAfter containment:")
    print(
        "  customer_records.csv reachable at email_agent? ",
        graph.is_reachable("customer_records.csv", "email_agent"),
    )
    print(
        "  customer_records.csv still reachable at analysis_agent (preserved work)? ",
        graph.is_reachable("customer_records.csv", "analysis_agent"),
    )

    # print("\nGraph snapshot (matches GraphSnapshot schema in api/openapi.yaml):")
    # print(json.dumps(graph.snapshot(), indent=2))

    print("\nRe-evaluating evt-0004 after containment:")
    post_containment_violations = detector.evaluate_event(events[3])
    print(post_containment_violations)


if __name__ == "__main__":
    main()
