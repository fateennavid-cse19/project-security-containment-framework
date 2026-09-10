"""Sanity check: replay the worked exfiltration example from Project-full-doc.docx
through the graph, show the dangerous path exists, contain it with a single
edge block, and show the safe work upstream still stands. Run:

    .venv/bin/python -m graph_engine.demo
"""
import json

from graph_engine.graph import CapabilityGraph
from graph_engine.models import EdgeAction

EVENTS_FILE = "schema/examples/cross_agent_exfiltration.json"


def main() -> None:
    events = json.load(open(EVENTS_FILE))
    graph = CapabilityGraph()

    # Apply the read + both delegate events (evt-0001..0003), but not the
    # already-denied send (evt-0004) yet -- we want to show the dangerous path
    # existing BEFORE any containment decision is made.
    for event in events[:3]:
        graph.apply_event(event)

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

    print("\nGraph snapshot (matches GraphSnapshot schema in api/openapi.yaml):")
    print(json.dumps(graph.snapshot(), indent=2))


if __name__ == "__main__":
    main()
