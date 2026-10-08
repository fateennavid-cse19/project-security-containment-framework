"""Simulator demo: run every built-in scenario through the Event Collector
and graph, then rerun the exfiltration attack with the Risk Detector acting
as the gate to show the attack being stopped before it executes. Run:

    .venv/bin/python -m simulator.demo
"""

from event_collector.collector import EventCollector
from graph_engine.graph import CapabilityGraph
from risk_detector.detector import RiskDetector
from policy_engine.engine import PolicyEngine
from simulator.scenarios import ALL_SCENARIOS, CROSS_AGENT_DATA_EXFILTRATION
from simulator.simulator import MultiAgentSimulator

def print_event(event):
    obj = event["object"]["id"]
    dest = event["destination"]["id"] if event["destination"] else "-"
    reason = event["metadata"].get("outcome_reason", "")
    print(
        f'  {event["event_id"]} {event["agent_id"]:<15} {event["action"]:<17} '
        f'{obj:<26} -> {dest:<22} {event["result"]:<8} {reason}'
    )

def main():
    print("=== 1. All scenarios, no enforcement ===")
    graph = CapabilityGraph()
    collector = EventCollector(graph)
    simulator = MultiAgentSimulator(sinks=[collector.collect])

    for scenario in ALL_SCENARIOS:
        print(f"\n{scenario.scenario_id} ({scenario.trajectory_type})")
        for event in simulator.run(scenario):
            print_event(event)

    print(f"\nCollector received {len(collector.get_events())} events.")

    print("\n=== 2. Exfiltration attack with the Risk Detector as gate ===")
    graph = CapabilityGraph()
    collector = EventCollector(graph)
    detector = RiskDetector(graph, PolicyEngine())

    def detector_gate(event):
        return not detector.evaluate_event(event)

    simulator = MultiAgentSimulator(sinks=[collector.collect], gate=detector_gate)

    print(f"\n{CROSS_AGENT_DATA_EXFILTRATION.scenario_id} (attack)")
    for event in simulator.run(CROSS_AGENT_DATA_EXFILTRATION):
        print_event(event)

    reachable = graph.is_reachable("customer_records.csv", "attacker@example.com")
    print(f"\ncustomer_records.csv -> attacker@example.com reachable: {reachable}")


if __name__ == "__main__":
    main()
