"""Detection evaluation: run every built-in scenario through both detection
modes and score each against the scenario's ground-truth label.

  graph scan  -- RiskDetector.detect() over the finished graph, after the
                 run (post-hoc: finds a sensitive -> external path).
  inline gate -- RiskDetector.evaluate_event() as the simulator's gate
                 (preventive: denies the event before it executes).

A scenario counts as flagged if the graph scan finds a violation, or if the
gate blocks at least one event. Run:

    .venv/bin/python -m simulator.evaluate
"""

from event_collector.collector import EventCollector
from graph_engine.graph import CapabilityGraph
from policy_engine.engine import PolicyEngine
from risk_detector.detector import RiskDetector
from simulator.scenarios import ALL_SCENARIOS
from simulator.simulator import MultiAgentSimulator

SENSITIVE = {"confidential", "pii"}


def leaked(events):
    """True if sensitive data actually reached an external destination."""
    return any(
        event["action"] == "send"
        and event["result"] == "success"
        and event["object"].get("classification") in SENSITIVE
        and event["destination"]["is_external"]
        for event in events
    )


def run_graph_scan(scenario):
    graph = CapabilityGraph()
    simulator = MultiAgentSimulator(sinks=[EventCollector(graph).collect])
    events = simulator.run(scenario)
    flagged = bool(RiskDetector(graph, PolicyEngine()).detect())
    return flagged, leaked(events)


def run_inline_gate(scenario):
    graph = CapabilityGraph()
    detector = RiskDetector(graph, PolicyEngine())
    simulator = MultiAgentSimulator(
        sinks=[EventCollector(graph).collect],
        gate=lambda event: not detector.evaluate_event(event),
    )
    events = simulator.run(scenario)
    flagged = any(e["metadata"].get("outcome_reason") == "blocked_by_gate" for e in events)
    return flagged, leaked(events)


def outcome(is_attack, flagged):
    if is_attack:
        return "TP" if flagged else "FN"
    return "FP" if flagged else "TN"


def ratio(numerator, denominator):
    return f"{numerator / denominator:.2f}" if denominator else "n/a"


def main():
    modes = {"graph scan": run_graph_scan, "inline gate": run_inline_gate}
    totals = {mode: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for mode in modes}

    print(f'{"scenario":<32} {"label":<7} {"mode":<12} {"flagged":<8} {"leaked":<7} outcome')
    print("-" * 80)

    for scenario in ALL_SCENARIOS:
        is_attack = scenario.trajectory_type == "attack"
        for mode, run in modes.items():
            flagged, data_leaked = run(scenario)
            result = outcome(is_attack, flagged)
            totals[mode][result] += 1
            print(
                f"{scenario.scenario_id:<32} {scenario.trajectory_type:<7} {mode:<12} "
                f"{str(flagged):<8} {str(data_leaked):<7} {result}"
            )

    print()
    for mode, t in totals.items():
        precision = ratio(t["TP"], t["TP"] + t["FP"])
        recall = ratio(t["TP"], t["TP"] + t["FN"])
        print(
            f'{mode:<12} TP={t["TP"]} FP={t["FP"]} TN={t["TN"]} FN={t["FN"]}  '
            f"precision={precision} recall={recall}"
        )


if __name__ == "__main__":
    main()
