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


def safe_ratio(numerator, denominator):
    """Return a numeric ratio, or None when the denominator is zero."""
    return numerator / denominator if denominator else None


def security_metrics(counts, attack_leaks=0, attack_total=None):
    """Calculate Phase 6.2 security-effectiveness metrics.

    ``counts`` must contain TP, FP, TN and FN. ``attack_leaks`` is the number
    of attack scenarios where sensitive data reached an external destination.
    ``attack_total`` defaults to TP + FN.
    """
    required = {"TP", "FP", "TN", "FN"}
    if set(counts) != required:
        raise ValueError("counts must contain TP, FP, TN and FN")

    if any(type(counts[key]) is not int or counts[key] < 0 for key in required):
        raise ValueError("confusion-matrix counts must be non-negative integers")

    if type(attack_leaks) is not int or attack_leaks < 0:
        raise ValueError("attack_leaks must be a non-negative integer")

    detected_attacks = counts["TP"] + counts["FN"]
    if attack_total is None:
        attack_total = detected_attacks

    if type(attack_total) is not int or attack_total < 0:
        raise ValueError("attack_total must be a non-negative integer")
    if attack_leaks > attack_total:
        raise ValueError("attack_leaks cannot exceed attack_total")

    total = sum(counts.values())
    benign_total = counts["TN"] + counts["FP"]

    attack_success_rate = safe_ratio(attack_leaks, attack_total)

    recall = safe_ratio(counts["TP"], counts["TP"] + counts["FN"])

    return {
        "precision": safe_ratio(counts["TP"], counts["TP"] + counts["FP"]),
        "recall": recall,
        "prohibited_path_coverage": recall,
        "accuracy": safe_ratio(counts["TP"] + counts["TN"], total),
        "false_positive_rate": safe_ratio(counts["FP"], benign_total),
        "false_negative_rate": safe_ratio(counts["FN"], detected_attacks),
        "benign_allow_rate": safe_ratio(counts["TN"], benign_total),
        "attack_success_rate": attack_success_rate,
        "attack_prevention_rate": (
            1 - attack_success_rate if attack_success_rate is not None else None
        ),
    }


def format_ratio(value):
    return f"{value:.2f}" if value is not None else "n/a"


def main():
    modes = {"graph scan": run_graph_scan, "inline gate": run_inline_gate}
    totals = {mode: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for mode in modes}
    attack_leaks = {mode: 0 for mode in modes}
    attack_total = sum(scenario.trajectory_type == "attack" for scenario in ALL_SCENARIOS)

    print(f'{"scenario":<42} {"label":<7} {"mode":<12} {"flagged":<8} {"leaked":<7} outcome')
    print("-" * 80)

    for scenario in ALL_SCENARIOS:
        is_attack = scenario.trajectory_type == "attack"
        for mode, run in modes.items():
            flagged, data_leaked = run(scenario)
            result = outcome(is_attack, flagged)
            totals[mode][result] += 1
            if is_attack and data_leaked:
                attack_leaks[mode] += 1
            print(
                f"{scenario.scenario_id:<42} {scenario.trajectory_type:<7} {mode:<12} "
                f"{str(flagged):<8} {str(data_leaked):<7} {result}"
            )

    print()
    for mode, counts in totals.items():
        metrics = security_metrics(
            counts,
            attack_leaks=attack_leaks[mode],
            attack_total=attack_total,
        )
        print(
            f'{mode:<12} TP={counts["TP"]} FP={counts["FP"]} '
            f'TN={counts["TN"]} FN={counts["FN"]}'
        )
        print(
            " " * 13
            + f'precision={format_ratio(metrics["precision"])} '
            + f'recall={format_ratio(metrics["recall"])} '
            + f'accuracy={format_ratio(metrics["accuracy"])} '
            + f'path_coverage={format_ratio(metrics["prohibited_path_coverage"])} '
            + f'FPR={format_ratio(metrics["false_positive_rate"])} '
            + f'FNR={format_ratio(metrics["false_negative_rate"])}'
        )
        print(
            " " * 13
            + f'benign_allow={format_ratio(metrics["benign_allow_rate"])} '
            + f'attack_success={format_ratio(metrics["attack_success_rate"])} '
            + f'attack_prevention={format_ratio(metrics["attack_prevention_rate"])}'
        )


if __name__ == "__main__":
    main()
