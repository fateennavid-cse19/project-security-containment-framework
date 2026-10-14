"""Phase 6.3: operational disruption and measured gate latency."""

import argparse
import json
import math
import random
import statistics
from time import perf_counter_ns

from disruption_optimizer.baselines import ContainmentGate
from event_collector.collector import EventCollector
from graph_engine.graph import CapabilityGraph
from policy_engine.engine import PolicyEngine
from simulator.scenarios import ALL_SCENARIOS
from simulator.simulator import MultiAgentSimulator
from simulator.evaluate import leaked


def percentile(values, percent):
    """Nearest-rank percentile."""
    if not values:
        return None

    ordered = sorted(values)

    index = max(
        0,
        math.ceil(percent / 100 * len(ordered)) - 1,
    )

    return ordered[index]


def latency_summary(values):
    """All input values and returned times are milliseconds."""
    return {
        "samples": len(values),
        "mean_ms": (
            statistics.mean(values) if values else None
        ),
        "median_ms": (
            statistics.median(values) if values else None
        ),
        "p95_ms": percentile(values, 95),
        "max_ms": max(values) if values else None,
    }


def run_once(scenario, mode):
    """Run a fresh scenario with optional timed containment."""
    graph = CapabilityGraph()
    collector = EventCollector(graph)

    gate = (
        ContainmentGate(graph, PolicyEngine(), mode)
        if mode != "none"
        else None
    )

    gate_times = []
    incident_times = []

    def timed_gate(event):
        previous_count = len(gate.decisions)

        start = perf_counter_ns()
        allowed = gate(event)

        elapsed_ms = (
            perf_counter_ns() - start
        ) / 1_000_000

        gate_times.append(elapsed_ms)

        if len(gate.decisions) > previous_count:
            incident_times.append(elapsed_ms)

        return allowed

    simulator = MultiAgentSimulator(
        sinks=[collector.collect],
        gate=timed_gate if gate else None,
    )

    start = perf_counter_ns()
    events = simulator.run(scenario)

    runtime_ms = (
        perf_counter_ns() - start
    ) / 1_000_000

    return (
        events,
        gate_times,
        incident_times,
        runtime_ms,
    )


def disruption(reference, contained, legitimate_steps):
    """
    Compare contained execution with an uncontained reference.

    Step numbers identify matching scripted actions.

    Only legitimate steps that succeeded in the reference run
    are eligible for legitimate-retention measurements.
    """
    reference_success = {
        event["metadata"]["step"]
        for event in reference
        if event["result"] == "success"
    }

    contained_success = {
        event["metadata"]["step"]
        for event in contained
        if event["result"] == "success"
    }

    if legitimate_steps is None:
        eligible = None
        retained = None
    else:
        eligible = reference_success & legitimate_steps
        retained = eligible & contained_success

    return {
        "total_steps": len(contained),
        "successful_steps": len(contained_success),

        "denied_steps": sum(
            event["result"] == "denied"
            for event in contained
        ),

        "error_steps": sum(
            event["result"] == "error"
            for event in contained
        ),

        "reference_successful_steps": len(reference_success),

        "all_action_completion_pct": (
            100 * len(contained_success) / len(contained)
            if contained
            else None
        ),

        # This includes malicious actions and must not be
        # interpreted as legitimate operational disruption.
        "reference_successes_lost": len(
            reference_success - contained_success
        ),

        "eligible_legitimate_steps": (
            len(eligible) if eligible is not None else None
        ),

        "retained_legitimate_steps": (
            len(retained) if retained is not None else None
        ),

        "legitimate_retention_pct": (
            100 * len(retained) / len(eligible)
            if eligible
            else None
        ),

        "legitimate_disruption_pct": (
            100 * len(eligible - contained_success)
            / len(eligible)
            if eligible
            else None
        ),

        "sensitive_data_leaked": leaked(contained),
    }


def evaluate(repeats=5, warmups=1, labels=None):
    """
    Compare all strategies using fresh graphs for every run.

    labels optionally maps scenario IDs to legitimate step numbers.
    Benign scenarios default to all steps being legitimate.
    Attack scenarios require explicit annotations.
    """
    if repeats < 1 or warmups < 0:
        raise ValueError(
            "repeats must be positive; "
            "warmups must be nonnegative"
        )

    labels = labels or {}

    known = {
        scenario.scenario_id: scenario
        for scenario in ALL_SCENARIOS
    }

    for name, steps in labels.items():
        if name not in known or not isinstance(steps, list):
            raise ValueError(
                "Labels must map known scenario IDs "
                "to step-number lists"
            )

        if any(
            type(step) is not int
            or not 1 <= step <= len(known[name].steps)
            for step in steps
        ):
            raise ValueError(
                "Invalid legitimate step number"
            )

    rows = []
    random_order = random.Random(42)

    for scenario in ALL_SCENARIOS:
        reference, _, _, _ = run_once(
            scenario,
            "none",
        )

        if scenario.scenario_id in labels:
            legitimate = set(
                labels[scenario.scenario_id]
            )
        elif scenario.trajectory_type == "benign":
            legitimate = set(
                range(1, len(scenario.steps) + 1)
            )
        else:
            legitimate = None

        modes = [
            "shutdown",
            "static",
            "adaptive",
        ]

        # Warm-up runs are excluded from reported timings.
        for _ in range(warmups):
            for mode in modes:
                run_once(scenario, mode)

        collected = {
            mode: {
                "events": None,
                "gate_times": [],
                "incident_times": [],
                "runtimes": [],
            }
            for mode in modes
        }

        for _ in range(repeats):
            order = modes.copy()
            random_order.shuffle(order)

            for mode in order:
                (
                    events,
                    gate_times,
                    incident_times,
                    runtime,
                ) = run_once(scenario, mode)

                data = collected[mode]

                if data["events"] is not None:
                    previous_results = [
                        event["result"]
                        for event in data["events"]
                    ]

                    current_results = [
                        event["result"]
                        for event in events
                    ]

                    if previous_results != current_results:
                        raise ValueError(
                            "Repeated runs produced "
                            "different outcomes"
                        )

                data["events"] = events
                data["gate_times"].extend(gate_times)
                data["incident_times"].extend(
                    incident_times
                )
                data["runtimes"].append(runtime)

        for mode in modes:
            data = collected[mode]

            rows.append({
                "scenario": scenario.scenario_id,
                "strategy": mode,

                "disruption": disruption(
                    reference,
                    data["events"],
                    legitimate,
                ),

                "gate_latency": latency_summary(
                    data["gate_times"]
                ),

                "incident_decision_latency": latency_summary(
                    data["incident_times"]
                ),

                "scenario_runtime": latency_summary(
                    data["runtimes"]
                ),
            })

    return {
        "repeats": repeats,
        "warmups": warmups,
        "rows": rows,

        "notes": [
            (
                "Latency uses measured wall-clock time; "
                "simulator timestamps are not timing measurements."
            ),
            (
                "Gate samples include allow and deny calls. "
                "Base-access-control rejections do not call the gate."
            ),
            (
                "Incident latency covers gate detection, planning "
                "and applying restrictions; collector and rendering "
                "are excluded."
            ),
            (
                "Attack scenarios need explicit legitimate-step "
                "annotations for legitimate retention metrics."
            ),
            (
                "Action completion and successes lost include "
                "malicious actions and are not legitimate disruption."
            ),
            (
                "Default adaptive weights are zero. "
                "Only three built-in scenarios are evaluated."
            ),
        ],
    }


def format_value(value):
    if value is None:
        return "N/A"

    return f"{value:.3f}"


def main():
    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "--repeats",
        type=int,
        default=5,
    )

    parser.add_argument(
        "--warmups",
        type=int,
        default=1,
    )

    parser.add_argument(
        "--labels",
        help=(
            "Optional JSON mapping scenario IDs "
            "to legitimate step numbers"
        ),
    )

    parser.add_argument(
        "--output",
        help="Optional output JSON path",
    )

    args = parser.parse_args()
    labels = None

    if args.labels:
        with open(
            args.labels,
            encoding="utf-8",
        ) as file:
            labels = json.load(file)

        if not isinstance(labels, dict):
            parser.error(
                "labels must be a JSON object"
            )

    try:
        report = evaluate(
            repeats=args.repeats,
            warmups=args.warmups,
            labels=labels,
        )
    except ValueError as error:
        parser.error(str(error))

    print(
        f"{'Scenario':34} "
        f"{'Strategy':10} "
        f"{'Retained %':>11} "
        f"{'Gate mean ms':>13} "
        f"{'Gate p95 ms':>12}"
    )

    for row in report["rows"]:
        retention = row["disruption"][
            "legitimate_retention_pct"
        ]

        mean = row["gate_latency"]["mean_ms"]
        p95 = row["gate_latency"]["p95_ms"]

        print(
            f"{row['scenario']:34} "
            f"{row['strategy']:10} "
            f"{format_value(retention):>11} "
            f"{format_value(mean):>13} "
            f"{format_value(p95):>12}"
        )

    for note in report["notes"]:
        print("*", note)

    if args.output:
        with open(
            args.output,
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                report,
                file,
                indent=2,
                allow_nan=False,
            )

        print("Report saved:", args.output)


if __name__ == "__main__":
    main()