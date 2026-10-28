import json
from pathlib import Path

from disruption_optimizer.baselines import ContainmentGate
from event_collector.collector import EventCollector
from graph_engine.graph import CapabilityGraph
from policy_engine.engine import PolicyEngine
from risk_detector.detector import RiskDetector
from simulator.evaluate import leaked, run_graph_scan, run_inline_gate
from simulator.metrics import disruption, run_once
from simulator.scenarios import (
    ALL_SCENARIOS,
    ATTACK_SCENARIOS,
    BENIGN_SCENARIOS,
    MIXED_WORKFLOW_CONFIDENTIAL_EXFILTRATION,
    PARALLEL_BRANCH_PII_EXFILTRATION,
)
from simulator.simulator import MultiAgentSimulator


LABELS_FILE = Path(__file__).resolve().parent.parent / "simulator" / "legitimate_step_labels.json"


#==================================================
# Dataset structure and labels
#==================================================

def load_labels():
    with open(LABELS_FILE, encoding="utf-8") as file:
        return json.load(file)


def test_dataset_is_balanced_and_scenario_ids_are_unique():
    assert len(BENIGN_SCENARIOS) == 6
    assert len(ATTACK_SCENARIOS) == 6
    assert len(ALL_SCENARIOS) == 12

    scenario_ids = [scenario.scenario_id for scenario in ALL_SCENARIOS]
    assert len(scenario_ids) == len(set(scenario_ids))


def test_every_attack_has_valid_legitimate_step_labels():
    labels = load_labels()
    attack_ids = {scenario.scenario_id for scenario in ATTACK_SCENARIOS}

    assert set(labels) == attack_ids

    for scenario in ATTACK_SCENARIOS:
        steps = labels[scenario.scenario_id]
        assert steps
        assert len(steps) == len(set(steps))
        assert all(type(step) is int for step in steps)
        assert all(1 <= step <= len(scenario.steps) for step in steps)


#==================================================
# Detection and containment behaviour
#==================================================

def test_inline_gate_allows_all_benign_scenarios():
    for scenario in BENIGN_SCENARIOS:
        graph = CapabilityGraph()
        detector = RiskDetector(graph, PolicyEngine())
        simulator = MultiAgentSimulator(
            sinks=[EventCollector(graph).collect],
            gate=lambda event: not detector.evaluate_event(event),
        )

        events = simulator.run(scenario)

        assert not any(
            event["metadata"].get("outcome_reason") == "blocked_by_gate"
            for event in events
        )
        assert not leaked(events)


def test_every_attack_is_blocked_without_sensitive_leak():
    for scenario in ATTACK_SCENARIOS:
        for mode in ("shutdown", "static", "adaptive"):
            graph = CapabilityGraph()
            gate = ContainmentGate(graph, PolicyEngine(), mode=mode)
            simulator = MultiAgentSimulator(
                sinks=[EventCollector(graph).collect],
                gate=gate,
            )

            events = simulator.run(scenario)

            assert gate.decisions
            assert not leaked(events)


def test_detection_evaluation_matches_dataset_ground_truth():
    graph_counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    inline_counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

    for scenario in ALL_SCENARIOS:
        is_attack = scenario.trajectory_type == "attack"

        graph_flagged, _ = run_graph_scan(scenario)
        inline_flagged, _ = run_inline_gate(scenario)

        graph_key = (
            "TP" if is_attack and graph_flagged
            else "FN" if is_attack
            else "FP" if graph_flagged
            else "TN"
        )
        inline_key = (
            "TP" if is_attack and inline_flagged
            else "FN" if is_attack
            else "FP" if inline_flagged
            else "TN"
        )

        graph_counts[graph_key] += 1
        inline_counts[inline_key] += 1

    assert graph_counts == {"TP": 6, "FP": 1, "TN": 5, "FN": 0}
    assert inline_counts == {"TP": 6, "FP": 0, "TN": 6, "FN": 0}


#==================================================
# Minimum-disruption evidence
#==================================================

def retention_for(scenario, mode, legitimate_steps):
    reference, _, _, _ = run_once(scenario, "none")
    contained, _, _, _ = run_once(scenario, mode)
    return disruption(reference, contained, set(legitimate_steps))["legitimate_retention_pct"]


def test_mixed_and_parallel_scenarios_measure_preserved_work():
    labels = load_labels()

    mixed = MIXED_WORKFLOW_CONFIDENTIAL_EXFILTRATION
    mixed_labels = labels[mixed.scenario_id]

    assert retention_for(mixed, "shutdown", mixed_labels) == 40.0
    assert retention_for(mixed, "static", mixed_labels) == 100.0
    assert retention_for(mixed, "adaptive", mixed_labels) == 100.0

    parallel = PARALLEL_BRANCH_PII_EXFILTRATION
    parallel_labels = labels[parallel.scenario_id]

    assert retention_for(parallel, "shutdown", parallel_labels) == 75.0
    assert retention_for(parallel, "static", parallel_labels) == 100.0
    assert retention_for(parallel, "adaptive", parallel_labels) == 100.0
