import json

import pytest
from jsonschema import Draft202012Validator

from event_collector.collector import EventCollector
from graph_engine.graph import CapabilityGraph
from policy_engine.engine import PolicyEngine
from risk_detector.detector import RiskDetector
from simulator.models import Scenario, Step
from simulator.scenarios import (
    ALL_SCENARIOS,
    BENIGN_REPORT_GENERATION,
    CROSS_AGENT_DATA_EXFILTRATION,
    PERMISSION_ESCALATION,
)
from simulator.simulator import MultiAgentSimulator


SCHEMA_FILE = "schema/event_schema.json"


def results(events):
    return [event["result"] for event in events]


def reasons(events):
    return [event["metadata"].get("outcome_reason") for event in events]


def test_all_scenarios_emit_schema_valid_events():
    validator = Draft202012Validator(json.load(open(SCHEMA_FILE)))
    events = MultiAgentSimulator().run_all(ALL_SCENARIOS)

    assert len(events) == sum(len(s.steps) for s in ALL_SCENARIOS)

    for event in events:
        validator.validate(event)


def test_event_ids_unique_and_timestamps_increase_across_runs():
    events = MultiAgentSimulator().run_all(ALL_SCENARIOS)

    ids = [event["event_id"] for event in events]
    timestamps = [event["timestamp"] for event in events]

    assert ids == [f"evt-{i:06d}" for i in range(1, len(events) + 1)]
    assert timestamps == sorted(timestamps)
    assert len(set(timestamps)) == len(timestamps)


def test_each_run_gets_its_own_trajectory_id():
    simulator = MultiAgentSimulator()

    first = simulator.run(BENIGN_REPORT_GENERATION)
    second = simulator.run(BENIGN_REPORT_GENERATION)

    assert {e["trajectory_id"] for e in first} == {"traj-benign_report_generation-001"}
    assert {e["trajectory_id"] for e in second} == {"traj-benign_report_generation-002"}


def test_ground_truth_label_comes_from_scenario():
    simulator = MultiAgentSimulator()

    benign = simulator.run(BENIGN_REPORT_GENERATION)
    attack = simulator.run(CROSS_AGENT_DATA_EXFILTRATION)

    assert all(
        e["ground_truth_label"] == {"trajectory_type": "benign", "attack_type": None}
        for e in benign
    )
    assert all(
        e["ground_truth_label"] == {
            "trajectory_type": "attack",
            "attack_type": "cross_agent_data_exfiltration",
        }
        for e in attack
    )


def test_benign_scenario_all_steps_succeed():
    events = MultiAgentSimulator().run(BENIGN_REPORT_GENERATION)

    assert set(results(events)) == {"success"}


def test_missing_permission_denied_until_granted():
    events = MultiAgentSimulator().run(PERMISSION_ESCALATION)

    assert results(events) == ["success", "success", "denied", "success", "success"]
    assert reasons(events)[2] == "missing_permission"

    grant = events[3]
    assert grant["object"] == {"type": "permission", "id": "perm-temp-external-send"}
    assert grant["permission_id"] is None
    assert grant["metadata"]["granted_permission_id"] == "perm-temp-external-send"


def test_sinks_receive_every_event_in_order():
    received = []
    simulator = MultiAgentSimulator(sinks=[received.append])

    events = simulator.run(CROSS_AGENT_DATA_EXFILTRATION)

    assert received == events


def test_gate_sees_proposed_event_and_can_deny_it():
    seen = []

    def gate(event):
        seen.append(event)
        return event["action"] != "send"

    events = MultiAgentSimulator(gate=gate).run(CROSS_AGENT_DATA_EXFILTRATION)

    assert results(events) == ["success", "success", "success", "denied"]
    assert reasons(events)[3] == "blocked_by_gate"
    assert all(event["result"] == "success" for event in seen)


def test_blocked_delegate_has_knock_on_effect_downstream():
    def gate(event):
        return not (
            event["agent_id"] == "analysis_agent" and event["action"] == "delegate"
        )

    events = MultiAgentSimulator(gate=gate).run(CROSS_AGENT_DATA_EXFILTRATION)

    assert results(events) == ["success", "success", "denied", "error"]
    assert reasons(events)[3] == "agent_does_not_hold_object"


def test_gate_not_consulted_when_base_access_control_denies():
    seen = []

    def gate(event):
        seen.append(event["event_id"])
        return True

    events = MultiAgentSimulator(gate=gate).run(PERMISSION_ESCALATION)

    assert events[2]["event_id"] not in seen


def test_jitter_is_reproducible_with_seed():
    first = MultiAgentSimulator(jitter_seconds=10, seed=42).run(BENIGN_REPORT_GENERATION)
    second = MultiAgentSimulator(jitter_seconds=10, seed=42).run(BENIGN_REPORT_GENERATION)

    assert [e["timestamp"] for e in first] == [e["timestamp"] for e in second]


def test_detector_gate_stops_exfiltration_end_to_end():
    graph = CapabilityGraph()
    collector = EventCollector(graph)
    detector = RiskDetector(graph, PolicyEngine())

    simulator = MultiAgentSimulator(
        sinks=[collector.collect],
        gate=lambda event: not detector.evaluate_event(event),
    )

    events = simulator.run(CROSS_AGENT_DATA_EXFILTRATION)

    assert results(events) == ["success", "success", "success", "denied"]
    assert len(collector.get_events()) == 4
    assert not graph.is_reachable("customer_records.csv", "attacker@example.com")


def make_scenario(step, trajectory_type="benign"):
    return Scenario(
        scenario_id="broken",
        trajectory_type=trajectory_type,
        attack_type=None,
        agents={"a": {"perm-a"}, "b": set()},
        resources={"data.csv": "internal"},
        tools={"some_tool"},
        externals={"out@example.com"},
        steps=[step],
    )


@pytest.mark.parametrize(
    "scenario, message",
    [
        (make_scenario(Step("ghost", "read", "data.csv", permission="perm-a")), "unknown agent"),
        (make_scenario(Step("a", "teleport", "data.csv", permission="perm-a")), "unknown action"),
        (make_scenario(Step("a", "read", "missing.csv", permission="perm-a")), "unknown resource/tool"),
        (make_scenario(Step("a", "read", "data.csv")), "needs a permission"),
        (make_scenario(Step("a", "send", "data.csv", to="nowhere", permission="perm-a")), "unknown destination"),
        (make_scenario(Step("a", "read", "data.csv", to="b", permission="perm-a")), "only delegate/send"),
        (make_scenario(Step("a", "read", "data.csv", permission="perm-a"), "suspicious"), "bad trajectory_type"),
    ],
)
def test_invalid_scenarios_rejected_before_any_event(scenario, message):
    received = []
    simulator = MultiAgentSimulator(sinks=[received.append])

    with pytest.raises(ValueError, match=message):
        simulator.run(scenario)

    assert received == []
