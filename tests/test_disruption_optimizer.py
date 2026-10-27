import copy
import math

import pytest

from disruption_optimizer.baselines import ContainmentGate
from disruption_optimizer.core import CostModel, edge_key, minimum_cut
from event_collector.collector import EventCollector
from graph_engine.graph import CapabilityGraph
from policy_engine.engine import PolicyEngine
from simulator.evaluate import leaked
from simulator.scenarios import (
    BENIGN_REPORT_GENERATION,
    CROSS_AGENT_DATA_EXFILTRATION,
    PERMISSION_ESCALATION,
)
from simulator.simulator import MultiAgentSimulator


SEND = ("email_agent", "attacker@example.com", "send")


def edge(source, target, action="delegate", cost=1.0, blocked=False):
    return {
        "source": source,
        "target": target,
        "action": action,
        "blocked": blocked,
        "cost": cost,
    }


def snapshot(*edges):
    ids = sorted({e["source"] for e in edges} | {e["target"] for e in edges})
    return {"nodes": [{"id": i} for i in ids], "edges": list(edges)}


def chain(costs=(1.0, 1.0, 1.0)):
    """src -> a -> b -> dst, with the given cost on each hop."""
    return snapshot(
        edge("src", "a", "read", costs[0]),
        edge("a", "b", "delegate", costs[1]),
        edge("b", "dst", "send", costs[2]),
    )


def cut_keys(plan):
    return {edge_key(e) for e in plan.edges}


def run(scenario, mode, cost_model=None):
    graph = CapabilityGraph()
    gate = ContainmentGate(graph, PolicyEngine(), mode=mode, cost_model=cost_model)
    simulator = MultiAgentSimulator(sinks=[EventCollector(graph).collect], gate=gate)
    return simulator.run(scenario), gate, graph


# -- cost model ---------------------------------------------------------------

def test_edge_key_is_source_target_action():
    assert edge_key(edge("a", "b", "send")) == ("a", "b", "send")


def test_static_cost_ignores_weights():
    key = ("a", "b", "delegate")
    model = CostModel(workload={key: 2.0}, criticality={key: 3.0})

    assert model.cost(edge("a", "b", cost=2.0)) == 2.0


def test_adaptive_cost_formula():
    key = ("a", "b", "delegate")
    model = CostModel(workload={key: 2.0}, criticality={key: 3.0})

    assert model.cost(edge("a", "b", cost=2.0), adaptive=True) == 2.0 * (1 + 2.0 + 3.0)


def test_missing_cost_defaults_to_one():
    assert CostModel().cost({"source": "a", "target": "b", "action": "send"}) == 1.0


@pytest.mark.parametrize("bad", [-1.0, math.inf, math.nan])
def test_invalid_costs_rejected(bad):
    key = ("a", "b", "delegate")

    with pytest.raises(ValueError):
        CostModel().cost(edge("a", "b", cost=bad))
    with pytest.raises(ValueError):
        CostModel(workload={key: bad}).cost(edge("a", "b"), adaptive=True)


# -- minimum cut --------------------------------------------------------------

def test_cut_selects_cheapest_edge():
    plan = minimum_cut(chain((5.0, 1.0, 3.0)), ["src"], ["dst"])

    assert plan.feasible
    assert cut_keys(plan) == {("a", "b", "delegate")}
    assert plan.cost == 1.0


def test_planning_does_not_modify_snapshot():
    snap = chain()
    before = copy.deepcopy(snap)

    minimum_cut(snap, ["src"], ["dst"])

    assert snap == before


def test_parallel_actions_are_cut_together():
    snap = snapshot(
        edge("src", "a", "read", 1.5),
        edge("a", "dst", "send", 1.0),
        edge("a", "dst", "delegate", 1.0),
    )

    plan = minimum_cut(snap, ["src"], ["dst"])

    assert cut_keys(plan) == {("src", "a", "read")}
    assert plan.cost == 1.5


def test_parallel_action_costs_are_summed():
    snap = snapshot(
        edge("src", "a", "read", 3.0),
        edge("a", "dst", "send", 1.0),
        edge("a", "dst", "delegate", 1.0),
    )

    plan = minimum_cut(snap, ["src"], ["dst"])

    assert cut_keys(plan) == {("a", "dst", "send"), ("a", "dst", "delegate")}
    assert plan.cost == 2.0


def test_blocked_edges_are_ignored():
    snap = snapshot(
        edge("src", "a", "read"),
        edge("a", "dst", "send", 5.0),
        edge("src", "dst", "send", 1.0, blocked=True),
    )

    plan = minimum_cut(snap, ["src"], ["dst"])

    assert cut_keys(plan) == {("src", "a", "read")}


def test_protected_edges_are_not_cut():
    model = CostModel(protected={("a", "b", "delegate")})

    plan = minimum_cut(chain((5.0, 1.0, 3.0)), ["src"], ["dst"], model=model)

    assert plan.feasible
    assert cut_keys(plan) == {("b", "dst", "send")}


def test_infeasible_when_every_edge_protected():
    snap = chain()
    model = CostModel(protected={edge_key(e) for e in snap["edges"]})

    plan = minimum_cut(snap, ["src"], ["dst"], model=model)

    assert not plan.feasible
    assert plan.edges == []
    assert plan.cost == 0.0


def test_multiple_sources_and_destinations_all_separated():
    snap = snapshot(
        edge("s1", "hub", "read", 5.0),
        edge("s2", "hub", "read", 5.0),
        edge("hub", "d1", "send", 5.0),
        edge("hub", "d2", "send", 5.0),
        edge("x", "hub", "delegate", 1.0),
    )

    plan = minimum_cut(snap, ["s1", "s2"], ["d1", "d2"])

    assert plan.feasible
    assert plan.cost == 10.0
    assert len(plan.edges) == 2


def test_adaptive_weights_change_the_selected_cut():
    snap = chain((2.0, 1.0, 3.0))
    model = CostModel(criticality={("a", "b", "delegate"): 5.0})

    static = minimum_cut(snap, ["src"], ["dst"], model=model)
    adaptive = minimum_cut(snap, ["src"], ["dst"], model=model, adaptive=True)

    assert cut_keys(static) == {("a", "b", "delegate")}
    assert cut_keys(adaptive) == {("src", "a", "read")}
    assert adaptive.cost == 2.0


# -- containment gate ---------------------------------------------------------

def test_unknown_mode_rejected():
    with pytest.raises(ValueError):
        ContainmentGate(CapabilityGraph(), PolicyEngine(), mode="panic")


@pytest.mark.parametrize("mode", ["shutdown", "static", "adaptive"])
def test_benign_workflow_untouched(mode):
    events, gate, _ = run(BENIGN_REPORT_GENERATION, mode)

    assert all(e["result"] == "success" for e in events)
    assert gate.decisions == []


@pytest.mark.parametrize("scenario", [CROSS_AGENT_DATA_EXFILTRATION, PERMISSION_ESCALATION])
@pytest.mark.parametrize("mode", ["shutdown", "static", "adaptive"])
def test_attacks_do_not_leak(scenario, mode):
    events, gate, _ = run(scenario, mode)

    assert not leaked(events)
    assert len(gate.decisions) == 1
    assert gate.decisions[0]["trigger_denied"]


def test_static_cut_blocks_only_the_send_edge():
    events, gate, graph = run(CROSS_AGENT_DATA_EXFILTRATION, "static")
    decision = gate.decisions[0]

    assert [e["result"] for e in events] == ["success", "success", "success", "denied"]
    assert decision["feasible"]
    assert {edge_key(e) for e in decision["edges"]} == {SEND}
    assert decision["cost"] == 1.0
    assert gate.blocked == {SEND}
    assert graph.is_reachable("customer_records.csv", "email_agent")


def test_shutdown_cuts_everything_and_stops_later_events():
    events, gate, _ = run(PERMISSION_ESCALATION, "shutdown")
    trigger = next(i for i, e in enumerate(events) if e["event_id"] == gate.decisions[0]["event_id"])

    assert gate.stopped
    assert gate.decisions[0]["cost"] == len(gate.decisions[0]["edges"])
    assert all(e["result"] != "success" for e in events[trigger:])


def test_shutdown_costs_more_than_static_cut():
    _, shutdown, _ = run(CROSS_AGENT_DATA_EXFILTRATION, "shutdown")
    _, static, _ = run(CROSS_AGENT_DATA_EXFILTRATION, "static")

    assert shutdown.decisions[0]["cost"] > static.decisions[0]["cost"]


def test_blocked_edge_stays_blocked_on_replay(make_event):
    _, gate, _ = run(CROSS_AGENT_DATA_EXFILTRATION, "static")
    replay = make_event("send", agent_id="email_agent", to="attacker@example.com")

    assert gate(replay) is False
    assert len(gate.decisions) == 1


def test_adaptive_avoids_critical_edge():
    model = CostModel(criticality={SEND: 5.0})

    _, gate, _ = run(CROSS_AGENT_DATA_EXFILTRATION, "adaptive", cost_model=model)
    decision = gate.decisions[0]

    assert decision["mode"] == "adaptive"
    assert SEND not in {edge_key(e) for e in decision["edges"]}
    assert decision["cost"] == 1.0


def test_infeasible_cut_still_denies_trigger():
    protected = {
        ("customer_records.csv", "file_agent", "read"),
        ("file_agent", "analysis_agent", "delegate"),
        ("analysis_agent", "email_agent", "delegate"),
        SEND,
    }

    events, gate, _ = run(CROSS_AGENT_DATA_EXFILTRATION, "static", CostModel(protected=protected))
    decision = gate.decisions[0]

    assert events[-1]["result"] == "denied"
    assert not decision["feasible"]
    assert decision["edges"] == []
    assert gate.blocked == set()
