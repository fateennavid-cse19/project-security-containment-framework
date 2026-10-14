from event_collector.collector import EventCollector
from graph_engine.graph import CapabilityGraph


def test_valid_event_is_stored_with_context_and_applied_to_graph(make_event):
    graph = CapabilityGraph()
    collector = EventCollector(graph)
    event = make_event("send", agent_id="email_agent", to="attacker@example.com")

    assert collector.collect(event) is True

    [collected] = collector.get_events()
    assert collected["event"] is event
    assert collected["context"]["sensitive_exposure"] == "external_exposure"
    assert graph.get_edge("email_agent", "attacker@example.com") is not None


def test_invalid_event_is_rejected_and_leaves_no_trace(make_event, capsys):
    graph = CapabilityGraph()
    collector = EventCollector(graph)
    event = make_event("read")
    del event["agent_id"]

    assert collector.collect(event) is False

    assert collector.get_events() == []
    assert graph.snapshot() == {"nodes": [], "edges": []}
    assert "Invalid event" in capsys.readouterr().out


def test_unknown_action_is_rejected_by_schema(make_event):
    collector = EventCollector(CapabilityGraph())
    event = make_event("read")
    event["action"] = "teleport"

    assert collector.collect(event) is False


def test_events_kept_in_arrival_order(make_event):
    collector = EventCollector(CapabilityGraph())
    events = [make_event("read"), make_event("delegate", to="analysis_agent")]

    for event in events:
        collector.collect(event)

    assert [c["event"]["event_id"] for c in collector.get_events()] == [e["event_id"] for e in events]


def test_works_outside_the_repo_root(make_event, tmp_path, monkeypatch):
    # The schema used to be opened with a path relative to the current
    # directory, so the collector crashed unless run from the repo root.
    monkeypatch.chdir(tmp_path)

    collector = EventCollector(CapabilityGraph())

    assert collector.collect(make_event("read")) is True
