import pytest
from jsonschema.exceptions import ValidationError

from audit_history import audit_logger
from audit_history.audit_logger import (
    filter_history,
    get_history,
    load_mock_events,
    log_collected_event,
    log_event,
)
from event_collector.collector import EventCollector


#============================================================
# Simple graph for Event Collector integration testing
#============================================================
class FakeGraph:
    def __init__(self):
        self.applied_events = []

    def apply_event(self, event):
        self.applied_events.append(event)


#============================================================
# Point the audit log at a temporary file, so tests never
# touch the real audit_history.jsonl
#============================================================
@pytest.fixture(autouse=True)
def audit_file(tmp_path, monkeypatch):
    path = tmp_path / "audit_history.jsonl"
    monkeypatch.setattr(audit_logger, "AUDIT_HISTORY_FILE", path)
    return path


#============================================================
# Collect the mock events and log them with their context
#============================================================
@pytest.fixture
def logged_history():
    graph = FakeGraph()
    collector = EventCollector(graph)

    for event in load_mock_events():
        assert collector.collect(event) is True

    assert len(graph.applied_events) == 3

    for collected_event in collector.get_events():
        log_collected_event(collected_event)

    return get_history()


#============================================================
# Load mock events
#============================================================
def test_load_mock_events():
    assert len(load_mock_events()) == 3


def test_empty_history_when_no_file():
    assert get_history() == []


#============================================================
# Check that invalid event is rejected
#============================================================
def test_invalid_event_is_rejected_and_not_logged():
    invalid_event = {
        "event_id": "evt-invalid",
        "timestamp": "2026-10-07T12:10:00Z",
        "trajectory_id": "test-run-001",
        "action": "read",
        "object": {
            "type": "resource",
            "id": "customer_records.csv",
            "classification": "confidential",
        },
        "result": "success",
    }

    with pytest.raises(ValidationError):
        log_event(invalid_event)

    assert get_history() == []


#============================================================
# Check first event
#============================================================
def test_read_event_logged_with_context(logged_history):
    assert len(logged_history) == 3

    record = logged_history[0]
    assert record["record_type"] == "agent_event"
    assert record["event_id"] == "evt-001"
    assert record["agent_id"] == "file_agent"
    assert record["action"] == "read"
    assert record["result"] == "success"
    assert record["context"] == {
        "trust_boundary": "none",
        "transfer_context": "none",
        "sensitive_exposure": "none",
    }


#============================================================
# Check internal delegation context
#============================================================
def test_internal_delegation_context(logged_history):
    record = logged_history[1]
    assert record["event_id"] == "evt-002"
    assert record["agent_id"] == "analysis_agent"
    assert record["action"] == "delegate"
    assert record["context"]["trust_boundary"] == "internal"
    assert record["context"]["transfer_context"] == "internal_transfer"
    assert record["context"]["sensitive_exposure"] == "none"


#============================================================
# Check denied external send context
#============================================================
def test_denied_external_send_context(logged_history):
    record = logged_history[2]
    assert record["event_id"] == "evt-003"
    assert record["action"] == "send"
    assert record["result"] == "denied"
    assert record["context"]["trust_boundary"] == "internal_to_external"
    assert record["context"]["transfer_context"] == "external_transfer"
    assert record["context"]["sensitive_exposure"] == "attempted_external_exposure"


#============================================================
# Test filtering
#============================================================
@pytest.mark.parametrize(
    "filters, expected_ids",
    [
        ({"agent_id": "email_agent"}, ["evt-003"]),
        ({"result": "denied"}, ["evt-003"]),
        ({"action": "read"}, ["evt-001"]),
        ({"trajectory_id": "test-run-001"}, ["evt-001", "evt-002", "evt-003"]),
        ({"record_type": "agent_event"}, ["evt-001", "evt-002", "evt-003"]),
        ({"agent_id": "email_agent", "result": "success"}, []),
        ({"trajectory_id": "no-such-run"}, []),
    ],
)
def test_filter_history(logged_history, filters, expected_ids):
    assert [record["event_id"] for record in filter_history(**filters)] == expected_ids
