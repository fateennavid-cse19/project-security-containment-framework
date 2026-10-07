import os
import sys
from pathlib import Path

from jsonschema.exceptions import ValidationError


#============================================================
# Add project root to Python path
#============================================================
ROOT_DIR = Path(__file__).resolve().parent.parent

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


from event_collector.collector import EventCollector

from audit_logger import (
    AUDIT_HISTORY_FILE,
    filter_history,
    get_history,
    load_mock_events,
    log_collected_event,
    log_event,
)


#============================================================
# Simple graph for Event Collector integration testing
#============================================================
class TestGraph:
    def __init__(self):
        self.applied_events = []

    def apply_event(self, event):
        self.applied_events.append(event)


#============================================================
# Remove old audit history
#============================================================
if AUDIT_HISTORY_FILE.exists():
    os.remove(AUDIT_HISTORY_FILE)


#============================================================
# Load mock events
#============================================================
mock_events = load_mock_events()

assert len(mock_events) == 3


#============================================================
# Test invalid event validation
#============================================================
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


#============================================================
# Check that invalid event is rejected
#============================================================
try:
    log_event(invalid_event)

    assert False, "Invalid event was accepted."

except ValidationError:
    pass

assert len(get_history()) == 0


#============================================================
# Create Event Collector
#============================================================
graph = TestGraph()
collector = EventCollector(graph)


#============================================================
# Collect valid events
#============================================================
for event in mock_events:
    collected = collector.collect(event)

    assert collected is True


#============================================================
# Check Event Collector output
#============================================================
collected_events = collector.get_events()

assert len(collected_events) == 3
assert len(graph.applied_events) == 3


#============================================================
# Log collected events with context
#============================================================
for collected_event in collected_events:
    log_collected_event(collected_event)


#============================================================
# Read audit history
#============================================================
history = get_history()

assert len(history) == 3


#============================================================
# Check first event
#============================================================
assert history[0]["record_type"] == "agent_event"
assert history[0]["event_id"] == "evt-001"
assert history[0]["agent_id"] == "file_agent"
assert history[0]["action"] == "read"
assert history[0]["result"] == "success"

assert history[0]["context"]["trust_boundary"] == "none"
assert history[0]["context"]["transfer_context"] == "none"
assert history[0]["context"]["sensitive_exposure"] == "none"


#============================================================
# Check internal delegation context
#============================================================
assert history[1]["event_id"] == "evt-002"
assert history[1]["agent_id"] == "analysis_agent"
assert history[1]["action"] == "delegate"

assert history[1]["context"]["trust_boundary"] == "internal"

assert (
    history[1]["context"]["transfer_context"]
    == "internal_transfer"
)

assert history[1]["context"]["sensitive_exposure"] == "none"


#============================================================
# Check denied external exposure context
#============================================================
assert history[2]["event_id"] == "evt-003"
assert history[2]["agent_id"] == "email_agent"
assert history[2]["action"] == "send"
assert history[2]["result"] == "denied"

assert (
    history[2]["context"]["trust_boundary"]
    == "internal_to_external"
)

assert (
    history[2]["context"]["transfer_context"]
    == "external_transfer"
)

assert (
    history[2]["context"]["sensitive_exposure"]
    == "attempted_external_exposure"
)


#============================================================
# Test filtering by agent
#============================================================
email_events = filter_history(
    agent_id="email_agent"
)

assert len(email_events) == 1
assert email_events[0]["event_id"] == "evt-003"


#============================================================
# Test filtering by result
#============================================================
denied_events = filter_history(
    result="denied"
)

assert len(denied_events) == 1
assert denied_events[0]["event_id"] == "evt-003"


#============================================================
# Test filtering by action
#============================================================
read_events = filter_history(
    action="read"
)

assert len(read_events) == 1
assert read_events[0]["event_id"] == "evt-001"


#============================================================
# Test tracing one complete run
#============================================================
run_history = filter_history(
    trajectory_id="test-run-001"
)

assert len(run_history) == 3

for record in run_history:
    assert record["trajectory_id"] == "test-run-001"


#============================================================
# Test filtering by record type
#============================================================
agent_events = filter_history(
    record_type="agent_event"
)

assert len(agent_events) == 3

for event in agent_events:
    assert event["record_type"] == "agent_event"


#============================================================
# Test result
#============================================================
print("All audit logger integration tests passed.")