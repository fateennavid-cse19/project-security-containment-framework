import os

from jsonschema.exceptions import ValidationError

from audit_logger import (
    AUDIT_HISTORY_FILE,
    filter_history,
    get_history,
    load_mock_events,
    log_event,
    log_security_decision,
)


#============================================================
# Remove old audit history
#============================================================
if AUDIT_HISTORY_FILE.exists():
    os.remove(AUDIT_HISTORY_FILE)


#============================================================
# Load mock events
#============================================================
mock_events = load_mock_events()


#============================================================
# Log mock events
#============================================================
for event in mock_events:
    log_event(event)


#============================================================
# Read audit history
#============================================================
history = get_history()

assert len(history) == 3


#============================================================
# Check the first event
#============================================================
assert history[0]["event_id"] == "evt-001"
assert history[0]["agent_id"] == "file_agent"
assert history[0]["action"] == "read"
assert history[0]["result"] == "success"


#============================================================
# Check the final denied event
#============================================================
assert history[2]["event_id"] == "evt-003"
assert history[2]["agent_id"] == "email_agent"
assert history[2]["action"] == "send"
assert history[2]["result"] == "denied"


#============================================================
# Test filtering by agent
#============================================================
email_events = filter_history(agent_id="email_agent")

assert len(email_events) == 1
assert email_events[0]["event_id"] == "evt-003"


#============================================================
# Test filtering by result
#============================================================
denied_events = filter_history(result="denied")

assert len(denied_events) == 1
assert denied_events[0]["result"] == "denied"


#============================================================
# Test filtering by action
#============================================================
read_events = filter_history(action="read")

assert len(read_events) == 1
assert read_events[0]["agent_id"] == "file_agent"


#============================================================
# Test filtering by trajectory
#============================================================
trajectory_events = filter_history(
    trajectory_id="test-run-001"
)

assert len(trajectory_events) == 3

for event in trajectory_events:
    assert event["trajectory_id"] == "test-run-001"


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
        "classification": "confidential"
    },
    "result": "success"
}


#============================================================
# Check that invalid event is rejected
#============================================================
try:
    log_event(invalid_event)

    assert False, "Invalid event was accepted."

except ValidationError:
    pass


#============================================================
# Check invalid event was not saved
#============================================================
history_after_invalid_event = get_history()

assert len(history_after_invalid_event) == 3


#============================================================
# Test valid security decision
#============================================================
security_decision = {
    "incident_id": "INC-001",
    "timestamp": "2026-10-07T14:30:00Z",
    "trajectory_id": "test-run-001",
    "severity": "critical",
    "violation": "compositional_privilege_escalation",
    "dangerous_path": [
        "customer_records.csv",
        "file_agent",
        "analysis_agent",
        "email_agent",
        "external_email",
    ],
    "containment_action": {
        "action": "block_connection",
        "source": "analysis_agent",
        "target": "email_agent",
    },
    "attack_prevented": True,
    "safe_workflow_continues": True,
}

log_security_decision(security_decision)

history = get_history()

assert len(history) == 4
assert history[3]["record_type"] == "security_decision"
assert history[3]["incident_id"] == "INC-001"
assert history[3]["severity"] == "critical"
assert history[3]["containment_action"]["action"] == "block_connection"
assert history[3]["attack_prevented"] is True
assert history[3]["safe_workflow_continues"] is True


#============================================================
# Test invalid security decision
#============================================================
invalid_security_decision = {
    "incident_id": "INC-002",
    "timestamp": "2026-10-07T14:35:00Z",
    "trajectory_id": "test-run-001",
    "severity": "critical",
    "violation": "compositional_privilege_escalation",
    "dangerous_path": [
        "file_agent",
        "email_agent",
    ],
    "attack_prevented": True,
    "safe_workflow_continues": True,
}


#============================================================
# Check that invalid security decision is rejected
#============================================================
try:
    log_security_decision(invalid_security_decision)

    assert False, "Invalid security decision was accepted."

except ValueError:
    pass


#============================================================
# Check that invalid decision was not saved
#============================================================
history = get_history()

assert len(history) == 4


#============================================================
# Test filtering by record type - agent events
#============================================================
agent_events = filter_history(
    record_type="agent_event"
)

assert len(agent_events) == 3

for event in agent_events:
    assert event["record_type"] == "agent_event"


#============================================================
# Test filtering by record type - security decisions
#============================================================
security_decisions = filter_history(
    record_type="security_decision"
)

assert len(security_decisions) == 1
assert security_decisions[0]["record_type"] == "security_decision"
assert security_decisions[0]["incident_id"] == "INC-001"


#============================================================
# Test tracing one complete run
#============================================================
run_history = filter_history(
    trajectory_id="test-run-001"
)

assert len(run_history) == 4

assert run_history[0]["event_id"] == "evt-001"
assert run_history[1]["event_id"] == "evt-002"
assert run_history[2]["event_id"] == "evt-003"
assert run_history[3]["incident_id"] == "INC-001"

for record in run_history:
    assert record["trajectory_id"] == "test-run-001"


#============================================================
# Test result
#============================================================
print("All audit logger tests passed.")