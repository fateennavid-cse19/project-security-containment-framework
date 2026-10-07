import json
from pathlib import Path

from jsonschema import validate


#============================================================
# File paths
#============================================================
BASE_DIR = Path(__file__).resolve().parent
MOCK_EVENTS_FILE = BASE_DIR / "mock_events.json"
AUDIT_HISTORY_FILE = BASE_DIR / "audit_history.jsonl"
EVENT_SCHEMA_FILE = BASE_DIR.parent / "schema" / "event_schema.json"


#============================================================
# Load mock events
#============================================================
def load_mock_events():
    with open(MOCK_EVENTS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


#============================================================
# Validate event against project schema
#============================================================
def validate_event(event):
    with open(EVENT_SCHEMA_FILE, "r", encoding="utf-8") as file:
        schema = json.load(file)

    validate(instance=event, schema=schema)


#============================================================
# Save one event to audit history
#============================================================
def log_event(event):
    validate_event(event)

    audit_record = {
        "record_type": "agent_event",
        **event,
    }

    with open(AUDIT_HISTORY_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(audit_record) + "\n")


#============================================================
# Save one security decision to audit history
#============================================================
def log_security_decision(decision):
    required_fields = [
        "incident_id",
        "timestamp",
        "trajectory_id",
        "severity",
        "violation",
        "dangerous_path",
        "containment_action",
        "attack_prevented",
        "safe_workflow_continues",
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in decision
    ]

    if missing_fields:
        raise ValueError(
            f"Missing security decision fields: {missing_fields}"
        )

    audit_record = {
        "record_type": "security_decision",
        **decision,
    }

    with open(AUDIT_HISTORY_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(audit_record) + "\n")


#============================================================
# Read audit history
#============================================================
def get_history():
    if not AUDIT_HISTORY_FILE.exists():
        return []

    events = []

    with open(AUDIT_HISTORY_FILE, "r", encoding="utf-8") as file:
        for line in file:
            events.append(json.loads(line))

    return events


#============================================================
# Filter audit history
#============================================================
def filter_history(
    agent_id=None,
    action=None,
    result=None,
    trajectory_id=None,
    record_type=None
):
    history = get_history()
    filtered_events = []

    for event in history:
        if agent_id is not None and event.get("agent_id") != agent_id:
            continue

        if action is not None and event.get("action") != action:
            continue

        if result is not None and event.get("result") != result:
            continue

        if (
            trajectory_id is not None
            and event.get("trajectory_id") != trajectory_id
        ):
            continue

        if (
            record_type is not None
            and event.get("record_type") != record_type
        ):
            continue

        filtered_events.append(event)

    return filtered_events


#============================================================
# Display audit history as a simple log view
#============================================================
def display_history(records=None):
    if records is None:
        records = get_history()

    if not records:
        print("No audit records found.")
        return

    print(
        f'{"Timestamp":<22} '
        f'{"Type":<18} '
        f'{"ID":<12} '
        f'{"Agent":<16} '
        f'{"Action":<18} '
        f'{"Result":<12} '
        f'{"Trajectory":<15}'
    )

    print("-" * 120)

    for record in records:
        record_type = record.get("record_type", "-")
        timestamp = record.get("timestamp", "-")
        trajectory_id = record.get("trajectory_id", "-")

        if record_type == "agent_event":
            record_id = record.get("event_id", "-")
            agent = record.get("agent_id", "-")
            action = record.get("action", "-")
            result = record.get("result", "-")

        elif record_type == "security_decision":
            record_id = record.get("incident_id", "-")
            agent = "-"

            containment_action = record.get(
                "containment_action",
                {}
            )

            action = containment_action.get(
                "action",
                "-"
            )

            if record.get("attack_prevented") is True:
                result = "prevented"
            else:
                result = "not_prevented"

        else:
            record_id = "-"
            agent = "-"
            action = "-"
            result = "-"

        print(
            f'{timestamp:<22} '
            f'{record_type:<18} '
            f'{record_id:<12} '
            f'{agent:<16} '
            f'{action:<18} '
            f'{result:<12} '
            f'{trajectory_id:<15}'
        )


#============================================================
# Main program
#============================================================
def main():
    events = load_mock_events()

    for event in events:
        log_event(event)

        print(
            f'Logged: {event["event_id"]} | '
            f'{event["agent_id"]} | '
            f'{event["action"]} | '
            f'{event["result"]}'
        )


#============================================================
# Run the program
#============================================================
if __name__ == "__main__":
    main()