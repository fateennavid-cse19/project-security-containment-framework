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
def log_event(event, context=None):
    validate_event(event)

    audit_record = {
        "record_type": "agent_event",
        **event,
    }

    if context is not None:
        audit_record["context"] = context

    with open(AUDIT_HISTORY_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(audit_record) + "\n")


#============================================================
# Save one collected event to audit history
#============================================================
def log_collected_event(collected_event):
    event = collected_event["event"]
    context = collected_event.get("context", {})

    log_event(
        event,
        context=context
    )


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
        "Timestamp | ID | Agent | Action | "
        "Result | Exposure | Trajectory"
    )

    print("-" * 110)

    for record in records:
        context = record.get("context", {})

        exposure = context.get(
            "sensitive_exposure",
            "-"
        )

        print(
            f'{record.get("timestamp", "-")} | '
            f'{record.get("event_id", "-")} | '
            f'{record.get("agent_id", "-")} | '
            f'{record.get("action", "-")} | '
            f'{record.get("result", "-")} | '
            f'{exposure} | '
            f'{record.get("trajectory_id", "-")}'
        )
