import pytest


@pytest.fixture
def make_event():
    """Builds one schema-valid event. Pass keyword overrides for the fields a
    test cares about; `to` is shorthand for a destination (external if it
    contains an "@")."""
    counter = iter(range(1, 10_000))

    def _make(
        action="read",
        agent_id="file_agent",
        obj_id="customer_records.csv",
        obj_type="resource",
        classification="confidential",
        to=None,
        to_type=None,
        result="success",
        permission_id="perm-test",
    ):
        obj = {"type": obj_type, "id": obj_id}
        if classification is not None:
            obj["classification"] = classification

        destination = None
        if to is not None:
            is_external = "@" in to
            destination = {
                "type": to_type or ("external" if is_external else "agent"),
                "id": to,
                "is_external": is_external,
            }

        return {
            "event_id": f"evt-test-{next(counter):03d}",
            "timestamp": "2026-10-14T09:00:00Z",
            "trajectory_id": "traj-test-001",
            "agent_id": agent_id,
            "action": action,
            "object": obj,
            "destination": destination,
            "permission_id": permission_id,
            "goal_id": None,
            "result": result,
            "ground_truth_label": None,
            "metadata": {},
        }

    return _make
