from policy_engine.engine import PolicyEngine
from policy_engine.policy import SENSITIVE_DATA_EXTERNAL


def test_engine_loads_sensitive_data_external_policy():
    assert PolicyEngine().get_policies() == [SENSITIVE_DATA_EXTERNAL]


def test_sensitive_data_external_policy_labels():
    assert SENSITIVE_DATA_EXTERNAL.policy_id == "POL-001"
    assert SENSITIVE_DATA_EXTERNAL.source_labels == {"confidential", "pii"}
    assert SENSITIVE_DATA_EXTERNAL.destination_labels == {"external"}
    # public and internal data are deliberately allowed to leave
    assert not {"public", "internal"} & SENSITIVE_DATA_EXTERNAL.source_labels
