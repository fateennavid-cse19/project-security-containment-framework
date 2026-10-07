from dataclasses import dataclass


@dataclass
class Policy:
    policy_id: str
    name: str
    source_labels: set[str]
    destination_labels: set[str]
    description: str

SENSITIVE_DATA_EXTERNAL = Policy(
    policy_id="POL-001",
    name="sensitive_data_external",
    source_labels={"confidential", "pii"},
    destination_labels={"external"},
    description="Sensitive data must not reach an external destination."
)