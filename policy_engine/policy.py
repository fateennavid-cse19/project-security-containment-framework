from dataclasses import dataclass


@dataclass
class Policy:

    """Represent a security policy defining prohibited source-to-destination paths.

    Source and destination labels identify which graph nodes are subject
    to the policy.
    """

    policy_id: str
    name: str
    source_labels: set[str]
    destination_labels: set[str]
    description: str

# POL-001: Prevent sensitive information from reaching external destinations through any combination of agent capabilities.
SENSITIVE_DATA_EXTERNAL = Policy(
    policy_id="POL-001",
    name="sensitive_data_external",
    source_labels={"confidential", "pii"},
    destination_labels={"external"},
    description="Sensitive data must not reach an external destination."
)