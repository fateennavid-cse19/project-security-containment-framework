def assess_severity(source_labels, destination_labels, agent_ids):
    """
    Assign a severity to an already detected policy violation.

    suspicious: Other policy violations.
    high: Sensitive data can reach an external destination.
    critical: That exposure involves two or more distinct agents.

    These are prototype rules, not an attack probability.
    """
    sensitive = bool(
        set(source_labels).intersection({"confidential", "pii"})
    )
    external = "external" in destination_labels

    if sensitive and external:
        if len(set(agent_ids)) >= 2:
            return {
                "severity": "critical",
                "severity_reason": (
                    "Sensitive data can reach an external destination "
                    "through multiple agents."
                ),
            }

        return {
            "severity": "high",
            "severity_reason": (
                "Sensitive data can reach an external destination."
            ),
        }

    return {
        "severity": "suspicious",
        "severity_reason": (
            "Policy violation detected; no sensitive external "
            "exposure rule applies."
        ),
    }