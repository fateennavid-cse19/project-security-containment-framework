import pytest

from context_classifier.classifier import ContextClassifier


@pytest.mark.parametrize(
    "action, classification, to, result, expected",
    [
        # no destination: nothing crosses a boundary
        ("read", "confidential", None, "success", ("none", "none", "none")),
        # internal hand-off of sensitive data is a transfer, not an exposure
        ("delegate", "confidential", "analysis_agent", "success", ("internal", "internal_transfer", "none")),
        # sensitive data leaving the organisation
        ("send", "confidential", "attacker@example.com", "success",
         ("internal_to_external", "external_transfer", "external_exposure")),
        ("send", "pii", "attacker@example.com", "success",
         ("internal_to_external", "external_transfer", "external_exposure")),
        # the attempt is still recorded when access control stops it
        ("send", "pii", "attacker@example.com", "denied",
         ("internal_to_external", "external_transfer", "attempted_external_exposure")),
        ("send", "pii", "attacker@example.com", "error",
         ("internal_to_external", "external_transfer", "unknown")),
        # public or internal data going external is not an exposure
        ("send", "public", "partners@example.com", "success",
         ("internal_to_external", "external_transfer", "none")),
        ("send", "internal", "partners@example.com", "success",
         ("internal_to_external", "external_transfer", "none")),
    ],
)
def test_classify(make_event, action, classification, to, result, expected):
    event = make_event(action, classification=classification, to=to, result=result)

    context = ContextClassifier().classify(event)

    assert (
        context["trust_boundary"],
        context["transfer_context"],
        context["sensitive_exposure"],
    ) == expected


def test_transfer_without_destination_is_unknown(make_event):
    event = make_event("send")  # malformed: send with no destination

    assert ContextClassifier().classify(event)["transfer_context"] == "unknown"


def test_missing_object_does_not_crash():
    event = {"action": "send", "destination": {"id": "x@example.com", "is_external": True}}

    assert ContextClassifier().classify(event)["sensitive_exposure"] == "none"
