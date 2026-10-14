

class ContextClassifier:

    """Classifies agent events based on trust boundaries, transfer behaviour,
    and potential exposure of sensitive information.
    """

    def classify(self, event):

        """Generate contextual security classifications for an agent event.

        Returns a dictionary containing trust boundary, transfer context,
        and sensitive exposure classifications.
        """

        context = {}

        # Evaluate the event across three independent security dimensions.
        context["trust_boundary"] = self._classify_trust_boundary(event)
        context["transfer_context"] = self._classify_transfer(event)
        context["sensitive_exposure"] = self._classify_sensitive_exposure(event)

        return context

    def _classify_trust_boundary(self, event):

        """Determine whether an event involves an internal or external destination."""

        destination = event.get("destination")

        # Events without a destination do not cross a destination trust boundary.
        if destination is None:
            return "none"

        # Identify actions directed outside the internal multi-agent environment.
        if destination.get("is_external", False):
            return "internal_to_external"

        return "internal"

    def _classify_transfer(self, event):

        """Classify delegation and sending actions as internal or external transfers."""

        action = event.get("action")
        destination = event.get("destination")

        # Only delegation and sending actions are treated as transfers.
        if action not in ("delegate", "send"):
            return "none"

        # A transfer without destination information cannot be classified reliably.
        if destination is None:
            return "unknown"

        if destination.get("is_external", False):
            return "external_transfer"

        return "internal_transfer"

    def _classify_sensitive_exposure(self, event):

        """Identify successful or attempted external exposure of sensitive data."""

        obj = event.get("object", {})
        destination = event.get("destination")
        result = event.get("result")

        classification = obj.get("classification")

        # Only confidential and personally identifiable information is treated as sensitive under the current classification rules.
        sensitive = classification in ("confidential", "pii")

        # Exposure requires both sensitive information and a known destination.
        if not sensitive or destination is None:
            return "none"

        # Internal destinations are not classified as external exposure.
        if not destination.get("is_external", False):
            return "none"

        # Distinguish completed external exposure from denied exposure attempts.
        if result == "success":
            return "external_exposure"

        if result == "denied":
            return "attempted_external_exposure"

        return "unknown"