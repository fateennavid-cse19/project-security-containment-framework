

class ContextClassifier:
    def classify(self, event):
        context = {}

        context["trust_boundary"] = self._classify_trust_boundary(event)
        context["transfer_context"] = self._classify_transfer(event)
        context["sensitive_exposure"] = self._classify_sensitive_exposure(event)

        return context

    def _classify_trust_boundary(self, event):
        destination = event.get("destination")

        if destination is None:
            return "none"

        if destination.get("is_external", False):
            return "internal_to_external"

        return "internal"

    def _classify_transfer(self, event):
        action = event.get("action")
        destination = event.get("destination")

        if action not in ("delegate", "send"):
            return "none"

        if destination is None:
            return "unknown"

        if destination.get("is_external", False):
            return "external_transfer"

        return "internal_transfer"

    def _classify_sensitive_exposure(self, event):
        obj = event.get("object", {})
        destination = event.get("destination")
        result = event.get("result")

        classification = obj.get("classification")

        sensitive = classification in ("confidential", "pii")

        if not sensitive or destination is None:
            return "none"

        if not destination.get("is_external", False):
            return "none"

        if result == "success":
            return "external_exposure"

        if result == "denied":
            return "attempted_external_exposure"

        return "unknown"