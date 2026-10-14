import json
from pathlib import Path

from jsonschema import validate
from jsonschema.exceptions import ValidationError
from context_classifier.classifier import ContextClassifier

# Resolve the event schema relative to the project directory, independently of the current working directory.
EVENT_SCHEMA_FILE = Path(__file__).resolve().parent.parent / "schema" / "event_schema.json"

class EventCollector:

    """Validates, classifies, and records agent events while updating
    the dynamic capability graph.
    """

    def __init__(self, graph):

        """Initialise the event collector with a capability graph and JSON schema."""

        self.graph = graph
        self.events = []
        self.classifier = ContextClassifier()

        # Load the event schema once for validation of subsequent events.
        with open(EVENT_SCHEMA_FILE) as file:
            self.schema = json.load(file)

    def validate_event(self, event):

        """Validate an event against the standard JSON event schema.

        Raises ValidationError if the event does not satisfy the schema.
        """

        validate(instance=event, schema=self.schema)

    def collect(self, event):

        """Process an incoming event through validation, classification,
        storage, and graph updating.

        Returns True if the event is accepted, or False if validation fails.
        """

        # Reject malformed events before they affect stored history or graph state.
        try:
            self.validate_event(event)
        except ValidationError as error:
            print(f"Invalid event: {error.message}")
            return False

        # Attach contextual security classifications to the validated event.
        context = self.classifier.classify(event)

        # Preserve the original event alongside its derived security context.
        collected_event = {
            "event": event,
            "context": context
        }

        # Record the event and update the capability graph to reflect its action.
        self.events.append(collected_event)
        self.graph.apply_event(event)

        return True

    def get_events(self):
        return self.events