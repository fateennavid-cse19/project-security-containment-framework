import json

from jsonschema import validate
from jsonschema.exceptions import ValidationError

class EventCollector:
    def __init__(self, graph):
        self.graph = graph
        self.events = []

        with open("schema/event_schema.json") as file:
            self.schema = json.load(file)

    def validate_event(self, event):
        validate(instance=event, schema=self.schema)

    def collect(self, event):
        try:
            self.validate_event(event)
        except ValidationError as error:
            print(f"Invalid event: {error.message}")
            return False

        self.events.append(event)
        self.graph.apply_event(event)

        return True

    def get_events(self):
        return self.events