

class EventCollector:
    def __init__(self, graph):
        self.graph = graph
        self.events = []

    def collect(self, event):
        self.events.append(event)
        self.graph.apply_event(event)