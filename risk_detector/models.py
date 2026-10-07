from dataclasses import dataclass


@dataclass
class Violation:
    policy_id: str
    source: str
    destination: str
    path: list[str]
    edges: list[dict]

    def to_dict(self):
        return {
            "policy_id": self.policy_id,
            "source": self.source,
            "destination": self.destination,
            "path": self.path,
            "edges": self.edges,
        }