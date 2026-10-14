from dataclasses import dataclass


@dataclass
class Violation:

    """Represent a detected security policy violation.

    Stores the violated policy, source and destination nodes,
    complete capability path, and associated edge information.
    """

    policy_id: str
    source: str
    destination: str
    path: list[str]
    edges: list[dict]

    def to_dict(self):

        """Convert the violation into a dictionary for logging, reporting,
        or serialisation through the API.
        """

        return {
            "policy_id": self.policy_id,
            "source": self.source,
            "destination": self.destination,
            "path": self.path,
            "edges": self.edges,
        }