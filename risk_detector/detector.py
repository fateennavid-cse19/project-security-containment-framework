

class RiskDetector:
    def __init__(self, graph, policy_engine):
        self.graph = graph
        self.policy_engine = policy_engine

    def _get_policy_nodes(self, policy):
        source_nodes = self.graph.get_nodes_by_label(
            policy.source_labels
        )

        destination_nodes = self.graph.get_nodes_by_label(
            policy.destination_labels
        )

        return source_nodes, destination_nodes
    
    def _find_violations(self, policy):
        source_nodes, destination_nodes = self._get_policy_nodes(policy)

        violations = []

        for source in source_nodes:
            for destination in destination_nodes:
                path = self.graph.find_path(source, destination)

                if path is not None:
                    violations.append({
                        "policy_id": policy.policy_id,
                        "source": source,
                        "destination": destination,
                        "path": path
                    })

        return violations

    def detect(self):
        violations = []

        for policy in self.policy_engine.get_policies():
            policy_violations = self._find_violations(policy)
            violations.extend(policy_violations)

        return violations

    def evaluate_event(self, event):
        violations = []

        destination = event.get("destination")

        if destination is None:
            return violations

        if not destination.get("is_external", False):
            return violations

        obj = event.get("object", {})
        source = obj.get("id")
        agent = event.get("agent_id")

        path = self.graph.find_path(source, agent)

        if path is None:
            return violations

        for policy in self.policy_engine.get_policies():
            classification = obj.get("classification")

            if classification in policy.source_labels:
                path_edges = self.graph.get_path_edges(path)

                violations.append({
                    "policy_id": policy.policy_id,
                    "source": source,
                    "destination": destination["id"],
                    "path": path + [destination["id"]],
                    "edges": [
                        {
                            "source": edge.source,
                            "target": edge.target,
                            "action": edge.action.value,
                            "permission_id": edge.permission_id,
                            "cost": edge.cost
                        }
                        for edge in path_edges
                    ] + [
                        {
                            "source": agent,
                            "target": destination["id"],
                            "action": event["action"],
                            "permission_id": event.get("permission_id"),
                            "cost": 1.0
                        }
                    ]
                })
                
        return violations