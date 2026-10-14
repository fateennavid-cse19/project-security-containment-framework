from risk_detector.models import Violation


class RiskDetector:

    """Detect prohibited capability paths by evaluating graph reachability
    against security policies.

    Supports both detection of existing paths and evaluation of proposed
    agent actions before they are added to the graph.
    """

    def __init__(self, graph, policy_engine):

        """Initialise the detector with a capability graph and policy engine."""

        self.graph = graph
        self.policy_engine = policy_engine

    def _get_policy_nodes(self, policy):

        """Retrieve graph nodes matching a policy's source and destination labels.

        Returns the matching source and destination node IDs.
        """

        # Identify protected resources and prohibited destinations using policy labels.
        source_nodes = self.graph.get_nodes_by_label(
            policy.source_labels
        )

        destination_nodes = self.graph.get_nodes_by_label(
            policy.destination_labels
        )

        return source_nodes, destination_nodes
    
    def _find_violations(self, policy):

        """Identify existing prohibited paths between policy-matching nodes.

        Returns violation records containing the policy, source,
        destination, and detected capability path.
        """

        source_nodes, destination_nodes = self._get_policy_nodes(policy)

        violations = []

        # Examine each protected source against every prohibited destination.
        for source in source_nodes:
            for destination in destination_nodes:
                # Search for a reachable path through currently active capabilities.
                path = self.graph.find_path(source, destination)

                # A reachable prohibited destination constitutes a policy violation.
                if path is not None:
                    violations.append({
                        "policy_id": policy.policy_id,
                        "source": source,
                        "destination": destination,
                        "path": path
                    })

        return violations

    def detect(self):

        """Detect all currently reachable prohibited paths across registered policies.

        Returns a combined list of detected policy violations.
        """

        violations = []

        # Evaluate the current capability graph against every registered policy.
        for policy in self.policy_engine.get_policies():
            policy_violations = self._find_violations(policy)
            # Combine violations detected under different security policies.
            violations.extend(policy_violations)

        return violations

    def evaluate_event(self, event):

        """Evaluate whether a proposed destination action would violate a security policy.

        Checks whether the event's source resource can already reach the acting
        agent through active capability edges. If the source and proposed
        destination match a prohibited policy combination, the proposed action
        is treated as completing an unsafe path.

        This check does not modify the graph or simulate arbitrary capability
        or permission changes.

        Returns a list of detected violations, or an empty list if none are found.
        """

        violations = []

        # Only events with a specified destination can complete the source-to-destination paths evaluated by this method.
        destination = event.get("destination")

        # Extract the proposed action's source resource and acting agent.
        if destination is None:
            return violations

        obj = event.get("object", {})
        source = obj.get("id")
        agent = event.get("agent_id")

        # Check whether the source resource already has an active path to the agent.
        # The proposed action is evaluated as an extension of this existing path.
        path = self.graph.find_path(source, agent)

        # Without an existing source-to-agent path, this proposed action cannot complete the prohibited path being evaluated.
        if path is None:
            return violations

        # Extract the source's sensitivity classification for policy matching.
        source_labels = set()

        if obj.get("classification"):
            source_labels.add(obj["classification"])

        # Classify the proposed destination independently of the current graph.
        destination_labels = self._get_destination_labels(destination)

        # Check whether the proposed source and destination match a prohibited combination defined by any registered security policy.
        for policy in self.policy_engine.get_policies():

            # A policy applies when both the source and destination labels match.
            source_matches = bool(
                source_labels.intersection(policy.source_labels)
            )

            destination_matches = bool(
                destination_labels.intersection(policy.destination_labels)
            )

            # Construct a violation only when both ends of the proposed path satisfy the policy's prohibited source-destination conditions.
            if source_matches and destination_matches:
                # Retrieve the existing capability edges contributing to the unsafe path.
                path_edges = self.graph.get_path_edges(path)

                # Represent the proposed destination action as the final edge of the prohibited path without adding that edge to the capability graph.
                violation = Violation(
                    policy_id=policy.policy_id,
                    source=source,
                    destination=destination["id"],
                    path=path + [destination["id"]],
                    edges=[
                        {
                            "source": edge.source,
                            "target": edge.target,
                            "action": edge.action.value,
                            "permission_id": edge.permission_id,
                            "cost": edge.cost,
                        }
                        for edge in path_edges
                    ] + [
                        {
                            "source": agent,
                            "target": destination["id"],
                            "action": event["action"],
                            "permission_id": event.get("permission_id"),
                            "cost": 1.0,
                        }
                    ],
                )

                violations.append(violation.to_dict())
        return violations

    def _get_destination_labels(self, destination):

        """Return security labels associated with a proposed destination.

        Currently identifies destinations marked as external.
        """

        labels = set()

        # Mark external destinations for matching against security policies.
        if destination.get("is_external", False):
            labels.add("external")

        return labels

    