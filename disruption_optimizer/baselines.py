from copy import deepcopy

from graph_engine.models import EdgeAction
from risk_detector.detector import RiskDetector

from disruption_optimizer.core import (
    CostModel,
    edge_key,
    minimum_cut,
)


class ContainmentGate:
    """Apply containment decisions before simulator actions execute."""

    def __init__(
        self,
        graph,
        policies,
        mode="adaptive",
        cost_model=None,
    ):
        valid_modes = {
            "shutdown",
            "static",
            "adaptive",
        }

        if mode not in valid_modes:
            raise ValueError(
                f"Unknown containment mode: {mode}"
            )

        self.graph = graph
        self.detector = RiskDetector(graph, policies)
        self.mode = mode
        self.cost_model = cost_model or CostModel()

        self.blocked = set()
        self.stopped = False
        self.decisions = []

    def _event_key(self, event):
        """Map a simulator event to its capability edge."""
        action = event["action"]
        agent = event["agent_id"]
        obj = event["object"]["id"]

        if action == "read":
            return obj, agent, action

        if action in {"write", "call"}:
            return agent, obj, action

        if action in {"send", "delegate"}:
            return (
                agent,
                event["destination"]["id"],
                action,
            )

        return None

    def __call__(self, event):
        """
        Return True to allow an event, or False to deny it.

        Restrictions are also held outside the graph, so replaying
        an event cannot silently restore a blocked connection.
        """
        if self.stopped:
            return False

        if self._event_key(event) in self.blocked:
            return False

        violations = self.detector.evaluate_event(event)

        if not violations:
            return True

        # Include the proposed action in a temporary graph.
        # The real graph is not changed during planning.
        prospective = deepcopy(self.graph)

        prospective.apply_event(
            dict(event, result="success")
        )

        snapshot = prospective.snapshot()

        if self.mode == "shutdown":
            self.stopped = True

            edges = [
                edge
                for edge in snapshot["edges"]
                if not edge["blocked"]
            ]

            cost = sum(
                self.cost_model.cost(edge)
                for edge in edges
            )

            reason = (
                "Full workflow shutdown after a detected violation."
            )

            feasible = True

        else:
            plan = minimum_cut(
                snapshot=snapshot,
                sources=[
                    violation["source"]
                    for violation in violations
                ],
                destinations=[
                    violation["destination"]
                    for violation in violations
                ],
                model=self.cost_model,
                adaptive=self.mode == "adaptive",
            )

            edges = plan.edges
            cost = plan.cost
            reason = plan.reason
            feasible = plan.feasible

        for edge in edges:
            self.blocked.add(edge_key(edge))

            self.graph.block_edge(
                edge["source"],
                edge["target"],
                EdgeAction(edge["action"]),
            )

        self.decisions.append({
            "mode": self.mode,
            "event_id": event["event_id"],
            "feasible": feasible,
            "edges": edges,
            "cost": cost,
            "reason": reason,
            "trigger_denied": True,
        })

        # Cutting an earlier connection cannot erase data already
        # held by an agent. Reject the unsafe triggering action too.
        # If constraints make the cut infeasible, deny this action
        # and record the infeasible result.
        return False