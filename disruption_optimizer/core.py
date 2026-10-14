"""Disruption cost model and constrained minimum-cut optimiser."""

from dataclasses import dataclass, field
import math

import networkx as nx


def edge_key(edge):
    """Identify a connection by its endpoints and action."""
    return (
        edge["source"],
        edge["target"],
        edge["action"],
    )


@dataclass
class CostModel:
    """
    Operational disruption costs.

    Static cost:
        base edge cost

    Adaptive cost:
        base cost * (1 + workload + criticality)

    workload and criticality are nonnegative weights supplied
    by the caller. protected contains edges that cannot be cut.
    """

    workload: dict = field(default_factory=dict)
    criticality: dict = field(default_factory=dict)
    protected: set = field(default_factory=set)

    def cost(self, edge, adaptive=False):
        key = edge_key(edge)
        base = float(edge.get("cost", 1.0))

        load = (
            float(self.workload.get(key, 0.0))
            if adaptive
            else 0.0
        )

        importance = (
            float(self.criticality.get(key, 0.0))
            if adaptive
            else 0.0
        )

        values = (base, load, importance)

        if not all(
            math.isfinite(value) and value >= 0
            for value in values
        ):
            raise ValueError(
                "Costs, workload and criticality must be "
                "finite and nonnegative."
            )

        result = base * (1 + load + importance)

        if not math.isfinite(result):
            raise ValueError("Calculated cost must be finite.")

        return result


@dataclass
class CutPlan:
    feasible: bool
    edges: list
    cost: float
    reason: str


def minimum_cut(
    snapshot,
    sources,
    destinations,
    model=None,
    adaptive=False,
):
    """
    Separate all supplied sources from all supplied destinations.

    Planning does not change the original capability graph.

    Parallel actions between the same nodes have their costs
    added together. Every action crossing the selected partition
    must be blocked.

    Protected edges receive a capacity larger than the total
    cost of every permissible edge cut.
    """
    model = model or CostModel()

    active_edges = [
        edge
        for edge in snapshot["edges"]
        if not edge["blocked"]
    ]

    costs = {
        edge_key(edge): model.cost(edge, adaptive)
        for edge in active_edges
    }

    bound = sum(costs.values()) + 1.0

    if not math.isfinite(bound):
        raise ValueError("Total cost must be finite.")

    graph = nx.DiGraph()

    graph.add_nodes_from(
        node["id"]
        for node in snapshot["nodes"]
    )

    # Unique objects avoid clashes with real node IDs.
    start = object()
    end = object()

    graph.add_nodes_from([start, end])

    for edge in active_edges:
        source, target, action = edge_key(edge)

        if edge_key(edge) in model.protected:
            capacity = bound
        else:
            capacity = costs[edge_key(edge)]

        previous_capacity = graph.get_edge_data(
            source,
            target,
            {},
        ).get("capacity", 0.0)

        graph.add_edge(
            source,
            target,
            capacity=previous_capacity + capacity,
        )

    for source in set(sources):
        if source in graph:
            graph.add_edge(
                start,
                source,
                capacity=bound,
            )

    for destination in set(destinations):
        if destination in graph:
            graph.add_edge(
                destination,
                end,
                capacity=bound,
            )

    value, partition = nx.minimum_cut(
        graph,
        start,
        end,
    )

    reachable, unreachable = partition

    if value >= bound:
        return CutPlan(
            feasible=False,
            edges=[],
            cost=0.0,
            reason=(
                "No permitted edge cut separates the endpoints."
            ),
        )

    selected_edges = [
        edge
        for edge in active_edges
        if (
            edge["source"] in reachable
            and edge["target"] in unreachable
        )
    ]

    total_cost = sum(
        costs[edge_key(edge)]
        for edge in selected_edges
    )

    return CutPlan(
        feasible=True,
        edges=selected_edges,
        cost=total_cost,
        reason="Minimum total edge disruption cost.",
    )