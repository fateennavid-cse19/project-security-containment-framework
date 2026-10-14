"""Dynamic Capability Graph (#6).

Wraps a networkx.MultiDiGraph and knows how to update itself from one Event
(schema/event_schema.json). This is the live data structure the Compositional
Risk Detector (#9) will search for prohibited paths, and that GET /graph
(api/openapi.yaml) serialises for the dashboard.

Edge direction follows data flow, not "who calls whom": a `read` edge points
from the resource to the agent (data flows INTO the agent), while `delegate`
and `send` point from the agent to whoever/wherever it hands the data to.
That's what lets a path like
    customer_records.csv -> file_agent -> analysis_agent -> email_agent -> attacker@example.com
(the worked example in the project doc) exist as one directed walk from a
protected resource to a prohibited destination.
"""
from __future__ import annotations

import networkx as nx

from graph_engine.models import EdgeAction, Node, NodeType

_OBJECT_TYPE_TO_NODE_TYPE = {
    "resource": NodeType.RESOURCE,
    "tool": NodeType.TOOL,
    "permission": NodeType.PERMISSION,
}

_DESTINATION_TYPE_TO_NODE_TYPE = {
    "agent": NodeType.AGENT,
    "tool": NodeType.TOOL,
    "external": NodeType.DESTINATION,
}

# Actions whose event.object is the flow's source (data moves object -> agent).
_INBOUND_ACTIONS = {"read"}
# Actions whose event.object is the flow's target (data moves agent -> object).
_OUTBOUND_ACTIONS = {"write", "call"}
# Actions that use event.destination as the flow's target (data moves agent -> destination).
_DESTINATION_ACTIONS = {"delegate", "send"}


class CapabilityGraph:
    def __init__(self) -> None:

        """Initialise a directed multigraph representing agent capabilities."""

        self._g = nx.MultiDiGraph()

    # -- node/edge primitives -------------------------------------------------

    def ensure_node(self, node_id: str, node_type: NodeType, labels: set[str] | None = None) -> Node:

        """Retrieve an existing node or create one with the specified type and labels.

        Existing nodes retain their identity and gain any newly supplied labels.
        """

        if node_id in self._g.nodes:
            existing = self._g.nodes[node_id]["data"]
            
            # Merge new classifications without discarding existing node labels.
            if labels:
                existing.labels |= labels
            return existing
        node = Node(id=node_id, type=node_type, labels=set(labels or ()))
        self._g.add_node(node_id, data=node)
        return node

    def add_edge(
        self,
        source: str,
        target: str,
        action: EdgeAction,
        permission_id: str | None = None,
        carries: dict | None = None,
        cost: float = 1.0,
        blocked: bool = False,
    ):

        """Add an action-specific directed capability edge to the graph.

        Edges store permission information, carried data, disruption cost,
        and containment status.
        """

        from graph_engine.models import Edge

        edge = Edge(
            source=source,
            target=target,
            action=action,
            permission_id=permission_id,
            carries=carries,
            cost=cost,
            blocked=blocked,
        )
        # keyed by action so repeated events of different actions between the
        # same pair of nodes don't clobber each other
        self._g.add_edge(source, target, key=action.value, data=edge)
        return edge

    def block_edge(self, source: str, target: str, action: EdgeAction) -> bool:

        """Minimum-disruption containment primitive: mark one edge blocked
        without deleting it, so the dashboard can still show what was cut."""

        if not self._g.has_edge(source, target, key=action.value):
            return False
        self._g.edges[source, target, action.value]["data"].blocked = True
        return True

    def revoke_permission(self, permission_id: str) -> int:

        """Blocks every edge that was authorised solely by this permission.
        Returns the number of edges blocked."""
        
        node = self._g.nodes.get(permission_id)
        if node is not None:
            # Update the permission node's status while preserving its audit visibility.
            node["data"].labels.discard("active")
            node["data"].labels.add("revoked")
        count = 0

        # Disable active edges associated with the revoked permission.
        for _, _, data in self._g.edges(data="data"):
            if data.permission_id == permission_id and not data.blocked:
                data.blocked = True
                count += 1
        return count

    # -- event ingestion --------------------------------------------------

    def apply_event(self, event: dict) -> None:

        """Update graph nodes and edges according to a validated agent event.

        The direction of each edge represents the direction of data flow.
        Denied actions are recorded as blocked edges.
        """

        agent_id = event["agent_id"]
        action = event["action"]
        self.ensure_node(agent_id, NodeType.AGENT)

        # Permission lifecycle events update permission state rather than creating ordinary data-flow edges.
        if action == "grant_permission":
            perm_id = event["object"]["id"]
            self.ensure_node(perm_id, NodeType.PERMISSION, labels={"active"})
            return
        if action == "revoke_permission":
            self.revoke_permission(event["object"]["id"])
            return

        obj = event["object"]

        # Preserve object sensitivity classifications as graph node labels.
        obj_labels = {obj["classification"]} if obj.get("classification") else set()
        self.ensure_node(obj["id"], _OBJECT_TYPE_TO_NODE_TYPE[obj["type"]], labels=obj_labels)

        # Denied actions remain visible in the graph but are excluded from active paths.
        blocked_on_arrival = event["result"] == "denied"

        # Orient edges according to data flow rather than the agent initiating the action: reads are inbound, while writes and transfers are outbound.
        if action in _INBOUND_ACTIONS:
            source, target = obj["id"], agent_id
        elif action in _OUTBOUND_ACTIONS:
            source, target = agent_id, obj["id"]
        elif action in _DESTINATION_ACTIONS:
            dest = event["destination"]
            # Label external destinations for subsequent policy and risk evaluation.
            dest_labels = {"external"} if dest["is_external"] else set()
            self.ensure_node(dest["id"], _DESTINATION_TYPE_TO_NODE_TYPE[dest["type"]], labels=dest_labels)
            source, target = agent_id, dest["id"]
        else:
            raise ValueError(f"Unknown action: {action}")

        # Record the capability relationship and its associated permission, transferred object information, and initial containment state.
        self.add_edge(
            source,
            target,
            EdgeAction(action),
            permission_id=event.get("permission_id"),
            carries=obj if action in _DESTINATION_ACTIONS else None,
            blocked=blocked_on_arrival,
        )

    # -- queries --------------------------------------------------

    def is_reachable(self, source: str, target: str) -> bool:
        """True if `target` is reachable from `source` using only non-blocked edges."""
        if source not in self._g or target not in self._g:
            return False

        active = self._active_graph()
        return nx.has_path(active, source, target)

    def snapshot(self) -> dict:
        """Matches the GraphSnapshot schema in api/openapi.yaml."""
        nodes = [self._g.nodes[n]["data"].to_dict() for n in self._g.nodes]
        edges = [d["data"].to_dict() for _, _, d in self._g.edges(data=True)]
        return {"nodes": nodes, "edges": edges}

    def get_nodes_by_label(self, labels):

        """Return IDs of nodes matching at least one of the specified labels."""

        matching_nodes = []

        for node_id in self._g.nodes:
            node = self._g.nodes[node_id]["data"]

            if node.labels.intersection(labels):
                matching_nodes.append(node_id)

        return matching_nodes

    def find_path(self, source: str, target: str):

        """Find the shortest active path between two nodes.

        Returns a list of node IDs, or None if no valid path exists.
        """

        # Both endpoints must exist before attempting path detection.
        if source not in self._g or target not in self._g:
            return None

        # Exclude blocked connections from the path search.
        active = self._active_graph()

        try:
            # Find the shortest path by number of edges, not disruption cost.
            return nx.shortest_path(active, source, target)
        except nx.NetworkXNoPath:
            return None

    def get_edge(self, source: str, target: str):

        """Return the first active edge between two nodes, or None if unavailable."""

        if not self._g.has_edge(source, target):
            return None

        # Multiple action-specific edges may exist between the same two nodes.
        for _, edge_data in self._g[source][target].items():
            edge = edge_data["data"]

            # Ignore contained connections and return only an active capability.
            if not edge.blocked:
                return edge

        return None

    def get_path_edges(self, path):

        """Retrieve active edge objects connecting consecutive nodes in a path."""

        edges = []

        # Convert each consecutive pair of nodes into its corresponding edge.
        for i in range(len(path) - 1):
            edge = self.get_edge(path[i], path[i + 1])

            # Only include connections that remain active.
            if edge is not None:
                edges.append(edge)

        return edges

    def _active_graph(self):

        """Construct a graph containing all nodes and only non-blocked edges."""

        # Create a separate graph for reachability checks without modifying the original graph or removing its blocked-edge records.
        active = nx.MultiDiGraph(
            (u, v, k, d)
            for u, v, k, d in self._g.edges(keys=True, data=True)
            # Exclude blocked edges from the active graph.
            if not d["data"].blocked
        )

        # Preserve isolated nodes, including those with no remaining active edges.
        active.add_nodes_from(self._g.nodes)

        return active