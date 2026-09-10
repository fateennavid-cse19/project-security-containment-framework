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
        self._g = nx.MultiDiGraph()

    # -- node/edge primitives -------------------------------------------------

    def ensure_node(self, node_id: str, node_type: NodeType, labels: set[str] | None = None) -> Node:
        if node_id in self._g.nodes:
            existing = self._g.nodes[node_id]["data"]
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
            node["data"].labels.discard("active")
            node["data"].labels.add("revoked")
        count = 0
        for _, _, data in self._g.edges(data="data"):
            if data.permission_id == permission_id and not data.blocked:
                data.blocked = True
                count += 1
        return count

    # -- event ingestion --------------------------------------------------

    def apply_event(self, event: dict) -> None:
        agent_id = event["agent_id"]
        action = event["action"]
        self.ensure_node(agent_id, NodeType.AGENT)

        if action == "grant_permission":
            perm_id = event["object"]["id"]
            self.ensure_node(perm_id, NodeType.PERMISSION, labels={"active"})
            return
        if action == "revoke_permission":
            self.revoke_permission(event["object"]["id"])
            return

        obj = event["object"]
        obj_labels = {obj["classification"]} if obj.get("classification") else set()
        self.ensure_node(obj["id"], _OBJECT_TYPE_TO_NODE_TYPE[obj["type"]], labels=obj_labels)

        blocked_on_arrival = event["result"] == "denied"

        if action in _INBOUND_ACTIONS:
            source, target = obj["id"], agent_id
        elif action in _OUTBOUND_ACTIONS:
            source, target = agent_id, obj["id"]
        elif action in _DESTINATION_ACTIONS:
            dest = event["destination"]
            dest_labels = {"external"} if dest["is_external"] else set()
            self.ensure_node(dest["id"], _DESTINATION_TYPE_TO_NODE_TYPE[dest["type"]], labels=dest_labels)
            source, target = agent_id, dest["id"]
        else:
            raise ValueError(f"Unknown action: {action}")

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
        active = nx.MultiDiGraph(
            (u, v, k, d) for u, v, k, d in self._g.edges(keys=True, data=True) if not d["data"].blocked
        )
        active.add_nodes_from(self._g.nodes)
        return nx.has_path(active, source, target)

    def snapshot(self) -> dict:
        """Matches the GraphSnapshot schema in api/openapi.yaml."""
        nodes = [self._g.nodes[n]["data"].to_dict() for n in self._g.nodes]
        edges = [d["data"].to_dict() for _, _, d in self._g.edges(data=True)]
        return {"nodes": nodes, "edges": edges}
