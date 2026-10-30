"""Stateful research API service, independent of the simulator."""

from copy import deepcopy
import json
from pathlib import Path
from threading import RLock

from jsonschema import Draft202012Validator, FormatChecker

from disruption_optimizer.core import CostModel, minimum_cut
from graph_engine.graph import CapabilityGraph
from graph_engine.models import EdgeAction
from risk_detector.severity import assess_severity


ROOT = Path(__file__).resolve().parents[1]


class APIError(ValueError):
    """An API error with an HTTP status code."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class SecurityService:
    """Manage graph state, policies and containment decisions."""

    def __init__(self):
        self.lock = RLock()
        self.graph = CapabilityGraph()

        self.policy = {
            "protected_sources": ["confidential", "pii"],
            "prohibited_sinks": ["external"],
            "risk_weights": {},
            "preservation_constraints": [],
        }

        self.blocked_pairs = set()
        self.isolated = set()
        self.revoked = set()
        self.stopped = False

        self.incidents = {}
        self.context = {}
        self.receipts = {}
        self.events = []

        schema_path = ROOT / "schema" / "event_schema.json"

        schema = json.loads(
            schema_path.read_text(encoding="utf-8")
        )

        self.validator = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )

    @staticmethod
    def state_fields():
        """State copied for previews and atomic batch updates."""
        return (
            "graph",
            "policy",
            "blocked_pairs",
            "isolated",
            "revoked",
            "stopped",
            "incidents",
            "context",
            "receipts",
            "events",
        )

    def fork(self):
        """Create an independent copy of the current service state."""
        clone = SecurityService()

        for name in self.state_fields():
            setattr(
                clone,
                name,
                deepcopy(getattr(self, name)),
            )

        return clone

    def validate_events(self, payload):
        """Validate every event before processing the batch."""
        batch = (
            payload
            if isinstance(payload, list)
            else [payload]
        )

        if not batch:
            raise APIError(
                "An event batch must not be empty"
            )

        for event in batch:
            errors = list(
                self.validator.iter_errors(event)
            )

            if errors:
                raise APIError(errors[0].message)

            action = event["action"]
            obj = event["object"]
            destination = event.get("destination")

            if action in {"send", "delegate"}:
                if not destination:
                    raise APIError(
                        "send/delegate require destination"
                    )

            if obj["type"] == "resource":
                if not obj.get("classification"):
                    raise APIError(
                        "Resource classification is required"
                    )

            if action in {
                "grant_permission",
                "revoke_permission",
            }:
                if obj["type"] != "permission":
                    raise APIError(
                        "Permission actions require "
                        "a permission object"
                    )

            if destination:
                external_type = (
                    destination["type"] == "external"
                )

                if (
                    external_type
                    != destination["is_external"]
                ):
                    raise APIError(
                        "Destination type and "
                        "is_external disagree"
                    )

        return batch

    def matches(self, node, selectors):
        """Match either a node ID or one of its labels."""
        labels = set(node.get("labels", []))

        return (
            node["id"] in selectors
            or bool(labels & set(selectors))
        )

    def violations(self, graph):
        """Find configured protected-source to prohibited-sink paths."""
        nodes = {
            node["id"]: node
            for node in graph.snapshot()["nodes"]
        }

        sources = [
            node
            for node in nodes.values()
            if self.matches(
                node,
                self.policy["protected_sources"],
            )
        ]

        sinks = [
            node
            for node in nodes.values()
            if self.matches(
                node,
                self.policy["prohibited_sinks"],
            )
        ]

        found = []

        for source in sources:
            for target in sinks:
                path = graph.find_path(
                    source["id"],
                    target["id"],
                )

                if path:
                    agents = [
                        node_id
                        for node_id in path
                        if nodes[node_id]["type"] == "agent"
                    ]

                    # A configured protected-to-prohibited path
                    # uses the project's exposure severity rules.
                    rating = assess_severity(
                        {"confidential"},
                        {"external"},
                        agents,
                    )

                    found.append({
                        "source": source["id"],
                        "target": target["id"],
                        "path": path,
                        **rating,
                    })

        return found

    def restricted(self, event):
        """Check persistent restrictions before allowing an action."""
        target = (
            event.get("destination") or {}
        ).get(
            "id",
            event["object"]["id"],
        )

        source = (
            event["object"]["id"]
            if event["action"] == "read"
            else event["agent_id"]
        )

        return (
            self.stopped
            or event["agent_id"] in self.isolated
            or target in self.isolated
            or (source, target) in self.blocked_pairs
            or event.get("permission_id") in self.revoked
        )

    def reapply(self):
        """Keep restrictions active when new events update the graph."""
        for edge in self.graph.snapshot()["edges"]:
            must_block = (
                self.stopped
                or edge["source"] in self.isolated
                or edge["target"] in self.isolated
                or (
                    edge["source"],
                    edge["target"],
                ) in self.blocked_pairs
            )

            if must_block:
                self.graph.block_edge(
                    edge["source"],
                    edge["target"],
                    EdgeAction(edge["action"]),
                )

        for permission in self.revoked:
            self.graph.revoke_permission(permission)

    def model(self, snapshot):
        """Build the disruption cost model from the active policy."""
        protected = set(
            self.policy["preservation_constraints"]
        )

        weights = self.policy["risk_weights"]
        model = CostModel()

        for edge in snapshot["edges"]:
            key = (
                edge["source"],
                edge["target"],
                edge["action"],
            )

            if (
                edge["source"] in protected
                or edge["target"] in protected
            ):
                model.protected.add(key)

            model.criticality[key] = weights.get(
                edge["action"],
                0,
            )

        return model

    def submit(self, payload, dry_run=False):
        """
        Process a complete batch atomically.

        A dry run changes only a temporary service copy.
        """
        batch = self.validate_events(payload)

        with self.lock:
            working = self.fork()

            results = [
                working.process(event)
                for event in batch
            ]

            if not dry_run:
                for name in self.state_fields():
                    setattr(
                        self,
                        name,
                        getattr(working, name),
                    )
            else:
                # These incidents exist only in the temporary copy.
                for result in results:
                    result.pop("incident_id", None)

            return results

    def process(self, event):
        """Process one validated event on the working service."""
        event = deepcopy(event)
        event_id = event["event_id"]

        # Repeating the same event does not create duplicate records.
        if event_id in self.receipts:
            old_event, old_decision = self.receipts[
                event_id
            ]

            if event != old_event:
                raise APIError(
                    "event_id already used "
                    "for different content",
                    409,
                )

            return deepcopy(old_decision)

        restricted = self.restricted(event)

        hypothetical = deepcopy(self.graph)

        if event["result"] != "error":
            hypothetical.apply_event(
                dict(event, result="success")
            )

        risks = (
            self.violations(hypothetical)
            if event["result"] != "error"
            else []
        )

        # Only successful observations add active graph edges.
        # A denied action can still provide evidence of an
        # attempted prohibited path.
        if event["result"] == "success":
            self.graph.apply_event(event)

            if event["action"] == "revoke_permission":
                self.revoked.add(
                    event["object"]["id"]
                )

            self.reapply()

        decision = {
            "event_id": event_id,
            "decision": (
                "block_connection"
                if restricted
                else "allow"
            ),
        }

        if risks:
            snapshot = hypothetical.snapshot()

            plan = minimum_cut(
                snapshot,
                [
                    risk["source"]
                    for risk in risks
                ],
                [
                    risk["target"]
                    for risk in risks
                ],
                self.model(snapshot),
                adaptive=True,
            )

            if plan.feasible:
                for edge in plan.edges:
                    self.blocked_pairs.add((
                        edge["source"],
                        edge["target"],
                    ))

                action = "block_connection"

            else:
                # Preservation constraints may make a cut
                # infeasible. Stop future actions in that case.
                self.stopped = True
                action = "emergency_stop"

            # An upstream cut cannot erase data already held
            # by a sender. Restrict the triggering transfer too.
            destination = event.get("destination")

            if (
                destination
                and event["action"] in {
                    "send",
                    "delegate",
                }
            ):
                self.blocked_pairs.add((
                    event["agent_id"],
                    destination["id"],
                ))

            self.reapply()

            risk = risks[0]

            selected = (
                plan.edges[0]
                if plan.edges
                else None
            )

            source = (
                selected["source"]
                if selected
                else event["agent_id"]
            )

            target = (
                selected["target"]
                if selected
                else None
            )

            incident_id = (
                f"INC-{len(self.incidents) + 1:06d}"
            )

            preserved = self.operational_agents()

            self.incidents[incident_id] = {
                "incident_id": incident_id,
                "severity": risk["severity"],
                "violation": "POL-001",
                "dangerous_path": risk["path"],

                "containment_action": {
                    "action": action,
                    "source": source,
                    "target": target,
                },

                # A successful observation may already have
                # executed externally. Do not call it prevented.
                "attack_prevented": (
                    event["result"] == "denied"
                ),

                "safe_workflow_continues": bool(
                    preserved
                ),

                "explanation": {
                    "protected_source": risk["source"],

                    "policy_rule": (
                        "Configured protected sources "
                        "must not reach prohibited sinks"
                    ),

                    "preserved_workflow": preserved,
                },
            }

            self.context[incident_id] = {
                "timestamp": event["timestamp"],
                "trajectory_id": event["trajectory_id"],
                "selected_edges": plan.edges,
                "cost": plan.cost,
                "feasible": plan.feasible,
                "event": event,
            }

            decision.update(
                decision=action,
                incident_id=incident_id,
            )

        self.events.append(event)

        self.receipts[event_id] = (
            event,
            deepcopy(decision),
        )

        return decision

    def operational_agents(self):
        """
        Return agents with remaining active graph connections.

        This is a graph proxy, not a task-completion measurement.
        """
        if self.stopped:
            return []

        snapshot = self.graph.snapshot()

        active = {
            edge[end]
            for edge in snapshot["edges"]
            if not edge["blocked"]
            for end in ("source", "target")
        }

        return [
            node["id"]
            for node in snapshot["nodes"]
            if (
                node["type"] == "agent"
                and node["id"] in active
                and node["id"] not in self.isolated
            )
        ]

    def contain(self, request):
        """Apply or preview a manual containment action."""
        allowed_fields = {
            "action",
            "source",
            "target",
            "simulate",
            "incident_id",
        }

        if (
            not isinstance(request, dict)
            or set(request) - allowed_fields
        ):
            raise APIError(
                "Invalid containment request"
            )

        required = {
            "action",
            "source",
            "target",
        }

        if not required <= set(request):
            raise APIError(
                "action, source and target are required"
            )

        action = request["action"]
        source = request["source"]
        target = request["target"]

        valid_actions = {
            "restrict",
            "block_connection",
            "isolate",
            "emergency_stop",
        }

        if (
            action not in valid_actions
            or not isinstance(source, str)
        ):
            raise APIError(
                "Invalid action or source"
            )

        if (
            target is not None
            and not isinstance(target, str)
        ):
            raise APIError(
                "target must be a string or null"
            )

        if type(
            request.get("simulate", False)
        ) is not bool:
            raise APIError(
                "simulate must be boolean"
            )

        incident_id = request.get("incident_id")

        if (
            incident_id is not None
            and incident_id not in self.incidents
        ):
            raise APIError(
                "Unknown incident",
                404,
            )

        with self.lock:
            preview = self.fork()
            before = preview.graph.snapshot()

            if action == "block_connection":
                if target is None:
                    raise APIError(
                        "block_connection requires target"
                    )

                preview.blocked_pairs.add((
                    source,
                    target,
                ))

            elif action == "restrict":
                if target is not None:
                    raise APIError(
                        "restrict uses source=permission ID, "
                        "target=null"
                    )

                preview.revoked.add(source)

            elif action == "isolate":
                if target is not None:
                    raise APIError(
                        "isolate requires target=null"
                    )

                preview.isolated.add(source)

            else:
                if target is not None:
                    raise APIError(
                        "emergency_stop requires target=null"
                    )

                preview.stopped = True

            preview.reapply()
            after = preview.graph.snapshot()

            cut = [
                old
                for old, new in zip(
                    before["edges"],
                    after["edges"],
                )
                if (
                    not old["blocked"]
                    and new["blocked"]
                )
            ]

            affected = {
                node_id
                for edge in cut
                for node_id in (
                    edge["source"],
                    edge["target"],
                )
            }

            agents = {
                node["id"]
                for node in before["nodes"]
                if node["type"] == "agent"
            }

            result = {
                "applied": not request.get(
                    "simulate",
                    False,
                ),

                "action": action,

                "disruption_estimate": {
                    # No task dependency model is available.
                    "tasks_interrupted": 0,

                    "agents_affected": len(
                        affected & agents
                    ),

                    "cost": sum(
                        edge["cost"]
                        for edge in cut
                    ),
                },

                "preserved_workflow": (
                    preview.operational_agents()
                ),
            }

            if result["applied"]:
                for name in self.state_fields():
                    setattr(
                        self,
                        name,
                        getattr(preview, name),
                    )

            return result

    def patch(self, patch):
        """Update only the policy fields supplied by the caller."""
        if (
            not isinstance(patch, dict)
            or set(patch) - set(self.policy)
        ):
            raise APIError(
                "Invalid policy fields"
            )

        for key, value in patch.items():
            if key == "risk_weights":
                import math

                if not isinstance(value, dict):
                    raise APIError(
                        "risk_weights must be an object"
                    )

                invalid_values = any(
                    type(weight) not in (int, float)
                    or not math.isfinite(weight)
                    or weight < 0
                    for weight in value.values()
                )

                if invalid_values:
                    raise APIError(
                        "risk_weights must be finite "
                        "nonnegative numbers"
                    )

                valid_names = {
                    action.value
                    for action in EdgeAction
                }

                if set(value) - valid_names:
                    raise APIError(
                        "risk_weights keys must be "
                        "edge action names"
                    )

            elif (
                not isinstance(value, list)
                or any(
                    not isinstance(item, str)
                    for item in value
                )
            ):
                raise APIError(
                    f"{key} must be an array of strings"
                )

        with self.lock:
            self.policy.update(
                deepcopy(patch)
            )

            return deepcopy(self.policy)