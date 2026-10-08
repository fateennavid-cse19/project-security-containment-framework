"""Multi-Agent Simulator (#1).

Replays a scripted Scenario step by step and turns every step into one
schema-valid Event (schema/event_schema.json). Each event is pushed to the
registered sinks (e.g. EventCollector.collect, audit_logger.log_event) as it
happens, so downstream components see a live stream rather than a batch.

Before an event is emitted, two checks decide its `result`:
  1. Base access control -- does the agent actually hold the permission it is
     using? If not, the event is recorded as "denied".
  2. The gate -- an optional callback that sees the proposed event before it
     executes. This is the hook the Enforcement Engine (#16) plugs into: if
     the gate rejects the event it is recorded as "denied" and has no effect.

Agents also track what data they hold, so containment has realistic knock-on
effects: if a delegate is blocked, the receiving agent never gets the data,
and its later attempt to send it comes out as "error" instead of succeeding.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import validate

from simulator.models import AgentState, Scenario, Step

EVENT_SCHEMA_FILE = Path(__file__).resolve().parent.parent / "schema" / "event_schema.json"

_PERMISSION_ACTIONS = {"grant_permission", "revoke_permission"}
_TRANSFER_ACTIONS = {"delegate", "send"}
_VALID_ACTIONS = {"read", "write", "call"} | _TRANSFER_ACTIONS | _PERMISSION_ACTIONS


class MultiAgentSimulator:
    def __init__(
        self,
        sinks=None,
        gate=None,
        start_time: datetime | None = None,
        step_seconds: float = 5.0,
        jitter_seconds: float = 0.0,
        seed: int | None = None,
        validate_events: bool = True,
    ):
        self.sinks = list(sinks or [])
        self.gate = gate
        self.step_seconds = step_seconds
        self.jitter_seconds = jitter_seconds
        self.validate_events = validate_events

        self._clock = start_time or datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc)
        self._rng = random.Random(seed)
        self._event_counter = 0
        self._run_counter = 0

        with open(EVENT_SCHEMA_FILE, "r", encoding="utf-8") as file:
            self._schema = json.load(file)

    def add_sink(self, sink) -> None:
        self.sinks.append(sink)

    # -- running scenarios --------------------------------------------------

    def run(self, scenario: Scenario) -> list[dict]:
        self._check_scenario(scenario)

        self._run_counter += 1
        trajectory_id = f"traj-{scenario.scenario_id}-{self._run_counter:03d}"

        agents = {
            agent_id: AgentState(agent_id, permissions=set(perms))
            for agent_id, perms in scenario.agents.items()
        }

        events = []

        for index, step in enumerate(scenario.steps, start=1):
            self._tick()
            event = self._build_event(scenario, step, index, trajectory_id)
            result, reason = self._decide(agents[step.agent], step, event)

            event["result"] = result
            if reason is not None:
                event["metadata"]["outcome_reason"] = reason

            if result == "success":
                self._apply_effects(agents, step)

            if self.validate_events:
                validate(instance=event, schema=self._schema)

            for sink in self.sinks:
                sink(event)

            events.append(event)

        return events

    def run_all(self, scenarios: list[Scenario]) -> list[dict]:
        events = []
        for scenario in scenarios:
            events.extend(self.run(scenario))
        return events

    # -- per-step logic -----------------------------------------------------

    def _decide(self, agent: AgentState, step: Step, event: dict):
        """Returns (result, reason). reason is None on success."""
        if step.action not in _PERMISSION_ACTIONS:
            if step.permission not in agent.permissions:
                return "denied", "missing_permission"

        if step.action in _TRANSFER_ACTIONS and step.target not in agent.holdings:
            return "error", "agent_does_not_hold_object"

        if self.gate is not None:
            proposed = {**event, "result": "success"}
            if not self.gate(proposed):
                return "denied", "blocked_by_gate"

        return "success", None

    def _apply_effects(self, agents: dict[str, AgentState], step: Step) -> None:
        agent = agents[step.agent]

        if step.action in ("read", "write"):
            agent.holdings.add(step.target)
        elif step.action == "delegate" and step.to in agents:
            agents[step.to].holdings.add(step.target)
        elif step.action == "grant_permission":
            agent.permissions.add(step.target)
        elif step.action == "revoke_permission":
            agent.permissions.discard(step.target)

    def _build_event(self, scenario: Scenario, step: Step, index: int, trajectory_id: str) -> dict:
        self._event_counter += 1

        metadata = {"scenario_id": scenario.scenario_id, "step": index}
        if step.note:
            metadata["note"] = step.note
        if step.action == "grant_permission":
            metadata["granted_permission_id"] = step.target

        return {
            "event_id": f"evt-{self._event_counter:06d}",
            "timestamp": self._clock.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "trajectory_id": trajectory_id,
            "agent_id": step.agent,
            "action": step.action,
            "object": self._build_object(scenario, step),
            "destination": self._build_destination(scenario, step),
            "permission_id": None if step.action == "grant_permission" else step.permission,
            "goal_id": step.goal or scenario.goal,
            "result": "success",  # placeholder, overwritten by _decide
            "ground_truth_label": {
                "trajectory_type": scenario.trajectory_type,
                "attack_type": scenario.attack_type,
            },
            "metadata": metadata,
        }

    def _build_object(self, scenario: Scenario, step: Step) -> dict:
        if step.action in _PERMISSION_ACTIONS:
            return {"type": "permission", "id": step.target}
        if step.target in scenario.resources:
            return {
                "type": "resource",
                "id": step.target,
                "classification": scenario.resources[step.target],
            }
        return {"type": "tool", "id": step.target}

    def _build_destination(self, scenario: Scenario, step: Step):
        if step.action not in _TRANSFER_ACTIONS:
            return None
        if step.to in scenario.agents:
            return {"type": "agent", "id": step.to, "is_external": False}
        if step.to in scenario.tools:
            return {"type": "tool", "id": step.to, "is_external": False}
        return {"type": "external", "id": step.to, "is_external": True}

    def _tick(self) -> None:
        jitter = self._rng.uniform(0, self.jitter_seconds) if self.jitter_seconds else 0.0
        self._clock += timedelta(seconds=self.step_seconds + jitter)

    # -- scenario sanity checks ---------------------------------------------

    def _check_scenario(self, scenario: Scenario) -> None:
        """Fail loudly on authoring mistakes instead of emitting bad events."""
        if scenario.trajectory_type not in ("benign", "attack"):
            raise ValueError(f"{scenario.scenario_id}: bad trajectory_type {scenario.trajectory_type!r}")

        known_destinations = set(scenario.agents) | scenario.tools | scenario.externals

        for index, step in enumerate(scenario.steps, start=1):
            where = f"{scenario.scenario_id} step {index}"

            if step.agent not in scenario.agents:
                raise ValueError(f"{where}: unknown agent {step.agent!r}")
            if step.action not in _VALID_ACTIONS:
                raise ValueError(f"{where}: unknown action {step.action!r}")

            if step.action in _PERMISSION_ACTIONS:
                continue

            if step.target not in scenario.resources and step.target not in scenario.tools:
                raise ValueError(f"{where}: unknown resource/tool {step.target!r}")
            if step.permission is None:
                raise ValueError(f"{where}: {step.action} needs a permission")

            if step.action in _TRANSFER_ACTIONS:
                if step.to not in known_destinations:
                    raise ValueError(f"{where}: unknown destination {step.to!r}")
            elif step.to is not None:
                raise ValueError(f"{where}: only delegate/send take a destination")