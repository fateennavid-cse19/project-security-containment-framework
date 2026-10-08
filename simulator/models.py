"""Scenario vocabulary for the Multi-Agent Simulator (#1).

A Scenario is pure data: who the agents are, what they're allowed to do, what
resources/tools/external endpoints exist, and the ordered script of steps the
agents will attempt. Keeping scenarios as data (not code) is what lets the
benchmark dataset (#35) grow without touching the simulator itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Step:
    agent: str
    action: str
    target: str                    # resource / tool / permission id
    to: str | None = None          # destination id, only for delegate/send
    permission: str | None = None  # permission the agent uses for this step
    goal: str | None = None        # overrides Scenario.goal for this step
    note: str | None = None


@dataclass
class Scenario:
    scenario_id: str
    trajectory_type: str           # "benign" | "attack"
    attack_type: str | None
    agents: dict[str, set[str]]    # agent id -> starting permissions
    resources: dict[str, str]      # resource id -> classification
    tools: set[str] = field(default_factory=set)
    externals: set[str] = field(default_factory=set)
    steps: list[Step] = field(default_factory=list)
    goal: str | None = None


@dataclass
class AgentState:
    """Runtime state of one scripted agent during a single run."""
    agent_id: str
    permissions: set[str] = field(default_factory=set)
    holdings: set[str] = field(default_factory=set)  # data ids the agent currently has