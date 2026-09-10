"""Typed vocabulary for the Dynamic Capability Graph (#6).

Kept in sync with the `object`/`destination`/`action` vocabularies in
schema/event_schema.json and the GraphSnapshot schema in api/openapi.yaml.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class NodeType(str, Enum):
    AGENT = "agent"
    TOOL = "tool"
    RESOURCE = "resource"
    DESTINATION = "destination"
    PERMISSION = "permission"
    GOAL = "goal"


class EdgeAction(str, Enum):
    READ = "read"
    WRITE = "write"
    CALL = "call"
    DELEGATE = "delegate"
    SEND = "send"


@dataclass
class Node:
    id: str
    type: NodeType
    labels: set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {"id": self.id, "type": self.type.value, "labels": sorted(self.labels)}


@dataclass
class Edge:
    source: str
    target: str
    action: EdgeAction
    permission_id: str | None = None
    carries: dict | None = None
    cost: float = 1.0
    blocked: bool = False

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "action": self.action.value,
            "blocked": self.blocked,
            "cost": self.cost,
        }
