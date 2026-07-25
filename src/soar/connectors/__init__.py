"""Connectors: the things a playbook can actually do.

Every connector declares whether it is **destructive** — meaning its effect
persists after the run and someone would have to undo it deliberately. That one
flag drives approval gating, rollback validation and what dry-run prints, so
getting it wrong is worse than not having it.

The bundled connectors are simulated. Wiring `isolate_host` to a real EDR is
twenty lines and a credential; what this repository provides is the machinery
around it — the approval gate, the idempotency key, the rollback path, the
audit record — which is the part that is actually hard and the part that is
usually missing.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class ConnectorError(RuntimeError):
    """Raised when an action cannot complete."""


@dataclass
class ActionResult:
    ok: bool
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    #: Set when the action found the world already in the desired state.
    already_done: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "message": self.message,
            "data": self.data,
            "already_done": self.already_done,
        }


@dataclass(frozen=True)
class Connector:
    """One callable action."""

    name: str
    summary: str
    handler: Callable[[dict[str, Any]], ActionResult]
    #: Effect persists after the run; someone must undo it deliberately.
    destructive: bool = False
    required_params: tuple[str, ...] = ()
    #: What dry-run prints. Written as a sentence about the world, not about
    #: the tool: "would isolate web-01", not "would call isolate_host".
    preview: str = ""

    def describe(self, params: dict[str, Any]) -> str:
        template = self.preview or f"would run {self.name}"
        try:
            return template.format(**params)
        except (KeyError, IndexError):
            return f"{template} ({params})"


class Registry:
    """The set of actions available to playbooks."""

    def __init__(self) -> None:
        self._connectors: dict[str, Connector] = {}

    def register(self, connector: Connector) -> None:
        if connector.name in self._connectors:
            raise ConnectorError(f"connector {connector.name!r} is already registered")
        self._connectors[connector.name] = connector

    def has(self, name: str) -> bool:
        return name in self._connectors

    def get(self, name: str) -> Connector:
        try:
            return self._connectors[name]
        except KeyError:
            raise ConnectorError(
                f"unknown action {name!r}; registered: {', '.join(self.names())}"
            ) from None

    def names(self) -> list[str]:
        return sorted(self._connectors)

    def all(self) -> list[Connector]:
        return [self._connectors[n] for n in self.names()]

    def is_destructive(self, name: str) -> bool:
        return self.has(name) and self._connectors[name].destructive


def default_registry() -> Registry:
    """The bundled simulated connectors."""
    from . import simulated

    registry = Registry()
    for connector in simulated.CONNECTORS:
        registry.register(connector)
    return registry
