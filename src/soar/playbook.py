"""Playbooks: what to do, in what order, and what has to be true first.

A response playbook is code that runs unattended at 03:00 against production,
usually while someone is panicking. Three properties follow from that, and they
shape the whole schema:

**Every destructive step declares how to undo it.** Isolating the wrong host
during an incident turns one problem into two, and the person who has to undo
it at 03:15 is the one who was already having a bad night. A step whose action
is destructive and which declares no rollback fails validation.

**Every step is idempotent by key.** Playbooks get re-run — the first attempt
timed out, the analyst pressed the button twice, the webhook fired twice. A
step that has already completed for the same key is skipped, not repeated.

**Approval is a property of the step, not of the run.** "Ask before doing
anything" gets clicked through; "ask before this specific irreversible action,
showing exactly what it will do" gets read.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class PlaybookError(ValueError):
    """Raised for a malformed playbook. Always names the step."""


class Approval(str, enum.Enum):
    NEVER = "never"      # run unattended
    ALWAYS = "always"    # always ask a human
    DESTRUCTIVE = "destructive"  # ask only when the action cannot be undone

    @property
    def label(self) -> str:
        return {
            Approval.NEVER: "automatic",
            Approval.ALWAYS: "requires approval",
            Approval.DESTRUCTIVE: "approval if irreversible",
        }[self]


@dataclass(frozen=True)
class Step:
    """One action in a playbook."""

    id: str
    action: str
    description: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    #: Expression over the run context; the step is skipped when it is false.
    when: str = ""
    approval: Approval = Approval.DESTRUCTIVE
    #: Action that reverses this one, with its parameters.
    rollback: dict[str, Any] = field(default_factory=dict)
    #: Continue the playbook if this step fails. Off by default: a response
    #: playbook that carries on after containment failed is worse than one that
    #: stops and pages someone.
    continue_on_error: bool = False
    timeout_s: int = 60
    #: Fields from the result to bind into the context for later steps.
    bind: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            raise PlaybookError("a step has no id")
        if not self.action:
            raise PlaybookError(f"step {self.id!r}: 'action' is required")


@dataclass(frozen=True)
class Playbook:
    """A named, versioned response procedure."""

    id: str
    name: str
    description: str
    steps: tuple[Step, ...]
    triggers: tuple[str, ...] = ()
    #: Parameters the caller must supply, e.g. host, user, ip.
    inputs: tuple[str, ...] = ()
    owner: str = ""
    version: str = "1"

    def __len__(self) -> int:
        return len(self.steps)

    def step(self, step_id: str) -> Step | None:
        return next((s for s in self.steps if s.id == step_id), None)

    def destructive_steps(self, registry: Any) -> list[Step]:
        return [s for s in self.steps if registry.is_destructive(s.action)]


def load(path: str | Path) -> Playbook:
    source = Path(path)
    if not source.exists():
        raise PlaybookError(f"playbook not found: {source}")
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise PlaybookError(f"{source.name}: invalid YAML: {exc}") from None
    return parse(data, source.name)


def load_dir(path: str | Path) -> list[Playbook]:
    base = Path(path)
    if not base.is_dir():
        raise PlaybookError(f"not a directory: {base}")
    playbooks = [load(p) for p in sorted(base.glob("*.y*ml"))]
    ids = [p.id for p in playbooks]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise PlaybookError(f"duplicate playbook id(s) in {base}: {', '.join(sorted(duplicates))}")
    return playbooks


def parse(data: dict[str, Any], where: str = "playbook") -> Playbook:
    if not isinstance(data, dict):
        raise PlaybookError(f"{where}: top level must be a mapping")
    for key in ("id", "steps"):
        if key not in data:
            raise PlaybookError(f"{where}: missing required key {key!r}")

    steps: list[Step] = []
    seen: set[str] = set()
    for raw in data["steps"] or []:
        if not isinstance(raw, dict):
            raise PlaybookError(f"{where}: each step must be a mapping")
        step_id = str(raw.get("id", ""))
        if not step_id:
            raise PlaybookError(f"{where}: a step has no id")
        if step_id in seen:
            raise PlaybookError(f"{where}: duplicate step id {step_id!r}")
        seen.add(step_id)

        try:
            approval = Approval(str(raw.get("approval", "destructive")).lower())
        except ValueError:
            raise PlaybookError(
                f"{where} step {step_id!r}: unknown approval {raw.get('approval')!r}; "
                f"expected one of {', '.join(a.value for a in Approval)}"
            ) from None

        rollback = raw.get("rollback") or {}
        if rollback and "action" not in rollback:
            raise PlaybookError(
                f"{where} step {step_id!r}: rollback needs an 'action'"
            )

        steps.append(
            Step(
                id=step_id,
                action=str(raw.get("action", "")),
                description=str(raw.get("description", "")).strip(),
                params=raw.get("params") or {},
                when=str(raw.get("when", "")).strip(),
                approval=approval,
                rollback=rollback,
                continue_on_error=bool(raw.get("continue_on_error", False)),
                timeout_s=int(raw.get("timeout_s", 60)),
                bind=raw.get("bind") or {},
            )
        )

    triggers = data.get("triggers") or []
    if isinstance(triggers, str):
        triggers = [triggers]
    inputs = data.get("inputs") or []
    if isinstance(inputs, str):
        inputs = [inputs]

    return Playbook(
        id=str(data["id"]),
        name=str(data.get("name", data["id"])),
        description=str(data.get("description", "")).strip(),
        owner=str(data.get("owner", "")),
        version=str(data.get("version", "1")),
        triggers=tuple(str(t) for t in triggers),
        inputs=tuple(str(i) for i in inputs),
        steps=tuple(steps),
    )


def validate(playbook: Playbook, registry: Any) -> list[str]:
    """Structural problems that would only surface mid-incident otherwise."""
    problems: list[str] = []

    for step in playbook.steps:
        if not registry.has(step.action):
            problems.append(
                f"step {step.id!r}: unknown action {step.action!r}; "
                f"registered: {', '.join(registry.names())}"
            )
            continue

        connector = registry.get(step.action)

        if connector.destructive and not step.rollback:
            problems.append(
                f"step {step.id!r}: {step.action!r} is destructive and declares no "
                "rollback. Undoing it at 03:15 will be someone's problem."
            )
        if step.rollback and not registry.has(step.rollback.get("action", "")):
            problems.append(
                f"step {step.id!r}: rollback action "
                f"{step.rollback.get('action')!r} is not registered"
            )

        missing = [p for p in connector.required_params if p not in step.params]
        if missing:
            problems.append(
                f"step {step.id!r}: {step.action!r} requires "
                f"{', '.join(missing)}"
            )

        if connector.destructive and step.approval is Approval.NEVER:
            problems.append(
                f"step {step.id!r}: {step.action!r} is destructive and set to run "
                "unattended. That is allowed, but say so deliberately rather than "
                "by omission."
            )

    # Placeholders that nothing will ever fill are the commonest playbook bug:
    # the run reaches production and interpolates the literal string.
    declared = set(playbook.inputs)
    produced = {name for step in playbook.steps for name in step.bind}
    for step in playbook.steps:
        for name in _placeholders(step.params) | _placeholders({"w": step.when}):
            root = name.split(".", 1)[0]
            if root not in declared and root not in produced and root != "incident":
                problems.append(
                    f"step {step.id!r}: references {{{name}}}, which is neither a "
                    "declared input nor bound by an earlier step"
                )

    return problems


def _placeholders(value: Any) -> set[str]:
    import re

    found: set[str] = set()
    if isinstance(value, str):
        found.update(re.findall(r"\{([a-zA-Z_][\w.]*)\}", value))
    elif isinstance(value, dict):
        for item in value.values():
            found |= _placeholders(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            found |= _placeholders(item)
    return found
