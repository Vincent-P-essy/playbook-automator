"""Execution: dry-run, approval, idempotency, rollback, and the record of it all.

The defaults are the design.

**Dry run is the default.** `run` without `--execute` shows what would happen
and changes nothing. A response tool whose default is to act is one that gets
run once by accident and then distrusted permanently.

**Rollback is automatic on failure, in reverse order.** A playbook that isolates
a host, revokes a token and then fails while disabling an account has left the
estate in a state nobody chose. Unless told otherwise, the engine walks back.

**Every step produces a record whether it ran or not**, including the ones
skipped by a condition and the ones that were already done. "Why didn't it
isolate the host?" is the question asked after an incident, and "the condition
on step 3 evaluated false because criticality was 'standard'" is the answer.
"""

from __future__ import annotations

import enum
import hashlib
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .connectors import ActionResult, ConnectorError, Registry
from .playbook import Approval, Playbook, Step

UTC = timezone.utc


class Outcome(str, enum.Enum):
    OK = "ok"
    SKIPPED = "skipped"
    ALREADY_DONE = "already_done"
    DENIED = "denied"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    DRY_RUN = "dry_run"

    @property
    def is_failure(self) -> bool:
        return self in (Outcome.FAILED, Outcome.DENIED)


@dataclass
class StepRecord:
    step_id: str
    action: str
    outcome: Outcome
    message: str
    started_at: str
    duration_ms: float
    params: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)
    approver: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_id,
            "action": self.action,
            "outcome": self.outcome.value,
            "message": self.message,
            "started_at": self.started_at,
            "duration_ms": round(self.duration_ms, 1),
            "params": self.params,
            "data": self.data,
            "approver": self.approver,
            "reason": self.reason,
        }


@dataclass
class RunResult:
    playbook_id: str
    run_id: str
    dry_run: bool
    started_at: str
    finished_at: str = ""
    records: list[StepRecord] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    rolled_back: bool = False

    @property
    def ok(self) -> bool:
        return not any(r.outcome.is_failure for r in self.records)

    @property
    def executed(self) -> list[StepRecord]:
        return [r for r in self.records if r.outcome in (Outcome.OK, Outcome.ALREADY_DONE)]

    def to_dict(self) -> dict[str, Any]:
        return {
            "playbook": self.playbook_id,
            "run_id": self.run_id,
            "dry_run": self.dry_run,
            "ok": self.ok,
            "rolled_back": self.rolled_back,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "steps": [r.to_dict() for r in self.records],
        }


def idempotency_key(playbook_id: str, step_id: str, params: dict[str, Any]) -> str:
    """Stable across re-runs of the same step against the same target.

    Derived from the resolved parameters rather than from a run id, so a second
    attempt after a timeout recognises the first attempt's work. Keying on the
    run would make every retry a fresh execution, which is exactly the bug this
    is here to avoid.
    """
    payload = json.dumps(
        {"playbook": playbook_id, "step": step_id, "params": params},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][\w.]*)\}")

#: How a dry run renders a value that only exists once something has run.
UNRESOLVED = "<unresolved: {}>"


def interpolate(value: Any, context: dict[str, Any], *, lenient: bool = False) -> Any:
    """Substitute ``{name}`` and ``{a.b}`` from the context.

    An unresolved placeholder raises rather than passing through as a literal.
    A playbook that blocks the IP address ``{incident.source_ip}`` is a firewall
    rule nobody meant to write.

    ``lenient`` is for dry runs, where values bound by earlier steps genuinely
    do not exist yet - nothing has executed to produce them. It renders those
    as ``<unresolved: name>`` so the preview shows the shape of what would
    happen and marks precisely which parts depend on the run. Failing instead
    would make dry run useless for any playbook that enriches before acting,
    which is every good one.
    """
    def resolve(path: str) -> Any:
        current: Any = context
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                if lenient:
                    return UNRESOLVED.format(path)
                raise KeyError(path)
        return current

    if isinstance(value, str):
        if _PLACEHOLDER.fullmatch(value):
            return resolve(value[1:-1])  # preserve the type
        return _PLACEHOLDER.sub(lambda m: str(resolve(m.group(1))), value)
    if isinstance(value, dict):
        return {k: interpolate(v, context, lenient=lenient) for k, v in value.items()}
    if isinstance(value, list):
        return [interpolate(v, context, lenient=lenient) for v in value]
    return value


def evaluate(expression: str, context: dict[str, Any]) -> bool:
    """Evaluate a step condition.

    Deliberately not ``eval``. A playbook is configuration, often authored by
    someone who is not the person who reviews the code that runs it, and a
    condition that can execute arbitrary Python is a remote code execution
    waiting for a pull request. Supported: ``a == b``, ``!=``, ``in``,
    ``not in``, ``>``, ``<``, and bare truthiness.
    """
    expression = expression.strip()
    if not expression:
        return True

    for operator in (" not in ", " in ", " == ", " != ", " >= ", " <= ", " > ", " < "):
        if operator in expression:
            left_raw, right_raw = expression.split(operator, 1)
            left = _resolve(left_raw.strip(), context)
            right = _resolve(right_raw.strip(), context)
            op = operator.strip()
            try:
                if op == "==":
                    return left == right
                if op == "!=":
                    return left != right
                if op == "in":
                    return left in right
                if op == "not in":
                    return left not in right
                if op == ">":
                    return float(left) > float(right)
                if op == "<":
                    return float(left) < float(right)
                if op == ">=":
                    return float(left) >= float(right)
                if op == "<=":
                    return float(left) <= float(right)
            except (TypeError, ValueError):
                return False
    return bool(_resolve(expression, context))


def _condition_resolvable(expression: str, context: dict[str, Any]) -> bool:
    """True when every name the condition reads is already in the context."""
    for operator in (" not in ", " in ", " == ", " != ", " >= ", " <= ", " > ", " < "):
        if operator in expression:
            left, right = expression.split(operator, 1)
            return all(_is_known(t.strip(), context) for t in (left, right))
    return _is_known(expression.strip(), context)


def _is_known(token: str, context: dict[str, Any]) -> bool:
    token = token.strip()
    if token.startswith(("'", '"')) or token in ("true", "True", "false", "False"):
        return True
    try:
        float(token)
        return True
    except ValueError:
        pass
    current: Any = context
    for part in token.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False
    return True


def _resolve(token: str, context: dict[str, Any]) -> Any:
    token = token.strip()
    if token.startswith(("'", '"')) and token.endswith(("'", '"')):
        return token[1:-1]
    if token in ("true", "True"):
        return True
    if token in ("false", "False"):
        return False
    try:
        return float(token) if "." in token else int(token)
    except ValueError:
        pass
    current: Any = context
    for part in token.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return token  # an unknown name is a literal, not an error
    return current


#: Approve every step. Never the default; supplied explicitly by `--yes`.
def approve_all(step: Step, preview: str) -> tuple[bool, str]:
    return True, "auto-approved"


def deny_all(step: Step, preview: str) -> tuple[bool, str]:
    return False, "no approver available"


class Engine:
    """Runs playbooks."""

    def __init__(
        self,
        registry: Registry,
        *,
        approver: Callable[[Step, str], tuple[bool, str]] = deny_all,
        completed: dict[str, dict[str, Any]] | None = None,
        on_event: Callable[[StepRecord], None] | None = None,
    ) -> None:
        self.registry = registry
        self.approver = approver
        #: Idempotency key -> the data that step produced, from a previous run.
        #: The data matters as much as the key: skipping a step without
        #: replaying what it bound leaves every later step referring to values
        #: that were never set, which turns a resume into a different failure.
        self.completed = completed or {}
        self.on_event = on_event

    def run(
        self,
        playbook: Playbook,
        inputs: dict[str, Any] | None = None,
        *,
        dry_run: bool = True,
        rollback_on_failure: bool = True,
    ) -> RunResult:
        inputs = inputs or {}
        missing = [name for name in playbook.inputs if name not in inputs]
        if missing:
            raise ValueError(
                f"playbook {playbook.id!r} requires input(s): {', '.join(missing)}"
            )

        started = datetime.now(UTC)
        result = RunResult(
            playbook_id=playbook.id,
            run_id=hashlib.sha256(
                f"{playbook.id}:{started.isoformat()}:{sorted(inputs.items())}".encode()
            ).hexdigest()[:12],
            dry_run=dry_run,
            started_at=started.isoformat(timespec="seconds"),
            context=dict(inputs),
        )

        #: Steps that changed something, for rollback in reverse.
        undo: list[tuple[Step, dict[str, Any]]] = []

        for step in playbook.steps:
            record = self._run_step(playbook, step, result.context, dry_run, undo)
            result.records.append(record)
            if self.on_event:
                self.on_event(record)

            if record.outcome.is_failure and not step.continue_on_error:
                if rollback_on_failure and undo and not dry_run:
                    result.rolled_back = True
                    result.records.extend(self._rollback(undo, result.context))
                break

        result.finished_at = datetime.now(UTC).isoformat(timespec="seconds")
        return result

    # -- internals ----------------------------------------------------------

    def _run_step(
        self,
        playbook: Playbook,
        step: Step,
        context: dict[str, Any],
        dry_run: bool,
        undo: list[tuple[Step, dict[str, Any]]],
    ) -> StepRecord:
        started = time.perf_counter()
        stamp = datetime.now(UTC).isoformat(timespec="seconds")

        def record(outcome: Outcome, message: str, **extra: Any) -> StepRecord:
            return StepRecord(
                step_id=step.id, action=step.action, outcome=outcome, message=message,
                started_at=stamp, duration_ms=(time.perf_counter() - started) * 1000,
                **extra,
            )

        try:
            params = interpolate(step.params, context, lenient=dry_run)
        except KeyError as exc:
            return record(
                Outcome.FAILED,
                f"cannot resolve {{{exc.args[0]}}} — it is not in the run context",
            )

        if step.when:
            if dry_run and not _condition_resolvable(step.when, context):
                # The condition depends on something an earlier step produces.
                # Saying "would skip" here would be a guess; saying which value
                # it turns on is the useful answer.
                connector = self.registry.get(step.action)
                preview = connector.describe(params)
                return record(
                    Outcome.DRY_RUN,
                    f"{preview} — only if `{step.when}`, which depends on the run",
                    params=params,
                )
            try:
                if not evaluate(step.when, context):
                    return record(
                        Outcome.SKIPPED,
                        f"condition not met: {step.when}",
                        params=params,
                    )
            except Exception as exc:  # noqa: BLE001
                return record(Outcome.FAILED, f"condition {step.when!r} failed: {exc}")

        connector = self.registry.get(step.action)
        preview = connector.describe(params)

        key = idempotency_key(playbook.id, step.id, params)
        if key in self.completed:
            # Replay what the step bound last time. Without this the resume
            # succeeds at this step and fails at the next one, referring to a
            # value nothing ever produced.
            previous = self.completed[key]
            for name, source in step.bind.items():
                if source in previous:
                    context[name] = previous[source]
            context.setdefault("steps", {})[step.id] = previous
            return record(
                Outcome.ALREADY_DONE,
                f"already completed in an earlier run (key {key})",
                params=params, data=previous,
            )

        needs_approval = step.approval is Approval.ALWAYS or (
            step.approval is Approval.DESTRUCTIVE and connector.destructive
        )

        if dry_run:
            note = " [would ask for approval]" if needs_approval else ""
            return record(Outcome.DRY_RUN, preview + note, params=params)

        approver_name = ""
        if needs_approval:
            approved, reason = self.approver(step, preview)
            approver_name = reason
            if not approved:
                return record(
                    Outcome.DENIED, f"not approved: {reason}",
                    params=params, approver=approver_name, reason=reason,
                )

        try:
            outcome_result: ActionResult = connector.handler(params)
        except ConnectorError as exc:
            return record(Outcome.FAILED, str(exc), params=params, approver=approver_name)
        except Exception as exc:  # noqa: BLE001
            return record(
                Outcome.FAILED, f"{type(exc).__name__}: {exc}",
                params=params, approver=approver_name,
            )

        if not outcome_result.ok:
            return record(
                Outcome.FAILED, outcome_result.message,
                params=params, data=outcome_result.data, approver=approver_name,
            )

        for name, source in step.bind.items():
            if source in outcome_result.data:
                context[name] = outcome_result.data[source]
        context.setdefault("steps", {})[step.id] = outcome_result.data

        # Only record for rollback what actually changed something. Re-running
        # a rollback for a no-op is how a rollback causes its own incident.
        if step.rollback and not outcome_result.already_done:
            undo.append((step, params))

        return record(
            Outcome.ALREADY_DONE if outcome_result.already_done else Outcome.OK,
            outcome_result.message,
            params=params, data=outcome_result.data, approver=approver_name,
        )

    def _rollback(
        self, undo: list[tuple[Step, dict[str, Any]]], context: dict[str, Any]
    ) -> list[StepRecord]:
        """Walk back in reverse. Rollback failures are recorded, never raised.

        A rollback that aborts halfway leaves the estate in a state nobody
        chose *and* nobody knows about. Every attempt is recorded and the walk
        continues.
        """
        records: list[StepRecord] = []
        for step, params in reversed(undo):
            stamp = datetime.now(UTC).isoformat(timespec="seconds")
            started = time.perf_counter()
            action = step.rollback.get("action", "")
            rollback_params = {**params, **(step.rollback.get("params") or {})}
            try:
                rollback_params = interpolate(rollback_params, context)
                result = self.registry.get(action).handler(rollback_params)
                message = result.message
                outcome = Outcome.ROLLED_BACK if result.ok else Outcome.FAILED
            except Exception as exc:  # noqa: BLE001
                message = f"rollback failed: {exc}"
                outcome = Outcome.FAILED
            records.append(
                StepRecord(
                    step_id=f"{step.id}:rollback", action=action, outcome=outcome,
                    message=message, started_at=stamp,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    params=rollback_params,
                )
            )
        return records


def completed_from(result: RunResult, playbook: Playbook) -> dict[str, dict[str, Any]]:
    """Idempotency key -> produced data, from a previous run.

    Carries the data as well as the key so a resumed run can replay what each
    skipped step bound into the context.
    """
    out: dict[str, dict[str, Any]] = {}
    for record in result.records:
        if record.outcome in (Outcome.OK, Outcome.ALREADY_DONE):
            out[idempotency_key(playbook.id, record.step_id, record.params)] = record.data
    return out
