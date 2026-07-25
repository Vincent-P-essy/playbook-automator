"""Command line interface.

`run` is a dry run unless you pass `--execute`. That is the single most
important design decision in the tool: a response system whose default is to
act gets run once by accident and distrusted permanently afterwards.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

from . import __version__
from .connectors import default_registry
from .engine import Engine, Outcome, RunResult, approve_all, completed_from
from .playbook import Approval, PlaybookError, load, load_dir, validate

OUTCOME_STYLE = {
    Outcome.OK: "green",
    Outcome.SKIPPED: "dim",
    Outcome.ALREADY_DONE: "cyan",
    Outcome.DENIED: "yellow",
    Outcome.FAILED: "bright_red",
    Outcome.ROLLED_BACK: "magenta",
    Outcome.DRY_RUN: "blue",
}


def _inputs(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise ValueError(f"input {pair!r} must be key=value")
        key, _, value = pair.partition("=")
        out[key.strip()] = value.strip()
    return out


def _render(result: RunResult, console: Console) -> None:
    header = Text()
    header.append(f"{result.playbook_id}", style="bold")
    header.append(f"  run {result.run_id}\n", style="dim")
    if result.dry_run:
        header.append("DRY RUN — nothing was changed", style="bold blue")
    elif result.rolled_back:
        header.append("FAILED and rolled back", style="bold magenta")
    elif result.ok:
        header.append("completed", style="bold green")
    else:
        header.append("FAILED", style="bold bright_red")
    console.print(Panel(header, border_style="blue", expand=False))

    table = Table(header_style="dim", show_lines=False)
    table.add_column("step", style="bold")
    table.add_column("action", style="cyan")
    table.add_column("outcome")
    table.add_column("what happened", overflow="fold")
    for record in result.records:
        table.add_row(
            record.step_id,
            record.action,
            Text(record.outcome.value, style=OUTCOME_STYLE[record.outcome]),
            record.message,
        )
    console.print(table)


def cmd_run(args: argparse.Namespace, console: Console) -> int:
    playbook = load(args.playbook)
    registry = default_registry()

    problems = validate(playbook, registry)
    if problems:
        console.print("[bold red]playbook did not validate:[/]")
        for problem in problems:
            console.print(f"  - {problem}")
        return 1

    def ask(step, preview: str) -> tuple[bool, str]:
        console.print()
        console.print(
            Panel(
                Text.assemble(
                    (preview, "bold"),
                    ("\n\nrollback: ", "dim"),
                    (step.rollback.get("action", "none declared"), "dim"),
                ),
                title=f"approval required — {step.id}",
                border_style="yellow",
                expand=False,
            )
        )
        if Confirm.ask("proceed?", default=False):
            return True, args.approver or "interactive"
        return False, "declined at the prompt"

    approver = approve_all if args.yes else (ask if sys.stdin.isatty() else None)
    engine = Engine(
        registry,
        approver=approver if approver else (lambda s, p: (False, "no approver available")),
    )

    if args.resume:
        previous = json.loads(Path(args.resume).read_text())
        engine.completed = completed_from(_result_from(previous), playbook)
        console.print(
            f"[dim]resuming: {len(engine.completed)} step(s) already completed[/]"
        )

    result = engine.run(
        playbook,
        _inputs(args.input),
        dry_run=not args.execute,
        rollback_on_failure=not args.no_rollback,
    )
    _render(result, console)

    if result.dry_run:
        gated = [s for s in playbook.steps if s.approval is not Approval.NEVER]
        console.print(
            f"\n[dim]nothing was changed. {len(gated)} step(s) would ask for "
            "approval. Add --execute to run for real.[/]"
        )

    if args.out:
        Path(args.out).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[dim]wrote {args.out}[/]")

    return 0 if result.ok else 1


def _result_from(payload: dict) -> RunResult:
    from .engine import StepRecord

    result = RunResult(
        playbook_id=payload["playbook"], run_id=payload["run_id"],
        dry_run=payload["dry_run"], started_at=payload["started_at"],
    )
    for record in payload["steps"]:
        result.records.append(
            StepRecord(
                step_id=record["step"], action=record["action"],
                outcome=Outcome(record["outcome"]), message=record["message"],
                started_at=record["started_at"], duration_ms=record["duration_ms"],
                params=record.get("params", {}), data=record.get("data", {}),
            )
        )
    return result


def cmd_validate(args: argparse.Namespace, console: Console) -> int:
    registry = default_registry()
    playbooks = load_dir(args.path) if Path(args.path).is_dir() else [load(args.path)]

    failures = 0
    for playbook in playbooks:
        problems = validate(playbook, registry)
        destructive = playbook.destructive_steps(registry)
        if problems:
            failures += 1
            console.print(f"[bold red]FAIL[/] {playbook.id}")
            for problem in problems:
                console.print(f"       {problem}")
        else:
            console.print(
                f"[green]OK[/]   {playbook.id:26} {len(playbook)} steps, "
                f"{len(destructive)} destructive, all with rollback"
            )
    if failures:
        console.print(f"\n[bold red]{failures} playbook(s) failed validation[/]")
        return 1
    console.print(f"\n[bold green]{len(playbooks)} playbook(s) valid[/]")
    return 0


def cmd_show(args: argparse.Namespace, console: Console) -> int:
    playbook = load(args.playbook)
    registry = default_registry()

    console.print(
        Panel(
            Text.assemble(
                (playbook.name + "\n", "bold"),
                (playbook.description or "", "dim"),
                ("\n\ninputs: ", "dim"), (", ".join(playbook.inputs) or "none", ""),
                ("\ntriggers: ", "dim"), (", ".join(playbook.triggers) or "none", ""),
            ),
            title=f"{playbook.id} v{playbook.version}",
            border_style="blue",
            expand=False,
        )
    )

    table = Table(header_style="dim")
    table.add_column("#", justify="right", style="dim")
    table.add_column("step", style="bold")
    table.add_column("action", style="cyan")
    table.add_column("gate")
    table.add_column("condition", style="dim")
    table.add_column("rollback", style="dim")
    for index, step in enumerate(playbook.steps, start=1):
        destructive = registry.is_destructive(step.action)
        gate = Text(step.approval.label, style="yellow" if destructive else "dim")
        table.add_row(
            str(index), step.id,
            Text(step.action, style="red" if destructive else "cyan"),
            gate,
            step.when or "—",
            step.rollback.get("action", "—"),
        )
    console.print(table)
    console.print("[dim]red actions are destructive: their effect outlives the run[/]")
    return 0


def cmd_actions(args: argparse.Namespace, console: Console) -> int:
    registry = default_registry()
    table = Table(title="Available actions", title_style="bold", header_style="dim")
    table.add_column("action", style="bold")
    table.add_column("destructive")
    table.add_column("requires", style="dim")
    table.add_column("what it does", overflow="fold")
    for connector in registry.all():
        table.add_row(
            connector.name,
            Text("yes", style="bright_red") if connector.destructive else Text("no", style="dim"),
            ", ".join(connector.required_params) or "—",
            connector.summary,
        )
    console.print(table)
    console.print(
        "\n[dim]Destructive actions gate on approval and must declare a rollback. "
        "The bundled connectors are simulated; wiring one to a real EDR is the "
        "handler function.[/]"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soar", description="Run incident-response playbooks, carefully."
    )
    parser.add_argument("--version", action="version", version=f"soar {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="run a playbook (dry run unless --execute)")
    p.add_argument("playbook")
    p.add_argument("--input", action="append", metavar="KEY=VALUE")
    p.add_argument("--execute", action="store_true", help="actually do it")
    p.add_argument("--yes", action="store_true", help="approve every gated step")
    p.add_argument("--approver", help="name recorded against approvals")
    p.add_argument("--no-rollback", action="store_true", help="leave changes in place on failure")
    p.add_argument("--resume", help="a previous run's JSON, to skip completed steps")
    p.add_argument("--out", help="write the run record here")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("validate", help="check a playbook or a directory of them")
    p.add_argument("path", nargs="?", default="playbooks")
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("show", help="show a playbook's steps and gates")
    p.add_argument("playbook")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("actions", help="list the available actions")
    p.set_defaults(func=cmd_actions)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    try:
        return int(args.func(args, console))
    except PlaybookError as exc:
        console.print(f"[bold red]playbook error:[/] {exc}")
        return 2
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]error:[/] {exc}")
        return 2
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
