"""Simulated connectors, with the state a real one would have to reason about.

These keep an in-memory world so the engine's interesting behaviour is
exercisable end to end: idempotency (isolating an already-isolated host reports
``already_done`` rather than failing), rollback (releasing restores the previous
state), and failure handling (the tokens connector refuses an unknown token
rather than silently succeeding).

Replacing one with a real integration means swapping the handler. Everything
around it — approval, idempotency key, rollback, audit — belongs to the engine
and does not change.
"""

from __future__ import annotations

from typing import Any

from . import ActionResult, Connector, ConnectorError

#: The simulated world. Reset between runs by the engine's test fixtures.
STATE: dict[str, Any] = {
    "isolated_hosts": set(),
    "blocked_ips": set(),
    "revoked_tokens": set(),
    "disabled_accounts": set(),
    "known_tokens": {"tok_a1b2c3", "tok_d4e5f6", "tok_legacy_svc"},
    "notifications": [],
    "tickets": [],
    "snapshots": {},
}


def reset() -> None:
    STATE["isolated_hosts"] = set()
    STATE["blocked_ips"] = set()
    STATE["revoked_tokens"] = set()
    STATE["disabled_accounts"] = set()
    STATE["known_tokens"] = {"tok_a1b2c3", "tok_d4e5f6", "tok_legacy_svc"}
    STATE["notifications"] = []
    STATE["tickets"] = []
    STATE["snapshots"] = {}


def _isolate_host(params: dict[str, Any]) -> ActionResult:
    host = str(params["host"])
    if host in STATE["isolated_hosts"]:
        # Idempotency is the connector's job as much as the engine's: a re-run
        # after a timeout must not report failure for work already done.
        return ActionResult(True, f"{host} was already isolated", already_done=True)
    STATE["isolated_hosts"].add(host)
    return ActionResult(True, f"isolated {host}", {"host": host})


def _release_host(params: dict[str, Any]) -> ActionResult:
    host = str(params["host"])
    if host not in STATE["isolated_hosts"]:
        return ActionResult(True, f"{host} was not isolated", already_done=True)
    STATE["isolated_hosts"].discard(host)
    return ActionResult(True, f"released {host} from isolation", {"host": host})


def _block_ip(params: dict[str, Any]) -> ActionResult:
    ip = str(params["ip"])
    if ip in STATE["blocked_ips"]:
        return ActionResult(True, f"{ip} was already blocked", already_done=True)
    STATE["blocked_ips"].add(ip)
    return ActionResult(True, f"blocked {ip} at the perimeter", {"ip": ip})


def _unblock_ip(params: dict[str, Any]) -> ActionResult:
    ip = str(params["ip"])
    STATE["blocked_ips"].discard(ip)
    return ActionResult(True, f"unblocked {ip}", {"ip": ip})


def _revoke_token(params: dict[str, Any]) -> ActionResult:
    token = str(params["token"])
    if token in STATE["revoked_tokens"]:
        return ActionResult(True, f"{token} was already revoked", already_done=True)
    if token not in STATE["known_tokens"]:
        # Refusing is the right answer. A connector that reports success for a
        # token it never found lets a playbook claim containment it did not do.
        raise ConnectorError(f"no such token {token!r}")
    STATE["revoked_tokens"].add(token)
    STATE["known_tokens"].discard(token)
    return ActionResult(True, f"revoked {token}", {"token": token})


def _disable_account(params: dict[str, Any]) -> ActionResult:
    account = str(params["account"])
    if account in STATE["disabled_accounts"]:
        return ActionResult(True, f"{account} was already disabled", already_done=True)
    STATE["disabled_accounts"].add(account)
    return ActionResult(True, f"disabled {account}", {"account": account})


def _enable_account(params: dict[str, Any]) -> ActionResult:
    account = str(params["account"])
    STATE["disabled_accounts"].discard(account)
    return ActionResult(True, f"re-enabled {account}", {"account": account})


def _snapshot_host(params: dict[str, Any]) -> ActionResult:
    """Forensics before containment, because isolation can destroy evidence."""
    host = str(params["host"])
    snapshot_id = f"snap-{abs(hash(host)) % 100000:05d}"
    STATE["snapshots"][host] = snapshot_id
    return ActionResult(True, f"captured {snapshot_id} for {host}", {"snapshot_id": snapshot_id})


def _lookup_host(params: dict[str, Any]) -> ActionResult:
    """Enrichment: read-only, so it never needs approval or rollback."""
    host = str(params["host"])
    criticality = "critical" if host.startswith(("pay", "core", "db")) else "standard"
    return ActionResult(
        True,
        f"{host}: {criticality}",
        {"host": host, "criticality": criticality, "owner": "platform"},
    )


def _notify(params: dict[str, Any]) -> ActionResult:
    channel = str(params.get("channel", "#security"))
    message = str(params.get("message", ""))
    STATE["notifications"].append({"channel": channel, "message": message})
    return ActionResult(True, f"notified {channel}", {"channel": channel})


def _open_ticket(params: dict[str, Any]) -> ActionResult:
    ticket_id = f"INC-{len(STATE['tickets']) + 4400}"
    STATE["tickets"].append({"id": ticket_id, **params})
    return ActionResult(True, f"opened {ticket_id}", {"ticket_id": ticket_id})


CONNECTORS = (
    Connector(
        "lookup_host", "Read asset criticality and owner", _lookup_host,
        required_params=("host",), preview="would look up {host}",
    ),
    Connector(
        "snapshot_host", "Capture a forensic snapshot before containment",
        _snapshot_host, required_params=("host",),
        preview="would snapshot {host} for forensics",
    ),
    Connector(
        "isolate_host", "Cut a host off the network", _isolate_host,
        destructive=True, required_params=("host",),
        preview="would ISOLATE {host} — it loses all network access",
    ),
    Connector(
        "release_host", "Return an isolated host to the network", _release_host,
        required_params=("host",), preview="would release {host} from isolation",
    ),
    Connector(
        "block_ip", "Block an address at the perimeter", _block_ip,
        destructive=True, required_params=("ip",),
        preview="would BLOCK {ip} at the perimeter",
    ),
    Connector(
        "unblock_ip", "Remove a perimeter block", _unblock_ip,
        required_params=("ip",), preview="would unblock {ip}",
    ),
    Connector(
        "revoke_token", "Revoke an API token", _revoke_token,
        destructive=True, required_params=("token",),
        preview="would REVOKE token {token} — anything using it stops working",
    ),
    Connector(
        "disable_account", "Disable a user account", _disable_account,
        destructive=True, required_params=("account",),
        preview="would DISABLE account {account}",
    ),
    Connector(
        "enable_account", "Re-enable a user account", _enable_account,
        required_params=("account",), preview="would re-enable {account}",
    ),
    Connector(
        "notify", "Post to a channel", _notify,
        preview="would notify {channel}",
    ),
    Connector(
        "open_ticket", "Open an incident ticket", _open_ticket,
        preview="would open a ticket",
    ),
)
