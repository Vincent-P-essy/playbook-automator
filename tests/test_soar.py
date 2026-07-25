"""Validation, dry run, approval gating, idempotency and rollback."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soar.connectors import ConnectorError, default_registry, simulated
from soar.engine import (
    Engine,
    Outcome,
    approve_all,
    completed_from,
    deny_all,
    evaluate,
    idempotency_key,
    interpolate,
)
from soar.playbook import PlaybookError, load, load_dir, parse, validate

PLAYBOOKS = Path(__file__).resolve().parent.parent / "playbooks"


@pytest.fixture(autouse=True)
def clean_world():
    simulated.reset()
    yield
    simulated.reset()


@pytest.fixture
def registry():
    return default_registry()


@pytest.fixture
def credential_playbook():
    return load(PLAYBOOKS / "compromised-credential.yaml")


INPUTS = {
    "token": "tok_a1b2c3", "host": "pay-web-03",
    "source_ip": "203.0.113.44", "reporter": "scanner",
}


class TestPlaybookParsing:
    def test_bundled_playbooks_load(self):
        playbooks = load_dir(PLAYBOOKS)
        assert len(playbooks) >= 2
        assert all(len(p) > 0 for p in playbooks)

    def test_missing_file(self, tmp_path):
        with pytest.raises(PlaybookError, match="not found"):
            load(tmp_path / "nope.yaml")

    def test_missing_id(self):
        with pytest.raises(PlaybookError, match="'id'"):
            parse({"steps": []})

    def test_step_without_action(self):
        with pytest.raises(PlaybookError, match="'action' is required"):
            parse({"id": "p", "steps": [{"id": "s"}]})

    def test_duplicate_step_ids(self):
        with pytest.raises(PlaybookError, match="duplicate step id"):
            parse({"id": "p", "steps": [
                {"id": "s", "action": "notify"}, {"id": "s", "action": "notify"}
            ]})

    def test_rollback_needs_an_action(self):
        with pytest.raises(PlaybookError, match="rollback needs an 'action'"):
            parse({"id": "p", "steps": [
                {"id": "s", "action": "notify", "rollback": {"params": {}}}
            ]})

    def test_unknown_approval(self):
        with pytest.raises(PlaybookError, match="unknown approval"):
            parse({"id": "p", "steps": [
                {"id": "s", "action": "notify", "approval": "maybe"}
            ]})


class TestValidation:
    def test_bundled_playbooks_validate(self, registry):
        for playbook in load_dir(PLAYBOOKS):
            assert validate(playbook, registry) == [], playbook.id

    def test_destructive_step_without_rollback_is_rejected(self, registry):
        # Undoing it at 03:15 will be someone's problem.
        playbook = parse({"id": "p", "inputs": ["host"], "steps": [
            {"id": "iso", "action": "isolate_host", "params": {"host": "{host}"}}
        ]})
        problems = validate(playbook, registry)
        assert any("declares no rollback" in p for p in problems)

    def test_unknown_action_lists_the_registered_ones(self, registry):
        playbook = parse({"id": "p", "steps": [{"id": "s", "action": "launch_missiles"}]})
        problems = validate(playbook, registry)
        assert any("registered:" in p for p in problems)

    def test_missing_required_param(self, registry):
        playbook = parse({"id": "p", "steps": [{"id": "s", "action": "isolate_host",
                                                "rollback": {"action": "release_host"}}]})
        assert any("requires host" in p for p in validate(playbook, registry))

    def test_placeholder_nothing_will_ever_fill(self, registry):
        # The commonest playbook bug: it reaches production and interpolates
        # the literal string.
        playbook = parse({"id": "p", "inputs": ["host"], "steps": [
            {"id": "s", "action": "notify", "params": {"message": "{nonexistent}"}}
        ]})
        problems = validate(playbook, registry)
        assert any("neither a declared input nor bound" in p for p in problems)

    def test_value_bound_by_an_earlier_step_is_accepted(self, registry):
        playbook = parse({"id": "p", "inputs": ["host"], "steps": [
            {"id": "look", "action": "lookup_host", "params": {"host": "{host}"},
             "bind": {"crit": "criticality"}},
            {"id": "say", "action": "notify", "params": {"message": "{crit}"}},
        ]})
        assert validate(playbook, registry) == []

    def test_destructive_step_set_to_run_unattended_is_flagged(self, registry):
        playbook = parse({"id": "p", "inputs": ["ip"], "steps": [
            {"id": "b", "action": "block_ip", "params": {"ip": "{ip}"},
             "approval": "never", "rollback": {"action": "unblock_ip"}}
        ]})
        assert any("unattended" in p for p in validate(playbook, registry))


class TestInterpolation:
    def test_simple_and_nested(self):
        context = {"host": "web-01", "asset": {"owner": "platform"}}
        assert interpolate("isolate {host}", context) == "isolate web-01"
        assert interpolate("{asset.owner}", context) == "platform"

    def test_whole_value_placeholder_keeps_its_type(self):
        assert interpolate("{n}", {"n": 42}) == 42
        assert isinstance(interpolate("{n}", {"n": 42}), int)

    def test_unresolved_raises_outside_a_dry_run(self):
        # A firewall rule for the literal address "{source_ip}" is not one
        # anybody meant to write.
        with pytest.raises(KeyError):
            interpolate("block {source_ip}", {})

    def test_unresolved_is_marked_in_a_dry_run(self):
        # Values bound by earlier steps genuinely do not exist yet.
        rendered = interpolate("block {source_ip}", {}, lenient=True)
        assert "unresolved" in rendered

    def test_recurses_into_structures(self):
        out = interpolate({"a": ["{x}", {"b": "{x}"}]}, {"x": "v"})
        assert out == {"a": ["v", {"b": "v"}]}


class TestConditions:
    @pytest.mark.parametrize(
        "expression,context,expected",
        [
            ("criticality == critical", {"criticality": "critical"}, True),
            ("criticality == critical", {"criticality": "standard"}, False),
            ("criticality != critical", {"criticality": "standard"}, True),
            ("distance > 5000", {"distance": 9000}, True),
            ("distance > 5000", {"distance": 100}, False),
            ("tag in tags", {"tag": "prod", "tags": ["prod", "eu"]}, True),
            ("tag not in tags", {"tag": "dev", "tags": ["prod"]}, True),
            ("", {}, True),
            ("flag", {"flag": True}, True),
            ("flag", {"flag": False}, False),
        ],
    )
    def test_evaluate(self, expression, context, expected):
        assert evaluate(expression, context) is expected

    def test_conditions_are_not_python(self):
        # A playbook is configuration, often written by someone who does not
        # review the code that runs it. eval() here is a remote code execution
        # waiting for a pull request.
        assert evaluate("__import__('os').system('true')", {}) is True  # a bare truthy string
        assert not simulated.STATE["notifications"]


class TestDryRun:
    def test_changes_nothing(self, credential_playbook, registry):
        engine = Engine(registry, approver=approve_all)
        result = engine.run(credential_playbook, INPUTS, dry_run=True)
        assert result.dry_run
        assert all(r.outcome is Outcome.DRY_RUN for r in result.records)
        assert not simulated.STATE["isolated_hosts"]
        assert not simulated.STATE["revoked_tokens"]
        assert not simulated.STATE["blocked_ips"]

    def test_is_the_default(self, credential_playbook, registry):
        assert Engine(registry).run(credential_playbook, INPUTS).dry_run

    def test_previews_describe_the_world_not_the_tool(self, credential_playbook, registry):
        result = Engine(registry).run(credential_playbook, INPUTS)
        revoke = next(r for r in result.records if r.step_id == "revoke")
        assert "tok_a1b2c3" in revoke.message
        assert "stops working" in revoke.message

    def test_a_condition_that_depends_on_the_run_says_so(self, credential_playbook, registry):
        # Claiming "would skip" would be a guess: the value it turns on does
        # not exist until something has executed.
        result = Engine(registry).run(credential_playbook, INPUTS)
        isolate = next(r for r in result.records if r.step_id == "isolate")
        assert "depends on the run" in isolate.message


class TestApproval:
    def test_destructive_steps_are_denied_without_an_approver(self, credential_playbook, registry):
        engine = Engine(registry, approver=deny_all)
        result = engine.run(credential_playbook, INPUTS, dry_run=False)
        denied = [r for r in result.records if r.outcome is Outcome.DENIED]
        assert denied
        assert not result.ok

    def test_non_destructive_steps_run_without_approval(self, credential_playbook, registry):
        engine = Engine(registry, approver=deny_all)
        result = engine.run(credential_playbook, INPUTS, dry_run=False)
        enrich = next(r for r in result.records if r.step_id == "enrich")
        assert enrich.outcome is Outcome.OK

    def test_always_approval_gates_even_a_reversible_action(self, registry):
        playbook = parse({"id": "p", "inputs": ["channel"], "steps": [
            {"id": "n", "action": "notify", "approval": "always",
             "params": {"channel": "{channel}"}}
        ]})
        result = Engine(registry, approver=deny_all).run(
            playbook, {"channel": "#x"}, dry_run=False
        )
        assert result.records[0].outcome is Outcome.DENIED

    def test_approver_name_is_recorded(self, credential_playbook, registry):
        engine = Engine(registry, approver=lambda s, p: (True, "n.duarte"))
        result = engine.run(credential_playbook, INPUTS, dry_run=False)
        revoke = next(r for r in result.records if r.step_id == "revoke")
        assert revoke.approver == "n.duarte"


class TestExecution:
    def test_full_run_changes_the_world(self, credential_playbook, registry):
        engine = Engine(registry, approver=approve_all)
        result = engine.run(credential_playbook, INPUTS, dry_run=False)
        assert result.ok
        assert "pay-web-03" in simulated.STATE["isolated_hosts"]
        assert "tok_a1b2c3" in simulated.STATE["revoked_tokens"]
        assert "203.0.113.44" in simulated.STATE["blocked_ips"]

    def test_condition_skips_a_standard_host(self, credential_playbook, registry):
        engine = Engine(registry, approver=approve_all)
        result = engine.run(
            credential_playbook, {**INPUTS, "host": "wiki-02"}, dry_run=False
        )
        isolate = next(r for r in result.records if r.step_id == "isolate")
        assert isolate.outcome is Outcome.SKIPPED
        assert "criticality == critical" in isolate.message
        assert "wiki-02" not in simulated.STATE["isolated_hosts"]

    def test_every_step_produces_a_record_even_when_skipped(
        self, credential_playbook, registry
    ):
        # "Why didn't it isolate the host?" is the post-incident question.
        result = Engine(registry, approver=approve_all).run(
            credential_playbook, {**INPUTS, "host": "wiki-02"}, dry_run=False
        )
        assert len(result.records) == len(credential_playbook)

    def test_missing_input_is_refused_before_anything_runs(
        self, credential_playbook, registry
    ):
        with pytest.raises(ValueError, match="requires input"):
            Engine(registry).run(credential_playbook, {"token": "t"}, dry_run=False)
        assert not simulated.STATE["revoked_tokens"]

    def test_bound_values_reach_later_steps(self, credential_playbook, registry):
        result = Engine(registry, approver=approve_all).run(
            credential_playbook, INPUTS, dry_run=False
        )
        assert result.context["criticality"] == "critical"
        announce = next(r for r in result.records if r.step_id == "announce")
        assert "INC-" in announce.params["message"]


class TestIdempotency:
    def test_the_same_step_and_params_produce_the_same_key(self):
        a = idempotency_key("pb", "step", {"host": "web-01"})
        b = idempotency_key("pb", "step", {"host": "web-01"})
        assert a == b

    def test_different_params_produce_different_keys(self):
        assert idempotency_key("pb", "s", {"host": "a"}) != idempotency_key("pb", "s", {"host": "b"})

    def test_resuming_skips_completed_steps(self, credential_playbook, registry):
        engine = Engine(registry, approver=approve_all)
        first = engine.run(credential_playbook, INPUTS, dry_run=False)
        assert first.ok

        resumed = Engine(
            registry, approver=approve_all,
            completed=completed_from(first, credential_playbook),
        ).run(credential_playbook, INPUTS, dry_run=False)

        assert all(
            r.outcome is Outcome.ALREADY_DONE for r in resumed.records
        ), [r.outcome for r in resumed.records]

    def test_a_connector_reports_work_already_done(self, registry):
        playbook = parse({"id": "p", "inputs": ["host"], "steps": [
            {"id": "iso", "action": "isolate_host", "params": {"host": "{host}"},
             "approval": "never", "rollback": {"action": "release_host"}}
        ]})
        engine = Engine(registry, approver=approve_all)
        engine.run(playbook, {"host": "web-01"}, dry_run=False)
        second = engine.run(playbook, {"host": "web-01"}, dry_run=False)
        assert second.records[0].outcome is Outcome.ALREADY_DONE
        assert second.ok


class TestRollback:
    def test_failure_walks_back_in_reverse(self, registry):
        # Isolate, block, then fail: the estate must not be left in a state
        # nobody chose.
        playbook = parse({"id": "p", "inputs": ["host", "ip"], "steps": [
            {"id": "iso", "action": "isolate_host", "params": {"host": "{host}"},
             "approval": "never", "rollback": {"action": "release_host"}},
            {"id": "blk", "action": "block_ip", "params": {"ip": "{ip}"},
             "approval": "never", "rollback": {"action": "unblock_ip"}},
            {"id": "boom", "action": "revoke_token", "params": {"token": "no_such_token"},
             "approval": "never", "rollback": {"action": "notify"}},
        ]})
        result = Engine(registry, approver=approve_all).run(
            playbook, {"host": "web-01", "ip": "198.51.100.7"}, dry_run=False
        )
        assert not result.ok
        assert result.rolled_back
        assert "web-01" not in simulated.STATE["isolated_hosts"]
        assert "198.51.100.7" not in simulated.STATE["blocked_ips"]

        rolled = [r for r in result.records if r.outcome is Outcome.ROLLED_BACK]
        # Reverse order: the block is undone before the isolation.
        assert [r.step_id for r in rolled] == ["blk:rollback", "iso:rollback"]

    def test_no_rollback_leaves_changes_in_place(self, registry):
        playbook = parse({"id": "p", "inputs": ["host"], "steps": [
            {"id": "iso", "action": "isolate_host", "params": {"host": "{host}"},
             "approval": "never", "rollback": {"action": "release_host"}},
            {"id": "boom", "action": "revoke_token", "params": {"token": "nope"},
             "approval": "never", "rollback": {"action": "notify"}},
        ]})
        result = Engine(registry, approver=approve_all).run(
            playbook, {"host": "web-01"}, dry_run=False, rollback_on_failure=False
        )
        assert not result.rolled_back
        assert "web-01" in simulated.STATE["isolated_hosts"]

    def test_already_done_steps_are_not_rolled_back(self, registry):
        # Undoing work this run did not do is how a rollback causes its own
        # incident.
        simulated.STATE["isolated_hosts"].add("web-01")
        playbook = parse({"id": "p", "inputs": ["host"], "steps": [
            {"id": "iso", "action": "isolate_host", "params": {"host": "{host}"},
             "approval": "never", "rollback": {"action": "release_host"}},
            {"id": "boom", "action": "revoke_token", "params": {"token": "nope"},
             "approval": "never", "rollback": {"action": "notify"}},
        ]})
        Engine(registry, approver=approve_all).run(
            playbook, {"host": "web-01"}, dry_run=False
        )
        assert "web-01" in simulated.STATE["isolated_hosts"]

    def test_continue_on_error_keeps_going(self, registry):
        playbook = parse({"id": "p", "steps": [
            {"id": "boom", "action": "revoke_token", "params": {"token": "nope"},
             "approval": "never", "continue_on_error": True,
             "rollback": {"action": "notify"}},
            {"id": "after", "action": "notify", "approval": "never",
             "params": {"channel": "#x"}},
        ]})
        result = Engine(registry, approver=approve_all).run(playbook, {}, dry_run=False)
        assert result.records[-1].step_id == "after"
        assert result.records[-1].outcome is Outcome.OK


class TestRecord:
    def test_serialises(self, credential_playbook, registry):
        result = Engine(registry, approver=approve_all).run(
            credential_playbook, INPUTS, dry_run=False
        )
        payload = json.dumps(result.to_dict())
        assert "run_id" in payload
        assert len(json.loads(payload)["steps"]) == len(credential_playbook)

    def test_connector_refuses_an_unknown_token_rather_than_claiming_success(self):
        # A connector that reports success for something it never found lets a
        # playbook claim containment it did not achieve.
        from soar.connectors.simulated import _revoke_token

        with pytest.raises(ConnectorError, match="no such token"):
            _revoke_token({"token": "tok_does_not_exist"})
