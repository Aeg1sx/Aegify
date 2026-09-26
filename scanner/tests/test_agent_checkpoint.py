"""Recovery tests never contact a provider or execute reviewed source."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aegify.agents.backends import AgentBackendError
from aegify.agents.catalog import AGENT_CATALOG
from aegify.agents.checkpoint import CheckpointBackend
from aegify.agents.models import AgentExplorationLimits, AgentRole
from aegify.agents.pipeline import SecurityAgentPipeline
from aegify.llm.budget import TokenBudget
from tests.test_agent_source_loop import NARRATIVE, ScriptedBackend, source_scan

SPEC = AGENT_CATALOG[AgentRole.STATIC]


class Backend:
    provider_name = "openai_api"

    def __init__(self, response=None):
        self.calls = 0
        self.response = NARRATIVE if response is None else response

    def invoke(self, *_args):
        raise AssertionError("must use the structured adapter")

    def invoke_turn(self, *_args):
        self.calls += 1
        return self.response


def test_saved_call_replays_after_caller_interruption_without_redispatch(tmp_path):
    path = tmp_path / "calls.json"
    backend = Backend()
    first = CheckpointBackend(backend, path, identity={"scan": "a"}, resume=False)
    assert first.invoke(SPEC, {"turn": 1}).summary == NARRATIVE["summary"]
    first.close()  # Caller dies after durable response, before its next turn.
    resumed_backend = Backend()
    resumed = CheckpointBackend(resumed_backend, path, identity={"scan": "a"}, resume=True)
    try:
        assert resumed.invoke(SPEC, {"turn": 1}).summary == NARRATIVE["summary"]
        resumed.invoke(SPEC, {"turn": 2})
        resumed.finish()
        assert resumed_backend.calls == 1
        assert resumed.replayed_calls == resumed.new_calls == 1
        assert path.stat().st_mode & 0o777 == 0o600
    finally:
        resumed.close()


def test_uncertain_dispatch_is_not_automatically_retried(tmp_path):
    class Interrupted(Backend):
        def invoke_turn(self, *_args):
            raise KeyboardInterrupt

    path = tmp_path / "calls.json"
    journal = CheckpointBackend(Interrupted(), path, identity={}, resume=False)
    try:
        with pytest.raises(KeyboardInterrupt):
            journal.invoke(SPEC, {})
    finally:
        journal.close()
    assert json.loads(path.read_text())["records"][0]["state"] == "pending"
    with pytest.raises(ValueError, match="uncertain dispatch"):
        CheckpointBackend(Backend(), path, identity={}, resume=True)


def test_process_exit_releases_lock_and_saved_response_survives(tmp_path):
    path = tmp_path / "calls.json"
    program = """
import os, sys
from pathlib import Path
from tests.test_agent_checkpoint import Backend, SPEC
from aegify.agents.checkpoint import CheckpointBackend
journal = CheckpointBackend(Backend(), Path(sys.argv[1]), identity={}, resume=False)
journal.invoke(SPEC, {})
os._exit(17)
"""
    result = subprocess.run(
        [sys.executable, "-c", program, str(path)], timeout=20, cwd=Path(__file__).parents[1]
    )
    assert result.returncode == 17
    backend = Backend()
    resumed = CheckpointBackend(backend, path, identity={}, resume=True)
    try:
        resumed.invoke(SPEC, {})
        resumed.finish()
        assert backend.calls == 0
    finally:
        resumed.close()


def test_failed_response_save_stops_later_dispatch_and_leaves_uncertainty(tmp_path, monkeypatch):
    path = tmp_path / "calls.json"
    backend = Backend()
    journal = CheckpointBackend(backend, path, identity={}, resume=False)
    save = journal._save

    def fail_completed():
        if journal.state.records and journal.state.records[-1].state == "completed":
            raise OSError("simulated full disk")
        save()

    monkeypatch.setattr(journal, "_save", fail_completed)
    try:
        with pytest.raises(AgentBackendError):
            journal.invoke(SPEC, {})
        with pytest.raises(AgentBackendError):
            journal.invoke(SPEC, {"later": True})
        assert backend.calls == 1
    finally:
        journal.close()
    with pytest.raises(ValueError, match="uncertain"):
        CheckpointBackend(Backend(), path, identity={}, resume=True)


def test_identity_prompt_and_complete_history_are_required(tmp_path):
    path = tmp_path / "calls.json"
    first = CheckpointBackend(Backend(), path, identity={"model": "a"}, resume=False)
    first.invoke(SPEC, {"source": "original"})
    first.close()
    with pytest.raises(ValueError, match="changed"):
        CheckpointBackend(Backend(), path, identity={"model": "b"}, resume=True)
    backend = Backend()
    resumed = CheckpointBackend(backend, path, identity={"model": "a"}, resume=True)
    try:
        with pytest.raises(ValueError, match="complete history"):
            resumed.finish()
        with pytest.raises(AgentBackendError, match="replay failed"):
            resumed.invoke(SPEC, {"source": "changed"})
        with pytest.raises(AgentBackendError, match="stopped"):
            resumed.invoke(SPEC, {"source": "original"})
        assert backend.calls == 0
    finally:
        resumed.close()


@pytest.mark.parametrize("response", [{"summary": "malformed-secret"}, {"summary": "\ud800"}])
def test_invalid_response_is_not_persisted_and_error_is_replayed(tmp_path, response):
    path = tmp_path / "calls.json"
    first = CheckpointBackend(Backend(response), path, identity={}, resume=False)
    try:
        with pytest.raises(AgentBackendError):
            first.invoke(SPEC, {})
    finally:
        first.close()
    assert "malformed-secret" not in path.read_text()
    assert json.loads(path.read_text())["records"][0]["response"] is None
    backend = Backend()
    resumed = CheckpointBackend(backend, path, identity={}, resume=True)
    try:
        with pytest.raises(AgentBackendError):
            resumed.invoke(SPEC, {})
        resumed.finish()
        assert backend.calls == 0
    finally:
        resumed.close()


def test_lock_permissions_links_and_torn_state_are_rejected(tmp_path):
    path = tmp_path / "calls.json"
    first = CheckpointBackend(Backend(), path, identity={}, resume=False)
    try:
        with pytest.raises(BlockingIOError):
            CheckpointBackend(Backend(), path, identity={}, resume=True)
    finally:
        first.close()
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        CheckpointBackend(Backend(), path, identity={}, resume=True)
    path.chmod(0o600)
    path.write_text('{"version":')
    with pytest.raises(ValueError):
        CheckpointBackend(Backend(), path, identity={}, resume=True)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(OSError):
        CheckpointBackend(Backend(), link, identity={}, resume=True)
    with pytest.raises(FileExistsError):
        CheckpointBackend(Backend(), path, identity={}, resume=False)


def test_six_roles_rebuild_facts_and_citations_without_provider_calls(tmp_path):
    scan, sources = source_scan(tmp_path / "source")
    path = tmp_path / "calls.json"
    first = CheckpointBackend(ScriptedBackend(), path, identity={"scan": scan.id}, resume=False)
    try:
        original = SecurityAgentPipeline(first, source_tools=True).run(scan, sources=sources)
        assert first.new_calls == 12
    finally:
        first.close()
    backend = ScriptedBackend()
    resumed = CheckpointBackend(backend, path, identity={"scan": scan.id}, resume=True)
    try:
        replay = SecurityAgentPipeline(resumed, source_tools=True).run(scan, sources=sources)
        assert not backend.calls and resumed.replayed_calls == 12
        assert [s.facts for s in replay.stages] == [s.facts for s in original.stages]
        assert [s.narrative for s in replay.stages] == [s.narrative for s in original.stages]
        assert [s.exploration.citations for s in replay.stages] == [
            s.exploration.citations for s in original.stages
        ]
        assert all(s.exploration.limits == AgentExplorationLimits() for s in replay.stages)
    finally:
        resumed.close()


def test_native_budget_restore_keeps_unknown_reservations_and_limits():
    original = TokenBudget(20_000, max_calls=2)
    for complete in (True, False):
        call = original.reserve(
            "agent:static",
            estimated_input=100,
            max_output=200,
            prompt_bytes=30,
            model="fixture",
            request_digest="sha256:" + "a" * 64,
        )
        original.settle(
            call,
            usage={"input_tokens": 10, "output_tokens": 20} if complete else {},
            usage_complete=complete,
            state="completed" if complete else "unknown",
        )
    resumed = TokenBudget(20_000, max_calls=2)
    resumed.restore_usage(original.get_token_usage())
    assert resumed.get_token_usage() == original.get_token_usage()
    assert resumed.reserved == 300
    assert not resumed.can_spend("agent:static", 1)
    with pytest.raises(ValueError, match="unused"):
        resumed.restore_usage(original.get_token_usage())
    bad = original.get_token_usage().model_copy(update={"input_tokens": 0})
    with pytest.raises(ValueError, match="disagrees"):
        TokenBudget(20_000, max_calls=2).restore_usage(bad)
