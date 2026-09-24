from __future__ import annotations

import errno
import io
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from aegify.agents.backends import (
    AgentBackendError,
    CommandAgentBackend,
    CommandBackendConfig,
    OpenAIResponsesBackend,
)
from aegify.agents.catalog import AGENT_CATALOG
from aegify.agents.models import AgentRole

SPEC = AGENT_CATALOG[AgentRole.STATIC]
NARRATIVE = {
    "summary": "Static evidence remains incomplete.",
    "claims": [],
    "evidence_gaps": ["No runtime observation"],
    "recommendations": ["Review the owned source fixture."],
}


def _completed() -> dict[str, Any]:
    return {
        "status": "completed",
        "error": None,
        "incomplete_details": None,
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": json.dumps(NARRATIVE)}],
            }
        ],
    }


def _mock_response(monkeypatch: pytest.MonkeyPatch, envelope: Any) -> list[dict[str, Any]]:
    requests = []

    def respond(request: Any, **_kwargs: Any) -> io.BytesIO:
        requests.append(json.loads(request.data))
        return io.BytesIO(json.dumps(envelope).encode())

    class Opener:
        open = staticmethod(respond)

    monkeypatch.setattr("urllib.request.urlopen", respond)
    monkeypatch.setattr("urllib.request.build_opener", lambda *_args: Opener())
    return requests


def _api() -> OpenAIResponsesBackend:
    return OpenAIResponsesBackend("fixture-only-key", model="fixture-model")


def test_openai_sends_strict_schema_and_accepts_completed_narrative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = _mock_response(monkeypatch, _completed())
    assert _api().invoke(SPEC, {}).model_dump() == NARRATIVE
    schema = requests[0]["text"]["format"]["schema"]
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["additionalProperties"] is False
    assert requests[0]["store"] is False


@pytest.mark.parametrize("status", ["incomplete", "failed", "cancelled", "queued", None])
def test_openai_never_accepts_unfinished_envelope_with_valid_json(
    monkeypatch: pytest.MonkeyPatch, status: str | None
) -> None:
    envelope = _completed()
    envelope["status"] = status
    envelope["incomplete_details"] = {"reason": "max_output_tokens"}
    _mock_response(monkeypatch, envelope)
    with pytest.raises(RuntimeError):
        _api().invoke(SPEC, {})


def test_openai_refusal_cannot_be_hidden_by_valid_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = _completed()
    envelope["output"][0]["content"].append({"type": "refusal", "refusal": "Fixture refusal"})
    _mock_response(monkeypatch, envelope)
    with pytest.raises(RuntimeError):
        _api().invoke(SPEC, {})


def test_codex_rejects_oversized_last_message_instead_of_accepting_prefix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    backend = CommandAgentBackend(
        CommandBackendConfig(kind="codex", executable=sys.executable, max_output_bytes=1024),
        tmp_path,
    )

    def run(command: list[str], *_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        output = Path(command[command.index("--output-last-message") + 1])
        output.write_text(json.dumps(NARRATIVE) + " " * 2048)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(backend, "_run", run)
    with pytest.raises(RuntimeError):
        backend.invoke(SPEC, {})


@pytest.mark.parametrize(
    "case",
    [
        "error",
        "inconsistent_status",
        "missing_output",
        "no_message",
        "two_messages",
        "tool_call",
        "wrong_role",
        "partial_message",
        "bad_content",
        "bad_text",
        "two_text_parts",
    ],
)
def test_openai_valid_json_does_not_override_bad_envelope(
    monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    envelope = _completed()
    message = envelope["output"][0]
    if case == "error":
        envelope["error"] = {"message": "private source must not reach an error"}
    elif case == "inconsistent_status":
        envelope["incomplete_details"] = {"reason": "max_output_tokens"}
    elif case == "missing_output":
        envelope.pop("output")
        envelope["output_text"] = json.dumps(NARRATIVE)
    elif case == "no_message":
        envelope["output"] = [{"type": "reasoning", "summary": []}]
    elif case == "two_messages":
        envelope["output"].append(message.copy())
    elif case == "tool_call":
        envelope["output"].append({"type": "function_call", "name": "not_executed"})
    elif case == "wrong_role":
        message["role"] = "user"
    elif case == "partial_message":
        message["status"] = "incomplete"
    elif case == "bad_content":
        message["content"] = None
    elif case == "bad_text":
        message["content"][0]["text"] = NARRATIVE
    elif case == "two_text_parts":
        message["content"].append(message["content"][0].copy())
    _mock_response(monkeypatch, envelope)
    with pytest.raises(AgentBackendError) as error:
        _api().invoke(SPEC, {})
    assert error.value.code in {"invalid_response", "provider_error"}
    assert "private source" not in str(error.value)


def test_openai_accepts_reasoning_item_without_treating_it_as_narrative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = _completed()
    envelope["output"].insert(0, {"type": "reasoning", "summary": []})
    _mock_response(monkeypatch, envelope)
    assert _api().invoke(SPEC, {}).model_dump() == NARRATIVE


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps({"summary": "Missing the required lists"}),
        json.dumps({**NARRATIVE, "claims": [42]}),
        json.dumps({**NARRATIVE, "unexpected": "private source"}),
        json.dumps({**NARRATIVE, "summary": "x" * 12_001}),
        '{"summary":"one","summary":"two"}',
        '{"summary":NaN}',
        "```json\n" + json.dumps(NARRATIVE) + "\n```",
        "[]",
    ],
)
def test_strict_provider_rejects_ambiguous_or_invalid_narrative(
    monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    envelope = _completed()
    envelope["output"][0]["content"][0]["text"] = raw
    _mock_response(monkeypatch, envelope)
    with pytest.raises(AgentBackendError) as error:
        _api().invoke(SPEC, {})
    assert error.value.code == "invalid_response"
    assert "private source" not in str(error.value)


def test_openai_refusal_and_incomplete_have_distinct_stop_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = _completed()
    envelope["output"][0]["content"] = [{"type": "refusal", "refusal": "private content"}]
    _mock_response(monkeypatch, envelope)
    with pytest.raises(AgentBackendError) as refused:
        _api().invoke(SPEC, {})
    assert refused.value.code == "refused"
    assert "private content" not in str(refused.value)
    envelope["status"] = "incomplete"
    _mock_response(monkeypatch, envelope)
    with pytest.raises(AgentBackendError) as incomplete:
        _api().invoke(SPEC, {})
    assert incomplete.value.code == "incomplete"


@pytest.mark.parametrize(
    "failure", ["http", "network", "timeout", "wrapped_timeout", "redirect", "size", "utf8"]
)
def test_openai_transport_bounds_and_errors_do_not_expose_provider_body(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    handlers: list[Any] = []

    class Opener:
        def open(self, request: Any, **_kwargs: Any) -> io.BytesIO:
            if failure == "http":
                raise urllib.error.HTTPError(
                    request.full_url, 429, "private body", {}, io.BytesIO(b"private body")
                )
            if failure == "network":
                raise urllib.error.URLError("private body")
            if failure == "timeout":
                raise TimeoutError("private body")
            if failure == "wrapped_timeout":
                raise urllib.error.URLError(TimeoutError("private body"))
            if failure == "redirect":
                handlers[0].redirect_request(
                    request, None, 302, "private body", {}, "https://not-contacted.invalid/"
                )
            return io.BytesIO(b"x" * 2_000_001 if failure == "size" else b"\xff")

    def build(*items: Any) -> Opener:
        handlers.extend(items)
        return Opener()

    monkeypatch.setattr("urllib.request.build_opener", build)
    with pytest.raises(AgentBackendError) as error:
        _api().invoke(SPEC, {})
    assert "private body" not in str(error.value)
    assert error.value.code == {
        "timeout": "timeout",
        "wrapped_timeout": "timeout",
        "size": "response_limit",
        "utf8": "invalid_response",
    }.get(failure, "provider_error")


def _command_backend(tmp_path: Path, *, limit: int = 1024) -> CommandAgentBackend:
    return CommandAgentBackend(
        CommandBackendConfig(kind="codex", executable=sys.executable, max_output_bytes=limit),
        tmp_path,
    )


@pytest.mark.skipif(os.name != "posix", reason="CLI process containment is POSIX-only")
@pytest.mark.parametrize("streams", ["stdout", "stderr", "both"])
def test_cli_stops_stream_overflow_before_process_finishes(tmp_path: Path, streams: str) -> None:
    backend = _command_backend(tmp_path)
    writes = {
        "stdout": "os.write(1, b'x' * 2048)",
        "stderr": "os.write(2, b'x' * 2048)",
        "both": "os.write(1, b'x' * 600); os.write(2, b'x' * 600)",
    }
    code = f"import os, time; {writes[streams]}; time.sleep(30)"
    start = time.monotonic()
    with pytest.raises(AgentBackendError) as error:
        backend._run([sys.executable, "-c", code], "fixture", {})
    assert error.value.code == "response_limit"
    assert time.monotonic() - start < 5


@pytest.mark.skipif(os.name != "posix", reason="CLI process containment is POSIX-only")
def test_cli_drains_output_while_sending_large_prompt(tmp_path: Path) -> None:
    backend = _command_backend(tmp_path, limit=200_000)
    code = (
        "import os, sys; os.write(2, b'x' * 160000); "
        "prompt = sys.stdin.buffer.read(); print(len(prompt))"
    )
    result = backend._run([sys.executable, "-c", code], "p" * 400_000, {})
    assert result.returncode == 0 and result.stdout.strip() == "400000"
    assert len(result.stderr) == 160_000


@pytest.mark.skipif(os.name != "posix", reason="CLI process containment is POSIX-only")
def test_cli_rejects_valid_output_when_prompt_pipe_closes_early(tmp_path: Path) -> None:
    code = "import os; os.close(0); print('" + json.dumps(NARRATIVE) + "')"
    with pytest.raises(AgentBackendError) as error:
        _command_backend(tmp_path)._run([sys.executable, "-c", code], "p" * 400_000, {})
    assert error.value.code == "process_error"


def _assert_child_stopped(pid: int) -> None:
    try:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            # Linux container PID 1 may retain a stopped orphan as a zombie.
            proc_status = Path(f"/proc/{pid}/stat")
            try:
                status = proc_status.read_text().rsplit(")", 1)[-1].strip()
                if status.startswith("Z"):
                    return
            except FileNotFoundError, ProcessLookupError:
                # Linux can return ESRCH when an exiting task disappears while
                # /proc is being read. Recheck liveness on the next iteration.
                pass
            time.sleep(0.02)
        pytest.fail("owned child continued running after the CLI invocation")
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


@pytest.mark.skipif(os.name != "posix", reason="CLI process containment is POSIX-only")
@pytest.mark.parametrize("error_type", [FileNotFoundError, ProcessLookupError])
def test_owned_child_observer_rechecks_disappearing_proc_status(
    monkeypatch: pytest.MonkeyPatch, error_type: type[OSError]
) -> None:
    owned_pid = 71234
    probes = []

    def probe(pid: int, sig: int) -> None:
        assert pid == owned_pid
        probes.append(sig)
        if sig == 0 and probes.count(0) == 1:
            return
        raise ProcessLookupError(errno.ESRCH, "owned fixture stopped")

    def read_status(path: Path, *args: Any, **kwargs: Any) -> str:
        assert path == Path(f"/proc/{owned_pid}/stat")
        code = errno.ESRCH if error_type is ProcessLookupError else errno.ENOENT
        raise error_type(code, "owned fixture disappeared during read")

    with monkeypatch.context() as patch:
        patch.setattr(os, "kill", probe)
        patch.setattr(Path, "read_text", read_status)
        patch.setattr(time, "sleep", lambda _: None)
        _assert_child_stopped(owned_pid)
    assert probes == [0, 0, signal.SIGKILL]


@pytest.mark.skipif(os.name != "posix", reason="CLI process containment is POSIX-only")
def test_owned_child_observer_rejects_live_child() -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with pytest.raises(pytest.fail.Exception, match="owned child continued running"):
            _assert_child_stopped(child.pid)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="CLI process containment is POSIX-only")
@pytest.mark.parametrize("parent_exits", [False, True])
def test_cli_terminates_owned_descendants_on_timeout_and_success(
    tmp_path: Path, parent_exits: bool
) -> None:
    backend = _command_backend(tmp_path)
    # Accelerate the same deadline path without weakening public config's 10s minimum.
    backend.config = backend.config.model_copy(update={"timeout_seconds": 0.5})
    pid_file = tmp_path / "owned-child.pid"
    code = (
        "import subprocess, sys, time; from pathlib import Path; "
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
        f"Path({str(pid_file)!r}).write_text(str(child.pid)); "
        + ("print('done')" if parent_exits else "time.sleep(30)")
    )
    start = time.monotonic()
    try:
        if parent_exits:
            assert backend._run([sys.executable, "-c", code], "", {}).stdout.strip() == "done"
        else:
            with pytest.raises(AgentBackendError) as error:
                backend._run([sys.executable, "-c", code], "p" * 400_000, {})
            assert error.value.code == "timeout"
        assert time.monotonic() - start < 5
    finally:
        if pid_file.exists():
            _assert_child_stopped(int(pid_file.read_text()))
    assert pid_file.exists(), "the test must actually launch its owned child"


@pytest.mark.skipif(os.name != "posix", reason="CLI process containment is POSIX-only")
def test_codex_monitors_message_file_while_process_runs(tmp_path: Path) -> None:
    backend = _command_backend(tmp_path)
    output = tmp_path / "last-message.json"
    code = (
        "from pathlib import Path; import time; "
        f"Path({str(output)!r}).write_bytes(b'x' * 2048); time.sleep(30)"
    )
    start = time.monotonic()
    with pytest.raises(AgentBackendError) as error:
        backend._run([sys.executable, "-c", code], "", {}, output_path=output)
    assert error.value.code == "response_limit"
    assert time.monotonic() - start < 5


@pytest.mark.parametrize("file_kind", ["missing", "symlink", "fifo", "invalid_utf8", "utf16"])
def test_codex_only_accepts_bounded_regular_utf8_message_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, file_kind: str
) -> None:
    if file_kind == "fifo" and os.name != "posix":
        pytest.skip("FIFO fixture requires POSIX")
    backend = _command_backend(tmp_path)

    def run(command: list[str], *_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        output = Path(command[command.index("--output-last-message") + 1])
        if file_kind == "symlink":
            fixture = tmp_path / "owned-message.json"
            fixture.write_text(json.dumps(NARRATIVE))
            output.symlink_to(fixture)
        elif file_kind == "fifo":
            os.mkfifo(output)
        elif file_kind == "invalid_utf8":
            output.write_bytes(b"\xff")
        elif file_kind == "utf16":
            output.write_bytes(json.dumps(NARRATIVE).encode("utf-16"))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(backend, "_run", run)
    with pytest.raises(AgentBackendError) as error:
        backend.invoke(SPEC, {})
    assert error.value.code == "invalid_response"


@pytest.mark.parametrize("kind", ["codex", "claude"])
def test_cli_invocation_accepts_complete_owned_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str
) -> None:
    backend = CommandAgentBackend(
        CommandBackendConfig(kind=kind, executable=sys.executable), tmp_path
    )
    monkeypatch.setenv("AEGIFY_PRIVATE_FIXTURE_SECRET", "never inherited")

    def run(
        command: list[str], prompt: str, environment: dict[str, str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        assert "AEGIFY_PRIVATE_FIXTURE_SECRET" not in environment
        assert "Static review fixture" in prompt
        if kind == "codex":
            assert command[command.index("--sandbox") + 1] == "read-only"
            assert 'approval_policy="never"' in command
            schema = json.loads(Path(command[command.index("--output-schema") + 1]).read_text())
            assert set(schema["required"]) == set(NARRATIVE)
            Path(command[command.index("--output-last-message") + 1]).write_text(
                json.dumps(NARRATIVE)
            )
            return subprocess.CompletedProcess(command, 0, "", "")
        assert command[command.index("--permission-mode") + 1] == "plan"
        assert command[command.index("--max-turns") + 1] == "1"
        wrapper = {
            "type": "result",
            "subtype": "success",
            "is_error": False,
            "result": json.dumps(NARRATIVE),
        }
        return subprocess.CompletedProcess(command, 0, json.dumps(wrapper), "")

    monkeypatch.setattr(backend, "_run", run)
    assert backend.invoke(SPEC, {"summary": "Static review fixture"}).model_dump() == NARRATIVE


@pytest.mark.parametrize(
    "override",
    [
        {"is_error": True},
        {"subtype": "error_max_turns"},
        {"type": "partial"},
        {"result": NARRATIVE},
        {"api_error_status": 429},
        {"stop_reason": "refusal"},
        {"stop_reason": "max_tokens"},
        {"stop_reason": {}},
    ],
)
def test_claude_result_failure_is_not_a_narrative(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, override: dict[str, Any]
) -> None:
    backend = CommandAgentBackend(
        CommandBackendConfig(kind="claude", executable=sys.executable), tmp_path
    )
    wrapper = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": json.dumps(NARRATIVE),
        **override,
    }
    monkeypatch.setattr(
        backend,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, json.dumps(wrapper), ""),
    )
    with pytest.raises(AgentBackendError):
        backend.invoke(SPEC, {})


@pytest.mark.skipif(os.name != "posix", reason="CLI process containment is POSIX-only")
@pytest.mark.parametrize(
    "code,expected",
    [
        ("import sys; print('private body', file=sys.stderr); sys.exit(7)", "process_error"),
        ("import os; os.write(1, b'\\xff')", "invalid_response"),
    ],
)
def test_cli_process_failure_is_bounded_and_does_not_disclose_stderr(
    tmp_path: Path, code: str, expected: str
) -> None:
    with pytest.raises(AgentBackendError) as error:
        _command_backend(tmp_path)._run([sys.executable, "-c", code], "", {})
    assert error.value.code == expected
    assert "private body" not in str(error.value)


@pytest.mark.skipif(os.name != "posix", reason="CLI process containment is POSIX-only")
@pytest.mark.parametrize("kind", ["codex", "claude"])
def test_cli_full_invocation_with_owned_program(tmp_path: Path, kind: str) -> None:
    executable = tmp_path / "owned-cli-fixture"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\nfrom pathlib import Path\n"
        "prompt = sys.stdin.read()\n"
        "assert 'Static review fixture' in prompt\n"
        f"narrative = {NARRATIVE!r}\n"
        "if '--output-last-message' in sys.argv:\n"
        "    schema_path = Path(sys.argv[sys.argv.index('--output-schema') + 1])\n"
        "    schema = json.loads(schema_path.read_text())\n"
        "    assert set(schema['required']) == set(narrative)\n"
        "    output = Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
        "    output.write_text(json.dumps(narrative))\n"
        "else:\n"
        "    print(json.dumps({'type': 'result', 'subtype': 'success', 'is_error': False, "
        "'stop_reason': 'end_turn', 'result': json.dumps(narrative)}))\n"
    )
    executable.chmod(0o700)
    backend = CommandAgentBackend(
        CommandBackendConfig(kind=kind, executable=str(executable), inherit_environment=[]),
        tmp_path,
    )
    assert backend.invoke(SPEC, {"summary": "Static review fixture"}).model_dump() == NARRATIVE


@pytest.mark.parametrize("outcome,exit_code", [("completed", 0), ("incomplete", 3), ("refused", 3)])
def test_agent_cli_persists_artifact_and_signals_unfinished_review_to_ci(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, outcome: str, exit_code: int
) -> None:
    from typer.testing import CliRunner

    from aegify.cli import app
    from aegify.models import ScanResult

    envelope = _completed()
    if outcome == "incomplete":
        envelope["status"] = "incomplete"
    elif outcome == "refused":
        envelope["output"][0]["content"] = [{"type": "refusal", "refusal": "Fixture refusal"}]
    requests = _mock_response(monkeypatch, envelope)
    source = tmp_path / "scan.json"
    source.write_text(ScanResult(id="owned-empty-scan").model_dump_json())
    artifact = tmp_path / "agent-run.json"
    result = CliRunner().invoke(
        app,
        [
            "agent-run",
            str(source),
            "--provider",
            "openai-api",
            "--model",
            "fixture-model",
            "--workspace",
            str(tmp_path),
            "--output-file",
            str(artifact),
        ],
        env={"OPENAI_API_KEY": "fixture-only-key"},
    )
    assert result.exit_code == exit_code, result.output
    retained = json.loads(artifact.read_text())
    assert retained["scan_id"] == "owned-empty-scan"
    assert len(requests) == 6
    assert retained["status"] == ("completed" if outcome == "completed" else "partial")
    for stage in retained["stages"]:
        assert stage["backend_error_code"] == ("" if outcome == "completed" else outcome)
        assert (stage["narrative"] is not None) == (outcome == "completed")
