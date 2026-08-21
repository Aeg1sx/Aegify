"""Tests for the deny-by-default verification harness contract."""

import hashlib
import io
from pathlib import Path

import pytest

from codeguard.harness.docker import DockerVerificationExecutor, _OutputCapture
from codeguard.harness.models import (
    VerificationPlan,
    VerificationStatus,
    VerificationStepResult,
)

PINNED_IMAGE = f"example.invalid/codeguard/jvm@sha256:{'a' * 64}"


def make_plan(**overrides: object) -> VerificationPlan:
    payload: dict[str, object] = {
        "version": 1,
        "name": "jvm-tests",
        "image": PINNED_IMAGE,
        "steps": [
            {
                "id": "unit",
                "command": ["./gradlew", "test", "--offline"],
                "working_directory": ".",
                "timeout_seconds": 120,
            }
        ],
    }
    payload.update(overrides)
    return VerificationPlan.model_validate(payload)


def test_plan_emits_required_isolation_controls_and_hashes(tmp_path: Path):
    (tmp_path / "App.java").write_text("class App {}\n")

    report = DockerVerificationExecutor("docker").plan(make_plan(), tmp_path)

    command = report.docker_commands[0]
    assert report.status == VerificationStatus.PLANNED
    assert report.workspace_sha256.startswith("sha256:")
    assert report.policy_sha256.startswith("sha256:")
    assert ["--network", "none"] == command[command.index("--network") :][:2]
    assert "--read-only" in command
    assert ["--cap-drop", "ALL"] == command[command.index("--cap-drop") :][:2]
    assert "no-new-privileges" in command
    assert ["--env", "HOME=/tmp"] == command[command.index("--env") :][:2]
    assert "XDG_CACHE_HOME=/tmp/.cache" in command
    assert "type=bind,src=<ephemeral-workspace>,dst=/workspace" in command
    assert str(tmp_path.resolve()) not in " ".join(command)


def test_plan_rejects_mutable_images_secrets_and_non_allowlisted_commands():
    with pytest.raises(ValueError, match="pinned"):
        make_plan(image="eclipse-temurin:21-jdk")

    with pytest.raises(ValueError, match="secrets"):
        make_plan(
            steps=[
                {
                    "id": "leak",
                    "command": ["mvn", "test", "--token=plaintext"],
                }
            ]
        )

    with pytest.raises(ValueError, match="not allowlisted"):
        make_plan(steps=[{"id": "shell", "command": ["sh", "-c", "id"]}])


def test_execute_uses_ephemeral_copy_and_preserves_source(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    original = source / "value.txt"
    original.write_text("original\n")

    class RecordingExecutor(DockerVerificationExecutor):
        def check_available(self) -> None:
            return

        def _execute_step(  # type: ignore[override]
            self,
            plan: VerificationPlan,
            step: object,
            command: list[str],
            container_name: str,
        ) -> VerificationStepResult:
            mount = command[command.index("--mount") + 1]
            source_value = mount.split("src=", 1)[1].split(",dst=", 1)[0]
            isolated = Path(source_value)
            assert isolated != source
            assert isolated.is_dir()
            (isolated / "value.txt").write_text("changed\n")
            return VerificationStepResult(
                id="unit",
                status=VerificationStatus.PASSED,
                command=["./gradlew", "test", "--offline"],
                container_name=container_name,
                exit_code=0,
                stdout_sha256="0" * 64,
                stderr_sha256="0" * 64,
            )

    report = RecordingExecutor("docker").execute(make_plan(), source)

    assert report.status == VerificationStatus.PASSED
    assert report.executed
    assert original.read_text() == "original\n"


def test_output_capture_hashes_full_stream_but_bounds_memory():
    content = b"0123456789"
    capture = _OutputCapture(limit=4)

    capture.drain(io.BytesIO(content))

    assert bytes(capture.preview) == b"0123"
    assert capture.total == len(content)
    assert capture.sha256 == hashlib.sha256(content).hexdigest()


def test_declared_artifact_is_hashed_and_retained_from_ephemeral_copy(
    tmp_path: Path,
):
    source = tmp_path / "source"
    retained = tmp_path / "retained"
    source.mkdir()
    (source / "App.java").write_text("class App {}\n")
    plan = make_plan(
        steps=[
            {
                "id": "scip",
                "command": ["scip-java", "index"],
                "outputs": ["index.scip"],
            }
        ]
    )

    class ArtifactExecutor(DockerVerificationExecutor):
        def check_available(self) -> None:
            return

        def _execute_step(  # type: ignore[override]
            self,
            plan: VerificationPlan,
            step: object,
            command: list[str],
            container_name: str,
        ) -> VerificationStepResult:
            mount = command[command.index("--mount") + 1]
            isolated = Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])
            (isolated / "index.scip").write_bytes(b"compiler-index")
            return VerificationStepResult(
                id="scip",
                status=VerificationStatus.PASSED,
                command=["scip-java", "index"],
                container_name=container_name,
                exit_code=0,
            )

    report = ArtifactExecutor("docker").execute(
        plan,
        source,
        artifact_directory=retained,
    )

    artifact = report.steps[0].artifacts[0]
    assert report.status == VerificationStatus.PASSED
    assert artifact.sha256 == hashlib.sha256(b"compiler-index").hexdigest()
    assert Path(artifact.retained_path).read_bytes() == b"compiler-index"
    assert not (source / "index.scip").exists()
