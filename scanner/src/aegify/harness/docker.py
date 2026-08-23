"""Local Docker executor with deny-by-default isolation controls."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from aegify.harness.models import (
    VerificationArtifact,
    VerificationPlan,
    VerificationReport,
    VerificationStatus,
    VerificationStep,
    VerificationStepResult,
)


class HarnessUnavailableError(RuntimeError):
    """Raised when Docker is missing or its daemon is not reachable."""


@dataclass
class _OutputCapture:
    """Drain a pipe while retaining only bounded preview bytes."""

    limit: int
    preview: bytearray = field(default_factory=bytearray)
    digest: object = field(default_factory=hashlib.sha256)
    total: int = 0

    def drain(self, pipe: BinaryIO) -> None:
        try:
            for chunk in iter(lambda: pipe.read(64 * 1024), b""):
                self.total += len(chunk)
                self.digest.update(chunk)  # type: ignore[attr-defined]
                remaining = self.limit - len(self.preview)
                if remaining > 0:
                    self.preview.extend(chunk[:remaining])
        finally:
            pipe.close()

    @property
    def sha256(self) -> str:
        return str(self.digest.hexdigest())  # type: ignore[attr-defined]


class DockerVerificationExecutor:
    """Execute a plan against an ephemeral copy, never the source checkout."""

    def __init__(self, docker_binary: str | None = None) -> None:
        self.docker = docker_binary or shutil.which("docker") or ""

    def check_available(self) -> None:
        if not self.docker:
            raise HarnessUnavailableError("Docker CLI is not installed")
        try:
            completed = subprocess.run(
                [self.docker, "info", "--format", "{{json .ServerVersion}}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise HarnessUnavailableError(f"Docker availability check failed: {error}") from error
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()[:1000]
            raise HarnessUnavailableError(f"Docker daemon is unavailable: {detail}")

    def plan(self, plan: VerificationPlan, workspace: Path) -> VerificationReport:
        source = workspace.resolve()
        self._validate_workspace(source)
        workspace_digest = self._workspace_digest(source, plan.policy.exclude)
        commands = [
            self._docker_command(
                plan,
                step,
                Path("<ephemeral-workspace>"),
                f"aegify-plan-{step.id}",
            )
            for step in plan.steps
        ]
        return VerificationReport(
            plan_name=plan.name,
            status=VerificationStatus.PLANNED,
            executed=False,
            image=plan.image,
            workspace_sha256=workspace_digest,
            policy_sha256=self._policy_digest(plan),
            docker_commands=commands,
        )

    def execute(
        self,
        plan: VerificationPlan,
        workspace: Path,
        artifact_directory: Path | None = None,
    ) -> VerificationReport:
        source = workspace.resolve()
        self._validate_workspace(source)
        self.check_available()
        report = VerificationReport(
            plan_name=plan.name,
            status=VerificationStatus.PASSED,
            executed=True,
            image=plan.image,
            workspace_sha256=self._workspace_digest(source, plan.policy.exclude),
            policy_sha256=self._policy_digest(plan),
        )

        with tempfile.TemporaryDirectory(prefix="aegify-verify-") as temp_dir:
            isolated = Path(temp_dir) / "workspace"
            shutil.copytree(
                source,
                isolated,
                symlinks=True,
                ignore=shutil.ignore_patterns(*plan.policy.exclude),
            )
            for step in plan.steps:
                container_name = f"aegify-{uuid.uuid4().hex[:12]}"
                command = self._docker_command(plan, step, isolated, container_name)
                report.docker_commands.append(command)
                result = self._execute_step(plan, step, command, container_name)
                artifacts, artifact_error = self._collect_artifacts(
                    plan,
                    step,
                    isolated,
                    artifact_directory,
                )
                result.artifacts = artifacts
                if artifact_error:
                    result.error = "; ".join(
                        item for item in (result.error, artifact_error) if item
                    )
                    if result.status == VerificationStatus.PASSED:
                        result.status = VerificationStatus.FAILED
                report.steps.append(result)
                if result.status != VerificationStatus.PASSED:
                    report.status = result.status
                    if plan.stop_on_failure:
                        break
        return report

    @staticmethod
    def _collect_artifacts(
        plan: VerificationPlan,
        step: VerificationStep,
        workspace: Path,
        artifact_directory: Path | None,
    ) -> tuple[list[VerificationArtifact], str]:
        artifacts: list[VerificationArtifact] = []
        working_directory = (workspace / step.working_directory).resolve()
        workspace_root = workspace.resolve()
        try:
            working_directory.relative_to(workspace_root)
        except ValueError:
            return [], "step working directory escaped the isolated workspace"
        for relative_output in step.outputs:
            source = (working_directory / relative_output).resolve()
            try:
                source.relative_to(working_directory)
            except ValueError:
                return artifacts, f"output escaped step working directory: {relative_output}"
            if not source.exists():
                return artifacts, f"declared output was not produced: {relative_output}"
            if source.is_symlink() or not source.is_file():
                return artifacts, f"declared output is not a regular file: {relative_output}"
            size = source.stat().st_size
            if size > plan.policy.max_artifact_bytes:
                return artifacts, (
                    f"declared output exceeds {plan.policy.max_artifact_bytes} bytes: "
                    f"{relative_output}"
                )
            digest = hashlib.sha256()
            with source.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            retained_path = ""
            if artifact_directory is not None:
                destination = artifact_directory.resolve() / step.id / relative_output
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                retained_path = str(destination)
            artifacts.append(
                VerificationArtifact(
                    relative_path=relative_output,
                    retained_path=retained_path,
                    size_bytes=size,
                    sha256=digest.hexdigest(),
                )
            )
        return artifacts, ""

    def _execute_step(
        self,
        plan: VerificationPlan,
        step: VerificationStep,
        command: list[str],
        container_name: str,
    ) -> VerificationStepResult:
        started = time.monotonic()
        stdout_capture = _OutputCapture(plan.policy.max_output_bytes)
        stderr_capture = _OutputCapture(plan.policy.max_output_bytes)
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if process.stdout is None or process.stderr is None:
                raise OSError("unable to capture Docker process output")
            threads = [
                threading.Thread(
                    target=stdout_capture.drain,
                    args=(process.stdout,),
                    daemon=True,
                ),
                threading.Thread(
                    target=stderr_capture.drain,
                    args=(process.stderr,),
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()
            try:
                return_code = process.wait(timeout=step.timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
                self._cleanup_container(container_name)
                for thread in threads:
                    thread.join(timeout=5)
                return self._step_result(
                    step,
                    container_name,
                    VerificationStatus.TIMEOUT,
                    started,
                    stdout_capture,
                    stderr_capture,
                    None,
                    f"step exceeded {step.timeout_seconds}s timeout",
                )
            for thread in threads:
                thread.join(timeout=5)
            status_value = (
                VerificationStatus.PASSED if return_code == 0 else VerificationStatus.FAILED
            )
            return self._step_result(
                step,
                container_name,
                status_value,
                started,
                stdout_capture,
                stderr_capture,
                return_code,
            )
        except OSError as error:
            self._cleanup_container(container_name)
            return self._step_result(
                step,
                container_name,
                VerificationStatus.ERROR,
                started,
                stdout_capture,
                stderr_capture,
                None,
                str(error),
            )

    def _docker_command(
        self,
        plan: VerificationPlan,
        step: VerificationStep,
        workspace: Path,
        container_name: str,
    ) -> list[str]:
        workdir = "/workspace"
        if step.working_directory not in {"", "."}:
            workdir = f"/workspace/{step.working_directory}"
        tmpfs_options = ["rw", "nosuid", "nodev"]
        tmpfs_options.append("exec" if plan.policy.tmpfs_executable else "noexec")
        tmpfs_options.append(f"size={plan.policy.tmpfs_size}")
        return [
            self.docker or "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(plan.policy.pids_limit),
            "--memory",
            plan.policy.memory,
            "--cpus",
            str(plan.policy.cpus),
            "--ulimit",
            "nofile=1024:1024",
            "--stop-timeout",
            "5",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--env",
            "HOME=/tmp",
            "--env",
            "XDG_CACHE_HOME=/tmp/.cache",
            "--tmpfs",
            f"/tmp:{','.join(tmpfs_options)}",
            "--mount",
            f"type=bind,src={workspace},dst=/workspace",
            "--workdir",
            workdir,
            plan.image,
            *step.command,
        ]

    def _step_result(
        self,
        step: VerificationStep,
        container_name: str,
        status_value: VerificationStatus,
        started: float,
        stdout: _OutputCapture,
        stderr: _OutputCapture,
        exit_code: int | None,
        error: str = "",
    ) -> VerificationStepResult:
        return VerificationStepResult(
            id=step.id,
            status=status_value,
            command=step.command,
            container_name=container_name,
            exit_code=exit_code,
            duration_seconds=time.monotonic() - started,
            stdout=bytes(stdout.preview).decode("utf-8", errors="replace"),
            stderr=bytes(stderr.preview).decode("utf-8", errors="replace"),
            stdout_sha256=stdout.sha256,
            stderr_sha256=stderr.sha256,
            stdout_truncated=stdout.total > stdout.limit,
            stderr_truncated=stderr.total > stderr.limit,
            error=error,
        )

    def _cleanup_container(self, container_name: str) -> None:
        if not self.docker:
            return
        try:
            subprocess.run(
                [self.docker, "rm", "-f", container_name],
                check=False,
                capture_output=True,
                timeout=10,
            )
        except OSError, subprocess.TimeoutExpired:
            pass

    @staticmethod
    def _validate_workspace(workspace: Path) -> None:
        if not workspace.is_dir():
            raise ValueError(f"verification workspace is not a directory: {workspace}")
        for path in workspace.rglob("*"):
            mode = path.lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                raise ValueError(f"unsupported special file in workspace: {path}")

    @staticmethod
    def _workspace_digest(workspace: Path, exclude: list[str]) -> str:
        digest = hashlib.sha256()
        excluded = set(exclude)
        for path in sorted(workspace.rglob("*")):
            relative = path.relative_to(workspace)
            if any(part in excluded for part in relative.parts):
                continue
            if path.is_symlink():
                digest.update(f"L\0{relative.as_posix()}\0{os.readlink(path)}\n".encode())
            elif path.is_file():
                digest.update(f"F\0{relative.as_posix()}\0".encode())
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                digest.update(b"\n")
        return f"sha256:{digest.hexdigest()}"

    @staticmethod
    def _policy_digest(plan: VerificationPlan) -> str:
        payload = json.dumps(
            plan.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        return f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}"
