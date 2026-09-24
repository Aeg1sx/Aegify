"""Bounded, source-only rule fixtures and a supervised scanner worker.

Fixtures are data, never Python modules or application commands. The process
boundary supplies a wall deadline and output limit; it is not an OS sandbox.
"""

from __future__ import annotations

import json
import math
import os
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegify.quality.benchmark import digest_bytes

MAX_RULE_BYTES = 128 * 1024
MAX_SUITE_BYTES = 2 * 1024 * 1024
MAX_INPUT_BYTES = 3 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_FILE_BYTES = 64 * 1024
RULE_ID_PATTERN = r"^AEG-[A-Z0-9-]{1,80}$"
IDENTITY_PATTERN = r"^[a-z][a-z0-9-]{0,63}$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def source_path(value: str) -> str:
    """Portable, source-relative identities, without normalization aliases."""
    import re

    if (
        len(value) > 256
        or not re.fullmatch(r"[A-Za-z0-9_./-]+", value)
        or any(not part or part.startswith(".") for part in value.split("/"))
        or len(value.split("/")) > 12
    ):
        raise ValueError("source paths must be bounded relative paths without dot segments")
    return value


class FixtureSource(StrictModel):
    path: str
    content: str

    _path = field_validator("path")(source_path)

    @field_validator("content")
    @classmethod
    def valid_content(cls, value: str) -> str:
        if "\0" in value or len(value.encode("utf-8")) > MAX_FILE_BYTES:
            raise ValueError("fixture source exceeds the byte limit or contains NUL")
        return value


class FixtureExpectation(StrictModel):
    rule_id: str = Field(pattern=RULE_ID_PATTERN)
    file_path: str
    line_start: int = Field(ge=1)

    _path = field_validator("file_path")(source_path)


class RuleFixture(StrictModel):
    id: str = Field(pattern=IDENTITY_PATTERN)
    files: list[FixtureSource] = Field(min_length=1, max_length=12)
    expected: list[FixtureExpectation] = Field(max_length=100)

    @model_validator(mode="after")
    def check_sources(self) -> RuleFixture:
        by_path = {item.path: item for item in self.files}
        folded = {item.path.casefold() for item in self.files}
        if len(folded) != len(self.files):
            raise ValueError("fixture contains duplicate or case-colliding source paths")
        for item in self.files:
            parts = item.path.casefold().split("/")
            if any("/".join(parts[:i]) in folded for i in range(1, len(parts))):
                raise ValueError("fixture file and directory paths collide")
        seen = set()
        for expected in self.expected:
            source = by_path.get(expected.file_path)
            if source is None or expected.line_start > len(source.content.splitlines()):
                raise ValueError("expected findings must name an existing source line")
            identity = (expected.rule_id, expected.file_path, expected.line_start)
            if identity in seen:
                raise ValueError("duplicate expected finding")
            seen.add(identity)
        return self


class RuleFixtureSuite(StrictModel):
    schema_version: Literal[1]
    suite_id: str = Field(pattern=IDENTITY_PATTERN)
    suite_version: str = Field(pattern=r"^\d{1,6}\.\d{1,6}\.\d{1,6}$")
    rule_id: str = Field(pattern=RULE_ID_PATTERN)
    cases: list[RuleFixture] = Field(min_length=1, max_length=20)

    @field_validator("schema_version", mode="before")
    @classmethod
    def explicit_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value

    @model_validator(mode="after")
    def check_suite(self) -> RuleFixtureSuite:
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("fixture IDs must be unique")
        total = 0
        for case in self.cases:
            if any(expected.rule_id != self.rule_id for expected in case.expected):
                raise ValueError("every expectation must name the suite rule")
            total += sum(len(item.content.encode("utf-8")) for item in case.files)
        if total > MAX_SOURCE_BYTES:
            raise ValueError("fixture source total exceeds the byte limit")
        return self


class FixtureMetrics(StrictModel):
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    precision: float | None
    recall: float | None

    @classmethod
    def counts(cls, tp: int, fp: int, fn: int) -> FixtureMetrics:
        return cls(
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=tp / (tp + fp) if tp + fp else None,
            recall=tp / (tp + fn) if tp + fn else None,
        )


class FixtureCaseResult(StrictModel):
    id: str
    status: Literal["passed", "failed", "incomplete"]
    source_digest: str
    duration_seconds: float
    files_scanned: int
    evaluated_rules: list[str]
    issues: list[str]
    parse_diagnostics: list[dict[str, Any]]
    actual: list[dict[str, Any]]
    metrics: FixtureMetrics | None
    unmatched_actual: list[str]
    unmatched_expected: list[str]


class FixtureReport(StrictModel):
    schema_version: Literal[1] = 1
    status: Literal["passed", "failed", "incomplete", "error"]
    issues: list[str] = Field(default_factory=list)
    diagnostics: list[dict[str, Any]] = Field(default_factory=list)
    suite_id: str = ""
    rule_id: str = ""
    positive_cases: int = 0
    negative_cases: int = 0
    cases: list[FixtureCaseResult] = Field(default_factory=list)
    metrics: FixtureMetrics | None = None
    manifest: dict[str, Any] = Field(default_factory=dict)
    result_digest: str = ""

    @property
    def exit_code(self) -> int:
        return {"passed": 0, "failed": 1, "error": 2, "incomplete": 3}[self.status]


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def result_digest(report: FixtureReport) -> str:
    """Exclude only runtime duration; keep every finding, gap and input identity."""
    value = report.model_dump(mode="json", exclude={"result_digest"})
    for case in value["cases"]:
        case.pop("duration_seconds")
    return digest_bytes(canonical_json(value))


def strict_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise ValueError("non-finite JSON value")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant)


def read_input(path: Path, limit: int) -> bytes:
    """Do not block opening a FIFO or follow an input symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("input must be a bounded regular file")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("input exceeds its byte limit")
    return raw


class FixtureWorkerError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _supervise(command: list[str], directory: Path, timeout_seconds: float) -> bytes:
    """Fixed scanner command only; never accept fixture-provided commands/env."""
    if os.name != "posix":
        raise FixtureWorkerError("unsupported_platform")
    deadline = time.monotonic() + timeout_seconds
    try:
        process = subprocess.Popen(
            command,
            cwd=directory,
            env={"PATH": os.defpath, "HOME": str(directory), "TMPDIR": str(directory)},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        raise FixtureWorkerError("worker_unavailable") from None
    output = bytearray()
    try:
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FixtureWorkerError("worker_timeout")
                for key, _mask in selector.select(min(remaining, 0.05)):
                    try:
                        chunk = os.read(key.fd, 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fd)
                    elif len(output) + len(chunk) > MAX_OUTPUT_BYTES:
                        raise FixtureWorkerError("worker_output_limit")
                    else:
                        output.extend(chunk)
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        if process.returncode != 0:
            raise FixtureWorkerError("worker_failed")
        return bytes(output)
    except subprocess.TimeoutExpired:
        raise FixtureWorkerError("worker_timeout") from None
    except OSError:
        raise FixtureWorkerError("worker_io_failed") from None
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.stdout is not None:
            process.stdout.close()
        process.wait()


def run_rule_fixtures(
    rule_yaml: str, suite: RuleFixtureSuite, *, timeout_seconds: float = 30
) -> FixtureReport:
    """Run one submitted rule through the real scanner, with no default rules or AI."""
    if os.name != "posix":
        return FixtureReport(status="error", issues=["unsupported_platform"])
    if (
        isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout_seconds)
        or not 0.01 <= timeout_seconds <= 120
    ):
        return FixtureReport(status="error", issues=["invalid_timeout"])
    try:
        rule_bytes = rule_yaml.encode("utf-8")
        if not rule_bytes.strip() or len(rule_bytes) > MAX_RULE_BYTES:
            raise ValueError("invalid rule size")
        # Revalidate even a previously constructed/mutated model.
        suite = RuleFixtureSuite.model_validate(suite.model_dump())
        suite_bytes = canonical_json(suite.model_dump(mode="json"))
        if len(suite_bytes) > MAX_SUITE_BYTES:
            raise ValueError("invalid suite size")
        material = canonical_json(
            {
                "rule_yaml": rule_yaml,
                "suite": suite.model_dump(mode="json"),
                "timeout_seconds": float(timeout_seconds),
            }
        )
        if len(material) > MAX_INPUT_BYTES:
            raise ValueError("invalid request size")
    except ValueError, UnicodeError, RecursionError:
        return FixtureReport(status="error", issues=["invalid_input"])
    manifest = {
        "rule_digest": digest_bytes(rule_bytes),
        "suite_digest": digest_bytes(suite_bytes),
        "wall_timeout_seconds": float(timeout_seconds),
    }
    try:
        with tempfile.TemporaryDirectory(prefix="aegify-rule-fixtures-") as temporary:
            directory = Path(temporary)
            request = directory / "request.json"
            request.write_bytes(material)
            request.chmod(0o400)
            raw = _supervise(
                [sys.executable, "-I", "-m", "aegify.quality.rule_fixture_worker", str(request)],
                directory,
                timeout_seconds,
            )
        report = FixtureReport.model_validate(strict_json(raw))
        if report.status == "error":
            report.manifest = manifest
            report.suite_id = suite.suite_id
            report.rule_id = suite.rule_id
            report.result_digest = result_digest(report)
        else:
            if (
                any(report.manifest.get(key) != value for key, value in manifest.items())
                or report.suite_id != suite.suite_id
                or report.rule_id != suite.rule_id
                or [case.id for case in report.cases] != [case.id for case in suite.cases]
                or report.result_digest != result_digest(report)
            ):
                raise FixtureWorkerError("worker_report_mismatch")
        return report
    except FixtureWorkerError as error:
        code = error.code
    except ValueError, UnicodeError, RecursionError:
        code = "invalid_worker_report"
    except OSError:
        code = "worker_io_failed"
    report = FixtureReport(
        status="error",
        issues=[code],
        suite_id=suite.suite_id,
        rule_id=suite.rule_id,
        manifest=manifest,
    )
    report.result_digest = result_digest(report)
    return report
