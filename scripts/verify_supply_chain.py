#!/usr/bin/env python3
"""Fail closed when executable dependencies are not immutably pinned."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PIN = re.compile(r"@sha256:[0-9a-f]{64}$")
USES = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)


def workflow_files() -> list[Path]:
    files = [ROOT / "action.yml"]
    files.extend((ROOT / ".github" / "workflows").glob("*.yml"))
    files.extend((ROOT / ".github" / "workflows").glob("*.yaml"))
    return sorted(set(files))


def verify_actions(errors: list[str]) -> int:
    checked = 0
    codeql_revisions: set[str] = set()
    for path in workflow_files():
        for reference in USES.findall(path.read_text(encoding="utf-8")):
            if reference.startswith("./") or reference.startswith("docker://"):
                continue
            checked += 1
            if "@" not in reference:
                errors.append(f"{path.relative_to(ROOT)}: action is not pinned: {reference}")
                continue
            revision = reference.rsplit("@", 1)[1]
            if reference.startswith("github/codeql-action/"):
                codeql_revisions.add(revision)
            if not FULL_SHA.fullmatch(revision):
                errors.append(
                    f"{path.relative_to(ROOT)}: action must use a full commit SHA: {reference}"
                )
    if len(codeql_revisions) != 1:
        errors.append("CodeQL init/analyze/upload-sarif must use the same action revision")
    return checked


def verify_uv_versions(errors: list[str]) -> None:
    """A Docker tag update must not diverge from uv's required version or CI."""
    project = (ROOT / "scanner" / "pyproject.toml").read_text(encoding="utf-8")
    required = re.search(r'required-version\s*=\s*"==([0-9.]+)"', project)
    if required is None:
        errors.append("scanner/pyproject.toml must pin uv required-version exactly")
        return
    expected = required.group(1)
    for path in ROOT.rglob("Dockerfile*"):
        if any(part in {".git", ".venv", "node_modules"} for part in path.parts):
            continue
        dockerfile = path.read_text(encoding="utf-8")
        for configured in re.findall(r"ghcr.io/astral-sh/uv:([^@\s]+)@", dockerfile):
            if configured != expected:
                errors.append(f"{path.relative_to(ROOT)}: uv tag must match required-version {expected}")
    for path in workflow_files():
        content = path.read_text(encoding="utf-8")
        # The setup step ends before the next step or job. No YAML dependency
        # is needed for this intentionally constrained workflow convention.
        for setup in re.finditer(r"uses: astral-sh/setup-uv@[^\n]+\n((?:[ \t]+[^\n]*\n)*)", content):
            configured = re.search(r'version:\s*[\'"]?([0-9.]+)', setup.group(1))
            if configured is None or configured.group(1) != expected:
                errors.append(f"{path.relative_to(ROOT)}: setup-uv must use {expected}")


def verify_dockerfiles(errors: list[str]) -> int:
    checked = 0
    for path in sorted(ROOT.rglob("Dockerfile*")):
        if any(part in {".git", ".venv", "node_modules"} for part in path.parts):
            continue
        arguments: dict[str, str] = {}
        for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw_line.strip()
            if line.startswith("ARG ") and "=" in line:
                name, value = line[4:].split("=", 1)
                arguments[name.strip()] = value.strip()
                if name.strip().endswith("_BASE") and not DIGEST_PIN.search(value.strip()):
                    errors.append(
                        f"{path.relative_to(ROOT)}:{line_number}: base image ARG is not digest-pinned"
                    )
            if not line.startswith("FROM "):
                continue
            tokens = [token for token in line.split()[1:] if not token.startswith("--")]
            if not tokens:
                errors.append(f"{path.relative_to(ROOT)}:{line_number}: malformed FROM")
                continue
            image = tokens[0]
            if image == "scratch":
                continue
            checked += 1
            variable = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", image)
            resolved = arguments.get(variable.group(1), "") if variable else image
            if not DIGEST_PIN.search(resolved):
                errors.append(
                    f"{path.relative_to(ROOT)}:{line_number}: base image is not digest-pinned: {image}"
                )
    return checked


def verify_npm_locks(errors: list[str]) -> int:
    checked = 0
    for path in (ROOT / "dashboard" / "package-lock.json", ROOT / "docs" / "package-lock.json"):
        lock = json.loads(path.read_text(encoding="utf-8"))
        if lock.get("lockfileVersion") != 3:
            errors.append(f"{path.relative_to(ROOT)}: package-lock must use lockfileVersion 3")
        for name, package in lock.get("packages", {}).items():
            resolved = package.get("resolved", "")
            if not resolved.startswith("https://registry.npmjs.org/"):
                continue
            checked += 1
            if not package.get("integrity", "").startswith("sha512-"):
                errors.append(
                    f"{path.relative_to(ROOT)}: node_modules/{name} lacks SHA-512 integrity"
                )
    return checked


def verify_uv_lock(errors: list[str]) -> int:
    path = ROOT / "scanner" / "uv.lock"
    checked = 0
    for block in path.read_text(encoding="utf-8").split("[[package]]")[1:]:
        if 'source = { registry = "https://pypi.org/simple" }' not in block:
            continue
        checked += 1
        if 'hash = "sha256:' not in block:
            name = re.search(r'^name = "([^"]+)"', block, re.MULTILINE)
            errors.append(
                f"{path.relative_to(ROOT)}: {name.group(1) if name else 'package'} lacks SHA-256 artifacts"
            )
    return checked


def main() -> int:
    errors: list[str] = []
    actions = verify_actions(errors)
    verify_uv_versions(errors)
    images = verify_dockerfiles(errors)
    npm_packages = verify_npm_locks(errors)
    python_packages = verify_uv_lock(errors)
    if errors:
        print("Supply-chain pinning policy failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(
        "Supply-chain pinning policy passed: "
        f"{actions} actions, {images} images, {npm_packages} npm packages, "
        f"{python_packages} Python packages verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
