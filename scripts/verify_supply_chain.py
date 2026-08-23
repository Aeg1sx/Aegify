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
    for path in workflow_files():
        for reference in USES.findall(path.read_text(encoding="utf-8")):
            if reference.startswith("./") or reference.startswith("docker://"):
                continue
            checked += 1
            if "@" not in reference:
                errors.append(f"{path.relative_to(ROOT)}: action is not pinned: {reference}")
                continue
            revision = reference.rsplit("@", 1)[1]
            if not FULL_SHA.fullmatch(revision):
                errors.append(
                    f"{path.relative_to(ROOT)}: action must use a full commit SHA: {reference}"
                )
    return checked


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
