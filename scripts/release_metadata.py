"""Validate release identity without importing or executing product code."""

from __future__ import annotations

import ast
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:(a|b|rc)([1-9][0-9]*))?")


def release_metadata(root: Path, requested_tag: str | None = None) -> dict[str, str]:
    project = tomllib.loads((root / "scanner/pyproject.toml").read_text())
    version = project["project"]["version"]
    match = VERSION.fullmatch(version)
    if match is None:
        raise ValueError("Unsupported release version")
    major, minor, patch, stage, number = match.groups()
    public_version = f"{major}.{minor}.{patch}"
    if stage:
        stage_label = {"a": "alpha", "b": "beta", "rc": "rc"}[stage]
        public_version += f"-{stage_label}.{number}"
    tag = f"v{public_version}"
    if requested_tag is not None and requested_tag != tag:
        raise ValueError(f"Release tag must be {tag}; received {requested_tag!r}")

    module = ast.parse((root / "scanner/src/aegify/__init__.py").read_text())
    declarations = [
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        )
    ]
    if declarations != [version]:
        raise ValueError("Scanner runtime version differs from its package metadata")
    lock = tomllib.loads((root / "scanner/uv.lock").read_text())
    locked_versions = [p["version"] for p in lock["package"] if p["name"] == "aegify-sast"]
    if locked_versions != [version]:
        raise ValueError("Scanner lockfile version differs from its package metadata")

    for directory in ("dashboard", "docs"):
        package = json.loads((root / directory / "package.json").read_text())
        npm_lock = json.loads((root / directory / "package-lock.json").read_text())
        versions = (
            package["version"],
            npm_lock["version"],
            npm_lock["packages"][""]["version"],
        )
        if any(value != public_version for value in versions):
            raise ValueError(f"{directory} package/lock versions must match {public_version}")

    sidebar = (root / "dashboard/src/components/sidebar.tsx").read_text()
    worker = (root / "dashboard/scripts/scan-worker.mjs").read_text()
    if f">v{public_version}</p>" not in sidebar or f'version: "{public_version}"' not in worker:
        raise ValueError("Dashboard display/worker version differs from package metadata")

    notes = f"docs/releases/{tag}.md"
    if not (root / notes).is_file() or not (root / notes).read_text().strip():
        raise ValueError(f"Missing reviewed release notes: {notes}")
    return {"tag": tag, "prerelease": str(stage is not None).lower(), "notes": notes}


def main() -> int:
    try:
        if len(sys.argv) > 2:
            raise ValueError("Usage: release_metadata.py [tag]")
        metadata = release_metadata(ROOT, sys.argv[1] if len(sys.argv) == 2 else None)
    except (ValueError, KeyError, OSError, SyntaxError, TypeError) as error:
        print(f"Release metadata check failed: {error}", file=sys.stderr)
        return 1
    for key, value in metadata.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
