#!/usr/bin/env python3
"""Record the beta.1 inventory correction without rebuilding or retagging it."""

import hashlib
import json
import os
import tomllib
from pathlib import Path

from verify_sbom import verify_sbom


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    source = Path("original-source")
    original = Path("original-assets")
    corrected = Path("corrected-assets")
    bom = json.loads((corrected / "aegify-sbom.cdx.json").read_text())
    lock_path = source / "scanner/uv.lock"
    project = tomllib.loads((source / "scanner/pyproject.toml").read_text())["project"]
    count, edges = verify_sbom(bom, tomllib.loads(lock_path.read_text()), project)
    record = {
        "release_tag": os.environ["RELEASE_TAG"],
        "release_source_commit": os.environ["RELEASE_COMMIT"],
        "correction_source_commit": os.environ["GITHUB_SHA"],
        "correction_workflow_run": (
            f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
            f"{os.environ['GITHUB_RUN_ID']}"
        ),
        "scope": "Universal scanner lockfile, including all extras and development groups",
        "lockfile_sha256": digest(lock_path),
        "dependency_components": count,
        "dependency_edges": edges,
        "generator": bom["metadata"]["tools"],
        "original_assets_sha256": {p.name: digest(p) for p in sorted(original.iterdir())},
        "corrected_sbom_sha256": digest(corrected / "aegify-sbom.cdx.json"),
        "wheel_changed": False,
        "release_tag_changed": False,
    }
    (corrected / "sbom-correction.json").write_text(json.dumps(record, indent=2) + "\n")
    notes = (source / "docs/releases/v0.3.0-beta.1.md").read_text()
    title, body = notes.split("\n", 1)
    correction = Path("docs/releases/v0.3.0-beta.1-sbom-correction.md").read_text()
    Path("corrected-release-notes.md").write_text(f"{title}\n\n{correction}\n{body}")


if __name__ == "__main__":
    main()
