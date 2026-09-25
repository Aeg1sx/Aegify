#!/usr/bin/env python3
"""Check uv's universal CycloneDX export against every locked package and edge.

The release inventory includes all project extras and development groups, across
platforms. It describes the source lockfile, not one installed Python environment.
Only registry packages and the editable project root are supported; other source
types must acquire explicit verification before they can enter a release.
"""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from pathlib import Path
from urllib.parse import quote


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_sbom(bom: dict, lock: dict, project: dict) -> tuple[int, int]:
    require(bom.get("bomFormat") == "CycloneDX", "Expected CycloneDX")
    require(bom.get("specVersion") == "1.5", "Expected the pinned uv CycloneDX 1.5 format")
    root_key = (project["name"], project["version"])
    packages = {(p["name"], p["version"]): p for p in lock["package"]}
    require(len(packages) == len(lock["package"]), "Ambiguous lockfile package identities")
    require(root_key in packages and len(packages) > 1, "Missing project or locked dependencies")
    root = bom.get("metadata", {}).get("component", {})
    require((root.get("name"), root.get("version")) == root_key, "Incorrect SBOM project version")
    components = [root, *bom.get("components", [])]
    inventory = {(c["name"], c["version"]): c for c in components}
    require(len(inventory) == len(components), "Duplicate SBOM package identity")
    require(inventory.keys() == packages.keys(), "SBOM package inventory differs from lockfile")
    refs = {c.get("bom-ref"): key for key, c in inventory.items()}
    require(None not in refs and "" not in refs and len(refs) == len(inventory), "Invalid BOM refs")

    for key, package in packages.items():
        component = inventory[key]
        if key == root_key:
            require(package["source"] == {"editable": "."}, "Unsupported project source")
            continue
        require("registry" in package["source"], f"Unsupported package source: {key}")
        expected_purl = f"pkg:pypi/{quote(key[0], safe='')}@{quote(key[1], safe='')}"
        require(component.get("purl") == expected_purl, f"Incorrect package URL: {key}")
        artifacts = [*package.get("wheels", [])]
        if package.get("sdist"):
            artifacts.append(package["sdist"])
        expected = set()
        for artifact in artifacts:
            digest = artifact["hash"]
            require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", digest)), f"Invalid lock hash: {key}")
            expected.add((artifact["url"], "SHA-256", digest.removeprefix("sha256:")))
        actual = {
            (reference["url"], digest["alg"], digest["content"])
            for reference in component.get("externalReferences", [])
            if reference.get("type") == "distribution"
            for digest in reference.get("hashes", [])
        }
        require(bool(expected) and actual == expected, f"Distribution hashes differ: {key}")

    def resolve(dependency: dict) -> tuple[str, str]:
        matches = [
            key
            for key, package in packages.items()
            if key[0] == dependency["name"]
            and ("version" not in dependency or key[1] == dependency["version"])
            and ("source" not in dependency or package["source"] == dependency["source"])
        ]
        require(len(matches) == 1, f"Unresolved or ambiguous dependency: {dependency}")
        return matches[0]

    # Activate project extras/groups and recursively requested dependency extras.
    # Markers are intentionally retained as the union of all supported platforms.
    expected_edges = {key: set() for key in packages}
    active_extras = {key: set() for key in packages}
    active_extras[root_key].update(packages[root_key].get("optional-dependencies", {}))
    reached = {root_key}
    pending = [root_key]
    while pending:
        key = pending.pop()
        package = packages[key]
        dependencies = list(package.get("dependencies", []))
        for extra in active_extras[key]:
            require(
                extra in package.get("optional-dependencies", {}), f"Missing extra: {key}/{extra}"
            )
            dependencies.extend(package["optional-dependencies"][extra])
        if key == root_key:
            for group in package.get("dev-dependencies", {}).values():
                dependencies.extend(group)
        for dependency in dependencies:
            target = resolve(dependency)
            expected_edges[key].add(target)
            extras = set(dependency.get("extra", []))
            if target not in reached or not extras <= active_extras[target]:
                reached.add(target)
                active_extras[target].update(extras)
                pending.append(target)
    require(reached == packages.keys(), "Lockfile contains packages outside the exported closure")

    actual_edges = {}
    for dependency in bom.get("dependencies", []):
        ref = dependency["ref"]
        require(ref in refs and ref not in actual_edges, "Unknown or duplicate dependency node")
        targets = dependency.get("dependsOn", [])
        require(len(targets) == len(set(targets)), "Duplicate dependency edge")
        require(all(target in refs for target in targets), "Dangling dependency reference")
        actual_edges[ref] = {refs[target] for target in targets}
    require(actual_edges.keys() == refs.keys(), "Missing dependency graph nodes")
    for ref, targets in actual_edges.items():
        require(targets == expected_edges[refs[ref]], f"Dependency edges differ: {refs[ref]}")
    return len(packages) - 1, sum(map(len, expected_edges.values()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", type=Path)
    parser.add_argument("--project", type=Path, default=Path("scanner"))
    args = parser.parse_args()
    bom = json.loads(args.sbom.read_text())
    lock = tomllib.loads((args.project / "uv.lock").read_text())
    project = tomllib.loads((args.project / "pyproject.toml").read_text())["project"]
    count, edges = verify_sbom(bom, lock, project)
    print(
        f"SBOM verified: project + {count} locked dependencies, {edges} edges, all artifact hashes"
    )


if __name__ == "__main__":
    main()
