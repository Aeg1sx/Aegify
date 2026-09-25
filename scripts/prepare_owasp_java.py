"""Prepare pinned external Java source/labels without executing corpus code."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

EVIDENCE = Path(__file__).resolve().parents[1] / "scanner/benchmarks/beta-quality-v1"


def prepare(archive: Path, output: Path, *, sample_per_class: int | None = None) -> None:
    manifest = json.loads((EVIDENCE / "java-corpus.json").read_text())
    selected = json.loads((EVIDENCE / "java-selection.json").read_text())["files"]
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("output must be a new directory with an existing parent")
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("archive must be a bounded regular file")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != manifest["archive_sha256"]:
        raise ValueError("archive SHA-256 does not match the frozen corpus")
    prefix = "BenchmarkJava-" + manifest["revision"]
    with (
        tarfile.open(archive) as source,
        tempfile.TemporaryDirectory(dir=output.parent) as temporary,
    ):
        members = source.getmembers()
        if len(members) > 20_000 or sum(item.size for item in members) > 256 * 1024 * 1024:
            raise ValueError("archive exceeds entry or byte bounds")
        seen: set[str] = set()
        root = Path(temporary) / "corpus"
        root.mkdir()
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or path.parts[0] != prefix
                or not (member.isdir() or member.isfile())
            ):
                raise ValueError("archive contains inadmissible entries")
            relative = path.relative_to(prefix).as_posix()
            if relative not in selected or member.isdir():
                continue
            if relative in seen or member.size > 1024 * 1024:
                raise ValueError("duplicate or oversized selected input")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("selected input is missing")
            with stream:
                material = stream.read(1024 * 1024 + 1)
            if hashlib.sha256(material).hexdigest() != selected[relative]:
                raise ValueError("selected input digest changed")
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(material)
            seen.add(relative)
        if seen != set(selected):
            raise ValueError("archive is missing selected inputs")
        if sample_per_class is not None:
            sample(root, sample_per_class)
        os.rename(root, output)


def sample(root: Path, per_class: int) -> None:
    """Select by case-name hash within each CWE/label group, before scanning."""
    if not 1 <= per_class <= 100:
        raise ValueError("sample size must be 1–100 per CWE/label class")
    labels = root / "expectedresults-1.2.csv"
    rows = [
        row
        for row in csv.reader(labels.read_text().splitlines())
        if row and not row[0].startswith("#")
    ]
    groups: dict[tuple[str, str], list[list[str]]] = {}
    for row in rows:
        groups.setdefault((row[3], row[2]), []).append(row)
    chosen = sorted(
        [
            row
            for group in groups.values()
            for row in sorted(group, key=lambda row: hashlib.sha256(row[0].encode()).hexdigest())[
                :per_class
            ]
        ]
    )
    names = {row[0] for row in chosen}
    for path in (root / "src/main/java/org/owasp/benchmark/testcode").glob("BenchmarkTest*.java"):
        if path.stem not in names:
            path.unlink()
    with labels.open("w", newline="") as stream:
        csv.writer(stream).writerows(chosen)
    (root / "sample-selection.json").write_text(
        json.dumps(
            {
                "method": "Ascending SHA256(case name), first N within each exact "
                "CWE/boolean-label group",
                "per_class": per_class,
                "full_label_cases": len(rows),
                "selected_label_cases": len(chosen),
                "selected_cases": sorted(names),
                "labels_changed": False,
                "limitations": "Stratified subset with helpers; "
                "not a full-corpus or application holdout result",
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-per-class", type=int)
    arguments = parser.parse_args()
    prepare(arguments.archive, arguments.output, sample_per_class=arguments.sample_per_class)
    print("Prepared digest-verified Java sources and original labels; no corpus code executed")
