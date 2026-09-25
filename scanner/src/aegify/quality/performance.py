"""Repeat static benchmarks in fresh processes; retain failures instead of dropping samples."""

from __future__ import annotations

import argparse
import json
import math
import os
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from aegify.quality.artifacts import parse_json_object, read_regular_file, write_report
from aegify.quality.provenance import json_digest


def distribution(values: list[float]) -> dict[str, float | int]:
    if not values or any(not math.isfinite(value) or value <= 0 for value in values):
        raise ValueError("measurements must be positive finite numbers")
    ordered = sorted(values)
    return {
        "samples": len(values),
        "min": min(values),
        "median": statistics.median(values),
        "p95_nearest_rank": ordered[math.ceil(0.95 * len(values)) - 1],
        "max": max(values),
    }


def identity(report: dict[str, Any]) -> str:
    provenance = report["provenance"]
    return json_digest(
        {
            "corpus": provenance.get("corpus_digest", report.get("source_digest")),
            "labels": provenance.get("ground_truth_digest", report.get("ground_truth_digest")),
            "implementation": provenance["implementation"],
            "config": provenance["config_digest"],
            "outcomes": report["outcomes_digest"],
            "evaluation": report.get("evaluation", "owned"),
        }
    )


def measure(
    kind: str, target: Path, labels: Path, *, repeats: int = 10, timeout: int = 300
) -> dict[str, Any]:
    if kind not in {"owned", "owasp-python", "owasp-java"}:
        raise ValueError("unsupported performance corpus")
    if not 2 <= repeats <= 30 or not 1 <= timeout <= 3600:
        raise ValueError("performance repetitions or timeout outside bounds")
    if os.name != "posix":
        raise ValueError("performance process-group limits require POSIX")
    samples: list[dict[str, Any]] = []
    reference: dict[str, Any] | None = None
    with tempfile.TemporaryDirectory(prefix="aegify-performance-") as directory:
        for index in range(repeats):
            path = Path(directory) / f"sample-{index}.json"
            command = [
                sys.executable,
                "-m",
                "aegify.quality.performance",
                "--worker",
                "--kind",
                kind,
                "--target",
                str(target.resolve()),
                "--labels",
                str(labels.resolve()),
                "--output",
                str(path),
            ]
            start = time.monotonic()
            process = None
            timed_out = False
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                returncode = process.wait(timeout=timeout)
            except OSError:
                returncode = None
            except subprocess.TimeoutExpired:
                timed_out = True
                assert process is not None
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                returncode = process.wait()
            except BaseException:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                raise
            sample: dict[str, Any] = {
                "index": index + 1,
                "process_wall_seconds": time.monotonic() - start,
                "returncode": returncode,
                "timed_out": timed_out,
                "valid": False,
            }
            try:
                if timed_out or returncode != 0:
                    raise ValueError("worker_timeout" if timed_out else "worker_failed")
                report = parse_json_object(read_regular_file(path, limit=64 * 1024 * 1024))
                if report["analysis_status"] != "completed" or report["analysis_gaps"]:
                    raise ValueError("analysis_incomplete")
                if reference is None:
                    reference = report
                if identity(report) != identity(reference):
                    raise ValueError("input_implementation_or_outcomes_changed")
                measurement = report["measurement"]
                scan_seconds = measurement["scan_seconds"]
                rss = measurement["peak_rss_self_bytes"]
                distribution([scan_seconds, sample["process_wall_seconds"], rss])
                sample.update(
                    valid=True,
                    scan_seconds=scan_seconds,
                    peak_rss_self_bytes=rss,
                    outcomes_digest=report["outcomes_digest"],
                    report_digest=json_digest(report),
                )
            except OSError, ValueError, KeyError, TypeError:
                sample["error"] = "sample_failed_or_identity_changed"
            samples.append(sample)
            if not sample["valid"]:
                break
    valid = len(samples) == repeats and all(sample["valid"] for sample in samples)
    return {
        "schema_version": 1,
        "evaluation": "fresh-process-static-performance-v1",
        "kind": kind,
        "valid": valid,
        "requested_repeats": repeats,
        "timeout_seconds": timeout,
        "samples": samples,
        "reference_identity": identity(reference) if reference else None,
        "provenance": reference["provenance"] if reference else None,
        "evaluation_complete": reference.get("evaluation_complete") if reference else None,
        "statistics": {
            field: distribution([sample[field] for sample in samples])
            for field in ("process_wall_seconds", "scan_seconds", "peak_rss_self_bytes")
        }
        if valid
        else None,
        "limitations": [
            "Fresh process per sample, sequential; OS filesystem cache is not cleared.",
            "Process wall time includes Python startup, source hashing, scan and report writing.",
            "RSS is each worker's process-lifetime high-water mark; not whole-service memory.",
            "Nearest-rank p95 equals the maximum below 20 samples; this is not a production SLO.",
            "No queue, database, worker concurrency, API latency or live AI provider is measured.",
            "Failed or changed samples invalidate the aggregate; no samples are silently omitted.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=["owned", "owasp-python", "owasp-java"], required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = args.target if args.target.is_dir() else args.target.parent
    if (
        args.output.resolve().is_relative_to(root.resolve())
        or args.output.resolve() == args.labels.resolve()
    ):
        parser.error("output must be outside the corpus and labels")
    if args.worker:
        if args.kind == "owned":
            from aegify.quality.benchmark_runner import run_owned_benchmark

            report = run_owned_benchmark(args.target, args.labels).model_dump(mode="json")
        else:
            from aegify.quality.owasp_runner import run_owasp

            report = run_owasp(args.target, args.labels, language=args.kind.removeprefix("owasp-"))
    else:
        report = measure(
            args.kind, args.target, args.labels, repeats=args.repeats, timeout=args.timeout
        )
    write_report(args.output, json.dumps(report, indent=2))
    raise SystemExit(0 if args.worker or report["valid"] else 1)


if __name__ == "__main__":
    main()
