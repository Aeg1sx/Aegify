# Hash selection regression, 2026-09-24

This records the `AEG-A02-002` / `AEG-A02-003` algorithm-selection fix. It combines
an owned-source comparison with a full rerun of the pinned OWASP Python corpus.
It does not establish general product precision or runtime cryptographic impact.

## Owned-source comparison

At workflow head `16b50dfea661125572a0a05cf310fa350909dc11`, 16 SHA-256 selections
were labeled MD5 and one `SinkPattern("hashlib.sha1", ...)` metadata constructor
was labeled SHA-1. Review of the retained locations found no selected MD5/SHA-1
operation. Exact callee and first-argument selection removes all 17 candidates;
the changed rules add none in this cohort. No GitHub alert was manually dismissed.

`self-scan-comparison.json` pins both rule digests and every source file digest.
The initial comparison included 302 files. The replay inventory retains the 301
tracked files, excluding generated `dashboard/next-env.d.ts`, which contributes
no hash candidate. The 17 removed locations and both rule counts are unchanged.

Use a checkout of the recorded source commit and the changed rule file from this
revision. From the project root, in a checkout with the scanner dependencies
installed:

```sh
git worktree add --detach /tmp/aegify-hash-source 16b50dfea661125572a0a05cf310fa350909dc11
cd scanner
uv run python benchmarks/hash-selection-v1/replay.py \
  --source-root /tmp/aegify-hash-source \
  --changed-rule ../rules/a02-cryptographic-failures/crypto.yml
```

The replay checks source/rule hashes, parses the source as data and compares
deduplicated `(rule, file, line)` candidates. It does not execute corpus code,
invoke a model or make network calls. Expected output is 16 MD5 and one SHA-1
candidate before the change, zero after, 17 removed and zero added. The baseline
commit must exist in the local Git object database.

## OWASP regression and repeatability

The official [OWASP Benchmark Python](https://github.com/OWASP-Benchmark/BenchmarkPython)
source and labels are from commit
`f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (upstream GPL-3.0). Obtain and verify
the archive with the instructions in `../owasp-python-v01/README.md`, then run
the current scanner against that source directory:

```sh
cd scanner
uv run aegify benchmark-owasp /path/to/BenchmarkPython \
  --expected-results /path/to/BenchmarkPython/expectedresults-0.1.csv \
  --output-file /tmp/hash-selection-owasp.json
```

`owasp-results.json` retains all aggregate, per-CWE and per-rule metrics, parser,
package, source/modelpack, rule and configuration provenance. `owasp-cases.csv`
retains all 1,230 case outcomes. The matching contract is unchanged from the
original benchmark. The frozen original files in `owasp-python-v01` are preserved.

Two independent processes produced identical provenance, case outcomes and
metrics. The new outcome digest is
`sha256:45aff2e6f1253bf6252febbdcc95ab18249b0a90f35088d760f8bf958d2a0ec9`.
Per-rule attribution changes from the original baseline, so its digest differs.
All aggregate and per-CWE confusion matrices remain unchanged:

| Scope | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| CWE-328, all candidates | 71 | 0 | 0 | 80 | 100% | 100% |
| All scored cases, all candidates | 209 | 114 | 225 | 645 | 64.71% | 48.16% |
| All scored cases, blocking | 21 | 28 | 413 | 731 | 42.86% | 4.84% |

All 1,236 Python files were analyzed without reported gaps. Thirty-seven CWE-501
cases remain unscored, and both commands correctly exit 3. The whole corpus does
not pass the quality/coverage gate. A public synthetic CWE subset with 100%
observed case precision/recall is not a general accuracy claim or a held-out
application evaluation. Other-CWE findings remain separately unscored.

Observed scan durations are 206.93 and 202.00 seconds; process RSS peaks are
368,787,456 and 367,460,352 bytes. These runs shared a macOS developer machine with
other work. They do not establish a speedup or fixed-hardware service guarantee.
