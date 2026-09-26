# Beta development acceptance, 2026-09-26

This evidence describes development after `v0.3.0-beta.1`. It does not change the
signed release tag or wheel. Source-only benchmarks do not establish runtime
impact, whole-product accuracy, private holdout performance or AI calibration.

## Python detection change

The corpus and original labels are unchanged from `../sql-expressions-v1`:
OWASP Benchmark Python revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`.
Archive SHA-256:
`0defda4cce2ea7675fbeae5b059b4d7cca7d49232529367133feb1adfb529096`.
Label SHA-256:
`6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c`.

The baseline source was frozen from main
`d4bd04e8779e767f0babce6bcdd5b4a6d3ee5922`. The candidate snapshot contains the
Python syntax change before subsequent checkpoint/acceptance tooling was added.
Both run through the same locked Python environment via `PYTHONPATH`; retained
implementation manifests identify their exact code and rule digests. The two
candidate reports have identical provenance and case outcomes. Later non-detector
changes produce a different implementation digest and must not be called an
identical implementation replay.

`python-detector.patch` and `java-runner.patch` reconstruct the early frozen source
snapshots from the baseline commit. Use `git apply --unidiff-zero` with the appropriate
patch in a separate checkout of that exact commit. `snapshot-reconstruction.json`
records verification of both reconstructed code digests. Neither changes upstream corpus data. They are archival
evidence, not additional patches to apply to the current development branch.

| All candidates: 1,193 scored labels | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 214 | 99 | 220 | 660 | 68.37% | 49.31% |
| Candidate | 215 | 94 | 219 | 665 | 69.58% | 49.54% |

The blocking channel changes from TP=21, FP=28, FN=413, TN=731 to TP=24, FP=20,
FN=410, TN=739. Advisory case outcomes do not change. All 1,236 Python files are
analyzed; 37 CWE-501 labels remain unscored. Both benchmark commands exit `3`.
They do not pass full coverage/accuracy acceptance.

**The no-case-regressions gate fails (exit `1`).** Eight FP→TN and one FN→TP
transitions accompany three TN→FP regressions: `BenchmarkTest00007`,
`BenchmarkTest00073` and `BenchmarkTest00520`. Correct `+=` propagation exposes
unsupported guard semantics. We do not suppress these flows, rewrite labels or
change thresholds to manufacture a passing score. The net improvement is five
fewer false-positive cases and one fewer missed case; the tradeoff remains open.

Each `python-*.json` aggregate has a matching `python-*-cases.csv` with all case
outcomes. `python-comparison.json` retains every change and `python-replay.json`
retains the identical-outcome check. Raw report hashes in the comparison refer to
the original embedded-case reports before CSV export. All-candidate results are
case/CWE outcomes, not alert-level adjudication. Public templates are correlated.

```bash
uv run --project scanner --locked aegify benchmark-owasp /corpora/BenchmarkPython \
  --expected-results /corpora/BenchmarkPython/expectedresults-0.1.csv \
  --output-file /tmp/python-current.json
uv run --project scanner --locked aegify compare-owasp \
  scanner/benchmarks/beta-quality-v1/python-baseline.json /tmp/python-current.json \
  --baseline-cases scanner/benchmarks/beta-quality-v1/python-baseline-cases.csv \
  --output-file /tmp/python-comparison.json
```

## External Java corpus

[OWASP Benchmark Java](https://github.com/OWASP-Benchmark/BenchmarkJava) is pinned
to `20cbf3d11123347e47ed89541e6942836def53f7`; its root license is GPL version 2.
`java-corpus.json` records the archive/label hashes. `java-selection.json` records
every selected upstream path and SHA-256: all 2,766 Java files, the original
2,740-label CSV and the license. Build assets and binaries are not selected.
No corpus code, build tool or dependency installer is run.

Download the pinned archive, then use the bounded local preparer. It checks the
archive hash and every selected file before publishing a new directory:

```bash
curl --fail --location --output /tmp/owasp-java.tar.gz \
  https://codeload.github.com/OWASP-Benchmark/BenchmarkJava/tar.gz/20cbf3d11123347e47ed89541e6942836def53f7
python3.14 scripts/prepare_owasp_java.py /tmp/owasp-java.tar.gz \
  --output /tmp/owasp-java
uv run --project scanner --locked aegify benchmark-owasp /tmp/owasp-java \
  --language java --expected-results /tmp/owasp-java/expectedresults-1.2.csv \
  --output-file /tmp/java-full.json
```

The optional `--sample-per-class 10` preparer flag selects ten cases per exact
CWE/boolean-label group by ascending SHA-256 of case name, before inspecting
scanner outcomes. It retains all helper Java sources and original selected label
values. The result has 220 labels across eleven CWEs, and writes
`sample-selection.json`. A sample result must never be presented as a full-corpus
result. This public, externally authored set is not independently adjudicated or
a private application holdout. The corpus/license and labels have not been
relicensed into the project's owned fixture suite.

The full scan analyzed all 2,766 Java files without reported analysis gaps.
`java-full.json` and `java-full-cases.csv` retain TP=282, FP=60, FN=1,050, TN=1,222
over 2,614 scored labels: precision 82.46%, recall 21.17%. Another 126 labels have
no executed CWE rule, so the command exits `3`. Evaluation wall time was 1,388.57 s
and process peak RSS 1,043,742,720 bytes; this single run overlapped diagnostic work.
It is not a p95 or SLO result.

`java-sample.json`, `java-sample-cases.csv` and `java-sample-selection.json` retain
the preselected 220-label scope: TP=25, FP=12, FN=75, TN=88 over 200 scored labels,
precision 67.57%, recall 25.00%. Twenty labels are unscored. All 246 selected Java
files were analyzed. The two scopes have different class prevalence and must not
be combined or treated as a detector improvement comparison. No Java detector
was tuned on these outcomes in this change. The full scan used the earlier frozen
Java-runner snapshot; the subset used the later acceptance-tooling snapshot, as
recorded by their different implementation digests.

## Provider, recovery and performance evidence

`codex-live.json` records a real Codex CLI `0.155.1` fixture run: six roles, twelve
calls, 110.04 seconds, all protocol/citation checks passed. Model resolution,
native token usage and billing are unobserved. A human-readable review of its
narratives found no adoption of the fixture comment's false runtime-impact claim.
This is a narrow conformance observation, not a measured security-review score.
Claude CLI was absent and API credentials unavailable; no live success is claimed
for them. The harness does not run in ordinary CI.

Checkpoint tests exercise replay without redispatch, abrupt process exit,
uncertain dispatch, full-disk failure, changed inputs, invalid replies, concurrent
writers, file admission, six-role source citations and native-budget restoration.
Checkpoints remain private local files and are deliberately not committed here.

The local full scanner suite passed 1,317 tests at 84.32% coverage with the owned
loopback fixture enabled. The later six saved-evidence checks run separately and
in PR CI. Type checking, lint, rule audit, wheel build, workflow audit and document
checks also pass. None of these checks overrides the per-case quality gate.

Fresh-process scanner measurement records engine/wall latency, per-process peak
RSS, input/implementation/outcome identity and failed samples. Original Python
diagnostic timings overlap other work and do not demonstrate a speedup or SLO.
Use the dedicated sequential performance harness for separately labeled samples.
Small owned-corpus results do not describe production queues or large repositories.

| Sequential workload | Runs | Process median | Process p95 | Engine median | Maximum RSS |
|---|---:|---:|---:|---:|---:|
| Owned core, 5 source files | 20 | 1.198 s | 1.240 s | 0.123 s | 73.19 MiB |
| Java stratified subset, 246 source files | 5 | 28.686 s | 28.887 s | 27.514 s | 154.70 MiB |

`core-performance.json` and `java-performance.json` retain all samples on the
same macOS arm64 host with twelve logical CPUs. They ran sequentially after the
other scanner evaluations had finished. No other scanner workload was active;
the host was not otherwise isolated and OS file caches remained warm. The code
digest matches the final development implementation. Every sample's input,
implementation and outcomes match within its workload. Java label coverage is
still incomplete. With five samples the nearest-rank p95 is simply the maximum,
not a reliable production tail estimate. No speedup against the overlapping
diagnostic runs or service-level latency guarantee is claimed.

See the [acceptance guide](../../../docs/project/beta-quality-acceptance.mdx) for
commands, controls and remaining release gates.
