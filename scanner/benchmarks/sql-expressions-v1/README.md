# Structural SQL expression regression, 2026-09-24

This records the `AEG-SQL-002` SQL argument and local expression change. It
measures static case selection. It does not establish runtime SQL injection,
general product accuracy, AI-agent quality or application-level recall.

## Corpus and observed change

The official [OWASP Benchmark Python](https://github.com/OWASP-Benchmark/BenchmarkPython)
source and labels are pinned to commit
`f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (upstream GPL-3.0). The archive SHA256 is
`0defda4cce2ea7675fbeae5b059b4d7cca7d49232529367133feb1adfb529096`; the label SHA256 is
`6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c`.
No corpus labels, case matching, thresholds or YAML rules were changed.

The previous detector searched every argument for SQL words and raw `%`, `+`
or formatting substrings. It could flag fixed SQL wildcard literals and arithmetic
inside bound parameters, while missing SQL assembled into a local variable.
The new version selects SQL text structurally, then follows bounded local values.

| All-candidate scope | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Previous full scored set | 209 | 99 | 225 | 660 | 67.86% | 48.16% |
| Current full scored set | 214 | 99 | 220 | 660 | 68.37% | 49.31% |
| Previous CWE-89 subset | 0 | 0 | 5 | 11 | Undefined | 0% |
| Current CWE-89 subset | 5 | 0 | 0 | 11 | 100% | 100% |

Overall F1 is 57.30% and accuracy is 73.26%. Five previously missed positive
CWE-89 cases now have an `AEG-SQL-002` advisory candidate. All other CWE metric
groups and the blocking channel are unchanged. Blocking remains TP=21, FP=28,
FN=413, TN=731. The five changed cases retain their IDs, selected call lines,
construction operators and local origin lines in `owasp-results.json`.

These are only five positive and eleven negative SQL cases, drawn from public,
correlated templates. The SQL precision/recall Wilson 95% intervals are
56.55%–100%; template correlation further limits inference. This result does not
establish 100% SQL accuracy on independent applications. The implementation was
frozen before running the changed scanner on these cases, but the public corpus
was already known and is not a private holdout.

All 1,236 Python files were analyzed with no reported analysis gap. Of 1,230
labels, 1,193 score and 37 CWE-501 cases remain unscored. Each command exits 3:
the full corpus still fails the coverage/quality acceptance gate. Different-CWE
findings remain separately unscored observations, not additional true positives.
The metrics match exact case path and CWE, not individual findings or entire
applications. Parser completion does not imply complete semantic coverage.

## Reproduce

Verify and extract the pinned archive using `../owasp-python-v01/README.md`.
Install this revision's locked scanner dependencies. Keep the corpus and output
directory separate from the scanner checkout. From `scanner/`, run in two
separate processes:

```sh
uv run --locked aegify benchmark-owasp /path/to/BenchmarkPython \
  --expected-results /path/to/BenchmarkPython/expectedresults-0.1.csv \
  --output-file /tmp/sql-expressions-run1.json
uv run --locked aegify benchmark-owasp /path/to/BenchmarkPython \
  --expected-results /path/to/BenchmarkPython/expectedresults-0.1.csv \
  --output-file /tmp/sql-expressions-run2.json
```

These commands parse source as data. They do not execute corpus applications,
install their dependencies, invoke AI or contact application targets. Do not
lower acceptance thresholds or treat exit 3 as a pass.

`owasp-results.json` contains aggregate, per-CWE and per-rule metrics; complete
source, label, configuration, implementation and package provenance; the changed
case evidence; baseline replay evidence; and both run measurements.
`owasp-cases.csv` retains every case outcome and matched rule/count. The preceding
`../cookie-options-v1` report is preserved unchanged.

The baseline was replayed from main commit
`2fd66bd4d72312f02ceba93ce56be5a25faa16a2`. A controlled replay loaded that source
through `PYTHONPATH` into the same locked development environment as the changed
scanner. Package, Python/platform, corpus, label, configuration and evaluated-rule
manifests match. Its metrics and case outcomes reproduce the prior report.
An earlier main-environment replay with additional optional storage packages
also produced identical metrics and outcomes; it is not the controlled baseline.

Both changed-scanner processes produced identical `provenance`, `cases`,
`metrics`, `by_cwe`, `by_rule` and `outcomes_digest`. The shared outcome digest is:

```text
sha256:85223a52deaee427fcc6852d94af095eef652b998aaf7a4b7522567570d87ef7
```

Compare these fields when replaying. Different platform/package manifests must
be disclosed. Raw report hashes and timings are observations, not deterministic
output identities. Runs used a macOS developer machine; the second run and the
controlled baseline overlapped. The JSON retains per-process wall times and RSS
high-water marks. These measurements do not establish a speedup, p95 latency or
service SLO.

## Owned syntax and safety-boundary regression

`tests/test_sql_expression_precision.py` adds 109 owned source checks covering
Python, JavaScript, TypeScript/TSX, paired near misses, local flows and aliases,
serialized facts, incomplete-analysis reporting and bounded work. Fixtures are
parsed, never executed against a database. The full local scanner suite passed
839 tests with one loopback-bind test skipped by the sandbox; coverage was 82.73%.
The separate core taint corpus remained TP=9, FP=0, FN=0.

The two motivating false positives in PR #61's database upgrade test, at lines
79 and 152 of head `81c5f4daed0e7544c3795206bca67cfb612ab29a`, no longer match
`AEG-SQL-002`. A dynamic identifier projection at line 85 is still a candidate;
source review finds fixture schema identifiers constrained by `quotedIdentifier`.
This detector does not model that helper as a sanitizer, and no vulnerability or
runtime impact is claimed. This check does not resolve PR review threads.

See `docs/analysis/rule-authoring.mdx` from the repository root for exact method
selection, grammar versions, extraction limits and unresolved interprocedural,
receiver-binding, alias, sanitizer and control-flow semantics. All construction
findings remain advisory candidates; `AEG-SQL-001` taint analysis is unchanged.
