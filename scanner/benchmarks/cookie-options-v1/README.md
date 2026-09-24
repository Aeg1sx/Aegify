# Structural cookie options regression, 2026-09-24

This records the `AEG-A05-005` / `AEG-A05-006` structural option change and the
shared `boolean_option` rule contract. It measures static case selection, not
runtime cookie behavior or general product accuracy.

## Scope and observed change

The official [OWASP Benchmark Python](https://github.com/OWASP-Benchmark/BenchmarkPython)
source and labels are pinned to commit
`f1291485808b66e20ddb6b01b10dc71b3df8c8ba` (upstream GPL-3.0). Corpus, label,
configuration and case/CWE matching identities match the preceding
`../hash-selection-v1` report. The prior reports are preserved unchanged.

The old unanchored negative lookahead could match after an explicitly true
option; a separate constructor expression also misspelled the true literal.
The new selector reads the selected keyword/object's literal facts and keeps
unresolved values unknown. All cookie matches remain advisory candidates.

| All-candidate scope | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Previous full scored set | 209 | 114 | 225 | 645 | 64.71% | 48.16% |
| Current full scored set | 209 | 99 | 225 | 660 | 67.86% | 48.16% |
| Previous CWE-614 subset | 24 | 15 | 0 | 0 | 61.54% | 100% |
| Current CWE-614 subset | 24 | 0 | 0 | 15 | 100% | 100% |

Overall F1 is 56.33% and accuracy is 72.84%. Every changed case is an official
CWE-614 negative with a literal `secure=True` on the selected call. The report
lists all 15 changed case IDs and source lines. Other-CWE and blocking-channel
metrics are identical to the prior baseline; blocking remains TP=21, FP=28,
FN=413, TN=731. The corpus does not separately establish CWE-1004 accuracy.

All 1,236 Python files were analyzed with no reported analysis gap. Of 1,230
labels, 1,193 score and 37 CWE-501 cases remain unscored. Both commands exit 3.
The full corpus still fails the coverage/quality acceptance gate. Public,
correlated templates are not an independent application or AI evaluation; the
39 cookie cases do not establish 100% general cookie accuracy. Findings with a
different CWE remain separately unscored observations.

## Reproduce

Verify and extract the pinned archive using `../owasp-python-v01/README.md`.
Install this revision's locked scanner dependencies. From `scanner/`, run twice
in separate processes, with the corpus and output directory kept separate:

```sh
uv run --locked aegify benchmark-owasp /path/to/BenchmarkPython \
  --expected-results /path/to/BenchmarkPython/expectedresults-0.1.csv \
  --output-file /tmp/cookie-options-run1.json
uv run --locked aegify benchmark-owasp /path/to/BenchmarkPython \
  --expected-results /path/to/BenchmarkPython/expectedresults-0.1.csv \
  --output-file /tmp/cookie-options-run2.json
```

The commands parse source as data. They do not execute corpus applications,
install their dependencies, invoke AI or contact application targets. Do not
lower the default quality thresholds to treat exit 3 as a pass.

`owasp-results.json` retains aggregate, per-CWE and per-rule metrics; complete
source, label, configuration, parser, package and implementation provenance;
changed outcomes; and both run measurements. `owasp-cases.csv` retains every
case outcome and matched rule/count. All provenance, cases and metric channels
matched across the two observed independent processes. Their outcome digest is:

```text
sha256:5cc2b4a7c50a4250f6711d810863d81d36560aa4442b6b5341877f2b10477198
```

Compare `outcomes_digest`, `cases`, `metrics`, `by_cwe` and `by_rule` between new
JSON reports. Same-environment replay should also match `provenance`; different
platform/package manifests must be disclosed separately. Timings and raw report
hashes are observational, not deterministic output identities.

Observed scan times were 200.82 and 194.71 seconds, with process RSS peaks of
369,623,040 and 370,638,848 bytes. These runs shared a macOS development machine
with other work. They do not establish a speedup, p95 latency or service SLO.

The 60 owned syntax/contract checks in `tests/test_cookie_option_precision.py`
also cover JS/TS/TSX, Go and Java fallback behavior. Those checks establish
selected syntax and uncertainty boundaries, not full framework compatibility.
See `docs/analysis/rule-authoring.mdx` from the repository root for supported
argument shapes, API references and unresolved binding/value-flow limitations.
