# OWASP Benchmark Python 0.1 diagnostic baseline

This is a static-only, exact-case/exact-CWE evaluation of the public Python
benchmark. It is not independent application validation or the official OWASP
BenchmarkUtils scorecard. The upstream application, scripts and dependencies
were not installed or executed, and no source was sent to an AI provider.

## Pinned inputs

- Official repository: <https://github.com/OWASP-Benchmark/BenchmarkPython>
- Commit: `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`
- Archive: <https://codeload.github.com/OWASP-Benchmark/BenchmarkPython/tar.gz/f1291485808b66e20ddb6b01b10dc71b3df8c8ba>
- Archive SHA-256: `0defda4cce2ea7675fbeae5b059b4d7cca7d49232529367133feb1adfb529096`
- Labels: `expectedresults-0.1.csv`
- Label SHA-256: `6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c`
- Label inventory: 1,230 cases, 452 positive and 778 negative, 14 CWEs.
- Source inventory: 1,230 case files, five Python helpers and `app.py`.

Upstream source is GPL-3.0 licensed. It is fetched separately; this directory
contains evaluation metadata and derived case outcomes, not the upstream code.

## Results and scope

The scanner analyzed 1,236 Python files without reported analysis gaps.
Thirty-seven CWE-501 cases have no executed rule with that exact CWE and remain
unscored (18 positive, 19 negative). The scored fraction is 96.99%.

| Channel | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| All candidates | 209 | 114 | 225 | 645 | 64.71% | 48.16% | 55.22% | 71.58% |
| Advisory | 197 | 95 | 237 | 664 | 67.47% | 45.39% | 54.27% | 72.17% |
| Blocking | 21 | 28 | 413 | 731 | 42.86% | 4.84% | 8.70% | 63.03% |

**These are case-level metrics within the exact-CWE scope, not the precision of
all emitted findings.** The scan produced 10,851 findings; 10,332 concern a
different CWE from the case label and 14 fall outside labeled case files. Those
observations remain unscored, not automatically false positives. The remaining
505 observations match the intended case/CWE and collapse to 323 detected cases.
The channel rows overlap: a case can have both advisory and blocking findings.

Candidate recall over **all 452 positive labels**, retaining the unsupported
category in the denominator, is 46.24%. Strict CWE identity gives no implicit
credit for related identifiers such as CWE-338 versus CWE-330. Any future alias
policy must be versioned and disclosed before comparing scores.

The baseline does not pass a 90% precision/recall release gate. It also returns
exit `3` because of the 37 unscored cases. Do not turn that into a successful
quality check or hide the category to increase the score.

`results.json` contains aggregate/CWE/rule metrics, input and implementation
digests, effective configuration and local measurements. `cases.csv` retains all
case outcomes and matched rule IDs. These labels have not been independently
adjudicated by the Aegify maintainers. Wilson intervals are descriptive only;
related synthetic templates violate a simple independent-sample interpretation.

## Replay

1. Use the Aegify revision containing this baseline and synchronize the scanner
   lockfile using its required uv version. Compare implementation, parser, rule,
   package and configuration digests with `results.json`.
2. Download the pinned archive above and verify its SHA-256. Extract into a new
   local directory with Python 3.14's `tarfile` data filter after rejecting links,
   special entries and unexpected paths/sizes. Keep benchmark code as input data.
3. Run the same command from the scanner environment:

```bash
aegify benchmark-owasp /absolute/path/BenchmarkPython-f1291485808b66e20ddb6b01b10dc71b3df8c8ba \
  --expected-results /absolute/path/BenchmarkPython-f1291485808b66e20ddb6b01b10dc71b3df8c8ba/expectedresults-0.1.csv \
  --output-file /absolute/path/outside-corpus/report.json
```

The runner does not download source, invoke a build or read corpus scanner
configuration. All selected inputs, including OpenAPI and data files, contribute
to the corpus hash. Both the label bytes and the corpus must remain unchanged
throughout analysis.

Compare `outcomes_digest` across fresh processes. Full JSON hashes differ when
timing or memory changes; do not mistake those fields for nondeterministic
detection. The recorded local runs are not fixed-hardware p50/p95 or a memory
service-level guarantee. Self and child RSS peaks have different scopes and are
not a simultaneous sum.

## Improvement priorities exposed by this corpus

- Inspect source, sink and interprocedural modeling for missed XSS, SQL and LDAP
  cases; check exact-CWE attribution before interpreting a missing prediction.
- Review path/command/code-flow false positives with nearby owned negatives,
  branch sensitivity and typed sanitizers.
- Correct cookie and XML option handling: matching both positive and negative
  cases is not useful discrimination.
- Review the large number of off-label advisory observations separately.
- Add an explicit CWE-501 model only with supported APIs, evidence and regression
  controls; an empty placeholder rule must not qualify a case for scoring.
- Preserve this baseline, then evaluate changes on separate application-family
  and commit splits to reduce benchmark-specific tuning.
