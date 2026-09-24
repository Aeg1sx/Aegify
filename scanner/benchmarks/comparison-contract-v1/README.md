# Saved OWASP comparison contract

`hash-to-cookie.json` was produced by `aegify compare-owasp` from the existing
hash-selection and cookie-options reports plus their case CSV files. All four
input artifacts are unchanged. The comparison checks their internal consistency,
recomputes every aggregate/CWE/rule metric and binds exact input/case identities.
It does not rescan an application, execute source or invoke an AI provider.

```bash
cd scanner
aegify compare-owasp benchmarks/hash-selection-v1/owasp-results.json \
  benchmarks/cookie-options-v1/owasp-results.json \
  --baseline-cases benchmarks/hash-selection-v1/owasp-cases.csv \
  --candidate-cases benchmarks/cookie-options-v1/owasp-cases.csv \
  --output-file /path/to/reports/hash-to-cookie.json
```

The command correctly returns **exit 3**: both historical evaluations contain 37
unscored CWE-501 cases. No case regression or coverage loss is observed, but the
overall evaluation remains incomplete and cannot pass a release quality gate.

There are 19 changed case records: 15 CWE-614 negatives change from false positive
to true negative in the all-candidate/advisory channels; four additional records
retain their case outcome while their matched-observation evidence changes.
All changes are retained in the artifact. Filtering only changed aggregate scores
would hide the latter evidence changes. The existing per-channel metrics and
the original reports' limitations remain authoritative for those historical runs.

This artifact validates the comparison workflow. It is not a new detection gain,
an independent label review, a holdout result or a statistical significance claim.
The original public synthetic cases share templates and have not been independently
adjudicated by Aegify maintainers. Artifact hashes identify the supplied reports
and do not authenticate their authors. Separate actual repeated runs are needed
for `--require-identical`; using one saved report twice establishes consistency only.
