# Python credential randomness evaluation

On 2026-11-21 two fresh scanner processes analyzed the 1,236 Python files and all 1,230 labels in OWASP BenchmarkPython revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. Both produced the same case outcomes and implementation fingerprint. [Upstream source and labels](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba)

| All candidates | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Previous Python flow evaluation | 236 | 98 | 216 | 680 | 70.66% | 52.21% |
| With credential-use tracking | 300 | 98 | 152 | 680 | 75.38% | 66.37% |

Aegify follows the standard Python pseudo-random generator into known Flask session credential fields, comparisons with a request credential, and writes to a mapping entry used in such a comparison. Each advisory cites the generator and use lines. Decoy imports, ordinary simulations, secure generators, distinct fields and overwritten values have separate local regression tests. Reviewers determine whether the application uses the value for authentication.

All 64 changed labels went from FN to TP in CWE-330. The category now has 99 TP, 227 TN, zero FP and zero FN. The blocking channel still has 41 TP, 29 FP, 411 FN and 749 TN across all categories. The no-case-regressions comparison passes against the immediately preceding scanner. Five false positives introduced in the earlier Python flow evaluation persist. [Earlier changes](../python-flow-v1/README.md)

Both 90% acceptance gates remain open. The scoring protocol leaves 9,460 findings with a different CWE and 12 outside a labeled file unadjudicated. These totals include reports under overlapping rule IDs. The corpus uses public templates and the scanner was developed with access to them. Independent application labels are still required.

## Reproduce

Use the pinned checkout and locked scanner dependencies. The benchmark writes the full report and exits 1 while the two 90% gates remain open.

```bash
uv run --project scanner --locked aegify benchmark-owasp /corpora/BenchmarkPython \
  --expected-results /corpora/BenchmarkPython/expectedresults-0.1.csv \
  --output-file /tmp/aegify-credential-results.json

uv run --project scanner --locked aegify compare-owasp \
  scanner/benchmarks/credential-randomness-v1/python.json /tmp/aegify-credential-results.json \
  --baseline-cases scanner/benchmarks/credential-randomness-v1/python-cases.csv \
  --require-identical --output-file /tmp/aegify-credential-replay.json
```

The saved [paired comparison](python-changes.json) covers all three disposition channels. The [fresh-process replay](python-replay.json) compares both original full reports. The [aggregate](python.json) and [case inventory](python-cases.csv) retain the data needed to recompute and verify every metric.
