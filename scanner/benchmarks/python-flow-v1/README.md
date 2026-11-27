# Python flow evaluation, 2026-11-21

Two fresh scanner processes analyzed all 1,236 Python files at OWASP BenchmarkPython revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. Both scored all 1,230 upstream labels and produced identical case outcomes. The command exits `1` because precision and recall fall below the configured 90% gates. [Upstream source and labels](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba)

| All candidates | Scored | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| Previous scanner, shared cases | 1,193 | 215 | 94 | 219 | 665 | 69.58% | 49.54% |
| Current scanner, shared cases | 1,193 | 228 | 98 | 206 | 661 | 69.94% | 52.53% |
| Current scanner, all labels | 1,230 | 236 | 98 | 216 | 680 | 70.66% | 52.21% |

The engine tracks writes to identity-related Flask session fields and handles two common Python assignment and conditional-expression patterns. The 37 newly scored CWE-501 labels contributed 8 TP, 0 FP, 10 FN and 19 TN. A static session write indicates a candidate for review. Application authorization and the meaning of a session field require additional evidence.

On the 1,193 shared labels, thirteen previously missed positives were detected and one false positive was cleared. Five previously correct negative cases became false positives (`00163`, `00440`, `00504`, `00833`, `01209`). The strict no-regressions comparison exits `1`. The blocking channel scored 41 TP, 29 FP, 411 FN and 749 TN over all labels. Its precision was 58.57% and recall was 9.07%.

The measurement uses exact case/CWE matching. It leaves 9,396 findings with other CWEs and 12 outside labeled cases unadjudicated. Independent application review is still needed for release acceptance. The full-case outcomes, input and implementation digests, channel-specific changes, and second-process comparison are retained alongside this file.

## Replay

Use a clean checkout of the pinned upstream revision and the locked scanner environment. The report must be outside the upstream source tree.

```bash
uv run --project scanner --locked aegify benchmark-owasp /corpora/BenchmarkPython \
  --expected-results /corpora/BenchmarkPython/expectedresults-0.1.csv \
  --output-file /tmp/aegify-python.json
uv run --project scanner --locked aegify compare-owasp \
  scanner/benchmarks/python-flow-v1/python.json /tmp/aegify-python.json \
  --baseline-cases scanner/benchmarks/python-flow-v1/python-cases.csv \
  --require-identical --output-file /tmp/aegify-python-replay.json
```

`python-replay.json` compares the original two embedded-case reports before CSV export. Replaying the retained aggregate and CSV also validates the outcomes digest. The previous implementation and case breakdown are in the [September acceptance record](../beta-quality-v1/README.md).
