# Python object deserialization

Aegify scanned the pinned OWASP Benchmark for Python as source on 2026-11-21. The scanner analyzed 1,236 Python files and scored all 1,230 labeled file and CWE pairs. The public inputs were available during development. AI was disabled for both runs. [Upstream revision](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba) · [Aggregate and provenance](python.json) · [Case inventory](python-cases.csv)

| Evaluation | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Previous scanner, all candidates | 425 | 74 | 27 | 704 | 85.17% | 94.03% |
| Updated scanner, all candidates | 425 | 67 | 27 | 711 | 86.38% | 94.03% |
| Updated scanner, advisory | 345 | 44 | 107 | 734 | 88.69% | 76.33% |
| Updated scanner, blocking | 162 | 46 | 290 | 732 | 77.88% | 35.84% |

For CWE-502 the scanner retained all 18 positive cases. Seven of the 12 previously flagged negatives cleared. Five negatives still have an advisory. Local fixed values, import binding, the selected loader and the actual data argument account for the changes. Nine additional positives now have a modeled source-to-reader path in the blocking channel. The blocking channel covers 15 of the 18 positives and flags zero of the 36 negatives. The paired comparison found no label regressions in any channel. [Case changes](python-changes.json) · [Previous evaluation](../flask-responses-v1/README.md)

Advisory and blocking channels overlap. The scorer leaves 9,374 findings for a different CWE and 12 findings outside labeled files unadjudicated. The 90% all-candidate precision target and independent application evaluation remain open. The two fresh processes agreed on every scored case. [Replay comparison](python-replay.json)

## Reproduce

Export the pinned upstream revision into an empty directory. Run the following commands from the Aegify checkout. The benchmark exits 1 after writing its report because precision is below the release target. Comparing an identical replay exits 0.

```sh
corpus_dir="$(mktemp -d)"
git -C /corpora/BenchmarkPython archive f1291485808b66e20ddb6b01b10dc71b3df8c8ba | tar -x -C "$corpus_dir"
uv run --project scanner --locked aegify benchmark-owasp "$corpus_dir" \
  --expected-results "$corpus_dir/expectedresults-0.1.csv" \
  --output-file /tmp/aegify-python-decoders.json
uv run --project scanner --locked aegify compare-owasp \
  scanner/benchmarks/python-decoders-v1/python.json /tmp/aegify-python-decoders.json \
  --baseline-cases scanner/benchmarks/python-decoders-v1/python-cases.csv \
  --require-identical --output-file /tmp/aegify-python-decoders-replay.json
```
