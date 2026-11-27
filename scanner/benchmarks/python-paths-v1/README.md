# Python filesystem path evaluation

Two fresh Aegify processes statically scanned 1,236 Python files and scored all 1,230 public OWASP labels on 2026-11-21. The input files, labels and scanner configuration matched the previous evaluation. Both processes used the same implementation and produced identical case outcomes. The source tree was exported at revision `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. [OWASP source and labels](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba)

| Evaluation | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Previous scanner, all candidates | 361 | 90 | 91 | 688 | 80.04% | 79.87% |
| Current scanner, all candidates | 380 | 72 | 72 | 706 | 84.07% | 84.07% |
| Current scanner, advisory | 309 | 50 | 143 | 728 | 86.07% | 68.36% |
| Current scanner, blocking | 141 | 44 | 311 | 734 | 76.22% | 31.19% |

All 55 changed all-candidate outcomes were in CWE-22. The scanner detected 60 of the 65 labeled path positives, up from 41. It flagged 27 of 103 labeled negatives, down from 45. Across the full set, 21 previous misses were recovered and 25 previous false positives cleared. Two previously detected positives were missed and seven previously clean negatives received findings. The paired regression gate exits 1. The 90% overall precision and recall gates remain open. [Paired outcomes](python-changes.json) · [Identical replay](python-replay.json)

The two lost positives pass data through a local list whose positions change after a removal. The seven newly flagged negatives compare the resolved path with the allowed directory using a string prefix. The scanner retains the path flow for review. The evaluator uses the upstream labels in all seven cases. [Case inventory](python-cases.csv)

The filesystem model selects the actual path argument, traces locally constructed `pathlib.Path` receivers and recognizes metadata checks in simple conditions. File content, open mode and display names have distinct roles. A metadata-only observation stays advisory. Source code and configuration are evaluated without running the scanned applications. [Rule contract](../../../docs/analysis/rule-authoring.mdx#python-filesystem-paths)

A case scores one file and CWE pair. Advisory and blocking results can overlap. The evaluator leaves 9,371 findings for other CWEs in labeled files and 12 findings outside labeled cases unadjudicated. The public benchmark was available during development. Independent application labels remain an open release requirement.

## Reproduce

Export the pinned upstream revision into an empty directory. Run the scanner and compare the saved outcomes. The scan exits 1 when it writes a complete report below the acceptance thresholds.

```sh
corpus_dir="$(mktemp -d)"
git -C /corpora/BenchmarkPython archive f1291485808b66e20ddb6b01b10dc71b3df8c8ba | tar -x -C "$corpus_dir"
uv run --project scanner --locked aegify benchmark-owasp "$corpus_dir" \
  --expected-results "$corpus_dir/expectedresults-0.1.csv" \
  --output-file /tmp/aegify-python-paths.json
uv run --project scanner --locked aegify compare-owasp \
  scanner/benchmarks/python-paths-v1/python.json /tmp/aegify-python-paths.json \
  --baseline-cases scanner/benchmarks/python-paths-v1/python-cases.csv \
  --require-identical --output-file /tmp/aegify-python-paths-replay.json
```

The aggregate report binds the implementation, rules, corpus, labels, configuration and individual outcomes. The comparison supports the tracked CSV as a case inventory. Absolute checkout paths and process timings can vary between runs. [Aggregate and provenance](python.json)
