# Flask responses and Python container reads

Two fresh Aegify processes scanned 1,236 Python files and scored 1,230 public OWASP labels on 2026-11-21. Both produced the same outcome for every case in each channel. The input revision was `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. Both runs used the default scanner and bundled rules, with AI disabled. [Upstream source and labels](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba) · [Aggregate and provenance](python.json) · [Replay](python-replay.json)

| Evaluation | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Previous scanner, all candidates | 380 | 72 | 72 | 706 | 84.07% | 84.07% |
| Current scanner, all candidates | 425 | 74 | 27 | 704 | 85.17% | 94.03% |
| Current scanner, advisory | 345 | 51 | 107 | 727 | 87.12% | 76.33% |
| Current scanner, blocking | 153 | 46 | 299 | 732 | 76.88% | 33.85% |

The Flask rule recovered all 31 previously missed XSS positives and flagged zero of 58 XSS negatives. It records the body, the HTTP source and the returned line. Every finding from this rule is advisory. In the blocking channel the XSS positives remain misses. [Response contract](../../../docs/analysis/rule-authoring.mdx#flask-html-response-bodies)

Exact local slot selection recovered another 14 positives across four CWEs. Five involved filesystem paths, three involved code generation, one involved a redirect and five involved XPath queries. Two previously clean negatives received findings. The path case checks the name before a file operation. The redirect case checks the parsed scheme and host before returning. The analyzer traces both values past their guards. Both count as false positives against the published labels. The paired regression gate exits 1. [Case changes](python-changes.json) · [Case inventory](python-cases.csv)

The all-candidate recall passes the 90% threshold. Precision remains below 90%. A case scores one file and CWE pair. The evaluator leaves 9,374 findings for a different CWE and 12 outside the labeled files unadjudicated. Advisory and blocking counts can overlap. The public data was available during development. Independently reviewed applications remain a release requirement. [Previous evaluation](../python-paths-v1/README.md)

## Reproduce

Export the pinned revision from a local copy of the upstream repository, then run the benchmark from the Aegify checkout. The first command that invokes Aegify exits 1 after writing the complete below-threshold report. The identical replay exits 0 with the recorded implementation, inputs and outcomes.

```sh
corpus_dir="$(mktemp -d)"
git -C /corpora/BenchmarkPython archive f1291485808b66e20ddb6b01b10dc71b3df8c8ba | tar -x -C "$corpus_dir"
uv run --project scanner --locked aegify benchmark-owasp "$corpus_dir" \
  --expected-results "$corpus_dir/expectedresults-0.1.csv" \
  --output-file /tmp/aegify-flask-responses.json
uv run --project scanner --locked aegify compare-owasp \
  scanner/benchmarks/flask-responses-v1/python.json /tmp/aegify-flask-responses.json \
  --baseline-cases scanner/benchmarks/flask-responses-v1/python-cases.csv \
  --require-identical --output-file /tmp/aegify-flask-replay.json
```
