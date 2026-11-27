# Python XML and control-flow evaluation

Two fresh scanner processes analyzed 1,236 Python files and scored all 1,230 public labels on 2026-11-21. Both produced identical case outcomes with the same implementation and rule digests. The scanner read source without importing the application. The OWASP source revision is `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. [Upstream source and labels](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba)

| Evaluation | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Previous scanner, all candidates | 300 | 98 | 152 | 680 | 75.38% | 66.37% |
| Current scanner, all candidates | 361 | 90 | 91 | 688 | 80.04% | 79.87% |
| Current scanner, advisory | 275 | 58 | 177 | 720 | 82.58% | 60.84% |
| Current scanner, blocking | 118 | 37 | 334 | 741 | 76.13% | 26.11% |

Across all candidates, the scanner recovered 61 missed positives and retained every previously detected positive. It cleared 28 false positives and introduced 20. The strict comparison checks each case and disposition channel independently and returned exit status 1. Both precision and recall are below the 90% acceptance threshold. [Paired case changes](python-changes.json)

## What changed

| Case label | Previous TP / FP / FN / TN | Current TP / FP / FN / TN |
|---|---|---|
| CWE-643 · XPath expressions | 8 / 6 / 43 / 129 | 46 / 6 / 5 / 129 |
| CWE-611 · External XML entities | 8 / 20 / 0 / 0 | 8 / 4 / 0 / 16 |
| CWE-501 · Trust boundary | 8 / 0 / 10 / 19 | 17 / 0 / 1 / 19 |

The XPath rule traces request input into the expression accepted by a resolved `lxml` or `elementpath` call. The SAX/DOM rules distinguish default parser behavior, explicit external-entity configuration and unresolved custom settings. Named local values retain their origin across proved dictionary or INI-option writes and append-only memory streams. The control-flow graph selects provable literal branches and follows iteration over known Flask request collections. These shared changes also affect findings outside XML. [Rule contracts and limitations](../../../docs/analysis/rule-authoring.mdx#python-xml-and-xpath)

A label scores a file and CWE pair. Advisory and blocking channels can overlap. The evaluator leaves 9,469 findings with another CWE and 12 outside a labeled file unadjudicated. The public corpus was available during development. Independent application labels and production measurements remain separate acceptance work.

## Reproduce

Export the pinned upstream tree into an empty directory. The evaluator hashes every file, including auxiliary inputs, so local Git metadata would change the corpus digest. The scan command writes a full report and exits 1 if either 90% detection gate is missed.

```bash
corpus_dir="$(mktemp -d)"
git -C /corpora/BenchmarkPython archive f1291485808b66e20ddb6b01b10dc71b3df8c8ba | tar -x -C "$corpus_dir"
uv run --project scanner --locked aegify benchmark-owasp "$corpus_dir" \
  --expected-results "$corpus_dir/expectedresults-0.1.csv" \
  --output-file /tmp/aegify-python-xml.json

uv run --project scanner --locked aegify compare-owasp \
  scanner/benchmarks/python-xml-v1/python.json /tmp/aegify-python-xml.json \
  --baseline-cases scanner/benchmarks/python-xml-v1/python-cases.csv \
  --output-file /tmp/aegify-python-xml-replay.json
```

The default comparison checks each scored case for regressions. Add `--require-identical` when replaying the exact scanner implementation. The [aggregate report](python.json) and [case inventory](python-cases.csv) retain the evidence required to recompute every metric. The [fresh-process comparison](python-replay.json) records the original replay.

The subsequent Wrangler scanner build scored the same 1,230 Python labels with zero changed cases or lost coverage. The comparator verified the corpus, labels, configuration and case identities across the two implementations. [Paired comparison](wrangler-comparison.json)
