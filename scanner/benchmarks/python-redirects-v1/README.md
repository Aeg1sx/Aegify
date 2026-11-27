# Python HTTP redirect destinations

Two fresh processes running the same installed wheel scored all 1,230 labeled file and CWE pairs from OWASP Benchmark for Python. Both read 1,236 Python source files with AI disabled. The commit used for both evaluations was `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`. [Upstream source](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba) · [Case outcomes](python-cases.csv) · [Evaluation](python.json)

| Build and scope | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Previous scanner, all candidates | 441 | 67 | 11 | 711 | 86.81% | 97.57% |
| Redirect update, all candidates | 445 | 63 | 7 | 715 | 87.60% | 98.45% |
| Previous scanner, CWE-601 | 9 | 5 | 4 | 16 | 64.29% | 69.23% |
| Redirect update, CWE-601 | 13 | 1 | 0 | 20 | 92.86% | 100.00% |

All four recovered positives and four cleared false positives also improved in the blocking channel. Advisory outcomes stayed identical on all 1,230 cases. No labeled case regressed in any channel. The one remaining CWE-601 false positive, BenchmarkTest00598, checks the parsed authority and scheme, but the destination comes from a dynamically selected object's method. Its return type remains unresolved. [Paired comparison](python-changes.json) · [Rule scope and controls](../../../docs/analysis/rule-authoring.mdx#python-http-redirect-destinations)

This public corpus informed development. Its measurements cover the matching labeled CWE in each file. Independent application labels and the overall 90% precision target remain open.

## Replay

Build the wheel from this checkout and install it with the locked dependencies. The recorded macOS arm64 environment used Python 3.14.7 and wheel SHA-256 `64d4899a404316e0c737ccdd5788aefcf028a466acce540f3f579d372a49cdee`. From the Aegify checkout, set `scanner_bin` to the installed CLI and `corpus_dir` to a clean export of the upstream revision above.

```sh
"$scanner_bin" benchmark-owasp "$corpus_dir" \
  --expected-results "$corpus_dir/expectedresults-0.1.csv" \
  --output-file /tmp/aegify-redirect-results.json
"$scanner_bin" compare-owasp scanner/benchmarks/python-redirects-v1/python.json \
  /tmp/aegify-redirect-results.json \
  --baseline-cases scanner/benchmarks/python-redirects-v1/python-cases.csv \
  --require-identical --output-file /tmp/aegify-redirect-replay.json
```

The first command writes the complete report and exits 1 while precision is below target. The second checks input identity, implementation identity and every labeled outcome. [Identical installed-wheel replay](python-replay.json) · [Scanner regression tests](../../tests/test_python_redirect.py)
