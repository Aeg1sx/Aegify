# Python LDAP search filters

The locally installed wheel analyzed all 1,236 Python files in the pinned OWASP Benchmark for Python and scored all 1,230 labeled file and CWE pairs on 2026-11-21. The scanner read source text with AI disabled. The benchmark's application and directory services were never started. [Upstream revision](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba) · [Case outcomes](python-cases.csv) · [Evaluation](python.json)

| Build and channel | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Previous scanner, all candidates | 425 | 67 | 27 | 711 | 86.38% | 94.03% |
| Directory search update, all candidates | 441 | 67 | 11 | 711 | 86.81% | 97.57% |
| Directory search update, advisory | 345 | 44 | 107 | 734 | 88.69% | 76.33% |
| Directory search update, blocking | 178 | 46 | 274 | 732 | 79.46% | 39.38% |

The scanner recovered the 16 previously missed CWE-90 positives. Each produced one filter finding under `AEG-A03-001`. All 13 negatives stayed clear. Every other labeled case kept its previous outcome. The advisory and blocking channels can overlap. The scorer left 9,374 different-CWE findings and 12 findings outside labeled files unadjudicated. The public set informed development. Independent application labels and the 90% all-candidate precision target remain open. [Paired changes](python-changes.json) · [Previous evaluation](../directory-boundaries-v1/README.md)

The static model checks the receiver and selects the actual filter argument for each library. It accepts the library filter encoder in a fixed, single-value assertion. The source fixtures cover renamed imports, relative factories, receiver replacement, cross-repository isolation, named operands and encoders in the wrong position. [Rule scope](../../../docs/analysis/rule-authoring.mdx#python-ldap-search-filters) · [Controls](../../tests/test_python_ldap.py)

## Replay

Use the wheel built from this checkout with its locked dependencies. The recorded macOS arm64 run used Python 3.14.7 and wheel SHA-256 `bab263fdca9a4a9474e00ff08c41c60b342b8cf5550f5b6b1957efbd8bcc69c3`. Set `corpus_dir` to a clean export of the upstream revision above and `scanner_bin` to the installed CLI. Run these commands from the Aegify checkout.

```sh
"$scanner_bin" benchmark-owasp "$corpus_dir" \
  --expected-results "$corpus_dir/expectedresults-0.1.csv" \
  --output-file /tmp/aegify-ldap-python.json
"$scanner_bin" compare-owasp scanner/benchmarks/python-ldap-v1/python.json \
  /tmp/aegify-ldap-python.json \
  --baseline-cases scanner/benchmarks/python-ldap-v1/python-cases.csv \
  --require-identical --output-file /tmp/aegify-ldap-replay.json
```

The benchmark writes its full result and exits 1 at the configured precision target. Two fresh installed processes had identical case outcomes and implementation identity. Run the comparison without `--require-identical` when comparing a different scanner build for regressions. [Replay result](python-replay.json)
